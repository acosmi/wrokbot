//! `sso_providers.oidc_config/saml_config` 的 v1/plaintext 兼容读与 v2 AAD 写。

use std::collections::BTreeMap;
use std::sync::Arc;

use openbot_contracts::ids::TenantId;
use openbot_domain::vault::{
    ColumnShape, DATA_KEY_BYTES, DataKey, EnvelopeV1, EnvelopeV2, KeyVersion, NONCE_BYTES, Nonce,
    RecordBinding, SecretBytes, SecretId, SecretKind, SecretPrincipal, WrappingKey,
    classify_column, decrypt_v1, open_v2, seal_v2,
};

/// 两个加密列的封闭名字；不能由 SQL/HTTP 输入自由指定。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SsoSecretColumn {
    Oidc,
    Saml,
}

impl SsoSecretColumn {
    pub(crate) const fn sql_name(self) -> &'static str {
        match self {
            Self::Oidc => "oidc_config",
            Self::Saml => "saml_config",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SsoVaultError {
    #[error("sso_vault_key_unavailable")]
    KeyUnavailable,
    #[error("sso_vault_ciphertext_rejected")]
    CiphertextRejected,
    #[error("sso_vault_random_unavailable")]
    RandomUnavailable,
}

#[derive(Debug)]
pub(crate) struct OpenedSsoConfig {
    pub plaintext: SecretBytes,
    pub needs_migration: bool,
}

/// 当前 KEK ring 与 legacy v1 key。Arc 只共享同一 allocation，不复制密钥字节。
#[derive(Clone)]
pub(crate) struct SsoConfigVault {
    tenant: TenantId,
    current_version: KeyVersion,
    keys: Arc<BTreeMap<u32, Arc<WrappingKey>>>,
    legacy_key: Arc<WrappingKey>,
}

impl SsoConfigVault {
    pub(crate) fn single_key(tenant: TenantId, version: KeyVersion, key: WrappingKey) -> Self {
        let key = Arc::new(key);
        Self {
            tenant,
            current_version: version,
            keys: Arc::new(BTreeMap::from([(version.get(), Arc::clone(&key))])),
            legacy_key: key,
        }
    }

    pub(crate) fn seal(
        &self,
        provider_id: &str,
        column: SsoSecretColumn,
        plaintext: &SecretBytes,
    ) -> Result<String, SsoVaultError> {
        let key = self
            .keys
            .get(&self.current_version.get())
            .ok_or(SsoVaultError::KeyUnavailable)?;
        let data_key = random_data_key()?;
        let envelope = seal_v2(
            key,
            &data_key,
            &self.binding(provider_id, column, self.current_version),
            random_nonce()?,
            random_nonce()?,
            plaintext.expose(),
        )
        .map_err(|_| SsoVaultError::CiphertextRejected)?;
        Ok(envelope.to_column_value())
    }

    pub(crate) fn open(
        &self,
        provider_id: &str,
        column: SsoSecretColumn,
        stored: String,
    ) -> Result<OpenedSsoConfig, SsoVaultError> {
        match classify_column(&stored) {
            ColumnShape::Plaintext => Ok(OpenedSsoConfig {
                plaintext: SecretBytes::new(stored.into_bytes()),
                needs_migration: true,
            }),
            ColumnShape::LegacyEnvelope => {
                let envelope =
                    EnvelopeV1::parse(&stored).map_err(|_| SsoVaultError::CiphertextRejected)?;
                let plaintext = decrypt_v1(&self.legacy_key, &envelope)
                    .map_err(|_| SsoVaultError::CiphertextRejected)?;
                Ok(OpenedSsoConfig {
                    plaintext,
                    needs_migration: true,
                })
            }
            ColumnShape::RecordEnvelope => {
                let envelope =
                    EnvelopeV2::parse(&stored).map_err(|_| SsoVaultError::CiphertextRejected)?;
                let version = envelope.key_version();
                let key = self
                    .keys
                    .get(&version.get())
                    .ok_or(SsoVaultError::KeyUnavailable)?;
                let plaintext =
                    open_v2(key, &self.binding(provider_id, column, version), &envelope)
                        .map_err(|_| SsoVaultError::CiphertextRejected)?;
                Ok(OpenedSsoConfig {
                    plaintext,
                    needs_migration: version != self.current_version,
                })
            }
        }
    }

    fn binding(
        &self,
        provider_id: &str,
        column: SsoSecretColumn,
        version: KeyVersion,
    ) -> RecordBinding {
        // SecretKind::Connector 是 credentials 表既有的“外部连接凭据”分类；secret_id 另加
        // sso-provider/column 命名空间，避免和 credentials UUID 身份发生 AAD 等价。
        RecordBinding::new(
            self.tenant.clone(),
            SecretId::new(format!("sso-provider/{provider_id}/{}", column.sql_name())),
            SecretKind::Connector,
            SecretPrincipal::Deployment,
            SecretPrincipal::Deployment,
            version,
        )
    }
}

impl core::fmt::Debug for SsoConfigVault {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SsoConfigVault")
            .field("tenant", &self.tenant)
            .field("current_version", &self.current_version)
            .field("key_versions", &self.keys.keys().collect::<Vec<_>>())
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

fn random_data_key() -> Result<DataKey, SsoVaultError> {
    let mut bytes = vec![0u8; DATA_KEY_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| SsoVaultError::RandomUnavailable)?;
    DataKey::from_bytes(bytes).map_err(|_| SsoVaultError::RandomUnavailable)
}

fn random_nonce() -> Result<Nonce, SsoVaultError> {
    let mut bytes = [0u8; NONCE_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| SsoVaultError::RandomUnavailable)?;
    Ok(Nonce::from_array(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault() -> SsoConfigVault {
        SsoConfigVault::single_key(
            TenantId::new("tenant-1"),
            KeyVersion::new(1),
            WrappingKey::from_bytes(vec![0x42; 32]).unwrap(),
        )
    }

    #[test]
    fn v2_is_bound_to_provider_column_and_tenant() {
        let vault = vault();
        let plaintext = SecretBytes::new(b"customer-directory-secret".to_vec());
        let sealed = vault
            .seal("acme", SsoSecretColumn::Oidc, &plaintext)
            .unwrap();
        assert!(!sealed.contains("customer-directory-secret"));
        let opened = vault
            .open("acme", SsoSecretColumn::Oidc, sealed.clone())
            .unwrap();
        assert_eq!(opened.plaintext.expose(), plaintext.expose());
        assert!(!opened.needs_migration);

        for (provider, column) in [
            ("other", SsoSecretColumn::Oidc),
            ("acme", SsoSecretColumn::Saml),
        ] {
            assert_eq!(
                vault.open(provider, column, sealed.clone()).unwrap_err(),
                SsoVaultError::CiphertextRejected
            );
        }
    }

    #[test]
    fn a_v2_value_sealed_by_another_key_never_returns_ciphertext_as_plaintext() {
        let sealed = vault()
            .seal(
                "acme",
                SsoSecretColumn::Saml,
                &SecretBytes::new(b"saml-signing-material".to_vec()),
            )
            .unwrap();
        let wrong_key = SsoConfigVault::single_key(
            TenantId::new("tenant-1"),
            KeyVersion::new(1),
            WrappingKey::from_bytes(vec![0x24; 32]).unwrap(),
        );

        assert_eq!(
            wrong_key
                .open("acme", SsoSecretColumn::Saml, sealed.clone())
                .unwrap_err(),
            SsoVaultError::CiphertextRejected
        );
        assert!(sealed.starts_with(r#"{"version":2"#));
        assert!(!sealed.contains("saml-signing-material"));
    }

    #[test]
    fn plaintext_is_accepted_only_as_a_migration_input() {
        let opened = vault()
            .open(
                "acme",
                SsoSecretColumn::Oidc,
                r#"{"clientId":"id","clientSecret":"secret"}"#.to_owned(),
            )
            .unwrap();
        assert!(opened.needs_migration);
        assert!(opened.plaintext.expose().ends_with(b"\"}"));
    }
}
