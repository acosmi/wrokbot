//! Dataset-bound Desktop master-key canary using the Vault's AES-256-GCM boundary.

use serde::{Deserialize, Serialize};

use super::aead::{aes_gcm_decrypt, aes_gcm_encrypt};
use super::{
    ApplicationKeyPurpose, KeyVersion, NONCE_BYTES, Nonce, SecretBytes, TAG_BYTES, VaultError,
    derive_application_key,
};

const AAD_PREFIX: &[u8] = b"openbot.desktop.vault.canary.v1\0";
const MARKER: &[u8] = b"openbot.desktop.vault.canary.ok.v1";
const ENVELOPE_SCHEMA: &str = "openbot-desktop-vault-canary";
const ENVELOPE_SCHEMA_VERSION: u64 = 1;
const ENVELOPE_MAX_BYTES: usize = 4096;

/// Closed dataset/key identity used only to form the canary AAD.
pub struct DesktopVaultCanaryBinding {
    dataset_id: String,
    deployment_id: String,
    tenant_id: String,
    key_id: String,
    key_version: KeyVersion,
}

impl DesktopVaultCanaryBinding {
    /// Validate the exact R275 identity shape.
    pub fn new(
        dataset_id: impl Into<String>,
        deployment_id: impl Into<String>,
        tenant_id: impl Into<String>,
        key_id: impl Into<String>,
        key_version: KeyVersion,
    ) -> Result<Self, VaultError> {
        let binding = Self {
            dataset_id: dataset_id.into(),
            deployment_id: deployment_id.into(),
            tenant_id: tenant_id.into(),
            key_id: key_id.into(),
            key_version,
        };
        if !valid_hex_id(&binding.dataset_id)
            || !valid_identity(&binding.deployment_id)
            || !valid_identity(&binding.tenant_id)
            || !valid_hex_id(&binding.key_id)
            || binding.key_version.get() != 1
        {
            return Err(VaultError::EnvelopeInvalid);
        }
        Ok(binding)
    }

    fn aad(&self) -> Vec<u8> {
        let mut aad = AAD_PREFIX.to_vec();
        for field in [
            self.dataset_id.as_bytes(),
            self.deployment_id.as_bytes(),
            self.tenant_id.as_bytes(),
            self.key_id.as_bytes(),
        ] {
            aad.extend_from_slice(&(field.len() as u32).to_be_bytes());
            aad.extend_from_slice(field);
        }
        aad.extend_from_slice(&self.key_version.get().to_be_bytes());
        aad
    }
}

impl core::fmt::Debug for DesktopVaultCanaryBinding {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DesktopVaultCanaryBinding(<redacted-identities>)")
    }
}

/// Strict canonical JSON envelope for one Desktop Vault canary.
pub struct DesktopVaultCanaryEnvelope {
    nonce: Nonce,
    ciphertext: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireEnvelope {
    schema: String,
    schema_version: u64,
    nonce: String,
    ciphertext: String,
}

impl DesktopVaultCanaryEnvelope {
    /// Parse a strict, bounded, canonical lowercase-hex canary envelope.
    pub fn parse(value: &str) -> Result<Self, VaultError> {
        if value.len() > ENVELOPE_MAX_BYTES {
            return Err(VaultError::EnvelopeInvalid);
        }
        let wire: WireEnvelope =
            serde_json::from_str(value).map_err(|_| VaultError::EnvelopeInvalid)?;
        if wire.schema != ENVELOPE_SCHEMA || wire.schema_version != ENVELOPE_SCHEMA_VERSION {
            return Err(VaultError::EnvelopeInvalid);
        }
        let nonce = decode_hex(&wire.nonce)?;
        let ciphertext = decode_hex(&wire.ciphertext)?;
        if nonce.len() != NONCE_BYTES || ciphertext.len() != MARKER.len() + TAG_BYTES {
            return Err(VaultError::EnvelopeInvalid);
        }
        Ok(Self {
            nonce: Nonce::from_slice(&nonce)?,
            ciphertext,
        })
    }

    /// Serialize the unique closed field order.
    #[must_use]
    pub fn to_column_value(&self) -> String {
        format!(
            "{{\"schema\":\"{ENVELOPE_SCHEMA}\",\"schemaVersion\":{ENVELOPE_SCHEMA_VERSION},\"nonce\":\"{}\",\"ciphertext\":\"{}\"}}",
            encode_hex(self.nonce.as_bytes()),
            encode_hex(&self.ciphertext)
        )
    }
}

impl core::fmt::Debug for DesktopVaultCanaryEnvelope {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DesktopVaultCanaryEnvelope(<redacted>)")
    }
}

/// Seal the fixed marker under the domain-derived canary key.
pub fn seal_desktop_vault_canary(
    master: &SecretBytes,
    binding: &DesktopVaultCanaryBinding,
    nonce: Nonce,
) -> Result<DesktopVaultCanaryEnvelope, VaultError> {
    let key = derive_application_key(master, ApplicationKeyPurpose::DesktopVaultCanary)?;
    let ciphertext = aes_gcm_encrypt(key.expose(), nonce, &binding.aad(), MARKER)?;
    Ok(DesktopVaultCanaryEnvelope { nonce, ciphertext })
}

/// Authenticate the exact marker under the caller-supplied identity.
pub fn open_desktop_vault_canary(
    master: &SecretBytes,
    binding: &DesktopVaultCanaryBinding,
    envelope: &DesktopVaultCanaryEnvelope,
) -> Result<(), VaultError> {
    let key = derive_application_key(master, ApplicationKeyPurpose::DesktopVaultCanary)?;
    let plaintext = aes_gcm_decrypt(
        key.expose(),
        envelope.nonce,
        &binding.aad(),
        &envelope.ciphertext,
    )?;
    if plaintext != MARKER {
        return Err(VaultError::Decrypt);
    }
    Ok(())
}

fn valid_hex_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identity(value: &str) -> bool {
    (1..=256).contains(&value.len()) && !value.chars().any(|ch| ch == '\0' || ch.is_control())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}

fn decode_hex(value: &str) -> Result<Vec<u8>, VaultError> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(VaultError::EnvelopeInvalid);
    }
    let mut decoded = Vec::with_capacity(value.len() / 2);
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(VaultError::EnvelopeInvalid);
    }
    for pair in pairs {
        decoded.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Ok(decoded)
}

fn nibble(byte: u8) -> Result<u8, VaultError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(VaultError::EnvelopeInvalid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> DesktopVaultCanaryBinding {
        DesktopVaultCanaryBinding::new(
            "1".repeat(32),
            "desktop-local-deployment",
            "desktop-local-tenant",
            "2".repeat(32),
            KeyVersion::new(1),
        )
        .unwrap()
    }

    #[test]
    fn round_trip_and_every_bound_input_are_authenticated() {
        let master = SecretBytes::new(vec![0x5a; 32]);
        let nonce = Nonce::from_array([0x33; NONCE_BYTES]);
        let envelope = seal_desktop_vault_canary(&master, &binding(), nonce).unwrap();
        let wire = envelope.to_column_value();
        let parsed = DesktopVaultCanaryEnvelope::parse(&wire).unwrap();
        open_desktop_vault_canary(&master, &binding(), &parsed).unwrap();
        assert_eq!(parsed.to_column_value(), wire);

        assert!(
            open_desktop_vault_canary(&SecretBytes::new(vec![0x5b; 32]), &binding(), &parsed)
                .is_err()
        );
        for changed in [
            DesktopVaultCanaryBinding::new(
                "3".repeat(32),
                "desktop-local-deployment",
                "desktop-local-tenant",
                "2".repeat(32),
                KeyVersion::new(1),
            )
            .unwrap(),
            DesktopVaultCanaryBinding::new(
                "1".repeat(32),
                "other-deployment",
                "desktop-local-tenant",
                "2".repeat(32),
                KeyVersion::new(1),
            )
            .unwrap(),
            DesktopVaultCanaryBinding::new(
                "1".repeat(32),
                "desktop-local-deployment",
                "other-tenant",
                "2".repeat(32),
                KeyVersion::new(1),
            )
            .unwrap(),
            DesktopVaultCanaryBinding::new(
                "1".repeat(32),
                "desktop-local-deployment",
                "desktop-local-tenant",
                "4".repeat(32),
                KeyVersion::new(1),
            )
            .unwrap(),
        ] {
            assert!(open_desktop_vault_canary(&master, &changed, &parsed).is_err());
        }
    }

    #[test]
    fn envelope_and_binding_shapes_are_closed() {
        let master = SecretBytes::new(vec![0x5a; 32]);
        let wire =
            seal_desktop_vault_canary(&master, &binding(), Nonce::from_array([0x44; NONCE_BYTES]))
                .unwrap()
                .to_column_value();
        for invalid in [
            wire.replace("\"schemaVersion\":1", "\"schemaVersion\":2"),
            wire.replace("\"nonce\":\"", "\"extra\":1,\"nonce\":\""),
            wire.replacen('a', "A", 1),
        ] {
            assert!(DesktopVaultCanaryEnvelope::parse(&invalid).is_err());
        }
        assert!(
            DesktopVaultCanaryBinding::new("x", "d", "t", "2".repeat(32), KeyVersion::new(1))
                .is_err()
        );
        assert!(
            derive_application_key(
                &SecretBytes::new(vec![0; 31]),
                ApplicationKeyPurpose::DesktopVaultCanary
            )
            .is_err()
        );
    }
}
