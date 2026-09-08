//! 动态 deployment-owned OIDC/SAML 的输入、公开投影与加密列明文格式。

use std::collections::BTreeSet;

use openbot_contracts::identity_provider::{
    MAX_IDENTITY_PROVIDER_CLIENT_ID_BYTES, MAX_IDENTITY_PROVIDER_CLIENT_SECRET_BYTES,
    MAX_IDENTITY_PROVIDER_DOMAINS, MAX_IDENTITY_PROVIDER_METADATA_BYTES,
    MAX_IDENTITY_PROVIDER_URL_BYTES, MAX_SAML_ENTITY_ID_BYTES,
};
pub use openbot_contracts::identity_provider::{RegisteredIdentityProvider, SsoProtocol};
use openbot_domain::identity::groups::{
    GroupClaimPath, GroupNormalization, IdentityProviderId, IdpGroupMapping,
};
use openbot_domain::vault::SecretBytes;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::auth::oidc::provider::parse_issuer;
use crate::auth::oidc::{EmailDomain, ProviderId};

const STORAGE_VERSION: u8 = 2;
const MAX_ATTRIBUTE_NAME_BYTES: usize = 1024;

/// 动态 SSO 配置错误；不携带 secret、metadata 或管理员输入。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SsoConfigError {
    #[error("sso_config_shape_rejected")]
    ShapeRejected,
    #[error("sso_config_protocol_ambiguous")]
    ProtocolAmbiguous,
    #[error("sso_config_provider_id_rejected")]
    ProviderIdRejected,
    #[error("sso_config_domain_rejected")]
    DomainRejected,
    #[error("sso_config_issuer_rejected")]
    IssuerRejected,
    #[error("sso_config_endpoint_rejected")]
    EndpointRejected,
    #[error("sso_config_group_mapping_rejected")]
    GroupMappingRejected,
    #[error("sso_config_secret_rejected")]
    SecretRejected,
    #[error("sso_config_metadata_rejected")]
    MetadataRejected,
}

/// 管理 API 接收的 secret。Deserialize 后立刻接管 String allocation；不可 Clone/Serialize。
pub struct SecretInput(SecretBytes);

impl SecretInput {
    pub(crate) fn into_secret(self) -> SecretBytes {
        self.0
    }
}

impl core::fmt::Debug for SecretInput {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SecretInput([REDACTED])")
    }
}

impl<'de> Deserialize<'de> for SecretInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(Self(SecretBytes::new(value.into_bytes())))
    }
}

/// Better Auth 兼容的 OIDC 注册体，加两项显式 group mapping。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OidcRegistrationInput {
    pub client_id: String,
    pub client_secret: SecretInput,
    #[serde(default)]
    pub discovery_endpoint: Option<String>,
    #[serde(default)]
    pub group_claim_path: Option<String>,
    #[serde(default)]
    pub group_normalization: Option<String>,
}

/// SAML metadata 输入；URL 不被服务端取回，只接受管理员直接给出的 XML。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlIdpMetadataInput {
    pub metadata: String,
}

/// Better Auth 兼容的 SAML 注册体；本项目只收验证所需的窄面。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SamlRegistrationInput {
    pub entry_point: String,
    pub idp_metadata: SamlIdpMetadataInput,
    #[serde(default)]
    pub email_attribute: Option<String>,
    #[serde(default)]
    pub group_attribute: Option<String>,
    #[serde(default)]
    pub group_normalization: Option<String>,
}

/// 注册/更新的线上 body；OIDC 与 SAML 配置必须恰有一个。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterIdentityProviderInput {
    pub provider_id: String,
    pub issuer: String,
    pub domain: String,
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub oidc_config: Option<OidcRegistrationInput>,
    #[serde(default)]
    pub saml_config: Option<SamlRegistrationInput>,
}

/// 校验后的 OIDC 明文配置；只在 seal/runtime 构造路径短暂存在。
pub(crate) struct OidcSecretConfig {
    pub client_id: String,
    pub client_secret: SecretBytes,
    pub group_claim_path: Option<Vec<String>>,
    pub group_normalization: GroupNormalization,
}

impl core::fmt::Debug for OidcSecretConfig {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OidcSecretConfig")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("group_claim_path", &self.group_claim_path)
            .field("group_normalization", &self.group_normalization)
            .finish()
    }
}

impl OidcSecretConfig {
    pub(crate) fn mapping(
        &self,
        provider: &ProviderId,
    ) -> Result<Option<IdpGroupMapping>, SsoConfigError> {
        self.group_claim_path
            .as_ref()
            .map(|segments| {
                let path = GroupClaimPath::from_segments(segments)
                    .map_err(|_| SsoConfigError::GroupMappingRejected)?;
                Ok(IdpGroupMapping::new(
                    IdentityProviderId::new(provider.as_str()),
                    path,
                    self.group_normalization,
                ))
            })
            .transpose()
    }
}

/// 校验后的 SAML 明文配置。
#[derive(Debug)]
pub(crate) struct SamlSecretConfig {
    pub entry_point: String,
    pub metadata: String,
    pub email_attribute: String,
    pub group_attribute: Option<String>,
    pub group_normalization: GroupNormalization,
}

impl SamlSecretConfig {
    pub(crate) fn mapping(
        &self,
        provider: &ProviderId,
    ) -> Result<Option<IdpGroupMapping>, SsoConfigError> {
        self.group_attribute
            .as_ref()
            .map(|attribute| {
                let path = GroupClaimPath::from_segments([attribute.as_str()])
                    .map_err(|_| SsoConfigError::GroupMappingRejected)?;
                Ok(IdpGroupMapping::new(
                    IdentityProviderId::new(provider.as_str()),
                    path,
                    self.group_normalization,
                ))
            })
            .transpose()
    }
}

/// 经过纯配置校验、尚未做 OIDC discovery/SAML metadata 解析的注册计划。
#[derive(Debug)]
pub(crate) enum RegistrationPlan {
    Oidc {
        provider_id: ProviderId,
        issuer: openidconnect::IssuerUrl,
        domains: BTreeSet<EmailDomain>,
        config: OidcSecretConfig,
    },
    Saml {
        provider_id: ProviderId,
        issuer: String,
        domains: BTreeSet<EmailDomain>,
        config: SamlSecretConfig,
    },
}

impl RegistrationPlan {
    pub(crate) fn parse(input: RegisterIdentityProviderInput) -> Result<Self, SsoConfigError> {
        if input
            .organization_id
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        {
            return Err(SsoConfigError::ShapeRejected);
        }
        let provider_id = ProviderId::parse(&input.provider_id)
            .map_err(|_| SsoConfigError::ProviderIdRejected)?;
        let domains = parse_domains(&input.domain)?;
        match (input.oidc_config, input.saml_config) {
            (Some(oidc), None) => {
                let issuer = validated_issuer(&input.issuer)?;
                validate_nonempty_bounded(&oidc.client_id, MAX_IDENTITY_PROVIDER_CLIENT_ID_BYTES)
                    .map_err(|_| SsoConfigError::ShapeRejected)?;
                if oidc.client_secret.0.is_empty()
                    || oidc.client_secret.0.len() > MAX_IDENTITY_PROVIDER_CLIENT_SECRET_BYTES
                {
                    return Err(SsoConfigError::SecretRejected);
                }
                let expected_discovery = issuer
                    .join(crate::auth::oidc::discovery::DISCOVERY_PATH_SUFFIX)
                    .map_err(|_| SsoConfigError::IssuerRejected)?;
                if oidc
                    .discovery_endpoint
                    .as_deref()
                    .is_some_and(|value| value != expected_discovery.as_str())
                {
                    return Err(SsoConfigError::EndpointRejected);
                }
                let (group_claim_path, group_normalization) =
                    parse_group_mapping(oidc.group_claim_path, oidc.group_normalization)?;
                Ok(Self::Oidc {
                    provider_id,
                    issuer,
                    domains,
                    config: OidcSecretConfig {
                        client_id: oidc.client_id,
                        client_secret: oidc.client_secret.into_secret(),
                        group_claim_path,
                        group_normalization,
                    },
                })
            }
            (None, Some(saml)) => {
                validate_saml_entity_id(&input.issuer)?;
                validate_https_url(&saml.entry_point)?;
                if saml.idp_metadata.metadata.is_empty()
                    || saml.idp_metadata.metadata.len() > MAX_IDENTITY_PROVIDER_METADATA_BYTES
                {
                    return Err(SsoConfigError::MetadataRejected);
                }
                let email_attribute = saml.email_attribute.unwrap_or_else(|| "email".to_owned());
                validate_attribute_name(&email_attribute)?;
                if let Some(attribute) = &saml.group_attribute {
                    validate_attribute_name(attribute)?;
                }
                let normalization =
                    parse_normalization(saml.group_normalization.as_deref())?.unwrap_or_default();
                Ok(Self::Saml {
                    provider_id,
                    issuer: input.issuer,
                    domains,
                    config: SamlSecretConfig {
                        entry_point: saml.entry_point,
                        metadata: saml.idp_metadata.metadata,
                        email_attribute,
                        group_attribute: saml.group_attribute,
                        group_normalization: normalization,
                    },
                })
            }
            _ => Err(SsoConfigError::ProtocolAmbiguous),
        }
    }

    pub(crate) const fn provider_id(&self) -> &ProviderId {
        match self {
            Self::Oidc { provider_id, .. } | Self::Saml { provider_id, .. } => provider_id,
        }
    }

    pub(crate) fn issuer_str(&self) -> &str {
        match self {
            Self::Oidc { issuer, .. } => issuer.as_str(),
            Self::Saml { issuer, .. } => issuer,
        }
    }

    pub(crate) const fn domains(&self) -> &BTreeSet<EmailDomain> {
        match self {
            Self::Oidc { domains, .. } | Self::Saml { domains, .. } => domains,
        }
    }

    pub(crate) const fn protocol(&self) -> SsoProtocol {
        match self {
            Self::Oidc { .. } => SsoProtocol::Oidc,
            Self::Saml { .. } => SsoProtocol::Saml,
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "protocol", rename_all = "lowercase")]
enum StoredConfigRef<'a> {
    Oidc {
        version: u8,
        client_id: &'a str,
        client_secret: &'a str,
        group_claim_path: &'a Option<Vec<String>>,
        group_normalization: &'a str,
    },
    Saml {
        version: u8,
        entry_point: &'a str,
        metadata: &'a str,
        email_attribute: &'a str,
        group_attribute: &'a Option<String>,
        group_normalization: &'a str,
    },
}

pub(crate) fn encode_plan(plan: &RegistrationPlan) -> Result<SecretBytes, SsoConfigError> {
    let stored = match plan {
        RegistrationPlan::Oidc { config, .. } => StoredConfigRef::Oidc {
            version: STORAGE_VERSION,
            client_id: &config.client_id,
            client_secret: core::str::from_utf8(config.client_secret.expose())
                .map_err(|_| SsoConfigError::SecretRejected)?,
            group_claim_path: &config.group_claim_path,
            group_normalization: config.group_normalization.as_str(),
        },
        RegistrationPlan::Saml { config, .. } => StoredConfigRef::Saml {
            version: STORAGE_VERSION,
            entry_point: &config.entry_point,
            metadata: &config.metadata,
            email_attribute: &config.email_attribute,
            group_attribute: &config.group_attribute,
            group_normalization: config.group_normalization.as_str(),
        },
    };
    serde_json::to_vec(&stored)
        .map(SecretBytes::new)
        .map_err(|_| SsoConfigError::ShapeRejected)
}

pub(crate) fn encode_decoded(config: &DecodedSecretConfig) -> Result<SecretBytes, SsoConfigError> {
    let stored = match config {
        DecodedSecretConfig::Oidc(config) => StoredConfigRef::Oidc {
            version: STORAGE_VERSION,
            client_id: &config.client_id,
            client_secret: core::str::from_utf8(config.client_secret.expose())
                .map_err(|_| SsoConfigError::SecretRejected)?,
            group_claim_path: &config.group_claim_path,
            group_normalization: config.group_normalization.as_str(),
        },
        DecodedSecretConfig::Saml(config) => StoredConfigRef::Saml {
            version: STORAGE_VERSION,
            entry_point: &config.entry_point,
            metadata: &config.metadata,
            email_attribute: &config.email_attribute,
            group_attribute: &config.group_attribute,
            group_normalization: config.group_normalization.as_str(),
        },
    };
    serde_json::to_vec(&stored)
        .map(SecretBytes::new)
        .map_err(|_| SsoConfigError::ShapeRejected)
}

#[derive(Deserialize)]
#[serde(tag = "protocol", rename_all = "lowercase", deny_unknown_fields)]
enum StoredConfigOwned {
    Oidc {
        version: u8,
        client_id: String,
        client_secret: String,
        group_claim_path: Option<Vec<String>>,
        group_normalization: String,
    },
    Saml {
        version: u8,
        entry_point: String,
        metadata: String,
        email_attribute: String,
        group_attribute: Option<String>,
        group_normalization: String,
    },
}

/// 解开后的 v2 明文；旧 Better Auth JSON 由 migration adapter 单独翻译。
pub(crate) fn decode_v2(value: &SecretBytes) -> Result<DecodedSecretConfig, SsoConfigError> {
    let parsed: StoredConfigOwned =
        serde_json::from_slice(value.expose()).map_err(|_| SsoConfigError::ShapeRejected)?;
    match parsed {
        StoredConfigOwned::Oidc {
            version,
            client_id,
            client_secret,
            group_claim_path,
            group_normalization,
        } if version == STORAGE_VERSION => Ok(DecodedSecretConfig::Oidc(OidcSecretConfig {
            client_id,
            client_secret: SecretBytes::new(client_secret.into_bytes()),
            group_claim_path,
            group_normalization: parse_normalization(Some(&group_normalization))?
                .ok_or(SsoConfigError::GroupMappingRejected)?,
        })),
        StoredConfigOwned::Saml {
            version,
            entry_point,
            metadata,
            email_attribute,
            group_attribute,
            group_normalization,
        } if version == STORAGE_VERSION => Ok(DecodedSecretConfig::Saml(SamlSecretConfig {
            entry_point,
            metadata,
            email_attribute,
            group_attribute,
            group_normalization: parse_normalization(Some(&group_normalization))?
                .ok_or(SsoConfigError::GroupMappingRejected)?,
        })),
        _ => Err(SsoConfigError::ShapeRejected),
    }
}

pub(crate) enum DecodedSecretConfig {
    Oidc(OidcSecretConfig),
    Saml(SamlSecretConfig),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyOidcConfig {
    client_id: String,
    client_secret: String,
    #[serde(default)]
    discovery_endpoint: Option<String>,
    #[serde(default)]
    group_claim_path: Option<String>,
    #[serde(default)]
    group_normalization: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacySamlMetadata {
    metadata: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacySamlConfig {
    entry_point: String,
    idp_metadata: LegacySamlMetadata,
    #[serde(default)]
    email_attribute: Option<String>,
    #[serde(default)]
    group_attribute: Option<String>,
    #[serde(default)]
    group_normalization: Option<String>,
}

pub(crate) fn decode_legacy(
    column: super::vault::SsoSecretColumn,
    value: &SecretBytes,
    issuer: &str,
) -> Result<DecodedSecretConfig, SsoConfigError> {
    match column {
        super::vault::SsoSecretColumn::Oidc => {
            let issuer = validated_issuer(issuer)?;
            let legacy: LegacyOidcConfig = serde_json::from_slice(value.expose())
                .map_err(|_| SsoConfigError::ShapeRejected)?;
            validate_nonempty_bounded(&legacy.client_id, MAX_IDENTITY_PROVIDER_CLIENT_ID_BYTES)
                .map_err(|_| SsoConfigError::ShapeRejected)?;
            if legacy.client_secret.is_empty()
                || legacy.client_secret.len() > MAX_IDENTITY_PROVIDER_CLIENT_SECRET_BYTES
            {
                return Err(SsoConfigError::SecretRejected);
            }
            if let Some(endpoint) = legacy.discovery_endpoint.as_deref() {
                let expected = issuer
                    .join(crate::auth::oidc::discovery::DISCOVERY_PATH_SUFFIX)
                    .map_err(|_| SsoConfigError::IssuerRejected)?;
                if endpoint != expected.as_str() {
                    return Err(SsoConfigError::EndpointRejected);
                }
            }
            let (group_claim_path, group_normalization) =
                parse_group_mapping(legacy.group_claim_path, legacy.group_normalization)?;
            Ok(DecodedSecretConfig::Oidc(OidcSecretConfig {
                client_id: legacy.client_id,
                client_secret: SecretBytes::new(legacy.client_secret.into_bytes()),
                group_claim_path,
                group_normalization,
            }))
        }
        super::vault::SsoSecretColumn::Saml => {
            let legacy: LegacySamlConfig = serde_json::from_slice(value.expose())
                .map_err(|_| SsoConfigError::ShapeRejected)?;
            validate_https_url(&legacy.entry_point)?;
            if legacy.idp_metadata.metadata.is_empty()
                || legacy.idp_metadata.metadata.len() > MAX_IDENTITY_PROVIDER_METADATA_BYTES
            {
                return Err(SsoConfigError::MetadataRejected);
            }
            let email_attribute = legacy.email_attribute.unwrap_or_else(|| "email".to_owned());
            validate_attribute_name(&email_attribute)?;
            if let Some(attribute) = &legacy.group_attribute {
                validate_attribute_name(attribute)?;
            }
            Ok(DecodedSecretConfig::Saml(SamlSecretConfig {
                entry_point: legacy.entry_point,
                metadata: legacy.idp_metadata.metadata,
                email_attribute,
                group_attribute: legacy.group_attribute,
                group_normalization: parse_normalization(legacy.group_normalization.as_deref())?
                    .unwrap_or_default(),
            }))
        }
    }
}

impl core::fmt::Debug for DecodedSecretConfig {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Oidc(config) => config.fmt(formatter),
            Self::Saml(config) => config.fmt(formatter),
        }
    }
}

fn parse_domains(raw: &str) -> Result<BTreeSet<EmailDomain>, SsoConfigError> {
    let parts: Vec<&str> = raw.split(',').map(str::trim).collect();
    if parts.is_empty()
        || parts.len() > MAX_IDENTITY_PROVIDER_DOMAINS
        || parts.iter().any(|part| part.is_empty())
    {
        return Err(SsoConfigError::DomainRejected);
    }
    let expected_count = parts.len();
    let domains = parts
        .into_iter()
        .map(|part| EmailDomain::parse(part).map_err(|_| SsoConfigError::DomainRejected))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if domains.is_empty() || domains.len() != expected_count {
        return Err(SsoConfigError::DomainRejected);
    }
    Ok(domains)
}

pub(crate) fn domains_column(domains: &BTreeSet<EmailDomain>) -> String {
    domains
        .iter()
        .map(EmailDomain::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn domains_from_column(value: &str) -> Result<BTreeSet<EmailDomain>, SsoConfigError> {
    parse_domains(value)
}

fn parse_group_mapping(
    path: Option<String>,
    normalization: Option<String>,
) -> Result<(Option<Vec<String>>, GroupNormalization), SsoConfigError> {
    let normalization = parse_normalization(normalization.as_deref())?;
    let path = path
        .map(|path| {
            let parsed = GroupClaimPath::from_dotted(&path)
                .map_err(|_| SsoConfigError::GroupMappingRejected)?;
            Ok(parsed.segments().map(str::to_owned).collect())
        })
        .transpose()?;
    if path.is_none() && normalization.is_some() {
        return Err(SsoConfigError::GroupMappingRejected);
    }
    Ok((path, normalization.unwrap_or_default()))
}

fn parse_normalization(raw: Option<&str>) -> Result<Option<GroupNormalization>, SsoConfigError> {
    match raw {
        None => Ok(None),
        Some("exact") => Ok(Some(GroupNormalization::Exact)),
        Some("trim_lowercase") => Ok(Some(GroupNormalization::TrimLowercase)),
        Some(_) => Err(SsoConfigError::GroupMappingRejected),
    }
}

fn validate_https_url(raw: &str) -> Result<(), SsoConfigError> {
    validate_nonempty_bounded(raw, MAX_IDENTITY_PROVIDER_URL_BYTES)
        .map_err(|_| SsoConfigError::EndpointRejected)?;
    let url = Url::parse(raw).map_err(|_| SsoConfigError::EndpointRejected)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(SsoConfigError::EndpointRejected);
    }
    Ok(())
}

pub(crate) fn validated_issuer(raw: &str) -> Result<openidconnect::IssuerUrl, SsoConfigError> {
    validate_nonempty_bounded(raw, MAX_IDENTITY_PROVIDER_URL_BYTES)
        .map_err(|_| SsoConfigError::IssuerRejected)?;
    parse_issuer(raw).map_err(|_| SsoConfigError::IssuerRejected)
}

/// SAML EntityID 是标识符 URI，不是要由服务端抓取的 endpoint；合法 `urn:` 不得套用 OIDC
/// “必须 HTTPS host”规则。真正会导航/收包的 SSO/ACS URL 仍走 [`validate_https_url`]。
pub(crate) fn validate_saml_entity_id(raw: &str) -> Result<(), SsoConfigError> {
    validate_nonempty_bounded(raw, MAX_SAML_ENTITY_ID_BYTES)
        .map_err(|_| SsoConfigError::IssuerRejected)?;
    let entity = Url::parse(raw).map_err(|_| SsoConfigError::IssuerRejected)?;
    if !matches!(entity.scheme(), "urn" | "http" | "https") || entity.fragment().is_some() {
        return Err(SsoConfigError::IssuerRejected);
    }
    if matches!(entity.scheme(), "http" | "https")
        && (entity.host_str().is_none()
            || !entity.username().is_empty()
            || entity.password().is_some())
    {
        return Err(SsoConfigError::IssuerRejected);
    }
    Ok(())
}

fn validate_nonempty_bounded(value: &str, max: usize) -> Result<(), ()> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        Err(())
    } else {
        Ok(())
    }
}

fn validate_attribute_name(value: &str) -> Result<(), SsoConfigError> {
    validate_nonempty_bounded(value, MAX_ATTRIBUTE_NAME_BYTES)
        .map_err(|_| SsoConfigError::ShapeRejected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oidc_body() -> RegisterIdentityProviderInput {
        serde_json::from_value(serde_json::json!({
            "providerId": "acme-oidc",
            "issuer": "https://idp.example.com",
            "domain": "Example.com, subsidiary.example.com",
            "oidcConfig": {
                "clientId": "client",
                "clientSecret": "directory-secret-sentinel",
                "discoveryEndpoint": "https://idp.example.com/.well-known/openid-configuration",
                "groupClaimPath": "resource_access.roles",
                "groupNormalization": "trim_lowercase"
            }
        }))
        .unwrap()
    }

    #[test]
    fn registration_is_one_protocol_and_domains_are_bare_normalized_values() {
        let plan = RegistrationPlan::parse(oidc_body()).unwrap();
        assert_eq!(plan.provider_id().as_str(), "acme-oidc");
        assert_eq!(
            domains_column(plan.domains()),
            "example.com,subsidiary.example.com"
        );
        for bad in [
            "https://victim.example/path",
            "victim.example/path",
            "victim.example?x=1",
            "victim.example#x",
            "victim.example,,other.example",
        ] {
            let mut body = oidc_body();
            body.domain = bad.to_owned();
            assert_eq!(
                RegistrationPlan::parse(body).unwrap_err(),
                SsoConfigError::DomainRejected,
                "{bad}"
            );
        }

        let saml: RegisterIdentityProviderInput = serde_json::from_value(serde_json::json!({
            "providerId":"urn-idp",
            "issuer":"urn:example:idp:directory",
            "domain":"example.com",
            "samlConfig":{
                "entryPoint":"https://idp.example/sso",
                "idpMetadata":{"metadata":"<metadata/>"}
            }
        }))
        .unwrap();
        let saml = RegistrationPlan::parse(saml).expect("SAML EntityID 可以是非网络 urn URI");
        assert_eq!(saml.issuer_str(), "urn:example:idp:directory");
        assert_eq!(saml.protocol(), SsoProtocol::Saml);

        assert_eq!(
            validate_saml_entity_id("javascript:alert(1)"),
            Err(SsoConfigError::IssuerRejected)
        );
    }

    #[test]
    fn secret_round_trip_is_v2_and_debug_is_redacted() {
        let plan = RegistrationPlan::parse(oidc_body()).unwrap();
        let encoded = encode_plan(&plan).unwrap();
        let rendered = format!("{plan:?}");
        assert!(!rendered.contains("directory-secret-sentinel"));
        let decoded = decode_v2(&encoded).unwrap();
        let DecodedSecretConfig::Oidc(decoded) = decoded else {
            panic!("协议漂移")
        };
        assert_eq!(decoded.client_id, "client");
        assert_eq!(decoded.client_secret.expose(), b"directory-secret-sentinel");
        assert_eq!(
            decoded.group_claim_path.unwrap(),
            ["resource_access", "roles"]
        );
    }

    #[test]
    fn ambiguous_protocol_and_discovery_override_are_rejected() {
        let both = serde_json::json!({
            "providerId":"acme", "issuer":"https://idp.example", "domain":"example.com",
            "oidcConfig":{"clientId":"id","clientSecret":"secret"},
            "samlConfig":{"entryPoint":"https://idp.example/sso","idpMetadata":{"metadata":"<x/>"}}
        });
        let input: RegisterIdentityProviderInput = serde_json::from_value(both).unwrap();
        assert_eq!(
            RegistrationPlan::parse(input).unwrap_err(),
            SsoConfigError::ProtocolAmbiguous
        );

        let mut wrong = oidc_body();
        wrong.oidc_config.as_mut().unwrap().discovery_endpoint =
            Some("https://attacker.example/discovery".to_owned());
        assert_eq!(
            RegistrationPlan::parse(wrong).unwrap_err(),
            SsoConfigError::EndpointRejected
        );

        let mut oversized = oidc_body();
        oversized.issuer = format!(
            "https://idp.example/{}",
            "a".repeat(MAX_IDENTITY_PROVIDER_URL_BYTES)
        );
        assert_eq!(
            RegistrationPlan::parse(oversized).unwrap_err(),
            SsoConfigError::IssuerRejected
        );
    }

    #[test]
    fn oidc_and_saml_expose_the_same_non_secret_group_audience_contract() {
        let RegistrationPlan::Oidc {
            provider_id,
            config,
            ..
        } = RegistrationPlan::parse(oidc_body()).unwrap()
        else {
            panic!("OIDC 计划漂移")
        };
        let oidc = config.mapping(&provider_id).unwrap().unwrap();
        assert_eq!(oidc.provider().as_str(), "acme-oidc");
        assert_eq!(oidc.normalization(), GroupNormalization::TrimLowercase);

        let input: RegisterIdentityProviderInput = serde_json::from_value(serde_json::json!({
            "providerId":"acme-saml",
            "issuer":"urn:example:idp:directory",
            "domain":"example.com",
            "samlConfig":{
                "entryPoint":"https://idp.example/sso",
                "idpMetadata":{"metadata":"<metadata/>"},
                "groupAttribute":"groups",
                "groupNormalization":"trim_lowercase"
            }
        }))
        .unwrap();
        let RegistrationPlan::Saml {
            provider_id,
            config,
            ..
        } = RegistrationPlan::parse(input).unwrap()
        else {
            panic!("SAML 计划漂移")
        };
        let saml = config.mapping(&provider_id).unwrap().unwrap();
        assert_eq!(saml.provider().as_str(), "acme-saml");
        assert_eq!(saml.normalization(), GroupNormalization::TrimLowercase);
    }
}
