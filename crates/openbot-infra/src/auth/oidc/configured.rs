//! 环境配置三家 provider → OIDC runtime 输入。
//!
//! callback URI 只从唯一 `OPENBOT_PUBLIC_URL` 的已解析值派生，不读 Host header。Microsoft
//! authority 只接受官方四类：`common` / `organizations` / `consumers` / canonical tenant GUID；
//! 由固定 `login.microsoftonline.com` 模板构造，管理员不能把 Entra client secret 指向别的 host。

use std::collections::BTreeSet;

use openbot_domain::vault::SecretBytes;
use openidconnect::ClientId;
use url::Url;

use super::error::OidcError;
use super::provider::{
    EntraTenantPolicy, MICROSOFT_CONSUMER_TENANT_ID, OidcProviderConfig, ProviderId, ProviderKind,
    ProviderOrigin, parse_issuer,
};
use super::redirect::{CanonicalRedirectUri, HTTPS_OR_HTTP};
use crate::auth::config::{AuthConfig, OAuthClient};

const MICROSOFT_AUTHORITY_ORIGIN: &str = "https://login.microsoftonline.com";
const MICROSOFT_ISSUER_TEMPLATE: &str = "https://login.microsoftonline.com/{tenantid}/v2.0";

/// client secret 与公开 provider config 的绑定；密钥由 `SecretBytes` 持有且 Debug 不打印。
pub struct ConfiguredOidcProvider {
    pub config: OidcProviderConfig,
    pub client_secret: SecretBytes,
}

impl core::fmt::Debug for ConfiguredOidcProvider {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ConfiguredOidcProvider")
            .field("config", &self.config)
            .field("client_secret", &"[REDACTED]")
            .finish()
    }
}

/// 三家可同时出现，顺序 Google → Microsoft → Okta 与上游登录面一致。
pub fn configured_oidc_providers(
    auth: &AuthConfig,
) -> Result<Vec<ConfiguredOidcProvider>, OidcError> {
    validate_public_base(&auth.public_url)?;
    let mut providers = Vec::with_capacity(3);
    if let Some(client) = &auth.google {
        providers.push(configured(
            "google",
            ProviderKind::Google,
            client,
            &auth.public_url,
        )?);
    }
    if let Some(microsoft) = &auth.microsoft {
        providers.push(configured(
            "microsoft",
            entra_kind(&microsoft.tenant_id)?,
            &microsoft.client,
            &auth.public_url,
        )?);
    }
    if let Some(okta) = &auth.okta {
        providers.push(configured(
            "okta",
            ProviderKind::DeploymentOwned {
                issuer: parse_issuer(&okta.issuer)?,
            },
            &okta.client,
            &auth.public_url,
        )?);
    }
    Ok(providers)
}

fn configured(
    id: &str,
    kind: ProviderKind,
    client: &OAuthClient,
    public_url: &str,
) -> Result<ConfiguredOidcProvider, OidcError> {
    let callback = format!(
        "{}/api/auth/oidc/{id}/callback",
        public_url.trim_end_matches('/')
    );
    Ok(ConfiguredOidcProvider {
        config: OidcProviderConfig::new(
            ProviderId::parse(id)?,
            kind,
            ProviderOrigin::EnvironmentConfigured,
            ClientId::new(client.client_id.clone()),
            CanonicalRedirectUri::parse(&callback, HTTPS_OR_HTTP)?,
            BTreeSet::new(),
            None,
        ),
        client_secret: SecretBytes::new(client.client_secret.expose().as_bytes().to_vec()),
    })
}

fn entra_kind(tenant: &str) -> Result<ProviderKind, OidcError> {
    let (authority_segment, issuer, policy) = match tenant {
        "common" => (
            "common".to_owned(),
            MICROSOFT_ISSUER_TEMPLATE.to_owned(),
            EntraTenantPolicy::TenantIndependent {
                allow_personal: true,
            },
        ),
        "organizations" => (
            "organizations".to_owned(),
            MICROSOFT_ISSUER_TEMPLATE.to_owned(),
            EntraTenantPolicy::TenantIndependent {
                allow_personal: false,
            },
        ),
        "consumers" => (
            "consumers".to_owned(),
            format!("{MICROSOFT_AUTHORITY_ORIGIN}/{MICROSOFT_CONSUMER_TENANT_ID}/v2.0"),
            EntraTenantPolicy::AllowList(
                [MICROSOFT_CONSUMER_TENANT_ID.to_owned()]
                    .into_iter()
                    .collect(),
            ),
        ),
        raw => {
            let parsed = uuid::Uuid::parse_str(raw).map_err(|_| OidcError::EntraTenantMalformed)?;
            let canonical = parsed.hyphenated().to_string();
            if canonical != raw {
                return Err(OidcError::EntraTenantMalformed);
            }
            (
                canonical.clone(),
                format!("{MICROSOFT_AUTHORITY_ORIGIN}/{canonical}/v2.0"),
                EntraTenantPolicy::AllowList([canonical].into_iter().collect()),
            )
        }
    };
    Ok(ProviderKind::Entra {
        authority: parse_issuer(&format!(
            "{MICROSOFT_AUTHORITY_ORIGIN}/{authority_segment}/v2.0"
        ))?,
        issuer: parse_issuer(&issuer)?,
        tenants: policy,
    })
}

fn validate_public_base(raw: &str) -> Result<(), OidcError> {
    let url = Url::parse(raw).map_err(|_| OidcError::RedirectUriNotCanonical)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.as_str().trim_end_matches('/') != raw.trim_end_matches('/')
    {
        return Err(OidcError::RedirectUriNotCanonical);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::config::{EnvMap, ExampleKeyPolicy, auth_config, default_session_lifetime};

    fn full_auth() -> AuthConfig {
        let mut env = EnvMap::new();
        for (name, value) in [
            ("GOOGLE_OAUTH_CLIENT_ID", "google-id"),
            ("GOOGLE_OAUTH_CLIENT_SECRET", "google-secret"),
            ("MICROSOFT_OAUTH_CLIENT_ID", "microsoft-id"),
            ("MICROSOFT_OAUTH_CLIENT_SECRET", "microsoft-secret"),
            ("MICROSOFT_OAUTH_TENANT_ID", "common"),
            ("OKTA_OAUTH_CLIENT_ID", "okta-id"),
            ("OKTA_OAUTH_CLIENT_SECRET", "okta-secret"),
            (
                "OKTA_OAUTH_ISSUER",
                "https://example.okta.com/oauth2/default",
            ),
            (
                "OPENBOT_SESSION_SECRET",
                "a-session-secret-with-at-least-32-chars",
            ),
            ("INITIAL_ADMIN_EMAILS", "admin@example.com"),
            (
                "KEY_ENCRYPTION_KEY",
                "//////////////////////////////////////////8=",
            ),
        ] {
            env.insert(name.to_owned(), value.to_owned());
        }
        let _ = crate::auth::config::KeyEncryptionKey::from_env_map(&env, ExampleKeyPolicy::Allow)
            .unwrap();
        auth_config(
            &env,
            Some("https://app.example.com"),
            default_session_lifetime(),
        )
        .unwrap()
        .unwrap()
    }

    #[test]
    fn three_environment_providers_have_exact_distinct_callbacks_and_redacted_secrets() {
        let providers = configured_oidc_providers(&full_auth()).unwrap();
        let ids: Vec<&str> = providers
            .iter()
            .map(|provider| provider.config.id().as_str())
            .collect();
        assert_eq!(ids, ["google", "microsoft", "okta"]);
        for provider in &providers {
            assert_eq!(
                provider.config.redirect_uri().as_str(),
                format!(
                    "https://app.example.com/api/auth/oidc/{}/callback",
                    provider.config.id().as_str()
                )
            );
            let debug = format!("{provider:?}");
            assert!(!debug.contains("google-secret"));
            assert!(!debug.contains("microsoft-secret"));
            assert!(!debug.contains("okta-secret"));
        }
    }

    #[test]
    fn common_uses_pinned_authority_and_tenant_template_but_bad_tenant_is_rejected() {
        let kind = entra_kind("common").unwrap();
        assert_eq!(
            kind.discovery_issuer().as_str(),
            "https://login.microsoftonline.com/common/v2.0"
        );
        assert!(kind.issuer().as_str().contains("tenantid"));
        assert!(matches!(
            kind.entra_tenants(),
            Some(EntraTenantPolicy::TenantIndependent {
                allow_personal: true
            })
        ));
        assert_eq!(
            entra_kind("contoso.onmicrosoft.com"),
            Err(OidcError::EntraTenantMalformed)
        );
        assert!(entra_kind("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").is_ok());
        assert_eq!(
            entra_kind("AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE"),
            Err(OidcError::EntraTenantMalformed)
        );
    }
}
