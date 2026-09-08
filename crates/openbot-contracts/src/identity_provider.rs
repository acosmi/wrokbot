//! Deployment-owned SAML/OIDC administrator wire contracts.
//!
//! The public projection deliberately cannot express client secrets, SAML metadata, or
//! certificates. Registration requests are a separate, serialize-only browser type: the Server
//! still deserializes secrets into infra's non-`Clone`, non-`Serialize` secret owner.

use serde::{Deserialize, Serialize};

/// Maximum number of deployment-owned providers accepted in one browser response.
pub const MAX_IDENTITY_PROVIDERS: usize = 256;
/// Maximum provider identifier length, matching the authoritative infra parser.
pub const MAX_IDENTITY_PROVIDER_ID_BYTES: usize = 64;
/// Maximum number of comma-separated email domains in one registration.
pub const MAX_IDENTITY_PROVIDER_DOMAINS: usize = 16;
/// Maximum OIDC client identifier length accepted by the Server.
pub const MAX_IDENTITY_PROVIDER_CLIENT_ID_BYTES: usize = 4 * 1024;
/// Maximum OIDC client secret length accepted by the Server.
pub const MAX_IDENTITY_PROVIDER_CLIENT_SECRET_BYTES: usize = 16 * 1024;
/// Maximum SAML metadata document length accepted by the Server.
pub const MAX_IDENTITY_PROVIDER_METADATA_BYTES: usize = 512 * 1024;
/// Maximum network URL length accepted by the Server.
pub const MAX_IDENTITY_PROVIDER_URL_BYTES: usize = 4 * 1024;
/// Maximum SAML entity identifier length accepted by the Server.
pub const MAX_SAML_ENTITY_ID_BYTES: usize = 1024;

/// Protocol spoken by one deployment-owned identity provider.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SsoProtocol {
    /// OpenID Connect discovery and authorization-code flow.
    Oidc,
    /// SAML 2.0 HTTP-POST flow.
    Saml,
}

/// Browser-safe identity-provider projection.
///
/// This type cannot carry a client secret, SAML metadata, or certificate.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisteredIdentityProvider {
    /// Stable deployment-local provider identifier.
    pub provider_id: String,
    /// OIDC issuer or SAML entity identifier.
    pub issuer: String,
    /// Canonical comma-separated email routing domains.
    pub domain: String,
    /// Provider protocol.
    pub protocol: SsoProtocol,
    /// Actor who originally registered it, or `None` after that actor was removed.
    pub registered_by: Option<String>,
}

/// Closed administrator list response.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityProvidersResponse {
    /// All deployment-owned dynamic providers; environment providers are excluded.
    pub providers: Vec<RegisteredIdentityProvider>,
}

/// Exact delete receipt for one dynamic provider.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityProviderRemoved {
    /// `true` only after the provider and its encrypted configuration were removed.
    pub removed: bool,
}

/// Serialize-only browser registration body.
///
/// It intentionally does not implement `Clone`, `Debug`, or `Deserialize`: the OIDC variant owns a
/// plaintext secret only until the same-origin request has been serialized. The Server receives the
/// same wire shape through infra's redacting, deserialize-only input type.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterIdentityProviderRequest {
    provider_id: String,
    issuer: String,
    domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    oidc_config: Option<OidcRegistrationRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    saml_config: Option<SamlRegistrationRequest>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OidcRegistrationRequest {
    client_id: String,
    #[serde(serialize_with = "crate::secret_text::serialize")]
    client_secret: zeroize::Zeroizing<String>,
    discovery_endpoint: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SamlRegistrationRequest {
    entry_point: String,
    idp_metadata: SamlMetadataRequest,
}

#[derive(Serialize)]
struct SamlMetadataRequest {
    metadata: String,
}

impl RegisterIdentityProviderRequest {
    /// Build the exact SAML registration wire shape consumed by the Server.
    #[must_use]
    pub fn saml(
        provider_id: String,
        domain: String,
        issuer: String,
        entry_point: String,
        metadata: String,
    ) -> Self {
        Self {
            provider_id,
            issuer,
            domain,
            oidc_config: None,
            saml_config: Some(SamlRegistrationRequest {
                entry_point,
                idp_metadata: SamlMetadataRequest { metadata },
            }),
        }
    }

    /// Build the exact OIDC registration wire shape consumed by the Server.
    ///
    /// Discovery is always derived from the issuer. A person cannot type an unrelated endpoint.
    #[must_use]
    pub fn oidc(
        provider_id: String,
        domain: String,
        issuer: String,
        client_id: String,
        client_secret: String,
    ) -> Self {
        Self::oidc_with_zeroizing_secret(
            provider_id,
            domain,
            issuer,
            client_id,
            zeroize::Zeroizing::new(client_secret),
        )
    }

    /// Transfer one transient write-only input directly into the request. The request erases its
    /// secret allocation when dropped; this does not claim control of HTTP/browser copies.
    #[must_use]
    pub fn oidc_with_zeroizing_secret(
        provider_id: String,
        domain: String,
        issuer: String,
        client_id: String,
        client_secret: zeroize::Zeroizing<String>,
    ) -> Self {
        let discovery_endpoint = format!(
            "{}/.well-known/openid-configuration",
            issuer.strip_suffix('/').unwrap_or(&issuer)
        );
        Self {
            provider_id,
            issuer,
            domain,
            oidc_config: Some(OidcRegistrationRequest {
                client_id,
                client_secret,
                discovery_endpoint,
            }),
            saml_config: None,
        }
    }

    /// Non-secret provider identifier used to bind the response receipt.
    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    /// Non-secret issuer used to bind the response receipt.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Requested domain text; the Server may return its canonical comma-separated form.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Protocol selected by the exclusive request shape.
    #[must_use]
    pub fn protocol(&self) -> SsoProtocol {
        if self.oidc_config.is_some() {
            SsoProtocol::Oidc
        } else {
            SsoProtocol::Saml
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidc_request_moves_the_existing_zeroizing_secret_and_preserves_the_wire() {
        let secret = zeroize::Zeroizing::new("allocation-canary".to_owned());
        let address = secret.as_ptr();
        let request = RegisterIdentityProviderRequest::oidc_with_zeroizing_secret(
            "idp".to_owned(),
            "example.test".to_owned(),
            "https://idp.example.test".to_owned(),
            "client".to_owned(),
            secret,
        );
        assert_eq!(
            request.oidc_config.as_ref().unwrap().client_secret.as_ptr(),
            address
        );
        assert_eq!(
            serde_json::to_value(&request).unwrap()["oidcConfig"]["clientSecret"],
            "allocation-canary"
        );
    }

    #[test]
    fn registration_bodies_are_protocol_exclusive_and_oidc_discovery_is_derived() {
        let saml = serde_json::to_value(RegisterIdentityProviderRequest::saml(
            "acme-saml".to_owned(),
            "acme.example".to_owned(),
            "urn:acme:idp".to_owned(),
            "https://idp.acme.example/sso".to_owned(),
            "<EntityDescriptor/>".to_owned(),
        ))
        .unwrap();
        assert_eq!(
            saml,
            serde_json::json!({
                "providerId":"acme-saml",
                "issuer":"urn:acme:idp",
                "domain":"acme.example",
                "samlConfig":{
                    "entryPoint":"https://idp.acme.example/sso",
                    "idpMetadata":{"metadata":"<EntityDescriptor/>"}
                }
            })
        );

        let oidc = serde_json::to_value(RegisterIdentityProviderRequest::oidc(
            "acme-oidc".to_owned(),
            "acme.example".to_owned(),
            "https://idp.acme.example/oauth2/default/".to_owned(),
            "client".to_owned(),
            "secret".to_owned(),
        ))
        .unwrap();
        assert_eq!(
            oidc,
            serde_json::json!({
                "providerId":"acme-oidc",
                "issuer":"https://idp.acme.example/oauth2/default/",
                "domain":"acme.example",
                "oidcConfig":{
                    "clientId":"client",
                    "clientSecret":"secret",
                    "discoveryEndpoint":"https://idp.acme.example/oauth2/default/.well-known/openid-configuration"
                }
            })
        );
    }

    #[test]
    fn public_projection_round_trip_has_no_secret_shape() {
        let response = IdentityProvidersResponse {
            providers: vec![RegisteredIdentityProvider {
                provider_id: "acme-saml".to_owned(),
                issuer: "urn:acme:idp".to_owned(),
                domain: "acme.example".to_owned(),
                protocol: SsoProtocol::Saml,
                registered_by: None,
            }],
        };
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(
            serde_json::from_value::<IdentityProvidersResponse>(value.clone()).unwrap(),
            response
        );
        let text = value.to_string();
        for forbidden in ["secret", "metadata", "certificate", "entryPoint"] {
            assert!(!text.contains(forbidden), "{forbidden}");
        }
    }
}
