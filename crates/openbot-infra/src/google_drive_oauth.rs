//! Curated Google web-server OAuth for the Drive REST connector.
//!
//! Unlike MCP OAuth, Google Drive is not an RFC 9728 protected MCP resource. The authorization,
//! token and revoke endpoints are reviewed constants from the fixed catalogue and Google docs;
//! callers cannot supply or discover alternatives at runtime.

use std::borrow::Cow;

use async_trait::async_trait;
use http::StatusCode;
use openbot_contracts::mcp::{McpOAuthClientAuthMethod, McpOAuthClientRegistration};
use openbot_domain::vault::SecretBytes;
use serde::Deserialize;
use url::Url;
use zeroize::{Zeroize as _, Zeroizing};

use crate::google_drive::{
    GOOGLE_DRIVE_API_BASE, GOOGLE_DRIVE_AUTHORIZATION_ENDPOINT, GOOGLE_DRIVE_ISSUER,
    GOOGLE_DRIVE_READONLY_SCOPE, GOOGLE_DRIVE_REVOCATION_ENDPOINT, GOOGLE_DRIVE_SERVER_ID,
    GOOGLE_DRIVE_TOKEN_ENDPOINT,
};
use crate::mcp_oauth::MCP_OAUTH_TOKEN_TIMEOUT;
use crate::net::safe_http::{SafeDialer, SafeHttpBudget, SafeHttpRequest, SchemePolicy};
use crate::store::plugin_user_credential::{
    OAuthRefreshExchange, OAuthTokenExchangeError, RotatingOAuthGrant, RotatingOAuthTokenExchanger,
};

const MAX_OAUTH_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_TOKEN_BYTES: usize = 64 * 1024;

/// Exact endpoints/resource used by one Drive OAuth adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoogleDriveOAuthEndpoints {
    /// Drive API resource base.
    pub resource: Url,
    /// Browser authorization endpoint.
    pub authorization: Url,
    /// Code/refresh token endpoint.
    pub token: Url,
    /// Token revocation endpoint.
    pub revocation: Url,
    /// Expected callback issuer when Google includes `iss`.
    pub issuer: String,
}

impl GoogleDriveOAuthEndpoints {
    /// Production pinned Google endpoints.
    pub fn pinned() -> Result<Self, GoogleDriveOAuthError> {
        Ok(Self {
            resource: parse_url(GOOGLE_DRIVE_API_BASE, SchemePolicy::HttpsOnly)?,
            authorization: parse_url(GOOGLE_DRIVE_AUTHORIZATION_ENDPOINT, SchemePolicy::HttpsOnly)?,
            token: parse_url(GOOGLE_DRIVE_TOKEN_ENDPOINT, SchemePolicy::HttpsOnly)?,
            revocation: parse_url(GOOGLE_DRIVE_REVOCATION_ENDPOINT, SchemePolicy::HttpsOnly)?,
            issuer: GOOGLE_DRIVE_ISSUER.to_owned(),
        })
    }
}

/// Stable Google OAuth failure without code/token/body values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GoogleDriveOAuthError {
    /// Registered client or fixed endpoint shape is invalid.
    #[error("google_drive_oauth_client_invalid")]
    InvalidClient,
    /// SafeDialer or Google endpoint unavailable.
    #[error("google_drive_oauth_unavailable")]
    Unavailable,
    /// Code/refresh grant was rejected and requires reconnect.
    #[error("google_drive_oauth_auth_required")]
    AuthRequired,
    /// Token response is malformed or missing a required secret.
    #[error("google_drive_oauth_response_invalid")]
    InvalidResponse,
}

/// Authorization URL plus callback facts stored in the one-time attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoogleDriveAuthorizationPlan {
    url: Url,
    issuer: String,
}

impl GoogleDriveAuthorizationPlan {
    /// Browser URL.
    #[must_use]
    pub const fn authorization_url(&self) -> &Url {
        &self.url
    }

    /// Issuer checked when present on callback.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
}

/// Code exchange secrets. Access is one-call; refresh is persisted by the connection transaction.
pub struct GoogleDriveCodeGrant {
    access_token: SecretBytes,
    refresh_token: SecretBytes,
    scope: String,
}

impl GoogleDriveCodeGrant {
    /// Consume into zeroizing secrets and granted scope.
    #[must_use]
    pub fn into_parts(self) -> (SecretBytes, SecretBytes, String) {
        (self.access_token, self.refresh_token, self.scope)
    }
}

impl core::fmt::Debug for GoogleDriveCodeGrant {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("GoogleDriveCodeGrant")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("scope_bytes", &self.scope.len())
            .finish()
    }
}

/// SafeDialer-backed Google Drive OAuth adapter.
#[derive(Clone)]
pub struct GoogleDriveOAuthClient {
    dialer: SafeDialer,
    endpoints: GoogleDriveOAuthEndpoints,
    scheme_policy: SchemePolicy,
}

impl GoogleDriveOAuthClient {
    /// Production pinned adapter.
    pub fn new(dialer: SafeDialer) -> Result<Self, GoogleDriveOAuthError> {
        Self::new_with_endpoints(
            dialer,
            GoogleDriveOAuthEndpoints::pinned()?,
            SchemePolicy::HttpsOnly,
        )
    }

    /// Explicit endpoint constructor for reviewed/local conformance environments.
    pub fn new_with_endpoints(
        dialer: SafeDialer,
        endpoints: GoogleDriveOAuthEndpoints,
        scheme_policy: SchemePolicy,
    ) -> Result<Self, GoogleDriveOAuthError> {
        for url in [
            &endpoints.resource,
            &endpoints.authorization,
            &endpoints.token,
            &endpoints.revocation,
        ] {
            parse_url(url.as_str(), scheme_policy)?;
        }
        if endpoints.issuer.is_empty()
            || endpoints.issuer.len() > 8 * 1024
            || endpoints.issuer.as_bytes().contains(&0)
        {
            return Err(GoogleDriveOAuthError::InvalidClient);
        }
        Ok(Self {
            dialer,
            endpoints,
            scheme_policy,
        })
    }

    /// Validate an admin registration against the curated Drive authority.
    pub fn validate_registration(
        &self,
        registration: &McpOAuthClientRegistration,
    ) -> Result<(), GoogleDriveOAuthError> {
        if registration.issuer() != self.endpoints.issuer
            || registration.auth_method() != McpOAuthClientAuthMethod::ClientSecretPost
            || registration.resource_metadata_url().is_some()
        {
            return Err(GoogleDriveOAuthError::InvalidClient);
        }
        Ok(())
    }

    /// Build Google authorization URL with offline consent, exact read-only scope and PKCE S256.
    pub fn authorization_plan(
        &self,
        oauth_client: &[u8],
        redirect_uri: &str,
        state: &str,
        code_challenge: &str,
    ) -> Result<GoogleDriveAuthorizationPlan, GoogleDriveOAuthError> {
        let client = StoredGoogleClient::parse(oauth_client, &self.endpoints.issuer)?;
        validate_redirect(redirect_uri, self.scheme_policy)?;
        if !valid_base64url(state, 512) || !valid_base64url(code_challenge, 128) {
            return Err(GoogleDriveOAuthError::InvalidClient);
        }
        let mut url = self.endpoints.authorization.clone();
        url.query_pairs_mut()
            .append_pair("client_id", &client.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", GOOGLE_DRIVE_READONLY_SCOPE)
            .append_pair("access_type", "offline")
            .append_pair("prompt", "consent")
            .append_pair("state", state)
            .append_pair("code_challenge", code_challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(GoogleDriveAuthorizationPlan {
            url,
            issuer: self.endpoints.issuer.clone(),
        })
    }

    /// Exchange one callback code; a refresh token is mandatory for a durable Drive connection.
    pub async fn exchange_authorization_code(
        &self,
        oauth_client: &[u8],
        code: &[u8],
        redirect_uri: &str,
        verifier: &[u8],
    ) -> Result<GoogleDriveCodeGrant, GoogleDriveOAuthError> {
        if code.is_empty() || code.len() > 16 * 1024 || code.contains(&0) || !valid_pkce(verifier) {
            return Err(GoogleDriveOAuthError::InvalidResponse);
        }
        validate_redirect(redirect_uri, self.scheme_policy)?;
        let client = StoredGoogleClient::parse(oauth_client, &self.endpoints.issuer)?;
        let code =
            core::str::from_utf8(code).map_err(|_| GoogleDriveOAuthError::InvalidResponse)?;
        let verifier =
            core::str::from_utf8(verifier).map_err(|_| GoogleDriveOAuthError::InvalidResponse)?;
        let body = google_form([
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", &client.client_id),
            ("client_secret", secret_str(&client.client_secret)?),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier),
        ]);
        let response = self.token_request(body).await?;
        let refresh = response
            .refresh_token
            .ok_or(GoogleDriveOAuthError::InvalidResponse)?;
        Ok(GoogleDriveCodeGrant {
            access_token: response.access_token,
            refresh_token: refresh,
            scope: response
                .scope
                .unwrap_or_else(|| GOOGLE_DRIVE_READONLY_SCOPE.to_owned()),
        })
    }

    /// Revoke a refresh token after local tombstone commit.
    pub async fn revoke_refresh_token(&self, token: &[u8]) -> Result<(), GoogleDriveOAuthError> {
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES || token.contains(&0) {
            return Err(GoogleDriveOAuthError::InvalidClient);
        }
        let token =
            core::str::from_utf8(token).map_err(|_| GoogleDriveOAuthError::InvalidClient)?;
        let body = google_form([("token", token)]);
        let budget = oauth_budget()?;
        let request = SafeHttpRequest::post_form_with_scheme(
            self.endpoints.revocation.clone(),
            self.scheme_policy,
            body,
            None,
            budget,
        )
        .map_err(|_| GoogleDriveOAuthError::InvalidClient)?;
        let response = self
            .dialer
            .execute(request)
            .await
            .map_err(|_| GoogleDriveOAuthError::Unavailable)?;
        if response.status().is_success() {
            Ok(())
        } else if response.status().is_server_error()
            || response.status() == StatusCode::TOO_MANY_REQUESTS
        {
            Err(GoogleDriveOAuthError::Unavailable)
        } else {
            Err(GoogleDriveOAuthError::AuthRequired)
        }
    }

    async fn token_request(
        &self,
        body: Vec<u8>,
    ) -> Result<GoogleTokenGrant, GoogleDriveOAuthError> {
        let request = SafeHttpRequest::post_form_with_scheme(
            self.endpoints.token.clone(),
            self.scheme_policy,
            body,
            None,
            oauth_budget()?,
        )
        .map_err(|_| GoogleDriveOAuthError::InvalidClient)?;
        let response = self
            .dialer
            .execute(request)
            .await
            .map_err(|_| GoogleDriveOAuthError::Unavailable)?;
        let (status, _, raw) = response.into_parts();
        let raw = Zeroizing::new(raw);
        if !status.is_success() {
            return Err(classify_error(status, &raw));
        }
        parse_token_response(&raw)
    }
}

impl core::fmt::Debug for GoogleDriveOAuthClient {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("GoogleDriveOAuthClient")
            .field("endpoints", &"[curated]")
            .field("scheme_policy", &self.scheme_policy)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl RotatingOAuthTokenExchanger for GoogleDriveOAuthClient {
    fn requires_refresh_rotation(&self) -> bool {
        false
    }

    async fn exchange_rotating(
        &self,
        request: OAuthRefreshExchange<'_>,
    ) -> Result<RotatingOAuthGrant, OAuthTokenExchangeError> {
        if request.server_id() != GOOGLE_DRIVE_SERVER_ID
            || request.endpoint() != self.endpoints.resource.as_str().trim_end_matches('/')
            || request.transport() != "google_drive_rest"
            || request.granted_scope() != GOOGLE_DRIVE_READONLY_SCOPE
            || !request.egress_allowlist().is_empty()
        {
            return Err(OAuthTokenExchangeError::InsufficientScope);
        }
        let client =
            StoredGoogleClient::parse(request.expose_oauth_client(), &self.endpoints.issuer)
                .map_err(map_exchange_error)?;
        let refresh = core::str::from_utf8(request.expose_refresh_token())
            .map_err(|_| OAuthTokenExchangeError::InvalidResponse)?;
        let body = google_form([
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", &client.client_id),
            (
                "client_secret",
                secret_str(&client.client_secret).map_err(map_exchange_error)?,
            ),
        ]);
        let response = self.token_request(body).await.map_err(map_exchange_error)?;
        if response
            .scope
            .as_deref()
            .is_some_and(|scope| scope != GOOGLE_DRIVE_READONLY_SCOPE)
        {
            return Err(OAuthTokenExchangeError::InsufficientScope);
        }
        Ok(RotatingOAuthGrant::new(
            response.access_token,
            response.refresh_token,
            response.scope,
        ))
    }
}

struct StoredGoogleClient {
    client_id: String,
    client_secret: SecretBytes,
}

impl StoredGoogleClient {
    fn parse(raw: &[u8], expected_issuer: &str) -> Result<Self, GoogleDriveOAuthError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire<'a> {
            #[serde(borrow)]
            client_id: Cow<'a, str>,
            #[serde(borrow)]
            client_secret: Cow<'a, str>,
            #[serde(borrow)]
            issuer: Cow<'a, str>,
            #[serde(default, borrow)]
            token_endpoint_auth_method: Option<Cow<'a, str>>,
            #[serde(default, borrow)]
            resource_metadata_url: Option<Cow<'a, str>>,
        }
        if raw.is_empty() || raw.len() > 64 * 1024 {
            return Err(GoogleDriveOAuthError::InvalidClient);
        }
        let mut wire: Wire<'_> =
            serde_json::from_slice(raw).map_err(|_| GoogleDriveOAuthError::InvalidClient)?;
        let valid = valid_component(&wire.client_id, 4 * 1024)
            && valid_component(&wire.client_secret, 16 * 1024)
            && wire.issuer == expected_issuer
            && wire.token_endpoint_auth_method.as_deref() == Some("client_secret_post")
            && wire.resource_metadata_url.is_none();
        if !valid {
            zeroize_cow(&mut wire.client_secret);
            return Err(GoogleDriveOAuthError::InvalidClient);
        }
        let result = Self {
            client_id: wire.client_id.to_string(),
            client_secret: SecretBytes::new(wire.client_secret.as_bytes().to_vec()),
        };
        zeroize_cow(&mut wire.client_secret);
        Ok(result)
    }
}

impl core::fmt::Debug for StoredGoogleClient {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("StoredGoogleClient")
            .field("client_id_bytes", &self.client_id.len())
            .field("client_secret", &"<redacted>")
            .finish()
    }
}

struct GoogleTokenGrant {
    access_token: SecretBytes,
    refresh_token: Option<SecretBytes>,
    scope: Option<String>,
}

#[derive(Deserialize)]
struct TokenWire<'a> {
    #[serde(borrow)]
    access_token: Cow<'a, str>,
    #[serde(borrow)]
    token_type: Cow<'a, str>,
    #[serde(default, borrow)]
    refresh_token: Option<Cow<'a, str>>,
    #[serde(default, borrow)]
    scope: Option<Cow<'a, str>>,
}

fn parse_token_response(raw: &[u8]) -> Result<GoogleTokenGrant, GoogleDriveOAuthError> {
    let mut wire: TokenWire<'_> =
        serde_json::from_slice(raw).map_err(|_| GoogleDriveOAuthError::InvalidResponse)?;
    let valid = wire.token_type.eq_ignore_ascii_case("bearer")
        && valid_component(&wire.access_token, MAX_TOKEN_BYTES)
        && wire
            .refresh_token
            .as_ref()
            .is_none_or(|token| valid_component(token, MAX_TOKEN_BYTES))
        && wire
            .scope
            .as_ref()
            .is_none_or(|scope| valid_component(scope, 16 * 1024));
    if !valid
        || wire
            .refresh_token
            .as_ref()
            .is_some_and(|refresh| refresh.as_bytes() == wire.access_token.as_bytes())
    {
        zeroize_token_wire(&mut wire);
        return Err(GoogleDriveOAuthError::InvalidResponse);
    }
    let result = GoogleTokenGrant {
        access_token: SecretBytes::new(wire.access_token.as_bytes().to_vec()),
        refresh_token: wire
            .refresh_token
            .as_ref()
            .map(|value| SecretBytes::new(value.as_bytes().to_vec())),
        scope: wire.scope.as_ref().map(ToString::to_string),
    };
    zeroize_token_wire(&mut wire);
    Ok(result)
}

fn google_form<const N: usize>(pairs: [(&str, &str); N]) -> Vec<u8> {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(key, value);
    }
    let form = Zeroizing::new(serializer.finish());
    form.as_bytes().to_vec()
}

fn classify_error(status: StatusCode, raw: &[u8]) -> GoogleDriveOAuthError {
    if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
        return GoogleDriveOAuthError::Unavailable;
    }
    #[derive(Deserialize)]
    struct ErrorWire<'a> {
        #[serde(borrow)]
        error: Cow<'a, str>,
    }
    match serde_json::from_slice::<ErrorWire<'_>>(raw)
        .ok()
        .map(|wire| wire.error)
        .as_deref()
    {
        Some("invalid_grant" | "invalid_client" | "unauthorized_client" | "invalid_token") => {
            GoogleDriveOAuthError::AuthRequired
        }
        _ => GoogleDriveOAuthError::InvalidResponse,
    }
}

fn oauth_budget() -> Result<SafeHttpBudget, GoogleDriveOAuthError> {
    SafeHttpBudget::new(MAX_OAUTH_RESPONSE_BYTES, MCP_OAUTH_TOKEN_TIMEOUT)
        .map_err(|_| GoogleDriveOAuthError::InvalidClient)
}

fn parse_url(value: &str, scheme: SchemePolicy) -> Result<Url, GoogleDriveOAuthError> {
    let url = Url::parse(value).map_err(|_| GoogleDriveOAuthError::InvalidClient)?;
    if url.cannot_be_a_base()
        || !scheme.accepts(url.scheme())
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(GoogleDriveOAuthError::InvalidClient);
    }
    Ok(url)
}

fn validate_redirect(value: &str, scheme: SchemePolicy) -> Result<(), GoogleDriveOAuthError> {
    let url = parse_url(value, scheme)?;
    if url.scheme() == "http" {
        let loopback = match url.host() {
            Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            None => false,
        };
        if !loopback {
            return Err(GoogleDriveOAuthError::InvalidClient);
        }
    }
    Ok(())
}

fn valid_base64url(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_pkce(value: &[u8]) -> bool {
    (43..=128).contains(&value.len())
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn valid_component(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.as_bytes().contains(&0)
}

fn secret_str(secret: &SecretBytes) -> Result<&str, GoogleDriveOAuthError> {
    core::str::from_utf8(secret.expose()).map_err(|_| GoogleDriveOAuthError::InvalidClient)
}

fn zeroize_cow(value: &mut Cow<'_, str>) {
    if let Cow::Owned(value) = value {
        value.zeroize();
    }
}

fn zeroize_token_wire(wire: &mut TokenWire<'_>) {
    zeroize_cow(&mut wire.access_token);
    if let Some(refresh) = &mut wire.refresh_token {
        zeroize_cow(refresh);
    }
}

fn map_exchange_error(error: GoogleDriveOAuthError) -> OAuthTokenExchangeError {
    match error {
        GoogleDriveOAuthError::Unavailable => OAuthTokenExchangeError::Unavailable,
        GoogleDriveOAuthError::AuthRequired => OAuthTokenExchangeError::AuthRequired,
        GoogleDriveOAuthError::InvalidClient | GoogleDriveOAuthError::InvalidResponse => {
            OAuthTokenExchangeError::InvalidResponse
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_registration_and_authorization_url_are_exact() {
        let registration = McpOAuthClientRegistration::new(
            "client".to_owned(),
            "GOOGLE-CLIENT-SECRET-CANARY".to_owned(),
            GOOGLE_DRIVE_ISSUER.to_owned(),
            McpOAuthClientAuthMethod::ClientSecretPost,
            None,
        )
        .unwrap();
        let endpoints = GoogleDriveOAuthEndpoints::pinned().unwrap();
        assert_eq!(
            endpoints.resource.as_str().trim_end_matches('/'),
            GOOGLE_DRIVE_API_BASE
        );
        let encoded = serde_json::to_vec(&registration).unwrap();
        let client = StoredGoogleClient::parse(&encoded, GOOGLE_DRIVE_ISSUER).unwrap();
        assert_eq!(client.client_id, "client");
        assert!(!format!("{client:?}").contains("GOOGLE-CLIENT-SECRET-CANARY"));
    }
}
