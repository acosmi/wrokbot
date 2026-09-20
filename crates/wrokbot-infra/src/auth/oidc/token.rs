//! Authorization Code + PKCE 的 token exchange，以及不可信 JOSE `kid` 提示解析。
//!
//! RFC 6749 form/basic-auth 编码交给钉版 `oauth2 5.0.0`；本模块不手拼 client secret。生产函数
//! 只接受 [`super::token_transport::SafeOauthHttpClient`]，所以协议库生成的 POST 最终仍只能走
//! 唯一 safe dialer。token response 的 access/refresh token 不在这里持久化；登录身份只接受
//! ID token，缺失即拒绝。
//!
//! JOSE header 的 `kid` **不被信任**：只用来决定 JWKS 缓存是否需要受限重拉，算法/issuer/
//! audience/nonce 全由 `openidconnect` verifier 从受信配置与已验证 keyset 判定。

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openidconnect::core::{CoreClient, CoreProviderMetadata};
use openidconnect::{
    AsyncHttpClient, AuthorizationCode, ClientSecret, JsonWebKeyId, PkceCodeVerifier,
    RequestTokenError, TokenResponse,
};
use serde::Deserialize;

use super::error::OidcError;
use super::provider::OidcProviderConfig;
use super::token_transport::SafeOauthHttpClient;

const MAX_JOSE_HEADER_BYTES: usize = 8 * 1024;
const MAX_KID_BYTES: usize = 256;

/// 用安全 transport 交换 code，返回原始 ID token 串。
pub async fn exchange_authorization_code(
    metadata: &CoreProviderMetadata,
    provider: &OidcProviderConfig,
    client_secret: Option<&ClientSecret>,
    code: AuthorizationCode,
    verifier: PkceCodeVerifier,
    transport: &SafeOauthHttpClient,
) -> Result<String, OidcError> {
    exchange_with(metadata, provider, client_secret, code, verifier, transport).await
}

async fn exchange_with<C>(
    metadata: &CoreProviderMetadata,
    provider: &OidcProviderConfig,
    client_secret: Option<&ClientSecret>,
    code: AuthorizationCode,
    verifier: PkceCodeVerifier,
    transport: &C,
) -> Result<String, OidcError>
where
    for<'client> C: AsyncHttpClient<'client>,
    for<'client> <C as AsyncHttpClient<'client>>::Error: Into<OidcError>,
{
    if metadata.token_endpoint().is_none() {
        return Err(OidcError::TokenEndpointMissing);
    }
    let redirect = provider.redirect_uri().to_openidconnect()?;
    let client: CoreClient<_, _, _, _, _, _> = CoreClient::from_provider_metadata(
        metadata.clone(),
        provider.client_id().clone(),
        client_secret.cloned(),
    )
    .set_redirect_uri(redirect);
    let request = client
        .exchange_code(code)
        .map_err(|_| OidcError::TokenEndpointMissing)?
        .set_pkce_verifier(verifier);
    let response = match request.request_async(transport).await {
        Ok(response) => response,
        Err(RequestTokenError::Request(error)) => return Err(error.into()),
        Err(RequestTokenError::ServerResponse(_)) => {
            return Err(OidcError::TokenExchangeRejected);
        }
        Err(RequestTokenError::Parse(_, _) | RequestTokenError::Other(_)) => {
            return Err(OidcError::ProviderResponseInvalid);
        }
    };
    let id_token = response.id_token().ok_or(OidcError::IdTokenMissing)?;
    Ok(id_token.to_string())
}

#[derive(Deserialize)]
struct KidOnlyHeader {
    #[serde(default)]
    kid: Option<String>,
    // `alg`/`typ` 等字段必须能存在，但不被本解析器读取。用 flatten 接住后立即丢弃；
    // 真正的算法判定在 verifier 的 allowlist，不在这里。
    #[serde(flatten)]
    _ignored: serde_json::Map<String, serde_json::Value>,
}

/// 从 JWT header 取一个**不可信提示**，只服务 JWKS cache lookup/rotation。
pub fn untrusted_key_id(raw_id_token: &str) -> Result<Option<JsonWebKeyId>, OidcError> {
    let mut segments = raw_id_token.split('.');
    let header = segments.next().ok_or(OidcError::IdTokenMalformed)?;
    let payload = segments.next().ok_or(OidcError::IdTokenMalformed)?;
    let signature = segments.next().ok_or(OidcError::IdTokenMalformed)?;
    if segments.next().is_some() || header.is_empty() || payload.is_empty() || signature.is_empty()
    {
        return Err(OidcError::IdTokenMalformed);
    }
    if header.len() > MAX_JOSE_HEADER_BYTES * 2 {
        return Err(OidcError::IdTokenMalformed);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(header)
        .map_err(|_| OidcError::IdTokenMalformed)?;
    if decoded.len() > MAX_JOSE_HEADER_BYTES {
        return Err(OidcError::IdTokenMalformed);
    }
    let header: KidOnlyHeader =
        serde_json::from_slice(&decoded).map_err(|_| OidcError::IdTokenMalformed)?;
    match header.kid {
        None => Ok(None),
        Some(kid)
            if !kid.is_empty()
                && kid.len() <= MAX_KID_BYTES
                && !kid.chars().any(char::is_control) =>
        {
            Ok(Some(JsonWebKeyId::new(kid)))
        }
        Some(_) => Err(OidcError::IdTokenMalformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::oidc::discovery::fixtures::discovery_document;
    use crate::auth::oidc::provider::ProviderOrigin;
    use crate::auth::oidc::provider::fixtures::{config, okta_kind};
    use crate::auth::oidc::redirect::{CanonicalRedirectUri, HTTPS_ONLY};
    use crate::auth::oidc::token_transport::SafeOauthHttpError;
    use http::header::CONTENT_TYPE;
    use openidconnect::core::CoreProviderMetadata;
    use openidconnect::{HttpRequest, HttpResponse};

    const ISSUER: &str = "https://idp.example";
    const TOKEN: &str = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoic3ViamVjdCIsImF1ZCI6Im9rdGEtY2xpZW50IiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjE4MDAwMDAwMDB9.c2ln";

    fn provider() -> OidcProviderConfig {
        config(
            "okta",
            okta_kind(ISSUER),
            ProviderOrigin::EnvironmentConfigured,
            &["example.com"],
        )
    }

    fn metadata() -> CoreProviderMetadata {
        serde_json::from_str(&discovery_document(ISSUER, "https://idp.example/jwks")).unwrap()
    }

    fn verifier() -> PkceCodeVerifier {
        PkceCodeVerifier::new("a".repeat(64))
    }

    #[tokio::test]
    async fn oauth_library_builds_the_code_pkce_and_exact_redirect_form() {
        let transport = |request: HttpRequest| async move {
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri(), "https://idp.example/v1/token");
            let body = String::from_utf8(request.body().clone()).unwrap();
            assert!(body.contains("grant_type=authorization_code"));
            assert!(body.contains("code=one-time-code"));
            assert!(body.contains("code_verifier="));
            assert!(body.contains("redirect_uri=https%3A%2F%2Fapp.example.com%2Fauth%2Fcallback"));
            assert!(
                !body.contains("client_secret"),
                "Basic auth 不把 secret 放 form"
            );
            Ok::<_, SafeFakeError>(
                http::Response::builder()
                    .status(200)
                    .header(CONTENT_TYPE, "application/json")
                    .body(
                        format!(
                            r#"{{"access_token":"access","token_type":"Bearer","id_token":"{TOKEN}"}}"#
                        )
                        .into_bytes(),
                    )
                    .unwrap(),
            )
        };
        let provider = provider();
        // fixture helper 固定 callback；正向钉住它就是生产精确 URI。
        assert_eq!(
            provider.redirect_uri(),
            &CanonicalRedirectUri::parse("https://app.example.com/auth/callback", HTTPS_ONLY)
                .unwrap()
        );
        let raw = exchange_with(
            &metadata(),
            &provider,
            Some(&ClientSecret::new("client-secret".to_owned())),
            AuthorizationCode::new("one-time-code".to_owned()),
            verifier(),
            &transport,
        )
        .await
        .unwrap();
        assert_eq!(raw, TOKEN);
        assert_eq!(provider.id().as_str(), "okta");
    }

    #[derive(Debug, thiserror::Error)]
    #[error("fake")]
    struct SafeFakeError;

    impl From<SafeFakeError> for OidcError {
        fn from(_: SafeFakeError) -> Self {
            Self::TokenExchangeRejected
        }
    }

    #[tokio::test]
    async fn missing_endpoint_exchange_failure_and_missing_id_token_are_distinct() {
        let mut without: serde_json::Value =
            serde_json::from_str(&discovery_document(ISSUER, "https://idp.example/jwks")).unwrap();
        without.as_object_mut().unwrap().remove("token_endpoint");
        let without: CoreProviderMetadata = serde_json::from_value(without).unwrap();
        let never = |_request: HttpRequest| async { Err::<HttpResponse, _>(SafeFakeError) };
        assert_eq!(
            exchange_with(
                &without,
                &provider(),
                None,
                AuthorizationCode::new("code".to_owned()),
                verifier(),
                &never,
            )
            .await,
            Err(OidcError::TokenEndpointMissing)
        );

        assert_eq!(
            exchange_with(
                &metadata(),
                &provider(),
                None,
                AuthorizationCode::new("code".to_owned()),
                verifier(),
                &never,
            )
            .await,
            Err(OidcError::TokenExchangeRejected)
        );

        let unavailable = |_request: HttpRequest| async {
            Err::<HttpResponse, _>(SafeOauthHttpError::TransportUnavailable)
        };
        assert_eq!(
            exchange_with(
                &metadata(),
                &provider(),
                None,
                AuthorizationCode::new("code".to_owned()),
                verifier(),
                &unavailable,
            )
            .await,
            Err(OidcError::TransportUnavailable)
        );

        let no_id = |_request: HttpRequest| async {
            Ok::<_, SafeFakeError>(
                http::Response::builder()
                    .status(200)
                    .header(CONTENT_TYPE, "application/json")
                    .body(br#"{"access_token":"a","token_type":"Bearer"}"#.to_vec())
                    .unwrap(),
            )
        };
        assert_eq!(
            exchange_with(
                &metadata(),
                &provider(),
                None,
                AuthorizationCode::new("code".to_owned()),
                verifier(),
                &no_id,
            )
            .await,
            Err(OidcError::IdTokenMissing)
        );

        let malformed = |_request: HttpRequest| async {
            Ok::<_, SafeFakeError>(
                http::Response::builder()
                    .status(200)
                    .header(CONTENT_TYPE, "application/json")
                    .body(b"not-json".to_vec())
                    .unwrap(),
            )
        };
        assert_eq!(
            exchange_with(
                &metadata(),
                &provider(),
                None,
                AuthorizationCode::new("code".to_owned()),
                verifier(),
                &malformed,
            )
            .await,
            Err(OidcError::ProviderResponseInvalid)
        );
    }

    fn token_with_header(header: serde_json::Value) -> String {
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        format!("{encoded}.e30.signature")
    }

    #[test]
    fn kid_is_only_a_bounded_untrusted_hint() {
        let token = token_with_header(serde_json::json!({"alg":"RS256","kid":"key-7"}));
        assert_eq!(untrusted_key_id(&token).unwrap().unwrap().as_str(), "key-7");
        assert_eq!(
            untrusted_key_id(&token_with_header(serde_json::json!({"alg":"RS256"}))).unwrap(),
            None
        );
        for bad in [
            "not-a-jwt".to_owned(),
            token_with_header(serde_json::json!({"kid":""})),
            token_with_header(serde_json::json!({"kid":"x".repeat(MAX_KID_BYTES + 1)})),
            token_with_header(serde_json::json!({"kid":"line\nbreak"})),
        ] {
            assert_eq!(untrusted_key_id(&bad), Err(OidcError::IdTokenMalformed));
        }
    }
}
