//! `oauth2::AsyncHttpClient` 到唯一 safe dialer 的受约束适配。
//!
//! `AsyncHttpClient` 原始接口能表达任意 method/header/body，不能直接作为项目出网 port。本类型在
//! 构造时锁定一个 token endpoint；每次调用只接受 oauth2 5.0.0 生成的精确形态：同一 URL、POST、
//! JSON Accept、form Content-Type、可选且唯一的 Authorization。其余 header/method/URL 一律拒绝，
//! 再收敛成 [`crate::net::safe_http::SafeHttpRequest`]。这样协议库负责 RFC 6749 编码，网络能力仍
//! 只有 safe dialer 一条。

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderName};
use http::{HeaderMap, Method, Response};
use openidconnect::{AsyncHttpClient, HttpRequest, HttpResponse, TokenUrl};
use url::Url;

use crate::net::safe_http::{AuthorizationValue, SafeDialer, SafeHttpBudget, SafeHttpRequest};

const JSON_ESSENCE: &str = "application/json";
const FORM_ESSENCE: &str = "application/x-www-form-urlencoded";

/// token transport 的无载荷错误。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SafeOauthHttpError {
    #[error("oidc_token_request_shape_rejected")]
    RequestShapeRejected,
    #[error("oidc_token_transport_unavailable")]
    TransportUnavailable,
    #[error("oidc_token_provider_failure")]
    ProviderFailure,
}

impl From<SafeOauthHttpError> for super::error::OidcError {
    fn from(error: SafeOauthHttpError) -> Self {
        match error {
            SafeOauthHttpError::RequestShapeRejected => Self::TokenExchangeRejected,
            SafeOauthHttpError::TransportUnavailable => Self::TransportUnavailable,
            SafeOauthHttpError::ProviderFailure => Self::ProviderResponseInvalid,
        }
    }
}

/// 只被允许调用一个 token endpoint 的 OAuth HTTP adapter。
#[derive(Clone)]
pub struct SafeOauthHttpClient {
    dialer: SafeDialer,
    token_endpoint: Url,
    budget: SafeHttpBudget,
}

impl SafeOauthHttpClient {
    /// 锁定 endpoint 与预算。endpoint 必须是 HTTPS，且无 userinfo/fragment。
    pub fn new(
        dialer: SafeDialer,
        token_endpoint: &TokenUrl,
        budget: SafeHttpBudget,
    ) -> Result<Self, SafeOauthHttpError> {
        let endpoint = token_endpoint.url().clone();
        // 用真正的 request 构造器复用同一份 URL/scheme 闸门，不抄一份检查。
        SafeHttpRequest::post_form(endpoint.clone(), Vec::new(), None, budget)
            .map_err(|_| SafeOauthHttpError::RequestShapeRejected)?;
        Ok(Self {
            dialer,
            token_endpoint: endpoint,
            budget,
        })
    }

    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, SafeOauthHttpError> {
        let plan = self.request_plan(request)?;
        let safe_response = self
            .dialer
            .execute(plan)
            .await
            .map_err(|_| SafeOauthHttpError::TransportUnavailable)?;
        let (status, headers, body) = safe_response.into_parts();
        if is_provider_failure_status(status) {
            return Err(SafeOauthHttpError::ProviderFailure);
        }

        // oauth2 只需要 Content-Type；不把 Set-Cookie、Server 等远端 header 扩进协议面。
        let mut response = Response::builder()
            .status(status)
            .body(body)
            .map_err(|_| SafeOauthHttpError::TransportUnavailable)?;
        if let Some(content_type) = headers.get(CONTENT_TYPE) {
            response
                .headers_mut()
                .insert(CONTENT_TYPE, content_type.clone());
        }
        Ok(response)
    }

    fn request_plan(&self, request: HttpRequest) -> Result<SafeHttpRequest, SafeOauthHttpError> {
        let (parts, body) = request.into_parts();
        if parts.method != Method::POST {
            return Err(SafeOauthHttpError::RequestShapeRejected);
        }
        let url = Url::parse(&parts.uri.to_string())
            .map_err(|_| SafeOauthHttpError::RequestShapeRejected)?;
        if url != self.token_endpoint {
            return Err(SafeOauthHttpError::RequestShapeRejected);
        }
        validate_headers(&parts.headers)?;

        let authorization = parts
            .headers
            .get(AUTHORIZATION)
            .map(|value| {
                value
                    .to_str()
                    .map_err(|_| SafeOauthHttpError::RequestShapeRejected)
                    .and_then(|raw| {
                        AuthorizationValue::parse(raw)
                            .map_err(|_| SafeOauthHttpError::RequestShapeRejected)
                    })
            })
            .transpose()?;

        SafeHttpRequest::post_form(url, body, authorization, self.budget)
            .map_err(|_| SafeOauthHttpError::RequestShapeRejected)
    }
}

fn is_provider_failure_status(status: http::StatusCode) -> bool {
    status.is_server_error() || status == http::StatusCode::TOO_MANY_REQUESTS
}

impl fmt::Debug for SafeOauthHttpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SafeOauthHttpClient")
            .field("scheme", &self.token_endpoint.scheme())
            .field("host", &self.token_endpoint.host_str())
            .field("port", &self.token_endpoint.port_or_known_default())
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}

impl<'client> AsyncHttpClient<'client> for SafeOauthHttpClient {
    type Error = SafeOauthHttpError;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + 'client>>;

    fn call(&'client self, request: HttpRequest) -> Self::Future {
        Box::pin(self.execute(request))
    }
}

fn validate_headers(headers: &HeaderMap) -> Result<(), SafeOauthHttpError> {
    for name in headers.keys() {
        if !is_allowed_request_header(name) {
            return Err(SafeOauthHttpError::RequestShapeRejected);
        }
    }
    if headers.get_all(ACCEPT).iter().count() != 1
        || headers.get_all(CONTENT_TYPE).iter().count() != 1
        || headers.get_all(AUTHORIZATION).iter().count() > 1
    {
        return Err(SafeOauthHttpError::RequestShapeRejected);
    }
    if !header_has_essence(headers, ACCEPT, JSON_ESSENCE)
        || !header_has_essence(headers, CONTENT_TYPE, FORM_ESSENCE)
    {
        return Err(SafeOauthHttpError::RequestShapeRejected);
    }
    Ok(())
}

fn is_allowed_request_header(name: &HeaderName) -> bool {
    matches!(name, &ACCEPT | &CONTENT_TYPE | &AUTHORIZATION)
}

fn header_has_essence(headers: &HeaderMap, name: HeaderName, expected: &str) -> bool {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|essence| essence.trim().eq_ignore_ascii_case(expected))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::safe_http::{EgressPolicy, SafeHttpError};
    use http::Request;
    use std::time::Duration;

    fn client() -> SafeOauthHttpClient {
        SafeOauthHttpClient::new(
            SafeDialer::new(EgressPolicy::default()),
            &TokenUrl::new("https://idp.example/token".to_owned()).unwrap(),
            SafeHttpBudget::new(64 * 1024, Duration::from_secs(10)).unwrap(),
        )
        .unwrap()
    }

    fn valid_request() -> HttpRequest {
        Request::builder()
            .method(Method::POST)
            .uri("https://idp.example/token")
            .header(ACCEPT, JSON_ESSENCE)
            .header(CONTENT_TYPE, FORM_ESSENCE)
            .header(AUTHORIZATION, "Basic c2VjcmV0")
            .body(b"grant_type=authorization_code&code=SECRET-CODE".to_vec())
            .unwrap()
    }

    #[test]
    fn exact_oauth_shape_becomes_a_redacted_safe_plan() {
        let plan = client().request_plan(valid_request()).unwrap();
        let debug = format!("{plan:?}");
        assert!(debug.contains("has_authorization: true"));
        let expected_length = b"grant_type=authorization_code&code=SECRET-CODE".len();
        assert!(debug.contains(&format!("body_bytes: {expected_length}")));
        assert!(!debug.contains("SECRET-CODE"));
        assert!(!debug.contains("c2VjcmV0"));
    }

    #[test]
    fn method_endpoint_and_header_surface_are_all_closed() {
        let client = client();

        let mut wrong_method = valid_request();
        *wrong_method.method_mut() = Method::GET;
        assert_eq!(
            client.request_plan(wrong_method).unwrap_err(),
            SafeOauthHttpError::RequestShapeRejected
        );

        let mut wrong_endpoint = valid_request();
        *wrong_endpoint.uri_mut() = "https://other.example/token".parse().unwrap();
        assert_eq!(
            client.request_plan(wrong_endpoint).unwrap_err(),
            SafeOauthHttpError::RequestShapeRejected
        );

        let mut extra_header = valid_request();
        extra_header
            .headers_mut()
            .insert("cookie", "session=secret".parse().unwrap());
        assert_eq!(
            client.request_plan(extra_header).unwrap_err(),
            SafeOauthHttpError::RequestShapeRejected
        );
    }

    #[test]
    fn invalid_content_type_and_oversized_body_fail_before_network() {
        let client = client();
        let mut wrong_type = valid_request();
        wrong_type
            .headers_mut()
            .insert(CONTENT_TYPE, "application/json".parse().unwrap());
        assert_eq!(
            client.request_plan(wrong_type).unwrap_err(),
            SafeOauthHttpError::RequestShapeRejected
        );

        let oversized = Request::builder()
            .method(Method::POST)
            .uri("https://idp.example/token")
            .header(ACCEPT, JSON_ESSENCE)
            .header(CONTENT_TYPE, FORM_ESSENCE)
            .body(vec![
                b'x';
                crate::net::safe_http::MAX_REQUEST_BODY_BYTES + 1
            ])
            .unwrap();
        assert_eq!(
            client.request_plan(oversized).unwrap_err(),
            SafeOauthHttpError::RequestShapeRejected
        );

        // 正向对照：底层真正的失败类别不是恒等于 request-shape。
        assert_ne!(
            SafeOauthHttpError::TransportUnavailable.to_string(),
            SafeHttpError::InvalidBudget.to_string()
        );
        assert!(is_provider_failure_status(
            http::StatusCode::TOO_MANY_REQUESTS
        ));
        assert!(is_provider_failure_status(http::StatusCode::BAD_GATEWAY));
        assert!(!is_provider_failure_status(http::StatusCode::BAD_REQUEST));
        assert!(!is_provider_failure_status(http::StatusCode::OK));
    }
}
