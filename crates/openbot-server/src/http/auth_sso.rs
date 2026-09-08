//! deployment-owned OIDC/SAML 的匿名 routing、SAML ACS/metadata 与 admin 写面。

use std::net::SocketAddr;

use axum::Json;
use axum::body::Body;
use axum::extract::rejection::{FormRejection, JsonRejection};
use axum::extract::{ConnectInfo, Form, Path, State};
use axum::http::header::{CONTENT_TYPE, COOKIE, LOCATION, ORIGIN, SET_COOKIE, USER_AGENT};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use openbot_contracts::auth::{EnterpriseSsoRoutingAccepted, EnterpriseSsoStartRequest, Role};
use openbot_contracts::error::AppError;
use openbot_contracts::identity_provider::{IdentityProviderRemoved, IdentityProvidersResponse};
use openbot_contracts::ids::ActorId;
use openbot_infra::auth::oidc::ProviderId;
use openbot_infra::auth::sso::{DynamicSsoStart, RegisterIdentityProviderInput, SamlStart};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::auth::{Authenticated, SensitiveAuthenticated};
use crate::error::HttpError;
use crate::http::ServerState;
use crate::http::auth_oidc::{dynamic_login_error, issued_session_response, no_store};

const ROUTE_COOKIE_NAME: &str = "openbot_sso_route";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Better Auth delete-provider 兼容 body。
pub struct ProviderIdBody {
    /// 要删除的 provider ID。
    pub provider_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
/// SAML HTTP-POST binding 的两字段 body。
pub struct SamlAcsForm {
    /// base64 SAML Response。
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,
    /// 本部署铸造的一次性 RelayState。
    #[serde(rename = "RelayState")]
    pub relay_state: String,
}

/// Email 命中/未命中始终 202 同体；唯一差异只在 HttpOnly ticket 的服务端记录里。
pub async fn route_email(
    State(state): State<ServerState>,
    headers: HeaderMap,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    body: Result<Json<EnterpriseSsoStartRequest>, JsonRejection>,
) -> Response {
    if !trusted_origin(&state, &headers) {
        return stable_error(StatusCode::FORBIDDEN, "authentication_origin_rejected");
    }
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return stable_error(StatusCode::BAD_REQUEST, "authentication_failed"),
    };
    let Some(service) = state.dynamic_sso() else {
        return stable_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
        );
    };
    let now = OffsetDateTime::now_utc();
    match service
        .route_email(&body.email, &address.ip().to_string(), now)
        .await
    {
        Ok(receipt) => {
            let Some(cookie) = route_cookie_header(
                receipt.ticket(),
                receipt.expires_at(),
                now,
                state.secure_session_cookie(),
            ) else {
                return stable_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authentication_unavailable",
                );
            };
            let mut response = (
                StatusCode::ACCEPTED,
                Json(EnterpriseSsoRoutingAccepted { accepted: true }),
            )
                .into_response();
            response.headers_mut().insert(SET_COOKIE, cookie);
            no_store(response.headers_mut());
            response
        }
        Err(error) => {
            let mut response = dynamic_login_error(error);
            response
                .headers_mut()
                .insert(SET_COOKIE, clear_route_cookie());
            response
        }
    }
}

/// 消耗匿名 route ticket；命中后才离开本站，未命中给统一失败页。
pub async fn continue_route(
    State(state): State<ServerState>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let Some(ticket) = unique_cookie(&headers, ROUTE_COOKIE_NAME) else {
        return stable_error(StatusCode::BAD_REQUEST, "authentication_failed");
    };
    let Some(service) = state.dynamic_sso() else {
        return stable_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
        );
    };
    match service
        .continue_route(
            &ticket,
            &address.ip().to_string(),
            OffsetDateTime::now_utc(),
        )
        .await
    {
        Ok(DynamicSsoStart::Oidc(url)) | Ok(DynamicSsoStart::Saml(SamlStart::Redirect(url))) => {
            redirect_with_cleared_ticket(url)
        }
        Ok(DynamicSsoStart::Saml(SamlStart::Post {
            destination,
            saml_request,
            relay_state,
        })) => saml_post_form(destination.as_str(), &saml_request, &relay_state),
        Err(error) => {
            let mut response = dynamic_login_error(error);
            response
                .headers_mut()
                .insert(SET_COOKIE, clear_route_cookie());
            response
        }
    }
}

/// SAML HTTP-POST ACS；RelayState 先烧，随后才解析/验签。
pub async fn saml_acs(
    State(state): State<ServerState>,
    Path(provider_id): Path<String>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    form: Result<Form<SamlAcsForm>, FormRejection>,
) -> Response {
    let Form(form) = match form {
        Ok(form) => form,
        Err(_) => return stable_error(StatusCode::BAD_REQUEST, "authentication_failed"),
    };
    let Ok(provider) = ProviderId::parse(&provider_id) else {
        return stable_error(StatusCode::BAD_REQUEST, "authentication_failed");
    };
    let Some(service) = state.dynamic_sso() else {
        return stable_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
        );
    };
    let now = OffsetDateTime::now_utc();
    let peer = address.ip().to_string();
    let user_agent = headers
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok());
    match service
        .saml_callback(
            &provider,
            &form.relay_state,
            &form.saml_response,
            now,
            &peer,
            user_agent,
        )
        .await
    {
        Ok(issued) => issued_session_response(&state, &issued, now),
        Err(error) => dynamic_login_error(error),
    }
}

/// 公开 SP metadata；只含本站 entity/ACS，不含 IdP 配置 secret。
pub async fn saml_metadata(
    State(state): State<ServerState>,
    Path(provider_id): Path<String>,
) -> Response {
    let Ok(provider) = ProviderId::parse(&provider_id) else {
        return stable_error(StatusCode::NOT_FOUND, "authentication_failed");
    };
    let Some(service) = state.dynamic_sso() else {
        return stable_error(StatusCode::NOT_FOUND, "authentication_failed");
    };
    match service
        .saml_metadata(&provider, OffsetDateTime::now_utc())
        .await
    {
        Ok(xml) => {
            let mut response = Response::new(Body::from(xml));
            response.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/samlmetadata+xml; charset=utf-8"),
            );
            no_store(response.headers_mut());
            response
        }
        Err(error) => dynamic_login_error(error),
    }
}

/// `GET /api/admin/identity-providers`。
pub async fn list(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
) -> Result<Response, HttpError> {
    require_admin(&auth)?;
    let service = state.dynamic_sso().ok_or(AppError::DependencyUnavailable {
        dependency: "dynamic_sso",
    })?;
    let providers = service
        .list()
        .await
        .map_err(|_| AppError::DependencyUnavailable {
            dependency: "dynamic_sso",
        })?;
    Ok(no_store_response(
        Json(IdentityProvidersResponse { providers }).into_response(),
    ))
}

/// `POST /api/auth/sso/register`；fresh admin + Origin。
pub async fn register(
    State(state): State<ServerState>,
    SensitiveAuthenticated(resolved): SensitiveAuthenticated,
    headers: HeaderMap,
    body: Result<Json<RegisterIdentityProviderInput>, JsonRejection>,
) -> Response {
    if let Err(error) = state
        .authorize_sensitive_write(&resolved, request_origin(&headers))
        .await
    {
        return HttpError::from(error).into_response();
    }
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return stable_error(StatusCode::BAD_REQUEST, "malformed_payload"),
    };
    let actor = resolved.context().actor().clone();
    let Some(service) = state.dynamic_sso() else {
        return stable_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
        );
    };
    match service
        .register(body, &actor, OffsetDateTime::now_utc())
        .await
    {
        Ok(provider) => no_store_response(Json(provider).into_response()),
        Err(error) => dynamic_login_error(error),
    }
}

/// `POST /api/auth/sso/update-provider`；更新会统一失效旧 account/session anchors。
pub async fn update(
    State(state): State<ServerState>,
    SensitiveAuthenticated(resolved): SensitiveAuthenticated,
    headers: HeaderMap,
    body: Result<Json<RegisterIdentityProviderInput>, JsonRejection>,
) -> Response {
    if let Err(error) = state
        .authorize_sensitive_write(&resolved, request_origin(&headers))
        .await
    {
        return HttpError::from(error).into_response();
    }
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return stable_error(StatusCode::BAD_REQUEST, "malformed_payload"),
    };
    let actor = resolved.context().actor().clone();
    let Some(service) = state.dynamic_sso() else {
        return stable_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
        );
    };
    match service
        .update(body, &actor, OffsetDateTime::now_utc())
        .await
    {
        Ok(provider) => no_store_response(Json(provider).into_response()),
        Err(error) => dynamic_login_error(error),
    }
}

/// `POST /api/auth/sso/delete-provider` 兼容面。
pub async fn remove_compat(
    State(state): State<ServerState>,
    SensitiveAuthenticated(resolved): SensitiveAuthenticated,
    headers: HeaderMap,
    body: Result<Json<ProviderIdBody>, JsonRejection>,
) -> Response {
    if let Err(error) = state
        .authorize_sensitive_write(&resolved, request_origin(&headers))
        .await
    {
        return HttpError::from(error).into_response();
    }
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return stable_error(StatusCode::BAD_REQUEST, "malformed_payload"),
    };
    remove_authorized(state, resolved.context().actor().clone(), body.provider_id).await
}

/// `DELETE /api/admin/identity-providers/{provider_id}`。
pub async fn remove_admin(
    State(state): State<ServerState>,
    SensitiveAuthenticated(resolved): SensitiveAuthenticated,
    headers: HeaderMap,
    Path(provider_id): Path<String>,
) -> Response {
    if let Err(error) = state
        .authorize_sensitive_write(&resolved, request_origin(&headers))
        .await
    {
        return HttpError::from(error).into_response();
    }
    remove_authorized(state, resolved.context().actor().clone(), provider_id).await
}

async fn remove_authorized(state: ServerState, actor: ActorId, provider_id: String) -> Response {
    let Ok(provider) = ProviderId::parse(&provider_id) else {
        return stable_error(StatusCode::BAD_REQUEST, "malformed_payload");
    };
    let Some(service) = state.dynamic_sso() else {
        return stable_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
        );
    };
    match service.remove(&provider, &actor).await {
        Ok(()) => {
            no_store_response(Json(IdentityProviderRemoved { removed: true }).into_response())
        }
        Err(error) => dynamic_login_error(error),
    }
}

fn require_admin(auth: &openbot_contracts::auth::AuthContext) -> Result<(), HttpError> {
    if auth.has_role(Role::Admin) {
        Ok(())
    } else {
        Err(AppError::ForbiddenRole {
            required: Role::Admin,
        }
        .into())
    }
}

fn trusted_origin(state: &ServerState, headers: &HeaderMap) -> bool {
    headers
        .get(ORIGIN)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|origin| state.trusts_login_origin(origin))
}

fn request_origin(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(ORIGIN)
        .map(|value| value.to_str().unwrap_or(""))
}

fn route_cookie_header(
    ticket: &str,
    expires_at: OffsetDateTime,
    now: OffsetDateTime,
    secure: bool,
) -> Option<HeaderValue> {
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{ROUTE_COOKIE_NAME}={ticket}; Path=/api/auth/sso/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        (expires_at - now).whole_seconds().max(0),
        secure
    ))
    .ok()
}

fn clear_route_cookie() -> HeaderValue {
    HeaderValue::from_static(
        "openbot_sso_route=; Path=/api/auth/sso/; HttpOnly; SameSite=Strict; Max-Age=0",
    )
}

fn unique_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut found = None;
    for header in headers.get_all(COOKIE) {
        let value = header.to_str().ok()?;
        for pair in value.split(';') {
            let Some((candidate, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if candidate == name {
                if found.is_some() || value.is_empty() || value.len() > 512 || !value.is_ascii() {
                    return None;
                }
                found = Some(value.to_owned());
            }
        }
    }
    found
}

fn redirect_with_cleared_ticket(url: url::Url) -> Response {
    let Ok(location) = HeaderValue::from_str(url.as_str()) else {
        return stable_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
        );
    };
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(LOCATION, location);
    response
        .headers_mut()
        .insert(SET_COOKIE, clear_route_cookie());
    no_store(response.headers_mut());
    response
}

fn saml_post_form(destination: &str, request: &str, relay_state: &str) -> Response {
    let body = format!(
        "<!doctype html><html><body><form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"SAMLRequest\" value=\"{}\"><input type=\"hidden\" name=\"RelayState\" value=\"{}\"><button type=\"submit\">Continue</button></form></body></html>",
        escape_html_attribute(destination),
        escape_html_attribute(request),
        escape_html_attribute(relay_state),
    );
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(SET_COOKIE, clear_route_cookie());
    no_store(response.headers_mut());
    response
}

fn escape_html_attribute(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            _ => output.push(character),
        }
    }
    output
}

fn stable_error(status: StatusCode, code: &'static str) -> Response {
    #[derive(Serialize)]
    struct BodyShape {
        code: &'static str,
    }
    let mut response = (status, Json(BodyShape { code })).into_response();
    no_store(response.headers_mut());
    response
}

fn no_store_response(mut response: Response) -> Response {
    no_store(response.headers_mut());
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_form_values_and_duplicate_route_cookies_are_closed() {
        assert_eq!(
            escape_html_attribute("https://idp.example/?x=\"<&"),
            "https://idp.example/?x=&quot;&lt;&amp;"
        );
        let duplicate = HeaderMap::from_iter([(
            COOKIE,
            HeaderValue::from_static("openbot_sso_route=one; openbot_sso_route=two"),
        )]);
        assert_eq!(unique_cookie(&duplicate, ROUTE_COOKIE_NAME), None);
        let one = HeaderMap::from_iter([(
            COOKIE,
            HeaderValue::from_static("x=1; openbot_sso_route=one"),
        )]);
        assert_eq!(
            unique_cookie(&one, ROUTE_COOKIE_NAME).as_deref(),
            Some("one")
        );
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let route_cookie = route_cookie_header(
            "opaque-route-ticket",
            now + time::Duration::minutes(2),
            now,
            true,
        )
        .unwrap();
        assert_eq!(
            route_cookie.to_str().unwrap(),
            "openbot_sso_route=opaque-route-ticket; Path=/api/auth/sso/; HttpOnly; SameSite=Strict; Max-Age=120; Secure"
        );
        assert!(!route_cookie.to_str().unwrap().contains("Domain="));
    }
}
