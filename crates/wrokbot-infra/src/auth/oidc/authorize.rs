//! 组装 Authorization Code 请求（v3 §6.2 条 3 的「Authorization Code」那一项）。
//!
//! 这一步把 [`super::attempt::LoginAttempt`] 里的三个一次性值（`state` / `nonce` /
//! PKCE challenge）与登记的精确 redirect URI 一起，铺进授权端点的查询串。
//!
//! # 只出 challenge，绝不出 verifier
//!
//! PKCE 的全部意义在于 verifier **不经过浏览器**。所以本模块拿到的是 `&LoginAttempt`
//! （不可变借用），而 verifier 只能通过 [`super::attempt::LoginAttempt::into_nonce_and_verifier`]
//! 消耗整个 attempt 才取得出来 —— 借用的这一侧根本够不到它。由
//! `the_authorization_url_carries_the_challenge_and_never_the_verifier` 钉住。
//!
//! # 换 token 那一步仍不在本模块
//!
//! Authorization Code 的后半段是向 token endpoint 发一次 **POST**，带上 `code`、
//! `code_verifier` 与 client 认证。本模块的出网端口 [`super::transport::MetadataTransport`]
//! 只有 GET，而且那是**刻意**的（见其模块文档：一个表达不出 POST 的端口，SSRF 面小一个
//! 量级）。
//! W-7 已把后半段落在 [`super::token`] + [`super::token_transport`]：后者只接受 oauth2
//! 生成的精确 token request，再收敛到唯一 safe dialer。GET metadata port 仍不增加 POST，
//! 因而 discovery/JWKS 调用点继续表达不出 body/header。

use openidconnect::core::CoreProviderMetadata;
use url::Url;

use super::attempt::LoginAttempt;
use super::error::OidcError;
use super::provider::OidcProviderConfig;

/// OIDC Core §3.1.2.1 要求每次认证请求都带的 scope。
pub const SCOPE_OPENID: &str = "openid";

/// 默认 scope 集合。
///
/// `email` 在列是因为本部署的**每一条授权判定都以地址为键**（见 `claims` 模块文档里
/// 上游那段说明）；不额外要 `profile`，因为没有任何判定读得上头像和显示名。
pub const DEFAULT_SCOPES: &[&str] = &[SCOPE_OPENID, "email"];

/// 组装授权请求 URL。
///
/// `scopes` 里没有 `openid` 时会被**补上**（补在最前），而不是报错：漏掉它是一个
/// 纯粹的调用点笔误，且补上之后的行为恰好就是调用点想要的。重复项会被去掉。
///
/// # Errors
///
/// [`OidcError::MetadataMalformed`]：discovery 文档里的 `authorization_endpoint` 解析不成
/// URL（能走到这里说明它已经过了 `discover` 的校验，实际不会发生）。
pub fn authorization_url(
    metadata: &CoreProviderMetadata,
    provider: &OidcProviderConfig,
    attempt: &LoginAttempt,
    scopes: &[&str],
) -> Result<Url, OidcError> {
    let mut url = Url::parse(metadata.authorization_endpoint().as_str())
        .map_err(|_| OidcError::MetadataMalformed)?;

    let mut scope_list: Vec<&str> = Vec::with_capacity(scopes.len() + 1);
    scope_list.push(SCOPE_OPENID);
    for scope in scopes {
        if !scope_list.contains(scope) {
            scope_list.push(scope);
        }
    }

    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", provider.client_id().as_str())
        .append_pair("redirect_uri", attempt.redirect_uri().as_str())
        .append_pair("scope", &scope_list.join(" "))
        .append_pair("state", attempt.state().secret())
        .append_pair("nonce", attempt.nonce().secret())
        .append_pair("code_challenge", attempt.pkce().challenge())
        .append_pair("code_challenge_method", attempt.pkce().method());

    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_SCOPES, SCOPE_OPENID, authorization_url};
    use crate::auth::oidc::attempt::{LoginAttempt, PKCE_METHOD_S256};
    use crate::auth::oidc::discovery::fixtures::discovery_document;
    use crate::auth::oidc::provider::fixtures::{config, okta_kind};
    use crate::auth::oidc::provider::{OidcProviderConfig, ProviderId, ProviderOrigin};
    use crate::auth::oidc::redirect::{CanonicalRedirectUri, HTTPS_ONLY};
    use openidconnect::core::CoreProviderMetadata;
    use std::collections::HashMap;
    use time::{Duration, OffsetDateTime};
    use url::Url;

    const ISSUER: &str = "https://example.okta-test.invalid/oauth2/default";
    const JWKS: &str = "https://example.okta-test.invalid/oauth2/default/v1/keys";
    const CALLBACK: &str = "https://app.example.com/auth/callback";

    fn metadata() -> CoreProviderMetadata {
        serde_json::from_str(&discovery_document(ISSUER, JWKS)).expect("夹具必须可解析")
    }

    fn provider() -> OidcProviderConfig {
        config(
            "okta",
            okta_kind(ISSUER),
            ProviderOrigin::EnvironmentConfigured,
            &["acme.example"],
        )
    }

    fn attempt() -> LoginAttempt {
        LoginAttempt::begin(
            ProviderId::parse("okta").unwrap(),
            CanonicalRedirectUri::parse(CALLBACK, HTTPS_ONLY).unwrap(),
            OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
            Duration::minutes(10),
        )
    }

    fn params(url: &Url) -> HashMap<String, String> {
        url.query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    /// 正向：八个参数齐备，值都来自本次尝试。
    #[test]
    fn the_authorization_request_carries_every_required_parameter() {
        let attempt = attempt();
        let url = authorization_url(&metadata(), &provider(), &attempt, DEFAULT_SCOPES).unwrap();
        let params = params(&url);

        assert_eq!(
            url.as_str().split('?').next().unwrap(),
            "https://example.okta-test.invalid/oauth2/default/v1/authorize"
        );
        assert_eq!(
            params.get("response_type").map(String::as_str),
            Some("code")
        );
        assert_eq!(
            params.get("client_id").map(String::as_str),
            Some("okta-client")
        );
        assert_eq!(
            params.get("redirect_uri").map(String::as_str),
            Some(CALLBACK)
        );
        assert_eq!(
            params.get("state").map(String::as_str),
            Some(attempt.state().secret().as_str())
        );
        assert_eq!(
            params.get("nonce").map(String::as_str),
            Some(attempt.nonce().secret().as_str())
        );
        assert_eq!(
            params.get("code_challenge").map(String::as_str),
            Some(attempt.pkce().challenge())
        );
        assert_eq!(
            params.get("code_challenge_method").map(String::as_str),
            Some(PKCE_METHOD_S256)
        );
        assert_eq!(
            params.get("scope").map(String::as_str),
            Some("openid email")
        );
    }

    /// `code_challenge_method` 恒为 `S256`，`plain` 无从出现。
    #[test]
    fn the_challenge_method_is_always_s256() {
        for _ in 0..8 {
            let attempt = attempt();
            let url =
                authorization_url(&metadata(), &provider(), &attempt, DEFAULT_SCOPES).unwrap();
            assert_eq!(
                params(&url)
                    .get("code_challenge_method")
                    .map(String::as_str),
                Some("S256")
            );
            assert!(!url.as_str().contains("plain"));
        }
    }

    /// URL 里只有 challenge，没有 verifier。
    ///
    /// 断言分两半：challenge 逐字节等于 attempt 里的那个（正向），且查询串里没有任何
    /// 名为 `code_verifier` 的参数（负向）。
    #[test]
    fn the_authorization_url_carries_the_challenge_and_never_the_verifier() {
        let attempt = attempt();
        let challenge = attempt.pkce().challenge().to_owned();
        let url = authorization_url(&metadata(), &provider(), &attempt, DEFAULT_SCOPES).unwrap();

        assert_eq!(
            params(&url).get("code_challenge"),
            Some(&challenge),
            "正向：challenge 必须出现且逐字节一致"
        );
        assert!(
            !params(&url).contains_key("code_verifier"),
            "verifier 绝不能进浏览器"
        );

        // verifier 只能靠消耗整个 attempt 取出来 —— 借用侧够不到它。
        let (_nonce, verifier) = attempt.into_nonce_and_verifier();
        assert!(
            !url.as_str().contains(verifier.secret().as_str()),
            "URL 里出现了 verifier 的明文"
        );
        assert_ne!(
            verifier.secret().as_str(),
            challenge,
            "challenge 是摘要不是原值"
        );
    }

    /// redirect URI 走的是**登记的那一串字节**。
    #[test]
    fn the_redirect_uri_on_the_wire_decodes_back_to_the_registered_bytes() {
        let attempt = attempt();
        let url = authorization_url(&metadata(), &provider(), &attempt, DEFAULT_SCOPES).unwrap();

        let on_the_wire = params(&url).remove("redirect_uri").unwrap();
        assert_eq!(on_the_wire, CALLBACK);
        assert_eq!(
            attempt.redirect_uri().assert_exact_match(&on_the_wire),
            Ok(()),
            "回到我们手上的那一串必须能通过精确比对"
        );
    }

    /// `openid` 缺失时补上，重复时去重，顺序稳定。
    #[test]
    fn the_openid_scope_is_always_present_exactly_once() {
        let attempt = attempt();

        // 没给 openid：补在最前。
        let url = authorization_url(&metadata(), &provider(), &attempt, &["email"]).unwrap();
        assert_eq!(
            params(&url).get("scope").map(String::as_str),
            Some("openid email")
        );

        // 给重复了：只出现一次。
        let url = authorization_url(
            &metadata(),
            &provider(),
            &attempt,
            &[SCOPE_OPENID, "email", "openid", "email"],
        )
        .unwrap();
        let scope = params(&url).remove("scope").unwrap();
        assert_eq!(scope, "openid email");
        assert_eq!(scope.matches("openid").count(), 1);

        // 空 scope 列表也仍然带 openid。
        let url = authorization_url(&metadata(), &provider(), &attempt, &[]).unwrap();
        assert_eq!(
            params(&url).get("scope").map(String::as_str),
            Some("openid")
        );
    }

    /// 授权端点自带查询串时不被覆盖（Okta 的自定义授权服务器会有）。
    #[test]
    fn a_preexisting_query_on_the_authorization_endpoint_survives() {
        let raw = format!(
            r#"{{
  "issuer": "{ISSUER}",
  "authorization_endpoint": "{ISSUER}/v1/authorize?idp=corporate",
  "jwks_uri": "{JWKS}",
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"]
}}"#
        );
        let metadata: CoreProviderMetadata = serde_json::from_str(&raw).unwrap();

        let attempt = attempt();
        let url = authorization_url(&metadata, &provider(), &attempt, DEFAULT_SCOPES).unwrap();
        let params = params(&url);
        assert_eq!(params.get("idp").map(String::as_str), Some("corporate"));
        assert_eq!(
            params.get("response_type").map(String::as_str),
            Some("code")
        );
    }

    /// 两次尝试产出的 URL 不同（state / nonce / challenge 都是新铸的）。
    #[test]
    fn two_attempts_never_produce_the_same_authorization_url() {
        let metadata = metadata();
        let provider = provider();
        let a = authorization_url(&metadata, &provider, &attempt(), DEFAULT_SCOPES).unwrap();
        let b = authorization_url(&metadata, &provider, &attempt(), DEFAULT_SCOPES).unwrap();
        assert_ne!(a, b);
    }
}
