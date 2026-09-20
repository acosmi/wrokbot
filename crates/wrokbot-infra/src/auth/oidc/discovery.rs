//! OIDC Discovery（v3 §6.2 条 3 的 issuer 校验 + 末段的 dialer / 大小 / 时间上限）。
//!
//! # 为什么不用 `CoreProviderMetadata::discover_async`
//!
//! `openidconnect` 自带的 discovery 函数在**同一次调用里顺手把 JWKS 也拉了** ——
//! `discover_async` 的函数体末尾是 `JsonWebKeySet::fetch_async(provider_metadata.jwks_uri(), …)`。
//! 而 §6.2 要求 JWKS 拉取有缓存与速率限制（见 `jwks` 模块）：一个每次 discovery 都无条件
//! 多打一发 JWKS 的实现，恰好是那条要求禁止的形态。它还要求 `C: AsyncHttpClient<'c>`，
//! 与本模块注入端口的形状不合（理由见 `transport` 模块文档）。
//!
//! 所以这里自己走三步：拼 URL → 过注入的 dialer → 解析并校验。**能复用的仍然复用**：
//! URL 拼接用 `IssuerUrl::join`，文档结构用 `CoreProviderMetadata` 的 serde 实现，
//! 两者都不重写。
//!
//! # `IssuerUrl::join` 不是 `Url::join`，这一点是必须的
//!
//! `openidconnect-4.0.1/src/types/mod.rs` 里 `IssuerUrl` 的 `impl` 块自带一个 `join`：
//! 它做的是**字符串拼接**（末尾没有 `/` 就补一个再接后缀），而不是 `url::Url::join` 的
//! RFC 3986 相对引用解析。差别在带路径段的 issuer 上是致命的：Okta 的
//! `https://example.okta.com/oauth2/default` 用 `Url::join` 会得到
//! `…/oauth2/.well-known/openid-configuration`（最后一段被当成文件名替换掉），
//! 而正确答案是 `…/oauth2/default/.well-known/openid-configuration`。
//! 由 `url_join_would_truncate_a_path_bearing_issuer` 实测对照钉住。
//!
//! # issuer 比对是 discovery 唯一的身份锚
//!
//! 拿回来的文档自报 `issuer`，必须与我们请求的那个逐字节相等（[`OidcError::IssuerMismatch`]）。
//! 没有这条，任何能应答那个 `.well-known` 路径的主机都能冒充任意 issuer。

use openidconnect::IssuerUrl;
use openidconnect::core::CoreProviderMetadata;
use url::Url;

use super::error::OidcError;
use super::transport::{JSON_ESSENCES, MetadataRequest, MetadataTransport};

/// OIDC Discovery 1.0 §4 的 well-known 后缀。
pub const DISCOVERY_PATH_SUFFIX: &str = ".well-known/openid-configuration";

/// 一次元数据取回的预算（v3 §6.2 末段的「大小/时间上限」）。
///
/// 两个值都由调用方给定，本模块只往下传（时间上限的执行在 dialer，见
/// [`MetadataRequest::timeout`]）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FetchBudget {
    max_bytes: usize,
    timeout: core::time::Duration,
}

impl FetchBudget {
    /// 建一份预算。
    #[must_use]
    pub const fn new(max_bytes: usize, timeout: core::time::Duration) -> Self {
        Self { max_bytes, timeout }
    }

    /// 字节上限。
    #[must_use]
    pub const fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// 墙钟上限。
    #[must_use]
    pub const fn timeout(&self) -> core::time::Duration {
        self.timeout
    }

    /// 组装成一次 [`MetadataRequest`]。
    #[must_use]
    pub const fn request(&self, url: Url) -> MetadataRequest {
        MetadataRequest::new(url, self.max_bytes, self.timeout)
    }
}

/// 由 issuer 推出 discovery 文档的 URL。
///
/// 走 `IssuerUrl::join`，理由见模块文档。
///
/// # Errors
///
/// 拼出来的串解析不成 URL 时返回 [`OidcError::IssuerNotBare`]（能走到这里说明 issuer 本身
/// 已过 [`super::provider::parse_issuer`] 的闸门，实际不会发生）。
pub fn discovery_url(issuer: &IssuerUrl) -> Result<Url, OidcError> {
    issuer
        .join(DISCOVERY_PATH_SUFFIX)
        .map_err(|_| OidcError::IssuerNotBare)
}

/// 取回并校验一个 provider 的 discovery 文档。
///
/// **不**顺带拉 JWKS —— 那属于 [`super::jwks`]，它有自己的缓存与速率限制。
///
/// # Errors
///
/// - [`OidcError::TransportUnavailable`]：dialer 没能完成；
/// - [`OidcError::MetadataStatusNotOk`] / [`OidcError::MetadataTooLarge`] /
///   [`OidcError::MetadataContentTypeInvalid`]：响应不合格（判据见
///   [`super::transport::MetadataResponse::into_json_body`]）；
/// - [`OidcError::MetadataMalformed`]：解不开成一份 OIDC 元数据；
/// - [`OidcError::IssuerMismatch`]：文档自报的 issuer 不是我们请求的那个。
pub async fn discover(
    issuer: &IssuerUrl,
    transport: &dyn MetadataTransport,
    budget: FetchBudget,
) -> Result<CoreProviderMetadata, OidcError> {
    discover_with_expected_issuer(issuer, issuer, transport, budget).await
}

/// 从 `authority` 拉取、但要求文档声明 `expected_issuer`。
///
/// 普通 OIDC 两者相同；Microsoft `common` / `organizations` authority 返回
/// `{tenantid}` issuer 模板，两者必须分开表达，不能放宽成“不检查 issuer”。
pub async fn discover_with_expected_issuer(
    authority: &IssuerUrl,
    expected_issuer: &IssuerUrl,
    transport: &dyn MetadataTransport,
    budget: FetchBudget,
) -> Result<CoreProviderMetadata, OidcError> {
    let request = budget.request(discovery_url(authority)?);
    let response = transport.get(&request).await?;
    let body = response.into_json_body(&request, JSON_ESSENCES)?;

    let metadata: CoreProviderMetadata =
        serde_json::from_slice(&body).map_err(|_| OidcError::MetadataMalformed)?;

    if metadata.issuer() != expected_issuer {
        return Err(OidcError::IssuerMismatch);
    }
    Ok(metadata)
}

#[cfg(test)]
pub(super) mod fixtures {
    //! discovery 文档夹具，供本模块与 `jwks` / `claims` 共用。

    /// 一份最小但**完整**的 discovery 文档。
    ///
    /// 只含 `CoreProviderMetadata` 的必填字段（无 serde `default` 且非 `Option` 的那些）：
    /// `issuer` / `authorization_endpoint` / `jwks_uri` / `response_types_supported` /
    /// `subject_types_supported` / `id_token_signing_alg_values_supported`。
    #[must_use]
    pub fn discovery_document(issuer: &str, jwks_uri: &str) -> String {
        format!(
            r#"{{
  "issuer": "{issuer}",
  "authorization_endpoint": "{issuer}/v1/authorize",
  "token_endpoint": "{issuer}/v1/token",
  "jwks_uri": "{jwks_uri}",
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256", "HS256", "EdDSA"]
}}"#
        )
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::discovery_document;
    use super::{
        DISCOVERY_PATH_SUFFIX, FetchBudget, discover, discover_with_expected_issuer, discovery_url,
    };
    use crate::auth::oidc::error::OidcError;
    use crate::auth::oidc::provider::{GOOGLE_ISSUER, parse_issuer};
    use crate::auth::oidc::transport::MetadataResponse;
    use crate::auth::oidc::transport::fake::FakeTransport;
    use url::Url;

    const OKTA: &str = "https://example.okta-test.invalid/oauth2/default";
    const OKTA_WELL_KNOWN: &str =
        "https://example.okta-test.invalid/oauth2/default/.well-known/openid-configuration";
    const OKTA_JWKS: &str = "https://example.okta-test.invalid/oauth2/default/v1/keys";

    fn budget() -> FetchBudget {
        FetchBudget::new(64 * 1024, core::time::Duration::from_secs(5))
    }

    #[tokio::test]
    async fn entra_common_authority_and_tenant_template_are_distinct_without_disabling_issuer_check()
     {
        let authority = parse_issuer("https://login.microsoftonline.com/common/v2.0").unwrap();
        let expected = parse_issuer("https://login.microsoftonline.com/{tenantid}/v2.0").unwrap();
        let url = discovery_url(&authority).unwrap();
        let body = discovery_document(
            expected.as_str(),
            "https://login.microsoftonline.com/common/discovery/v2.0/keys",
        );
        let transport = FakeTransport::new();
        transport.push_json(url.as_str(), &body);
        let metadata = discover_with_expected_issuer(&authority, &expected, &transport, budget())
            .await
            .unwrap();
        assert_eq!(metadata.issuer(), &expected);

        let ordinary = FakeTransport::new();
        ordinary.push_json(url.as_str(), &body);
        assert_eq!(
            discover(&authority, &ordinary, budget()).await,
            Err(OidcError::IssuerMismatch),
            "tenant-independent 支持不能退化成关闭 issuer check"
        );
    }

    /// 带路径段的 issuer 拼出正确的 well-known URL；无路径段的也对。
    #[test]
    fn the_well_known_url_preserves_the_issuer_path() {
        let okta = parse_issuer(OKTA).unwrap();
        assert_eq!(discovery_url(&okta).unwrap().as_str(), OKTA_WELL_KNOWN);

        let google = parse_issuer(GOOGLE_ISSUER).unwrap();
        assert_eq!(
            discovery_url(&google).unwrap().as_str(),
            "https://accounts.google.com/.well-known/openid-configuration"
        );

        // issuer 自带末尾斜杠时不能拼出双斜杠。
        let trailing = parse_issuer("https://idp.example/").unwrap();
        assert_eq!(
            discovery_url(&trailing).unwrap().as_str(),
            "https://idp.example/.well-known/openid-configuration"
        );
    }

    /// 负向对照：`url::Url::join` 会把 issuer 的最后一段吃掉。
    ///
    /// 这条不是在测我们的代码，而是在**记录我们为什么不能用那个函数** —— 也是上一条
    /// 断言的意义所在（否则「路径保住了」在两个函数行为相同的世界里是废话）。
    #[test]
    fn url_join_would_truncate_a_path_bearing_issuer() {
        let naive = Url::parse(OKTA)
            .unwrap()
            .join(DISCOVERY_PATH_SUFFIX)
            .unwrap();
        assert_eq!(
            naive.as_str(),
            "https://example.okta-test.invalid/oauth2/.well-known/openid-configuration",
            "Url::join 把 `default` 当成文件名替换掉了"
        );
        assert_ne!(naive.as_str(), OKTA_WELL_KNOWN);
    }

    /// 正向：一份合格的文档取得回来，端点原样解出。
    #[tokio::test]
    async fn a_well_formed_document_is_accepted() {
        let transport = FakeTransport::new();
        transport.push_json(OKTA_WELL_KNOWN, &discovery_document(OKTA, OKTA_JWKS));

        let issuer = parse_issuer(OKTA).unwrap();
        let metadata = discover(&issuer, &transport, budget())
            .await
            .expect("合格文档必须被接受");

        assert_eq!(metadata.issuer(), &issuer);
        assert_eq!(metadata.jwks_uri().as_str(), OKTA_JWKS);
        assert_eq!(transport.calls_for(OKTA_WELL_KNOWN), 1);
        assert_eq!(
            transport.total_calls(),
            1,
            "discovery 不得顺手把 JWKS 也拉了 —— 那是 jwks 模块的活"
        );
    }

    /// 负向：文档自报的 issuer 与请求的不一致即拒。
    #[tokio::test]
    async fn a_document_claiming_a_different_issuer_is_refused() {
        let transport = FakeTransport::new();
        transport.push_json(
            OKTA_WELL_KNOWN,
            &discovery_document("https://evil.example", OKTA_JWKS),
        );

        let issuer = parse_issuer(OKTA).unwrap();
        assert_eq!(
            discover(&issuer, &transport, budget()).await.err(),
            Some(OidcError::IssuerMismatch)
        );
    }

    /// 负向：issuer 只差一条末尾斜杠也算不同 —— 比对是逐字节的。
    #[tokio::test]
    async fn issuer_comparison_is_byte_exact() {
        let transport = FakeTransport::new();
        transport.push_json(
            OKTA_WELL_KNOWN,
            &discovery_document(&format!("{OKTA}/"), OKTA_JWKS),
        );

        let issuer = parse_issuer(OKTA).unwrap();
        assert_eq!(
            discover(&issuer, &transport, budget()).await.err(),
            Some(OidcError::IssuerMismatch)
        );
    }

    /// 负向：dialer 说不通、体积超预算、类型不对、JSON 坏 —— 各自的稳定 code。
    #[tokio::test]
    async fn transport_and_document_failures_map_to_their_own_codes() {
        let issuer = parse_issuer(OKTA).unwrap();

        // dialer 说不通（假 dialer 没排任何应答）。
        let silent = FakeTransport::new();
        assert_eq!(
            discover(&issuer, &silent, budget()).await.err(),
            Some(OidcError::TransportUnavailable)
        );

        // 体积超预算。
        let fat = FakeTransport::new();
        fat.push_json(OKTA_WELL_KNOWN, &discovery_document(OKTA, OKTA_JWKS));
        let tiny_budget = FetchBudget::new(8, core::time::Duration::from_secs(5));
        assert_eq!(
            discover(&issuer, &fat, tiny_budget).await.err(),
            Some(OidcError::MetadataTooLarge)
        );

        // Content-Type 不对。
        let html = FakeTransport::new();
        html.push(
            OKTA_WELL_KNOWN,
            Ok(MetadataResponse::new(
                200,
                Some("text/html".to_owned()),
                discovery_document(OKTA, OKTA_JWKS).into_bytes(),
            )),
        );
        assert_eq!(
            discover(&issuer, &html, budget()).await.err(),
            Some(OidcError::MetadataContentTypeInvalid)
        );

        // JSON 坏 / 缺必填字段。
        let broken = FakeTransport::new();
        broken.push_json(OKTA_WELL_KNOWN, "{ not json");
        assert_eq!(
            discover(&issuer, &broken, budget()).await.err(),
            Some(OidcError::MetadataMalformed)
        );

        let incomplete = FakeTransport::new();
        incomplete.push_json(
            OKTA_WELL_KNOWN,
            r#"{"issuer":"https://example.okta-test.invalid/oauth2/default"}"#,
        );
        assert_eq!(
            discover(&issuer, &incomplete, budget()).await.err(),
            Some(OidcError::MetadataMalformed)
        );

        // 正向对照：同一个 issuer + 合格应答仍然成功 —— 上面五条不是「discover 恒失败」。
        let good = FakeTransport::new();
        good.push_json(OKTA_WELL_KNOWN, &discovery_document(OKTA, OKTA_JWKS));
        assert!(discover(&issuer, &good, budget()).await.is_ok());
    }

    /// 预算原样传到 dialer 手上（时间上限本模块执行不了，只能传递）。
    #[tokio::test]
    async fn the_budget_reaches_the_dialer_unchanged() {
        let budget = FetchBudget::new(1234, core::time::Duration::from_millis(777));
        let request = budget.request(Url::parse(OKTA_WELL_KNOWN).unwrap());
        assert_eq!(request.max_body_bytes(), 1234);
        assert_eq!(request.timeout(), core::time::Duration::from_millis(777));
        assert_eq!(request.url().as_str(), OKTA_WELL_KNOWN);
    }
}
