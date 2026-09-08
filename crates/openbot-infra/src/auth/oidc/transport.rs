//! 出网端口：本模块**唯一**能接触网络的地方，而它自己没有实现。
//!
//! # 为什么传输必须是注入的
//!
//! v3 §6.2 逐字：「OIDC discovery/JWKS 与任何 IdP metadata fetch 使用和 remote Agent/MCP
//! **相同的** safe dialer、redirect/IP 校验、大小/时间上限」。「相同的」是这条约束的全部
//! 重量所在 —— 只要 OIDC 能自己开一条出网路径，它就是**第二条**出网路径，而 §10.5 把
//! SSRF 面收口在一个 dialer 上的前提正是「只有一条」。
//!
//! 于是本模块的构造是：协议在这里，传输在别处，两者由 [`MetadataTransport`] 缝合。直接
//! 后果是一条**构造性**的防线 —— 不是「我们记得不要绕过 dialer」，而是这个模块里压根没有
//! socket、没有 DNS、没有 HTTP 客户端，绕过 dialer 的代码**写不出来**。根 `Cargo.toml` 把
//! `openidconnect` 声明成 `default-features = false` 正是同一条裁决的另一半：它自带的
//! `reqwest` + `rustls-tls` 一旦进来就是那第二条路径。
//!
//! W-7 已在完成独立 delta audit 后实现 [`crate::net::safe_http::SafeDialer`]：TLS 选
//! rustls + ring，ring 的 C/汇编 build.rs 与 Windows 预生成对象被显式记入审计和 deny guard。
//! 本模块只实现从窄 GET port 到该 dialer 的一条适配；socket/DNS/TLS 仍不在 OIDC 协议代码里。
//!
//! # 为什么是自己的窄 trait，而不是直接用 `oauth2::AsyncHttpClient`
//!
//! `oauth2 5.0.0` 的 `AsyncHttpClient`（`oauth2-5.0.0/src/endpoint.rs`）签名是
//! `trait AsyncHttpClient<'c> { type Error; type Future: Future<..> + 'c; fn call(&'c self, HttpRequest) -> Self::Future; }`，
//! 并对任意 `T: Fn(HttpRequest) -> F` 有一条 blanket impl。两条理由让它不适合当本模块的端口：
//!
//! 1. **它不是对象安全的**。带生命周期参数的关联 `Future` 类型使 `dyn AsyncHttpClient` 无法
//!    书写，于是每个持有 dialer 的结构体都得带上一个泛型参数并把它一路传染下去。而 dialer
//!    在本项目里是**运行期选定**的依赖（Desktop 与多用户 Server 的 egress 策略不同），必须
//!    能装进 `Arc<dyn …>`。
//! 2. **窄本身就是安全属性**。`AsyncHttpClient::call` 收的是任意 `http::Request<Vec<u8>>`：
//!    任意 method、任意 header、任意 body。本模块真正需要的只有「GET 这个绝对 URL，把带上限
//!    的响应给我」。一个**表达不出** POST 和自定义 header 的端口，比一个表达得出、再靠调用点
//!    自律不用的端口，SSRF 面小一整个量级。
//!
//! 代价要说清楚：本模块因此**不使用** `openidconnect` 自带的
//! `CoreProviderMetadata::discover_async`（它要求 `C: AsyncHttpClient<'c>`）。这不算损失，
//! 因为那个函数在同一次调用里**顺手把 JWKS 也拉了**（见其函数体末尾的
//! `JsonWebKeySet::fetch_async`），而 §6.2 要求 JWKS 拉取有缓存与速率限制 —— 一个每次
//! discovery 都无条件多打一发 JWKS 的实现，恰好是这条要求禁止的形态。文档解析、issuer 比对
//! 与 `.well-known` 路径拼接仍然复用 `openidconnect` 的类型与方法，见 `discovery` 模块。

use async_trait::async_trait;
use http::header::CONTENT_TYPE;
use url::Url;

use crate::net::safe_http::{SafeDialer, SafeHttpBudget, SafeHttpRequest, SchemePolicy};

use super::error::OidcError;

/// dialer 未能完成这次取回：连不上、超时、被 egress 策略拒绝、TLS 不过。
///
/// **刻意只有一个变体**。区分「连不上」与「被策略拒绝」会把内网可达性做成一个可被外部
/// 探测的信道 —— v3 §6.2 要求 pre-auth 面不泄露组织拓扑，同一条理由在内网拓扑上更成立。
/// dialer 实现自己该 `tracing` 出去多少细节是它的事，那是受控 trace，不是穿越边界的契约。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("oidc_transport_unavailable")]
pub struct TransportUnavailable;

impl From<TransportUnavailable> for OidcError {
    fn from(_: TransportUnavailable) -> Self {
        Self::TransportUnavailable
    }
}

/// 一次对 IdP 元数据端点的取回请求。
///
/// 结构里**没有** method、header、body 三个字段，这是本类型的主要设计内容：见模块文档。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataRequest {
    url: Url,
    max_body_bytes: usize,
    timeout: core::time::Duration,
}

impl MetadataRequest {
    /// 构造一次取回。
    ///
    /// `max_body_bytes` 与 `timeout` 是 v3 §6.2「大小/时间上限」的两半，**由调用方给定**
    /// 而不是本模块写死：上限是部署策略，写死就等于把它藏进一个没人能改的常量里。
    #[must_use]
    pub const fn new(url: Url, max_body_bytes: usize, timeout: core::time::Duration) -> Self {
        Self {
            url,
            max_body_bytes,
            timeout,
        }
    }

    /// 要取的绝对 URL。
    #[must_use]
    pub const fn url(&self) -> &Url {
        &self.url
    }

    /// 响应体字节上限。
    ///
    /// dialer 应当在读取时就截断；协议层**另外**再验一次（见
    /// [`MetadataResponse::into_json_body`]）—— 那不是重复劳动，而是不把「上限有没有生效」
    /// 这件事完全押在一个可被替换的实现上。
    #[must_use]
    pub const fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    /// 这次取回的墙钟上限。
    ///
    /// 协议层**不能**执行它（本模块没有时钟也没有执行器，见模块文档），所以它是一条
    /// 交给 dialer 的声明。这条不对称是诚实的：假装能在这里超时会让调用方以为有一道
    /// 其实不存在的闸门。
    #[must_use]
    pub const fn timeout(&self) -> core::time::Duration {
        self.timeout
    }
}

/// 一次取回的结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataResponse {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl MetadataResponse {
    /// 由 dialer（或测试里的确定性假实现）构造。
    #[must_use]
    pub fn new(status: u16, content_type: Option<String>, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type,
            body,
        }
    }

    /// HTTP 状态码。
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// `Content-Type` 头的原值（若有）。
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    /// 响应体原字节。
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// 把响应收敛成「可以拿去解析的 JSON 字节」，否则给出稳定 code。
    ///
    /// 四道判据按这个顺序：状态码 → 大小 → `Content-Type` → 交给调用方解析。
    ///
    /// # 与 `openidconnect` 的一处**有意分歧**
    ///
    /// `openidconnect` 的 `http_utils::check_content_type` 写的是
    /// `headers.get(CONTENT_TYPE).map_or(Ok(()), …)` —— **缺失** `Content-Type` 时直接放行。
    /// 本函数 fail-closed：没有 `Content-Type` 就拒。理由是 repository contract §5 条 3 的
    /// 「空 / 坏 / 未知一律 fail-closed」，而这里的具体风险是一个只会吐字节、不声明类型的
    /// 中间设备（透明代理、错配的错误页）会被当成合法元数据源解析。
    ///
    /// # Errors
    ///
    /// - [`OidcError::MetadataStatusNotOk`]：状态码非 200；
    /// - [`OidcError::MetadataTooLarge`]：体积超过 `request` 声明的上限；
    /// - [`OidcError::MetadataContentTypeInvalid`]：缺失或不在 `allowed_essences` 内。
    pub fn into_json_body(
        self,
        request: &MetadataRequest,
        allowed_essences: &[&str],
    ) -> Result<Vec<u8>, OidcError> {
        if self.status != 200 {
            return Err(OidcError::MetadataStatusNotOk);
        }
        if self.body.len() > request.max_body_bytes() {
            return Err(OidcError::MetadataTooLarge);
        }
        let Some(content_type) = self.content_type.as_deref() else {
            return Err(OidcError::MetadataContentTypeInvalid);
        };
        if !essence_is_one_of(content_type, allowed_essences) {
            return Err(OidcError::MetadataContentTypeInvalid);
        }
        Ok(self.body)
    }
}

/// `Content-Type` 的 essence（`type/subtype`，去掉 `;` 之后的参数）是否落在允许集内。
///
/// RFC 7231 §3.1.1.1 规定 media type 大小写不敏感且可带可选空白与参数，所以比对前要
/// 先切掉 `;` 后缀、去空白、转小写 —— 这与 `openidconnect::http_utils::content_type_has_essence`
/// 的做法一致（那个函数是 `pub(crate)`，本模块够不到，只能同构实现）。
fn essence_is_one_of(content_type: &str, allowed_essences: &[&str]) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();
    allowed_essences
        .iter()
        .any(|allowed| essence == allowed.to_ascii_lowercase())
}

/// 注入的出网能力。
///
/// 实现者是 safe dialer（v3 §10.5）。它负责 DNS 解析结果的 IP 校验、重定向策略、
/// TLS、以及 [`MetadataRequest`] 声明的大小与时间上限。
#[async_trait]
pub trait MetadataTransport: Send + Sync {
    /// 对 `request.url()` 发一次 **GET**。
    ///
    /// 没有别的方法，也没有让调用方指定 method 的参数 —— 这是端口的设计内容而不是遗漏。
    ///
    /// # Errors
    ///
    /// 未能完成时返回 [`TransportUnavailable`]；它不携带任何来自远端的字节。
    async fn get(
        &self,
        request: &MetadataRequest,
    ) -> Result<MetadataResponse, TransportUnavailable>;
}

#[async_trait]
impl MetadataTransport for SafeDialer {
    async fn get(
        &self,
        request: &MetadataRequest,
    ) -> Result<MetadataResponse, TransportUnavailable> {
        let budget = SafeHttpBudget::new(request.max_body_bytes(), request.timeout())
            .map_err(|_| TransportUnavailable)?;
        let plan = SafeHttpRequest::get(request.url().clone(), SchemePolicy::HttpsOnly, budget)
            .map_err(|_| TransportUnavailable)?;
        let response = self.execute(plan).await.map_err(|_| TransportUnavailable)?;
        let content_type = response
            .header(&CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let (status, _, body) = response.into_parts();
        Ok(MetadataResponse::new(status.as_u16(), content_type, body))
    }
}

/// discovery 与 JWKS 都接受的 JSON essence。
///
/// OpenID Connect Discovery 1.0 §4.2 要求 discovery 文档是 `application/json`；JWKS 端点
/// 在现实中两种都出现（RFC 7517 §8.5.1 登记了 `application/jwk-set+json`），所以放行两个。
/// **只放行这两个**，不做「凡是以 `+json` 结尾都算」的宽松匹配：那会把
/// `application/problem+json`（错误页）也当成合法元数据。
pub const JSON_ESSENCES: &[&str] = &["application/json", "application/jwk-set+json"];

#[cfg(test)]
pub(super) mod fake {
    //! 确定性假 dialer。`pub(super)` 让 oidc 模块树里的兄弟模块共用一份，不出 crate。
    //!
    //! 它按**请求 URL** 查预置应答，并记录每个 URL 被请求了多少次 —— 后者是 JWKS
    //! rotation 速率限制那组测试的核心断言对象（「这次到底有没有真的打出去」）。
    //!
    //! 队列语义：同一个 URL 可以排多个应答，取一次弹一个；**最后一个会一直重复**。
    //! 这样「第一次拿到旧 keyset、之后一直拿到新 keyset」这种轮转场景可以直接排出来。

    use std::collections::HashMap;
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::{MetadataRequest, MetadataResponse, MetadataTransport, TransportUnavailable};

    /// 假 dialer。
    #[derive(Debug, Default)]
    pub struct FakeTransport {
        queued: Mutex<HashMap<String, Vec<Result<MetadataResponse, TransportUnavailable>>>>,
        calls: Mutex<Vec<String>>,
    }

    impl FakeTransport {
        /// 空的假 dialer：任何 URL 都回 [`TransportUnavailable`]。
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// 给某个 URL 排一个应答。
        pub fn push(&self, url: &str, response: Result<MetadataResponse, TransportUnavailable>) {
            self.queued
                .lock()
                .expect("测试内不会毒化锁")
                .entry(url.to_owned())
                .or_default()
                .push(response);
        }

        /// 排一个 200 + `application/json` 的应答。
        pub fn push_json(&self, url: &str, body: &str) {
            self.push(
                url,
                Ok(MetadataResponse::new(
                    200,
                    Some("application/json".to_owned()),
                    body.as_bytes().to_vec(),
                )),
            );
        }

        /// 某个 URL 至今被请求了几次。
        #[must_use]
        pub fn calls_for(&self, url: &str) -> usize {
            self.calls
                .lock()
                .expect("测试内不会毒化锁")
                .iter()
                .filter(|called| called.as_str() == url)
                .count()
        }

        /// 总请求次数。
        #[must_use]
        pub fn total_calls(&self) -> usize {
            self.calls.lock().expect("测试内不会毒化锁").len()
        }
    }

    #[async_trait]
    impl MetadataTransport for FakeTransport {
        async fn get(
            &self,
            request: &MetadataRequest,
        ) -> Result<MetadataResponse, TransportUnavailable> {
            let url = request.url().to_string();
            self.calls
                .lock()
                .expect("测试内不会毒化锁")
                .push(url.clone());

            let mut queued = self.queued.lock().expect("测试内不会毒化锁");
            let Some(slot) = queued.get_mut(&url) else {
                return Err(TransportUnavailable);
            };
            match slot.len() {
                0 => Err(TransportUnavailable),
                // 最后一个应答一直重复。
                1 => slot[0].clone(),
                _ => slot.remove(0),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        JSON_ESSENCES, MetadataRequest, MetadataResponse, MetadataTransport, TransportUnavailable,
        essence_is_one_of,
    };
    use crate::auth::oidc::error::OidcError;
    use url::Url;

    fn req(max: usize) -> MetadataRequest {
        MetadataRequest::new(
            Url::parse("https://idp.example.com/.well-known/openid-configuration").unwrap(),
            max,
            core::time::Duration::from_secs(5),
        )
    }

    /// 正向：200 + JSON + 体积在预算内 => 字节原样交出。
    #[test]
    fn a_well_formed_response_yields_its_body() {
        let body = br#"{"issuer":"https://idp.example.com"}"#.to_vec();
        let resp = MetadataResponse::new(200, Some("application/json".into()), body.clone());
        assert_eq!(resp.into_json_body(&req(4096), JSON_ESSENCES), Ok(body));
    }

    /// 负向：非 200。
    #[test]
    fn non_200_is_refused() {
        let resp = MetadataResponse::new(404, Some("application/json".into()), b"{}".to_vec());
        assert_eq!(
            resp.into_json_body(&req(4096), JSON_ESSENCES),
            Err(OidcError::MetadataStatusNotOk)
        );
    }

    /// 负向 + 边界正向：协议层自己再验一次大小上限。
    ///
    /// 这条钉的是「dialer 说它截断了」与「确实截断了」之间的差别 —— 上限如果只由一个
    /// 可替换的实现执行，它就不是闸门。
    #[test]
    fn oversized_body_is_refused_and_the_exact_budget_is_accepted() {
        let over = MetadataResponse::new(200, Some("application/json".into()), vec![b'x'; 11]);
        assert_eq!(
            over.into_json_body(&req(10), JSON_ESSENCES),
            Err(OidcError::MetadataTooLarge)
        );

        // 正向对照：恰好等于预算不算超 —— 否则上一条在「恒判超」的世界里同样通过。
        let exact = MetadataResponse::new(200, Some("application/json".into()), vec![b'x'; 10]);
        assert!(exact.into_json_body(&req(10), JSON_ESSENCES).is_ok());
    }

    /// 负向：缺失 `Content-Type` fail-closed —— 与 `openidconnect` 的 fail-open 有意分歧。
    #[test]
    fn missing_content_type_is_refused() {
        let resp = MetadataResponse::new(200, None, b"{}".to_vec());
        assert_eq!(
            resp.into_json_body(&req(4096), JSON_ESSENCES),
            Err(OidcError::MetadataContentTypeInvalid)
        );
    }

    /// essence 比对：大小写、参数、空白按 RFC 7231 §3.1.1.1 忽略；不相干类型拒绝。
    #[test]
    fn content_type_essence_matching_follows_rfc7231() {
        // 正向：三种合法写法都认。
        assert!(essence_is_one_of("application/json", JSON_ESSENCES));
        assert!(essence_is_one_of(
            "APPLICATION/JSON; charset=utf-8",
            JSON_ESSENCES
        ));
        assert!(essence_is_one_of(
            " application/jwk-set+json ",
            JSON_ESSENCES
        ));

        // 负向：错误页与 HTML 不认；尤其 `problem+json` 必须被拒，
        // 否则一个 RFC 7807 错误页会被当成元数据解析。
        assert!(!essence_is_one_of("text/html", JSON_ESSENCES));
        assert!(!essence_is_one_of(
            "application/problem+json",
            JSON_ESSENCES
        ));
        assert!(!essence_is_one_of("", JSON_ESSENCES));
    }

    /// [`TransportUnavailable`] 收敛成稳定 code，且与 [`OidcError`] 的码逐字相同。
    #[test]
    fn transport_failure_maps_to_the_stable_code() {
        assert_eq!(
            TransportUnavailable.to_string(),
            "oidc_transport_unavailable"
        );
        assert_eq!(
            OidcError::from(TransportUnavailable),
            OidcError::TransportUnavailable
        );
        assert_eq!(
            OidcError::from(TransportUnavailable).code(),
            TransportUnavailable.to_string()
        );
    }

    /// 端口是对象安全的 —— 这是选窄 trait 而非 `oauth2::AsyncHttpClient` 的**理由本身**，
    /// 所以它值一条测试：哪天有人把它改成带生命周期关联类型的形状，这里编译不过。
    #[test]
    fn the_port_is_object_safe() {
        struct Never;
        #[async_trait::async_trait]
        impl MetadataTransport for Never {
            async fn get(
                &self,
                _request: &MetadataRequest,
            ) -> Result<MetadataResponse, TransportUnavailable> {
                Err(TransportUnavailable)
            }
        }
        let _boxed: std::sync::Arc<dyn MetadataTransport> = std::sync::Arc::new(Never);
    }
}
