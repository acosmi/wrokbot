//! OIDC 协议实现（v3 §6.2）。
//!
//! # 这个模块最重要的一条性质：它发不出请求
//!
//! 协议实现在这里，**传输实现不在这里**。出网是一个注入的端口
//! （[`transport::MetadataTransport`]），由项目自己的 safe dialer 兑现；本模块里没有
//! socket、没有 DNS、没有 HTTP 客户端，一行都没有。
//!
//! 为什么把这条放在最前面：v3 §6.2 末段要求 OIDC discovery / JWKS 与任何 IdP metadata
//! fetch「使用和 remote Agent/MCP **相同的** safe dialer、redirect/IP 校验、大小/时间上限」。
//! 「相同的」是这条约束的全部重量 —— §10.5 把 SSRF 面收口在**一个** dialer 上，前提是
//! 只有一条出网路径。协议库自带的第二条路径不会因为「我们记得不用它」而消失。
//!
//! 所以这里的构造是把纪律换成结构：**绕过 safe dialer 的代码在这个模块里写不出来**，
//! 因为没有可以写的地方。根 `Cargo.toml` 把 `openidconnect` 声明成
//! `default-features = false`（关掉它自带的 `reqwest` + `rustls-tls`）是同一条裁决的另一半。
//! 端口为什么是自己的窄 trait 而不是 `oauth2::AsyncHttpClient`，见 [`transport`] 的模块文档。
//!
//! # 模块地图
//!
//! | 模块 | 负责 | §6.2 对应 |
//! | --- | --- | --- |
//! | [`transport`] | 注入的出网端口 + 响应闸门（状态码 / 大小 / `Content-Type`） | 末段 |
//! | [`provider`] | 三家 provider 的类型化差异、issuer 闸门、注册表 | 条 1 / 2 / 9 |
//! | [`email`] | routing 用的窄 email 类型 | 条 2 |
//! | [`routing`] | email domain routing + **统一响应** | 条 2 / 末段 |
//! | [`ratelimit`] | 限速**判定**（纯函数，不含存储） | 末段 |
//! | [`preauth`] | pre-auth 面投影（只有 provider ID + 一个布尔值） | 末段 |
//! | [`redirect`] | 精确 redirect URI（登记期规范形 + 使用期逐字节） | 条 3 |
//! | [`attempt`] | 一次性的 `state` / `nonce` / PKCE S256 | 条 3 |
//! | [`authorize`] | 组装 Authorization Code 请求 | 条 3 |
//! | [`discovery`] | discovery 文档取回与 issuer 校验 | 条 3 |
//! | [`jwks`] | JWKS 缓存、轮转与**重拉限速** | 条 3 |
//! | [`claims`] | ID token 校验 + Entra 地址链 + 租户策略 | 条 3 / 5 |
//! | [`error`] | 稳定 code | v3 §15.3 |
//!
//! # 时间与随机数都不是本模块自己取的
//!
//! 每一条过期 / 冷却 / 限速判定都收调用方传入的 `now: OffsetDateTime`；W-7b 因 SAML 图
//! 已直接引入 chrono，ID token 的 `exp` / `iat` 也由 [`claims::build_verifier_at`] 注入同一时刻。
//!
//! # 仍明确**不做**（不假装 G2 已整关）
//!
//! 1. **SAML 独立外审/跨平台发行**。协议实现位于兄弟模块 `crate::auth::sso`；本机 xmlsec
//!    真签名矩阵已过，但 Linux CI、Windows 原生构建与外部 XSW 审计仍未完成（R50）。
//! 2. **IdP access/refresh token 落库**。身份登录不需要它们，按数据最小化主动丢弃；
//!    `sso_providers.oidc_config` 的 client secret 仍是 vault 数据。本模块的
//!    [`OidcProviderConfig`] 里**没有** client secret 字段，secret 只以单次调用的参数形式
//!    出现在 [`claims::build_verifier`] 上。
//! 3. **第一次外部安全审计**。本批有本机负向矩阵和供应链 delta，不冒充 §24 G2 的外审。

pub mod attempt;
pub mod attempt_postgres;
pub mod authorize;
pub mod claims;
pub mod configured;
pub mod coordinator;
pub mod discovery;
pub mod email;
pub mod error;
pub mod jwks;
pub mod preauth;
pub mod provider;
pub mod ratelimit;
pub mod ratelimit_postgres;
pub mod redirect;
pub mod routing;
pub mod session_issuer;
pub mod token;
pub mod token_transport;
pub mod transport;

pub use attempt::{CallbackLoginAttempt, LoginAttempt, LoginAttemptStore, S256Pkce};
pub use attempt_postgres::{PostgresAttemptError, PostgresLoginAttemptStore};
pub use authorize::authorization_url;
pub use claims::{DirectoryClaims, VerifiedIdentity, verify_id_token, verify_with_group_mapping};
pub use configured::{ConfiguredOidcProvider, configured_oidc_providers};
pub use coordinator::{OidcLoginCoordinator, OidcLoginError, OidcProviderRuntime};
pub use discovery::{FetchBudget, discover, discover_with_expected_issuer};
pub use email::EmailDomain;
pub use error::OidcError;
pub use jwks::{JwksCache, JwksRefreshPolicy};
pub use preauth::PreAuthSurface;
pub use provider::{
    EntraTenantPolicy, IssuerTrust, MICROSOFT_CONSUMER_TENANT_ID, OidcProviderConfig, ProviderId,
    ProviderKind, ProviderOrigin, ProviderRegistry,
};
pub use ratelimit::{RateLimitCounter, RateLimitDecision, RateLimitPolicy};
pub use ratelimit_postgres::{
    OidcRateLimitBucket, PostgresOidcRateLimiter, PostgresRateLimitError,
};
pub use redirect::CanonicalRedirectUri;
pub use routing::{EmailRoutingOutcome, UniformRoutingResponse, route_email};
pub use session_issuer::{
    IssuedSession, PostgresOidcSessionIssuer, SessionCookieValue, SessionIssueError,
};
pub use token::{exchange_authorization_code, untrusted_key_id};
pub use token_transport::{SafeOauthHttpClient, SafeOauthHttpError};
pub use transport::{MetadataRequest, MetadataResponse, MetadataTransport, TransportUnavailable};
