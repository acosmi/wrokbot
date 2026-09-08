//! 认证适配器：IdP 配置、OIDC 协议实现、session 存储。
//!
//! # 这一层负责什么，不负责什么
//!
//! **负责**：与外部身份提供方对话的协议细节（OIDC 的 discovery / JWKS / Authorization Code +
//! PKCE / ID token 校验），以及把这些结果落成数据库行。
//!
//! **不负责**身份与授权的**规则**：谁是管理员、撤权怎么生效、组怎么投影成 membership、
//! session 什么时候算过期 —— 那些是 `openbot-domain::identity` 的领域判定，本模块只调用它们。
//! 一条判据线：如果一个问题的答案不依赖网络也不依赖数据库，它就不该在这里回答。
//!
//! **不读环境变量**（与 crate 根的模块文档一致）：[`config::AuthConfig`] 由启动层把已经读好的
//! 环境映射交进来构造。这条不是洁癖 —— 在解析器里直接读进程环境，等于让每一条测试都对
//! **不受控的全机状态**下断言，同一条测试换台机器或与别的测试并发就会翻。
//!
//! # 传输是注入的，不是自带的
//!
//! v3 §6.2 逐字：「OIDC discovery/JWKS 与任何 IdP metadata fetch 使用和 remote Agent/MCP
//! 相同的 safe dialer、redirect/IP 校验、大小/时间上限」。OIDC 协议子树因此不拥有 socket；
//! `openidconnect` 仍以 `default-features = false` 引入。W-7 的唯一真实网络实现位于
//! `crate::net::safe_http`，metadata 窄 GET 与 token 窄 POST adapter 都只能注入它。
//!
//! 这样做的直接后果是：一个绕过 safe dialer 的出网路径**不可能**从这个模块里长出来 ——
//! 它压根没有能力自己发请求。

#[cfg(feature = "server-runtime")]
pub mod config;
#[cfg(feature = "server-runtime")]
pub mod oidc;
pub mod single_user;
#[cfg(feature = "server-sso")]
pub mod sso;
