//! `openbot-server` —— Server transport：Axum HTTP/SSE/WS、static GUI、health/readiness。
//!
//! # 所有权边界（v3 §5.1 / §5.2 / §15 / §16.1）
//!
//! 负责（transport 四件事，**只有**这四件，v3 §5.2）：
//!
//! 1. 认证：从 session cookie / IdP 结果构造 `AuthContext`，交给 `openbot-application`。
//! 2. framing：HTTP / SSE / WebSocket 的编解码。
//! 3. 输入大小限制。
//! 4. 错误映射：把 `AppError` 映射成 v3 §15.3 的固定语义 —— 未登录 401；角色不足 403；
//!    资源不可见统一 404（防枚举）；policy refusal 403 + stable code；stale generation /
//!    lease 冲突 409；空 thread history 200 + 空列表。文案可本地化，code / status / audit
//!    类型不变。
//!
//! 另外负责：提供与 Desktop **相同**的静态 GUI bundle（v3 §13.1）、health / readiness 探针。
//!
//! 明确**不**负责：
//!
//! - 实现任何业务规则（v3 §5.2 逐字禁止）。所有 use case 都必须穿过
//!   `openbot-application::ApplicationService`。
//! - 接受自由 method string、renderer 自报角色、renderer 自报 `principal=admin`、任意数据库
//!   query（v3 §5.2 四条逐字禁止项）。
//! - 把 computer token 交给浏览器（v3 §12.4）；Server 的 screen viewer 用同源 `wss` +
//!   session cookie + CSRF-style origin check。
//!
//! # 当前状态（G1 + W-4/W-5 + G3 thread/history/memory/run-runtime + SSE/WS）
//!
//! Phase 0 本 crate 刻意为空；G1 落**第一个垂直切片**所需的最小集合。四条 G1 判据里
//! 「ApplicationService 经 Axum/Tauri 结果一致」与「tracing/metrics/redaction 从首个
//! vertical slice 生效」由本 crate 兑现 Axum 那一侧。
//!
//! | 模块 | 内容 | 出处 |
//! | --- | --- | --- |
//! | [`auth`] | [`AuthResolver`] port 与 [`auth::Authenticated`] 提取器 | §5.2 / §5.3 |
//! | [`database`] | fresh / Rust-managed / legacy 启动分流与原子 bootstrap | §14.1 / R54 |
//! | [`error`] | `AppError` → HTTP 的**投影**（只出稳定码，不出内部细节） | §15.3 |
//! | [`limits`] | [`limits::REQUEST_BODY_LIMIT_BYTES`] | §5.2 |
//! | [`metrics`] | Prometheus 指标、label 基数台账、显式 recorder 安装 | §16.4 |
//! | [`readiness`] | 三态 [`readiness::ReadinessVerdict`] 与它的注入口 | §16.1 |
//! | [`telemetry`] | request span、request_id 消毒、subscriber 构造器 | §16.4 |
//! | [`http`] | 路由表与 handler | parity ledger 四条，见下表 |
//!
//! G1 四条路由之外，W-4 追加 `/api/me`、admin status/people list/role/access，W-5 batch 3
//! 追加 admin audit keyset GET；它们仍只做 framing，全部穿同一个 `ApplicationService`。
//!
//! - `GET /api/channels` —— 台账 `api-channels-list-get`（parity）把落点钉成
//!   `openbot-server::http::channels::list`，[`http::channels::list`] 逐字兑现它。
//! - `GET /health` —— 台账 `health-get`（parity），落点 `openbot-server::http::health`，
//!   `migration_rule: preserve`，恒 200、public、不碰数据库。
//! - `GET /readiness` —— 台账 `readiness-get`（新增，`T-API-0147`）。三态与那条
//!   fail-closed 503 裁决见 [`readiness`] 模块文档。
//! - `GET /metrics` —— 台账 `metrics-get`（新增，`T-API-0148`），落点
//!   `openbot-server::http::metrics`。不另开监听端口，见 [`http::metrics`] 模块文档。
//! - `GET /api/admin/audit-events` —— 台账 `api-admin-audit-events-get`（parity），只做 query
//!   framing；admin gate、归一与页长在 application，SQL/keyset 在 infra（R56）。
//! - `GET /api/me/session` / `POST /api/auth/sign-out` —— R91；前者只投影revocable，
//!   后者经已验session+trusted Origin后只删当前PostgreSQL session并清HttpOnly cookie。
//! - `POST /api/threads/mint` / `GET /api/threads/{thread_id}` —— R64；只做 auth/path/JSON
//!   framing，CSPRNG 与 PostgreSQL scope 判定均经 typed ApplicationService。
//! - `GET /api/threads/{thread_id}/events` —— R65 authenticated SSE；只把 Last-Event-ID 变成
//!   typed cursor 并 frame AppEvent，replay/LISTEN/ACL 全在 application/infra。
//! - `GET /api/threads/{thread_id}/ws` —— R67 same-origin/read-only/subprotocol WebSocket；与 SSE
//!   共用同一 typed durable stream，client data 不能铸造 event。
//! - `/api/memories` 六条读写/recall —— R66；owner scope/原子写在 application/infra，Server
//!   只做 session、trusted Origin、JSON/path/query framing。
//! - Server main 启动 R67 run relay；G4 consumer 未接时明确写 failed terminal，不伪造回复。
//! - 独立 `openbot-migrate` binary 承载 R68 Intelligence import/FK finalize；Server main 零调用点。
//!
//! # 还没有的东西（不要当成"已经有了"）
//!
//! - **active connections**：§16.4 点名了它，但本 crate **从不拥有监听 socket**（`Router`
//!   交给宿主去 accept），所以只记得了**在飞请求数**，那是另一件事、用的是另一个名字。
//!   把在飞请求数改叫 connections 就是造假，见 [`metrics`] 模块文档。
//! - **OTel exporter**：§16.4 明说 exporter「只在管理员显式配置 collector 地址时才建连」，
//!   而配置面是 G2（§15.4）。此刻引入只会得到一个零调用点的依赖，所以刻意不引入。
//!   **本 crate 没有任何默认外发的遥测端点**（§16.4「零 phone-home」）。
//! - **完整 GUI route/components**：Server 可托管经校验的同源静态 bundle；31+1 route 与其余
//!   components/golden 仍是 G6 工作，不能由静态托管存在推导为完成。
//! - credentials/computer（含 policy 管理写面）等其余 HTTP 路由仍未落地。W-7 已接环境/动态 OIDC、SAML
//!   routing/metadata/ACS、动态 IdP 管理与 keyed session/group refresh；外部 SAML/XSW 审计、
//!   KMS/HSM 与跨平台原生发行未完成，不能据此宣称 G2。

#![deny(missing_docs)]

pub mod auth;
pub mod config;
pub mod database;
pub mod error;
pub mod http;
pub mod limits;
pub mod metrics;
pub mod readiness;
pub mod telemetry;

pub use auth::{
    AuthResolver, PostgresSessionAuthResolver, ResolvedAuth, SensitiveAuthenticated,
    SensitiveWriteSecurity, SingleUserAuthResolver,
};
pub use error::HttpError;
pub use http::static_app::StaticApp;
pub use http::{ServerBuilder, ServerState, router};
pub use limits::REQUEST_BODY_LIMIT_BYTES;
pub use metrics::{MetricsHandle, install_recorder};
pub use openbot_infra::auth::single_user::SINGLE_USER_ACTOR_ID;
pub use readiness::{FnReadinessProbe, ReadinessProbe, ReadinessStatus, ReadinessVerdict};
