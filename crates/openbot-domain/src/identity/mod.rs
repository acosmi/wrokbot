//! identity —— 身份、角色、撤权、组与 session 寿命的**领域规则**（v3 §6.1 / §6.2 条 5–10 /
//! §6.3 / §6.5）。
//!
//! # 边界：什么在这里，什么不在
//!
//! OIDC / SAML **协议本身**不在这里：discovery、JWKS 轮换、PKCE、签名覆盖校验、assertion
//! replay 都要发请求、读时钟、验密钥，全部是 I/O，归 `openbot-infra`。本模块拿到的是那些
//! 协议**已经验证过之后**的结论 —— 一个地址、一组 claim、一个时刻 —— 然后回答「这个人是
//! 谁、能做什么、这张票据还算不算数」。
//!
//! 因此本模块每个函数都是纯函数：不读时钟（`OffsetDateTime` 由调用方传入）、不生成随机数
//! （token 与密钥由调用方给）、不落盘、不发请求。这不是洁癖：授权判定是全系统最需要能被
//! 逐条重放对账的一段逻辑，一旦掺进环境依赖，「为什么这个人当时被拒了」就再也回答不了。
//!
//! # 七个子模块与它们各自挡住的失效
//!
//! | 子模块 | 挡住的失效 | 出处 |
//! | --- | --- | --- |
//! | [`email`] | 大小写不同的两行 = 同一个人只有一行被强制 | `parity/tables.yaml::tbl-revoked-access` |
//! | [`roles`] | 缺角色行被静默降级成 `user`；floor 被 UI 降权；设角色写成一次插入 | §6.2 条 6/7 |
//! | [`revocation`] | 被移除的人换条路径又签进来；删 user 行当成移除 | §6.2 条 8 |
//! | [`generation`] | 撤权后旧票据继续有效；用字典序比 generation | §6.2 条 10 / §28.1 R23 |
//! | [`session`] | 明文 token 落库；活动把绝对期限续命；「为什么被登出」压成一个布尔 | §6.3 |
//! | [`signed_value`] | 一个用途的签名被当另一个用途重放 | 上游 `auth/signed-value.ts` |
//! | [`groups`] | 包声明的 channel 对所有人不可达（上游 #82） | §6.5 |
//!
//! # 一条贯穿全模块的构造性链路
//!
//! 这几个类型不是七个互不相干的工具箱，它们串成一条**只能从头走到尾**的路：
//!
//! ```text
//! NormalizedEmail          唯一构造入口做规范化
//!        │
//!        ▼
//! revocation::screen_sign_in(…, SignInPath)   两条登录路径共用同一道闸门
//!        │
//!        ▼
//! AccessCleared            没有第二个构造函数
//!        │
//!        ├──────────────▶ EffectivePrincipal ──▶ 组投影（groups）
//!        │
//!        └──────────────▶ session::authenticate ──▶ SessionState
//! ```
//!
//! 关键在于中间那个 [`revocation::AccessCleared`]：它没有 public 字段、没有 `Default`、
//! 没有第二个构造函数，而铸造 session 与构造有效主体**都要求它**。于是「撤权检查漏了一条
//! 路径」不再是一个需要 review 发现的疏忽，而是**编译不过** —— 这正是上游
//! `auth/index.ts` 用两个 databaseHook（`user.create.before` 与 `session.create.before`）
//! 加一段注释在守的东西，那段注释逐字写着「用户钩子只对新账号触发，没有这一条被移除的人
//! 直接又签回来了」。注释守得住的前提是下一个人会读它。

pub mod email;
pub mod generation;
pub mod groups;
pub mod revocation;
pub mod roles;
pub mod session;
pub mod signed_value;
