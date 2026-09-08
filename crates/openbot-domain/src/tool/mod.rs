//! 工具执行管线里属于**纯判定**的那几段（v3 §8.1 / §8.2 / §8.5）。
//!
//! # 这一层负责什么
//!
//! §8.1 那条唯一执行管线有十二段，其中 I/O 的部分（写库、发请求、起沙箱）在
//! `openbot-application` 与 `openbot-infra`。留在这里的是判定与状态迁移：
//!
//! - **谁能走到哪一步**（[`pipeline`]）：十二段做成十二个类型，跨段跳跃没有语法可写；
//! - **一个工具声明了什么**（[`metadata`]）：§8.2 的九项固定声明，以及未知 effect 的
//!   fail-closed；
//! - **实参的身份**（[`args`]）：§8.5 绑定进 approval 的那个规范化摘要；
//! - **一份批准还算不算数**（[`approval`]）：§8.5 的九个绑定字段 + 四个失效事件；
//! - **能不能重放**（[`commit`]）：§17.2 条 9「non-idempotent unknown commit 不自动重放」。
//!
//! **不负责**：CEL 求值（那是 `crate::policy`）、实际执行、写库、时钟、随机数。
//!
//! # 三条承重不变量，以及它们各自落在哪
//!
//! | 不变量 | 出处 | 落点 | 兑现方式 |
//! | --- | --- | --- | --- |
//! | 任一 acting effect 之前都有 durable decision + attempt | §17.2 条 2 | [`pipeline::DecisionRecorded`] | 它是 [`pipeline::ReadyToExecute`] 的**唯一**来源，而它自己的唯一来源是一个必须处理写失败的 `Result` —— 跳过 decision 拿 capability 编译不过 |
//! | 未知 effect 固定按 write/execute | §8.2 | [`metadata::EffectClassification::classify`] | 没有 `Effect::Unknown`，也没有会返回 `Read` 的解析入口；降级留标记 |
//! | non-idempotent unknown commit 不自动重放 | §17.2 条 9 | [`commit::judge_replay`] + [`pipeline::ReconciliationRequired`] | 前者给判据，后者**没有**通往重试的边 |
//!
//! 三条都配了正向对照（happy path 走得通、已声明 effect 认得出、幂等工具确实可重放），
//! 否则每一条断言在"这套 API 压根没实现"的世界里同样成立。
//!
//! # 与 `crate::policy` 的边界
//!
//! 本模块**不 import** `crate::policy`。管线需要的只是策略的**结论**
//! （[`pipeline::PolicyVerdict`]）与版本标记（[`approval::PolicyVersionTag`]），两者都是
//! 本模块自己的窄类型。这样 CEL 引擎怎么实现、policy 文档长什么样，都不会牵动这条管线的
//! 编译面；集成时由 application 层做一次映射。
//!
//! # 与 `crate::audit` 的方向
//!
//! 依赖是**单向**的：`tool` → `audit`，反过来没有。工具侧复用 audit 的摘要原语
//! （[`crate::audit::hash::Sha256Digest`] 与它的规范编码写入器）而不是再造一份十六进制
//! 编解码；[`pipeline::ProjectedToolCall::audit_payload`] 则是 audit 那份字段 allowlist
//! 的实际消费点 —— 这次调用能往审计里记什么，完全由 [`crate::audit::payload::AuditFact`]
//! 的变体决定。

pub mod approval;
pub mod args;
pub mod commit;
pub mod metadata;
pub mod pipeline;
