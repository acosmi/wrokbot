//! 审计链（v3 §8.6）：事件类型、payload 字段 allowlist、hash chain、签名 checkpoint、
//! retention 窗口判定。
//!
//! # 这一层负责什么
//!
//! 全是**纯判定与纯编码**：给定一条事件与它的前驱，`row_hash` 是多少；给定一段行，链有没有
//! 断、断在哪；给定一个 `AUDIT_RETENTION_DAYS` 原值，策略是三态里的哪一态；给定一批待删行，
//! 删之前该落哪条 closure checkpoint。
//!
//! **不负责**：写库、发 SQL、取 advisory lock、读环境变量、拿时钟、持有签名密钥。时间戳与
//! 密钥都是入参。理由与整个 `openbot-domain` 一致（repository contract §4）：`row_hash` 一旦取决于
//! 领域层自己读到的墙钟，同一条事件重放两次就会得到两个摘要，"确定性重放"当场失效。
//!
//! # 上游现状原样保留，不重建（§8.6 / §28.1 R5）
//!
//! `audit_events` 的 append-only 由数据库触发器强制，不是由应用纪律维持 —— 上游
//! `0007_audit_retention_window.sql` 的注释给的理由成立且必须保留：**应用不是唯一能碰到
//! 这张表的东西**。本仓的 DDL 真源在 `crates/openbot-infra/sql/baseline_0012.sql`，本轮实读：
//!
//! - 函数 `prevent_audit_event_mutation()` 上挂两个触发器 ——
//!   `audit_events_append_only`（`BEFORE DELETE OR UPDATE ... FOR EACH ROW`）与
//!   `audit_events_no_truncate`（`BEFORE TRUNCATE ... FOR EACH STATEMENT`）。
//! - `UPDATE` 与 `TRUNCATE` **无条件拒绝**，并且这一判定写在读任何设置之前。顺序是设计的
//!   一部分：语句级触发器没有 `OLD`，若先读设置再比 `OLD.created_at`，比较对象是 NULL、
//!   `IF` 不成立、控制流落到 `RETURN OLD`，TRUNCATE 就放行了 —— 而那条路**恰好只在
//!   retention sweep 已设好窗口的那一刻可达**（0012 的注释原文：happy-path 测试不会走到的状态）。
//! - `DELETE` 只在会话声明了 `openbot.audit_retention_days` 且行
//!   `created_at < now() - N days` 时放行。
//!
//! 三条推论写进了各自的模块：**不做表分区**（改分区 = 建新表 + 搬行 + 换名，违反 §14.3）；
//! hash chain 以**追加 nullable 列**落地（[`chain`]）；retention 判定与触发器**同号**
//! （[`retention`]）。
//!
//! # payload：上游是黑名单，我们做白名单，这是一次明确的"不照译"
//!
//! 上游 `server/src/audit.ts` 顶部的 `sensitiveKeys` 是一份**黑名单**（本轮复算 **27** 项：
//! `sed -n '/^const sensitiveKeys = new Set(\[/,/^\]);/p' server/src/audit.ts | grep -cE '^\s+"'`
//! 在 commit `891df72f1827454d8b353d108fe5dd2313b7e30d` 上得 27），`redactAuditPayload`
//! 递归遍历任意对象，把命中的**键名**换成 `"[REDACTED]"`。
//!
//! v3 §8.6 要的是**字段 allowlist**。两者的差别不是严格程度，是**失效方向**：
//!
//! | | 漏掉一个键的后果 |
//! | --- | --- |
//! | 黑名单 | 那个键的值**原样落盘** —— 一次泄漏，且没有任何东西会报警 |
//! | 白名单 | 那条事实**记不进去** —— 少一条审计信息，写入侧当场看得见 |
//!
//! 黑名单还有两处结构性缺口，与实现质量无关：值里的内容它一眼都没看（`{note: "口令是…"}`
//! 全身而退），以及**新键名默认安全**（加一个 `user_message` 字段不会命中任何条目，一次
//! 正常的功能开发就把整段对话写进了审计表，没有闸门会红）。
//!
//! 所以 [`payload`] 把 allowlist 做成构造性事实：payload 的唯一入口是封闭 enum
//! [`payload::AuditFact`]，没有任何接受自由键名或 `serde_json::Value` 的构造函数。
//! 我们还把上游那 27 个键当成自己的体检项 ——
//! `field_ledger_is_disjoint_from_upstream_sensitive_keys` 断言我们的字段台账与它**不相交**，
//! 并配了正向对照证明判据不是恒真。
//!
//! # 模块导航
//!
//! | 模块 | 内容 | §8.6 对应条款 |
//! | --- | --- | --- |
//! | [`hash`] | SHA-256 摘要 + 无歧义的长度前缀规范编码 | hash chain 的前提 |
//! | [`payload`] | 字段 allowlist、human takeover 三阶段、secret 输入只记长度 | payload allowlist / takeover / secret |
//! | [`event`] | [`event::AuditEvent`] 与 57 项事件类型封闭目录 | 表语义保持上游 |
//! | [`chain`] | `row_hash` / `prev_hash`、genesis 语义、带断点位置的链校验 | hash chain 追加 nullable 列 |
//! | [`checkpoint`] | genesis / periodic / closure 三种 checkpoint + HMAC 签名 | 周期 checkpoint 签名后入库 |
//! | [`retention`] | `AUDIT_RETENTION_DAYS` 三态解析、窗口判定、closure 规划 | retention 原名原义 |
//!
//! # Desktop 的承诺边界
//!
//! §8.6 逐字：Desktop 同样 append-only，但**只承诺可追溯，不宣称抵抗设备所有者 / root
//! 篡改**。签名密钥与数据库在同一台机器上，root 拿得到密钥就能重算整条链和全部 checkpoint。
//! 这条限制写在这里而不是只写在发布说明里，是因为一条被误以为能防 root 的链，会让人不去
//! 部署真正能防的东西（外部不可变 sink）。

pub mod chain;
pub mod checkpoint;
pub mod event;
pub mod hash;
pub mod payload;
pub mod retention;
