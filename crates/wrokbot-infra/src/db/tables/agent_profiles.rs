//! `public.agent_profiles` 的类型化行 —— 上游 server/src/db/schema/coworker.ts::agentProfiles。
//!
//! 列名、列序（`pg_attribute.attnum`）、可空性与类型逐列对应上游 0012 终态，真源是
//! `fixtures/db/schema-0012.json`；`COLUMN_SPECS` 与真库的一致性由
//! `crate::db::compat::check_migration_boundary` 在活库上机械核对。
//!
//! 主键：PRIMARY KEY (agent_id)。
//!
//! 外键：
//!
//! - FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
//! - FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE SET NULL
//!
//! ⚠️ 本表承载敏感数据：`callback_token_hash` 是回调令牌的散列。散列不是原文，但它是**验证物**
//! —— 泄漏之后可以离线爆破低熵令牌，所以按 secret 处理而不是按摘要处理。repository contract §5 不变量 8
//! 要求 secret 不进模型、GUI state、browser event、普通日志与 trace，所以该列已登记进
//! `crate::db::tables::SECRET_COLUMNS`，`Row` 的 `Debug` 会把它渲染成 `<redacted>`。
//! **取值本身仍在字段里** —— 脱敏只挡住日志与 panic 消息这条默认打开的泄漏路径，把值往别处传
//! 仍是调用方的责任。`callback_token_issued_at` 只是签发时刻，具名豁免见
//! `crate::db::tables::SECRET_SCAN_EXEMPTIONS`。

crate::db::tables::define_table! {
    table = "agent_profiles";
    agent_id: String = ("agent_id", "text", true),
    owner_user_id: Option<String> = ("owner_user_id", "text", false),
    title: String = ("title", "text", true),
    role_description: String = ("role_description", "text", true),
    avatar_seed: String = ("avatar_seed", "text", true),
    visibility: crate::db::types::AgentVisibility = ("visibility", "agent_visibility", true),
    deleted_at: Option<time::OffsetDateTime> = ("deleted_at", "timestamp with time zone", false),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
    callback_token_hash: Option<String> = ("callback_token_hash", "text", false),
    callback_token_issued_at: Option<time::OffsetDateTime> = ("callback_token_issued_at", "timestamp with time zone", false),
}
