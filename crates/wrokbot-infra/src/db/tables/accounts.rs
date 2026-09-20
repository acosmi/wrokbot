//! `public.accounts` 的类型化行 —— 上游 server/src/db/schema/core.ts::accounts。
//!
//! 列名、列序（`pg_attribute.attnum`）、可空性与类型逐列对应上游 0012 终态，真源是
//! `fixtures/db/schema-0012.json`；`COLUMN_SPECS` 与真库的一致性由
//! `crate::db::compat::check_migration_boundary` 在活库上机械核对。
//!
//! 主键：PRIMARY KEY (id)。
//!
//! 外键：
//!
//! - FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
//!
//! ⚠️ 本表承载敏感数据：`access_token` / `id_token` / `password` / `refresh_token` 是**明文**
//! text 列（`parity/tables.yaml::tbl-accounts` 的 notes 逐字写明「加密=无」）。repository contract §5
//! 不变量 8 要求 secret 不进模型、GUI state、browser event、普通日志与 trace，所以这四列已登记
//! 进 `crate::db::tables::SECRET_COLUMNS`，`Row` 的 `Debug` 会把它们渲染成 `<redacted>`。
//! **取值本身仍在字段里** —— 脱敏只挡住日志与 panic 消息这条默认打开的泄漏路径，把值往别处传
//! 仍是调用方的责任。

crate::db::tables::define_table! {
    table = "accounts";
    id: String = ("id", "text", true),
    account_id: String = ("account_id", "text", true),
    provider_id: String = ("provider_id", "text", true),
    user_id: String = ("user_id", "text", true),
    access_token: Option<String> = ("access_token", "text", false),
    refresh_token: Option<String> = ("refresh_token", "text", false),
    id_token: Option<String> = ("id_token", "text", false),
    access_token_expires_at: Option<time::OffsetDateTime> = ("access_token_expires_at", "timestamp with time zone", false),
    refresh_token_expires_at: Option<time::OffsetDateTime> = ("refresh_token_expires_at", "timestamp with time zone", false),
    scope: Option<String> = ("scope", "text", false),
    password: Option<String> = ("password", "text", false),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
    issuer: Option<String> = ("issuer", "text", false),
}
