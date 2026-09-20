//! `public.mcp_user_credentials` 的类型化行 —— 上游
//! server/src/db/schema/plugins.ts::mcpUserCredentials。
//!
//! 列名、列序（`pg_attribute.attnum`）、可空性与类型逐列对应上游 0012 终态，真源是
//! `fixtures/db/schema-0012.json`；`COLUMN_SPECS` 与真库的一致性由
//! `crate::db::compat::check_migration_boundary` 在活库上机械核对。
//!
//! 主键：PRIMARY KEY (server_id, user_id)。
//!
//! 外键：
//!
//! - FOREIGN KEY (credential_id) REFERENCES credentials(id)
//! - FOREIGN KEY (server_id) REFERENCES mcp_servers(id) ON DELETE CASCADE
//! - FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
//!
//! 本表**不含** secret 列：`credential_id` 是指向 `credentials` 表的外键 uuid，是指针不是凭据，
//! 密文本体在 `credentials.encrypted_value`。它命中 secret 词根扫描但已具名豁免，理由见
//! `crate::db::tables::SECRET_SCAN_EXEMPTIONS`。

crate::db::tables::define_table! {
    table = "mcp_user_credentials";
    server_id: String = ("server_id", "text", true),
    user_id: String = ("user_id", "text", true),
    credential_id: uuid::Uuid = ("credential_id", "uuid", true),
    scope: String = ("scope", "text", true),
    connected_at: time::OffsetDateTime = ("connected_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}
