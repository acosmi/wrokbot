//! `public.credentials` 的类型化行 —— 上游 server/src/db/schema/core.ts::credentials。
//!
//! 列名、列序（`pg_attribute.attnum`）、可空性与类型逐列对应上游 0012 终态，真源是
//! `fixtures/db/schema-0012.json`；`COLUMN_SPECS` 与真库的一致性由
//! `crate::db::compat::check_migration_boundary` 在活库上机械核对。
//!
//! 主键：PRIMARY KEY (id)。
//!
//! ⚠️ 本表承载敏感数据：`encrypted_value` 是 vault 密文本体。repository contract §5 不变量 8 要求 secret
//! 不进模型、GUI state、browser event、普通日志与 trace，所以 `encrypted_value` 一列已登记进
//! `crate::db::tables::SECRET_COLUMNS`，`Row` 的 `Debug` 会把它渲染成 `<redacted>`。
//! **取值本身仍在字段里** —— 脱敏只挡住日志与 panic 消息这条默认打开的泄漏路径，把值往别处传
//! 仍是调用方的责任。
//!
//! `key_id` 刻意**不**脱敏：它是解密密钥的标识符而不是密钥本身，遮掉它会让密钥轮换的排障无从
//! 下手。该豁免带书面理由登记在 `crate::db::tables::SECRET_SCAN_EXEMPTIONS`。

crate::db::tables::define_table! {
    table = "credentials";
    id: uuid::Uuid = ("id", "uuid", true),
    kind: crate::db::types::CredentialKind = ("kind", "credential_kind", true),
    provider: String = ("provider", "text", true),
    encrypted_value: String = ("encrypted_value", "text", true),
    key_id: String = ("key_id", "text", true),
    metadata: serde_json::Value = ("metadata", "jsonb", true),
    revoked_at: Option<time::OffsetDateTime> = ("revoked_at", "timestamp with time zone", false),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}
