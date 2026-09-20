//! `public.sso_providers` 的类型化行 —— 上游 server/src/db/schema/core.ts::ssoProviders。
//!
//! 列名、列序（`pg_attribute.attnum`）、可空性与类型逐列对应上游 0012 终态，真源是
//! `fixtures/db/schema-0012.json`；`COLUMN_SPECS` 与真库的一致性由
//! `crate::db::compat::check_migration_boundary` 在活库上机械核对。
//!
//! 主键：PRIMARY KEY (id)。
//! 唯一：UNIQUE (provider_id)。
//!
//! 外键：
//!
//! - FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
//!
//! ⚠️ 本表承载敏感数据：`oidc_config` / `saml_config` 承载 SSO 凭据 —— 上游
//! `server/src/auth/encrypt-sso-config.ts::ENCRYPTED_FIELDS` 点名要加密的就是这两列，
//! 即上游自己也认定它们装的是 secret。repository contract §5 不变量 8 要求 secret 不进模型、GUI state、
//! browser event、普通日志与 trace，所以这两列已登记进 `crate::db::tables::SECRET_COLUMNS`，
//! `Row` 的 `Debug` 会把它们渲染成 `<redacted>`。**取值本身仍在字段里** —— 脱敏只挡住日志与
//! panic 消息这条默认打开的泄漏路径，把值往别处传仍是调用方的责任。

crate::db::tables::define_table! {
    table = "sso_providers";
    id: String = ("id", "text", true),
    issuer: String = ("issuer", "text", true),
    oidc_config: Option<String> = ("oidc_config", "text", false),
    saml_config: Option<String> = ("saml_config", "text", false),
    user_id: Option<String> = ("user_id", "text", false),
    provider_id: String = ("provider_id", "text", true),
    organization_id: Option<String> = ("organization_id", "text", false),
    domain: String = ("domain", "text", true),
}
