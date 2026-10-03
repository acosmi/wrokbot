//! Current native0040 preference row; the historical native0021 registry stays fixed.

crate::db::tables::define_table! {
    table = "user_ui_preferences";
    deployment_id: String = ("deployment_id", "text", true),
    tenant_id: String = ("tenant_id", "text", true),
    actor_user_id: String = ("actor_user_id", "text", true),
    theme: Option<String> = ("theme", "text", false),
    locale: Option<String> = ("locale", "text", false),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
    revision: Option<i64> = ("revision", "bigint", false),
}
