//! `public.user_ui_preferences` actor/deployment/tenant settings (native 0021).

crate::db::tables::define_table! {
    table = "user_ui_preferences";
    deployment_id: String = ("deployment_id", "text", true),
    tenant_id: String = ("tenant_id", "text", true),
    actor_user_id: String = ("actor_user_id", "text", true),
    theme: Option<String> = ("theme", "text", false),
    locale: Option<String> = ("locale", "text", false),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}
