//! `public.user_memory_controls` actor/tenant runtime memory-write setting (native 0022).

crate::db::tables::define_table! {
    table = "user_memory_controls";
    tenant_id: String = ("tenant_id", "text", true),
    actor_user_id: String = ("actor_user_id", "text", true),
    writes_enabled: bool = ("writes_enabled", "boolean", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}
