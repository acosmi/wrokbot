//! `public.user_run_cost_budgets` actor/deployment/tenant settings (native 0026).

crate::db::tables::define_table! {
    table = "user_run_cost_budgets";
    deployment_id: String = ("deployment_id", "text", true),
    tenant_id: String = ("tenant_id", "text", true),
    actor_user_id: String = ("actor_user_id", "text", true),
    currency: String = ("currency", "text", true),
    max_cost_micro_units: i64 = ("max_cost_micro_units", "bigint", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}
