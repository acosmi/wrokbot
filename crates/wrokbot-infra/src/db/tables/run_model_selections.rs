//! Private historical run binding (native 0031), without any credential value or authority grant.

crate::db::tables::define_table! {
    table = "run_model_selections";
    run_id: String = ("run_id", "text", true),
    deployment_id: String = ("deployment_id", "text", true),
    tenant_id: String = ("tenant_id", "text", true),
    owner_user_id: String = ("owner_user_id", "text", true),
    auth_generation: i64 = ("auth_generation", "bigint", true),
    connection_id: uuid::Uuid = ("connection_id", "uuid", true),
    connection_revision: i64 = ("connection_revision", "bigint", true),
    secret_id: uuid::Uuid = ("secret_id", "uuid", true),
    protocol: String = ("protocol", "text", true),
    endpoint: String = ("endpoint", "text", true),
    model: String = ("model", "text", true),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
}
