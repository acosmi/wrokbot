//! Durable SDK Gateway credential-rotation operations (native 0033).

crate::db::tables::define_table! {
    table = "sdk_gateway_operations";
    id: uuid::Uuid = ("id", "uuid", true),
    connection_id: uuid::Uuid = ("connection_id", "uuid", true),
    deployment_id: String = ("deployment_id", "text", true),
    tenant_id: String = ("tenant_id", "text", true),
    owner_user_id: String = ("owner_user_id", "text", true),
    expected_revision: i64 = ("expected_revision", "bigint", true),
    auth_generation: i64 = ("auth_generation", "bigint", true),
    from_generation: i64 = ("from_generation", "bigint", true),
    to_generation: i64 = ("to_generation", "bigint", true),
    state: String = ("state", "text", true),
    candidate_secret_id: Option<uuid::Uuid> = ("candidate_secret_id", "uuid", false),
    token_admitted_at: Option<time::OffsetDateTime> = ("token_admitted_at", "timestamp with time zone", false),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
    completed_at: Option<time::OffsetDateTime> = ("completed_at", "timestamp with time zone", false),
}
