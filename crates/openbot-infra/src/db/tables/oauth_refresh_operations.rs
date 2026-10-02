//! Durable OAuth refresh operations; no token or ciphertext is copied here.

crate::db::tables::define_table! {
    table = "oauth_refresh_operations";
    operation_id: uuid::Uuid = ("operation_id", "uuid", true),
    credential_id: uuid::Uuid = ("credential_id", "uuid", true),
    generation: i64 = ("generation", "bigint", true),
    actor_id: String = ("actor_id", "text", true),
    auth_generation: i64 = ("auth_generation", "bigint", true),
    server_id: String = ("server_id", "text", true),
    client_credential_id: uuid::Uuid = ("client_credential_id", "uuid", true),
    server_generation: i64 = ("server_generation", "bigint", true),
    server_updated_at: time::OffsetDateTime = ("server_updated_at", "timestamp with time zone", true),
    client_updated_at: time::OffsetDateTime = ("client_updated_at", "timestamp with time zone", true),
    resource: String = ("resource", "text", true),
    transport: String = ("transport", "text", true),
    egress_allow_cidrs: Vec<Option<String>> = ("egress_allow_cidrs", "text[]", true),
    granted_scope: String = ("granted_scope", "text", true),
    state: String = ("state", "text", true),
    admitted_at: Option<time::OffsetDateTime> = ("admitted_at", "timestamp with time zone", false),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    completed_at: Option<time::OffsetDateTime> = ("completed_at", "timestamp with time zone", false),
}
