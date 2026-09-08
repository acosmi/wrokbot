//! `public.model_connections` personal custom-model authority (native 0030).
//!
//! `current_secret_id` is a private relation pointer, not the credential value. Its composite
//! foreign key binds the current secret to this connection, deployment, tenant and owner.

crate::db::tables::define_table! {
    table = "model_connections";
    id: uuid::Uuid = ("id", "uuid", true),
    deployment_id: String = ("deployment_id", "text", true),
    tenant_id: String = ("tenant_id", "text", true),
    owner_user_id: String = ("owner_user_id", "text", true),
    name: String = ("name", "text", true),
    protocol: String = ("protocol", "text", true),
    endpoint: String = ("endpoint", "text", true),
    model: String = ("model", "text", true),
    enabled: bool = ("enabled", "boolean", true),
    revision: i64 = ("revision", "bigint", true),
    current_secret_id: uuid::Uuid = ("current_secret_id", "uuid", true),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
    deleted_at: Option<time::OffsetDateTime> = ("deleted_at", "timestamp with time zone", false),
}
