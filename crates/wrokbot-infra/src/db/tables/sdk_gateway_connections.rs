//! SDK Gateway account connection authority (native 0033).

crate::db::tables::define_table! {
    table = "sdk_gateway_connections";
    id: uuid::Uuid = ("id", "uuid", true),
    deployment_id: String = ("deployment_id", "text", true),
    tenant_id: String = ("tenant_id", "text", true),
    owner_user_id: String = ("owner_user_id", "text", true),
    name: String = ("name", "text", true),
    issuer: String = ("issuer", "text", true),
    client_id: String = ("client_id", "text", true),
    account_id: String = ("account_id", "text", true),
    organization_id: Option<String> = ("organization_id", "text", false),
    auth_contract_version: i16 = ("auth_contract_version", "smallint", true),
    error_contract_version: i16 = ("error_contract_version", "smallint", true),
    enabled: bool = ("enabled", "boolean", true),
    revision: i64 = ("revision", "bigint", true),
    credential_generation: i64 = ("credential_generation", "bigint", true),
    auth_generation: i64 = ("auth_generation", "bigint", true),
    state: String = ("state", "text", true),
    current_secret_id: Option<uuid::Uuid> = ("current_secret_id", "uuid", false),
    pending_operation_id: Option<uuid::Uuid> = ("pending_operation_id", "uuid", false),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
    deleted_at: Option<time::OffsetDateTime> = ("deleted_at", "timestamp with time zone", false),
}
