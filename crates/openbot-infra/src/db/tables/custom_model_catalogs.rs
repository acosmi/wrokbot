//! Persistent custom-model identity and definition revision (native 0046).
//!
//! Definition revisions are independent of the original connection CAS revision.

crate::db::tables::define_table! {
    table = "custom_model_catalogs";
    connection_id: uuid::Uuid = ("connection_id", "uuid", true),
    deployment_id: String = ("deployment_id", "text", true),
    tenant_id: String = ("tenant_id", "text", true),
    owner_user_id: String = ("owner_user_id", "text", true),
    model_id: String = ("model_id", "text", true),
    catalog_revision: i64 = ("catalog_revision", "bigint", true),
    protocol: String = ("protocol", "text", true),
    endpoint: String = ("endpoint", "text", true),
    model: String = ("model", "text", true),
    enabled: bool = ("enabled", "boolean", true),
    retired: bool = ("retired", "boolean", true),
}
