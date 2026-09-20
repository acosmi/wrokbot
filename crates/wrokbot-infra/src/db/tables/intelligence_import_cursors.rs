//! `public.intelligence_import_cursors` typed row（native 0016）。

crate::db::tables::define_table! {
    table = "intelligence_import_cursors";
    bundle_id: String = ("bundle_id", "text", true),
    aggregate_kind: String = ("aggregate_kind", "text", true),
    deployment_id: String = ("deployment_id", "text", true),
    cursor: String = ("cursor", "text", true),
    last_hash: String = ("last_hash", "text", true),
    imported_count: i64 = ("imported_count", "bigint", true),
    status: String = ("status", "text", true),
    provenance: serde_json::Value = ("provenance", "jsonb", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}
