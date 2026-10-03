//! Minimal stable-name retirement facts; no source content or execution grant.
crate::db::tables::define_table! {
    table = "sandboxed_component_retired_names";
    name: String = ("name", "text", true),
    retired_editing_revision: i64 = ("retired_editing_revision", "bigint", true),
    retired_at: time::OffsetDateTime = ("retired_at", "timestamp with time zone", true),
}
