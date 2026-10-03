//! Minimal permanent skill identity retirement; no instructions or grants.
crate::db::tables::define_table! {
    table = "skill_retired_slugs";
    slug: String = ("slug", "text", true),
    retired_revision: i64 = ("retired_revision", "bigint", true),
    retired_at: time::OffsetDateTime = ("retired_at", "timestamp with time zone", true),
}
