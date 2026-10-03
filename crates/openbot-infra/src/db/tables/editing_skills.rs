//! Current native0039 skills; the fixed upstream ten-column registry remains unchanged.
crate::db::tables::define_table! {
    table = "skills";
    id: String = ("id", "text", true),
    owner_user_id: Option<String> = ("owner_user_id", "text", false),
    slug: String = ("slug", "text", true),
    title: String = ("title", "text", true),
    summary: String = ("summary", "text", true),
    instructions: String = ("instructions", "text", true),
    origin: String = ("origin", "text", true),
    installed_by: Option<String> = ("installed_by", "text", false),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
    revision: Option<i64> = ("revision", "bigint", false),
}
