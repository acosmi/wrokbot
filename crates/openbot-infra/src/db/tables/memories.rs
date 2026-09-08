//! `public.memories` typed row（native 0016）。

crate::db::tables::define_table! {
    table = "memories";
    memory_id: String = ("memory_id", "text", true),
    tenant_id: String = ("tenant_id", "text", true),
    owner_user_id: String = ("owner_user_id", "text", true),
    scope_kind: String = ("scope_kind", "text", true),
    scope_id: Option<String> = ("scope_id", "text", false),
    memory_kind: String = ("memory_kind", "text", true),
    content: Option<String> = ("content", "text", false),
    tags: Vec<Option<String>> = ("tags", "text[]", true),
    sensitivity: String = ("sensitivity", "text", true),
    source_thread_id: Option<String> = ("source_thread_id", "text", false),
    source_message_id: Option<String> = ("source_message_id", "text", false),
    origin: String = ("origin", "text", true),
    created_by: String = ("created_by", "text", true),
    supersedes_id: Option<String> = ("supersedes_id", "text", false),
    status: String = ("status", "text", true),
    expires_at: Option<time::OffsetDateTime> = ("expires_at", "timestamp with time zone", false),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}
