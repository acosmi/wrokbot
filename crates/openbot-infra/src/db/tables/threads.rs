//! `public.threads` typed row（native 0016）。

crate::db::tables::define_table! {
    table = "threads";
    thread_id: String = ("thread_id", "text", true),
    tenant_id: String = ("tenant_id", "text", true),
    deployment_id: String = ("deployment_id", "text", true),
    created_by: String = ("created_by", "text", true),
    anchor_kind: String = ("anchor_kind", "text", true),
    anchor_id: String = ("anchor_id", "text", true),
    title: Option<String> = ("title", "text", false),
    status: String = ("status", "text", true),
    next_message_seq: i64 = ("next_message_seq", "bigint", true),
    next_event_seq: i64 = ("next_event_seq", "bigint", true),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
    deleted_at: Option<time::OffsetDateTime> = ("deleted_at", "timestamp with time zone", false),
}
