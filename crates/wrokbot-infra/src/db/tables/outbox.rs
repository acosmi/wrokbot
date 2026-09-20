//! `public.outbox` typed row（native 0016）。

crate::db::tables::define_table! {
    table = "outbox";
    outbox_id: String = ("outbox_id", "text", true),
    aggregate_kind: String = ("aggregate_kind", "text", true),
    aggregate_id: String = ("aggregate_id", "text", true),
    seq: i64 = ("seq", "bigint", true),
    destination: String = ("destination", "text", true),
    delivery_class: String = ("delivery_class", "text", true),
    payload: serde_json::Value = ("payload", "jsonb", true),
    status: String = ("status", "text", true),
    attempt_count: i32 = ("attempt_count", "integer", true),
    available_at: time::OffsetDateTime = ("available_at", "timestamp with time zone", true),
    claimed_by: Option<String> = ("claimed_by", "text", false),
    claim_expires_at: Option<time::OffsetDateTime> = ("claim_expires_at", "timestamp with time zone", false),
    delivered_at: Option<time::OffsetDateTime> = ("delivered_at", "timestamp with time zone", false),
    last_error_code: Option<String> = ("last_error_code", "text", false),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}
