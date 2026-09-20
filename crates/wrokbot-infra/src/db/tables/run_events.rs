//! `public.run_events` typed row（native 0016）。

crate::db::tables::define_table! {
    table = "run_events";
    run_id: String = ("run_id", "text", true),
    seq: i64 = ("seq", "bigint", true),
    thread_id: String = ("thread_id", "text", true),
    event_seq: i64 = ("event_seq", "bigint", true),
    event_type: String = ("event_type", "text", true),
    payload: serde_json::Value = ("payload", "jsonb", true),
    terminal: bool = ("terminal", "boolean", true),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
}
