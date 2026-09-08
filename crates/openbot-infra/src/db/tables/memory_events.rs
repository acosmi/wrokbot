//! `public.memory_events` typed row（native 0016）。

crate::db::tables::define_table! {
    table = "memory_events";
    memory_id: String = ("memory_id", "text", true),
    seq: i64 = ("seq", "bigint", true),
    event_type: String = ("event_type", "text", true),
    actor_id: String = ("actor_id", "text", true),
    metadata: serde_json::Value = ("metadata", "jsonb", true),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
}
