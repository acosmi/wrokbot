//! `public.messages` typed row（native 0016）。

crate::db::tables::define_table! {
    table = "messages";
    message_id: String = ("message_id", "text", true),
    thread_id: String = ("thread_id", "text", true),
    seq: i64 = ("seq", "bigint", true),
    role: String = ("role", "text", true),
    content: serde_json::Value = ("content", "jsonb", true),
    search_text: String = ("search_text", "text", true),
    run_id: Option<String> = ("run_id", "text", false),
    actor_id: Option<String> = ("actor_id", "text", false),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
}
