//! `public.thread_memberships` typed row（native 0016）。

crate::db::tables::define_table! {
    table = "thread_memberships";
    thread_id: String = ("thread_id", "text", true),
    user_id: String = ("user_id", "text", true),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
}
