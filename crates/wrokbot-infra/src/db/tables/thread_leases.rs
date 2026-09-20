//! `public.thread_leases` typed row（native 0016）。

crate::db::tables::define_table! {
    table = "thread_leases";
    thread_id: String = ("thread_id", "text", true),
    owner_id: String = ("owner_id", "text", true),
    fencing_token: i64 = ("fencing_token", "bigint", true),
    acquired_at: time::OffsetDateTime = ("acquired_at", "timestamp with time zone", true),
    expires_at: time::OffsetDateTime = ("expires_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}
