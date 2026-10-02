//! Exact current foreground owner, maintained only by the native 0036 run trigger.

crate::db::tables::define_table! {
    table = "thread_run_occupancy";
    thread_id: String = ("thread_id", "text", true),
    run_id: String = ("run_id", "text", true),
}
