//! `public.tool_attempts` 的执行尝试行（native 0013，v3 §7.4 / §8.1）。
//!
//! 一次 call 可以有多次 attempt，主键固定为 `(tool_call_id, attempt_seq)`；每个 attempt id
//! 另有唯一约束。capability id 在 decision+attempt 事务提交后铸造，写入后才可进入 executing。

crate::db::tables::define_table! {
    table = "tool_attempts";
    tool_call_id: String = ("tool_call_id", "text", true),
    attempt_seq: i64 = ("attempt_seq", "bigint", true),
    attempt_id: String = ("attempt_id", "text", true),
    capability_id: Option<String> = ("capability_id", "text", false),
    status: String = ("status", "text", true),
    commit_state: Option<String> = ("commit_state", "text", false),
    output_bytes: Option<i64> = ("output_bytes", "bigint", false),
    duration_ms: Option<i64> = ("duration_ms", "bigint", false),
    error_code: Option<String> = ("error_code", "text", false),
    started_at: Option<time::OffsetDateTime> = ("started_at", "timestamp with time zone", false),
    finished_at: Option<time::OffsetDateTime> = ("finished_at", "timestamp with time zone", false),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_use_capability_id_is_redacted() {
        let row = Row {
            tool_call_id: "call-1".to_owned(),
            attempt_seq: 0,
            attempt_id: "attempt-1".to_owned(),
            capability_id: Some("SENTINEL-CAPABILITY".to_owned()),
            status: "MARKER-VISIBLE".to_owned(),
            commit_state: None,
            output_bytes: None,
            duration_ms: None,
            error_code: None,
            started_at: None,
            finished_at: None,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        let rendered = format!("{row:?}");
        assert!(rendered.contains("MARKER-VISIBLE"));
        assert!(!rendered.contains("SENTINEL-CAPABILITY"));
        assert!(rendered.contains("<redacted>"));
    }
}
