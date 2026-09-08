//! `public.audit_checkpoints` 的类型化行（native 0013，v3 §8.6）。
//!
//! checkpoint 本体由 `openbot-domain::audit::checkpoint` 定义；本表保存它的展开字段与
//! HMAC-SHA256 签名。event id 刻意不做外键：closure checkpoint 必须在对应 audit row 被
//! retention 删除后继续存在，外键会把证据和被证明对象绑成同生共死。

crate::db::tables::define_table! {
    table = "audit_checkpoints";
    sequence: i64 = ("sequence", "bigint", true),
    checkpoint_kind: String = ("checkpoint_kind", "text", true),
    first_event_id: String = ("first_event_id", "text", true),
    first_row_hash: String = ("first_row_hash", "text", true),
    last_event_id: String = ("last_event_id", "text", true),
    last_row_hash: String = ("last_row_hash", "text", true),
    event_count: i64 = ("event_count", "bigint", true),
    unlinked_rows_before: Option<i64> = ("unlinked_rows_before", "bigint", false),
    retention_days: Option<i32> = ("retention_days", "integer", false),
    signature: String = ("signature", "text", true),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_signature_is_redacted_but_boundary_hashes_are_visible() {
        let row = Row {
            sequence: 0,
            checkpoint_kind: "genesis".to_owned(),
            first_event_id: "event-1".to_owned(),
            first_row_hash: "a".repeat(64),
            last_event_id: "event-1".to_owned(),
            last_row_hash: "a".repeat(64),
            event_count: 1,
            unlinked_rows_before: Some(7),
            retention_days: None,
            signature: "SENTINEL-CHECKPOINT-SIGNATURE".to_owned(),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        let rendered = format!("{row:?}");
        assert!(!rendered.contains("SENTINEL-CHECKPOINT-SIGNATURE"));
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains(&"a".repeat(64)));
    }
}
