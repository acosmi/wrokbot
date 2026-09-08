//! `public.tool_calls` 的 durable decision 行（native 0013，v3 §8.1 / §8.2）。
//!
//! 不保存原始 arguments，只保存规范摘要与权威 actor/target/metadata。`run_id` 已落列且
//! `(run_id, call_seq)` 唯一；到 G3 创建 `runs` 表时再以 expand-only 补外键，0013 不能为了
//! 一个尚不存在的被引用表越界创建整套 G3 schema。

crate::db::tables::define_table! {
    table = "tool_calls";
    tool_call_id: String = ("tool_call_id", "text", true),
    run_id: String = ("run_id", "text", true),
    call_seq: i64 = ("call_seq", "bigint", true),
    decision_id: String = ("decision_id", "text", true),
    actor_id: String = ("actor_id", "text", true),
    bot_id: String = ("bot_id", "text", true),
    tool_name: String = ("tool_name", "text", true),
    schema_hash: String = ("schema_hash", "text", true),
    catalog_generation: i64 = ("catalog_generation", "bigint", true),
    args_hash: String = ("args_hash", "text", true),
    target_kind: String = ("target_kind", "text", true),
    target_id: String = ("target_id", "text", true),
    effect: String = ("effect", "text", true),
    effect_downgraded: bool = ("effect_downgraded", "boolean", true),
    idempotency: String = ("idempotency", "text", true),
    idempotency_key: Option<String> = ("idempotency_key", "text", false),
    approval_class: String = ("approval_class", "text", true),
    policy_version: String = ("policy_version", "text", true),
    decided_at: time::OffsetDateTime = ("decided_at", "timestamp with time zone", true),
}

/// Native-current projection columns after 0020 adds the durable approval link.
pub const CURRENT_COLUMNS: &[&str] = &[
    "tool_call_id",
    "run_id",
    "call_seq",
    "decision_id",
    "actor_id",
    "bot_id",
    "tool_name",
    "schema_hash",
    "catalog_generation",
    "args_hash",
    "target_kind",
    "target_id",
    "effect",
    "effect_downgraded",
    "idempotency",
    "idempotency_key",
    "approval_class",
    "policy_version",
    "decided_at",
    "approval_id",
];

/// Current durable tool call with optional proof-of-intent identity.
#[derive(Clone, Debug, PartialEq)]
pub struct CurrentRow {
    /// Native 0013 decision shape.
    pub call: Row,
    /// Native 0020 approval row; NULL exactly when human approval was not required.
    pub approval_id: Option<String>,
}

impl TryFrom<&tokio_postgres::Row> for CurrentRow {
    type Error = crate::db::RowDecodeError;

    fn try_from(row: &tokio_postgres::Row) -> Result<Self, Self::Error> {
        Ok(Self {
            call: Row::try_from(row)?,
            approval_id: row.try_get("approval_id").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "approval_id", source)
            })?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argument_hash_and_idempotency_key_are_not_debuggable() {
        let row = Row {
            tool_call_id: "call-1".to_owned(),
            run_id: "run-1".to_owned(),
            call_seq: 0,
            decision_id: "decision-1".to_owned(),
            actor_id: "actor-1".to_owned(),
            bot_id: "bot-1".to_owned(),
            tool_name: "MARKER-VISIBLE".to_owned(),
            schema_hash: "a".repeat(64),
            catalog_generation: 1,
            args_hash: "SENTINEL-ARGS-HASH".to_owned(),
            target_kind: "browser_tab".to_owned(),
            target_id: "tab-1".to_owned(),
            effect: "write".to_owned(),
            effect_downgraded: false,
            idempotency: "keyed".to_owned(),
            idempotency_key: Some("SENTINEL-IDEMPOTENCY-KEY".to_owned()),
            approval_class: "every_call".to_owned(),
            policy_version: "pv-1".to_owned(),
            decided_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        let rendered = format!("{row:?}");
        assert!(rendered.contains("MARKER-VISIBLE"));
        assert!(!rendered.contains("SENTINEL-ARGS-HASH"));
        assert!(!rendered.contains("SENTINEL-IDEMPOTENCY-KEY"));
        assert_eq!(rendered.matches("<redacted>").count(), 2);
    }
}
