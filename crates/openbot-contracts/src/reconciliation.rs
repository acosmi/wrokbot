//! Unknown run 的只读持久事实投影；不授予处置、继续或重放权限。

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::AppError;
use crate::ids::{RunId, ThreadId};

/// 完整查询应答的序列化字节上限。
pub const MAX_RUN_RECONCILIATION_RESPONSE_BYTES: usize = 256 * 1024;
/// 单页最大尝试数；不会静默截断非法请求上限。
pub const MAX_RUN_RECONCILIATION_PAGE: u32 = 100;
/// 未提供 limit 时的页大小。
pub const DEFAULT_RUN_RECONCILIATION_PAGE: u32 = 50;
/// 本入口内部身份的 UTF-8 字节上限。
pub const MAX_RUN_RECONCILIATION_ID_BYTES: usize = 512;

/// 原 run 内的稳定二元排序位置；不是权限或跨页快照。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunReconciliationCursor {
    /// 原 tool call 的非负序号。
    pub call_sequence: i64,
    /// 同一 call 内的非负 attempt 序号。
    pub attempt_sequence: i64,
}

impl RunReconciliationCursor {
    /// 验证二元位置而不改变任何数值。
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.call_sequence >= 0 && self.attempt_sequence >= 0
    }
}

/// 两宿主共享的封闭 URL query；领域入口仍重复校验 typed 值。
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunReconciliationQuery {
    /// 与 afterAttemptSequence 成对提供。
    pub after_call_sequence: Option<i64>,
    /// 与 afterCallSequence 成对提供。
    pub after_attempt_sequence: Option<i64>,
    /// 省略为50，显式范围1–100。
    pub limit: Option<u32>,
}

impl RunReconciliationQuery {
    /// 拒绝半个或非法 cursor，不截断 limit。
    pub fn into_parts(self) -> Result<(Option<RunReconciliationCursor>, Option<u32>), AppError> {
        let after = match (self.after_call_sequence, self.after_attempt_sequence) {
            (None, None) => None,
            (Some(call_sequence), Some(attempt_sequence)) => Some(RunReconciliationCursor {
                call_sequence,
                attempt_sequence,
            }),
            _ => return Err(AppError::MalformedPayload { field: "after" }),
        };
        validate_page(after, self.limit)?;
        Ok((after, self.limit))
    }
}

/// 校验来自任一 transport 的分页值，返回实际页上限。
pub fn validate_page(
    after: Option<RunReconciliationCursor>,
    limit: Option<u32>,
) -> Result<u32, AppError> {
    if after.is_some_and(|cursor| !cursor.is_valid()) {
        return Err(AppError::MalformedPayload { field: "after" });
    }
    let limit = limit.unwrap_or(DEFAULT_RUN_RECONCILIATION_PAGE);
    if !(1..=MAX_RUN_RECONCILIATION_PAGE).contains(&limit) {
        return Err(AppError::MalformedPayload { field: "limit" });
    }
    Ok(limit)
}

/// 身份是 opaque 字符串，不能把旧 run 身份伪限定为 UUID。
#[must_use]
pub fn valid_reconciliation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_RUN_RECONCILIATION_ID_BYTES
        && !value.chars().any(char::is_control)
}

/// 本查询唯一可返回的原 run 终态。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunReconciliationStatus {
    /// 原结果未决；查询本身不会解除它。
    ReconciliationRequired,
}

/// 数据库原始尝试状态的封闭投影。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunReconciliationAttemptStatus {
    /// 已持久登记决定，不推断是否产生外部效果。
    DecisionRecorded,
    /// 已进入执行，外部效果仍可能未确认。
    Executing,
    /// 原执行记录已收口，不是本查询新取得的外部证明。
    Completed,
    /// 原尝试需要查证。
    ReconciliationRequired,
    /// 原尝试已中止。
    Aborted,
}

/// 原记录中的提交状态；字段为 null 时只表示未记录。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunReconciliationCommitState {
    /// 原记录为已提交。
    Committed,
    /// 原记录为未提交。
    NotCommitted,
    /// 原记录为未知。
    Unknown,
}

/// 不含参数、目标、能力、凭据、错误正文或工具结果的尝试事实。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunReconciliationAttempt {
    /// 内部 tool call 身份。
    pub tool_call_id: String,
    /// 原 call 序号。
    pub call_sequence: i64,
    /// 内部 attempt 身份。
    pub attempt_id: String,
    /// 原 attempt 序号。
    pub attempt_sequence: i64,
    /// 原尝试状态。
    pub status: RunReconciliationAttemptStatus,
    /// 原提交记录；null 绝不解释为未发送或未提交。
    pub recorded_commit_state: Option<RunReconciliationCommitState>,
    /// 原创建时间。
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// 原开始时间，未记录为 null。
    #[serde(with = "time::serde::rfc3339::option")]
    pub started_at: Option<OffsetDateTime>,
    /// 原结束时间，未记录为 null。
    #[serde(with = "time::serde::rfc3339::option")]
    pub finished_at: Option<OffsetDateTime>,
}

/// 一条受当前权限限制的数据库快照；不具有处置或继续 authority。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunReconciliationSnapshot {
    /// 受权 thread 身份。
    pub thread_id: ThreadId,
    /// 当前 actor 拥有的原 run 身份。
    pub run_id: RunId,
    /// 保持原 Unknown 终态。
    pub status: RunReconciliationStatus,
    /// 原 run 的 terminal 事件序号。
    pub terminal_event_sequence: u64,
    /// 当前 statement 的数据库时间。
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
    /// 当前 foreground 占用事实，不是可执行许可。
    pub foreground_blocked: bool,
    /// 本页最小尝试投影；空列表不证明没有外部效果。
    pub attempts: Vec<RunReconciliationAttempt>,
    /// 有下一页时的原 run 内位置。
    pub next: Option<RunReconciliationCursor>,
    /// 本批没有任何写、处置、继续或重试动作。
    pub available_actions: [(); 0],
}

/// 由第一方业务事务产生的正向事实，不是原 attempt 的结果改写。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunEffectReceiptFact {
    /// 原 remember 事务曾创建 memory；不表示 memory 目前仍 active。
    MemoryCreated,
}

/// 不含业务目标、正文、能力或绑定摘要的历史提交引用。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunEffectReceipt {
    /// 同事务产生的内部回执身份。
    pub receipt_id: String,
    /// 原 tool call 身份。
    pub tool_call_id: String,
    /// 原 call 序号。
    pub call_sequence: i64,
    /// 原 attempt 身份。
    pub attempt_id: String,
    /// 原 attempt 序号。
    pub attempt_sequence: i64,
    /// 受支持的正向业务事实。
    pub fact: RunEffectReceiptFact,
    /// PG 事务内记录时间，不是精确 commit 时间。
    #[serde(with = "time::serde::rfc3339")]
    pub recorded_at: OffsetDateTime,
}

/// 当前 owner 获准读取的正向回执页；空页不证明未提交。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunEffectReceiptsSnapshot {
    /// 受权 thread 身份。
    pub thread_id: ThreadId,
    /// 原 run 身份。
    pub run_id: RunId,
    /// 原 Unknown 终态保持不变。
    pub status: RunReconciliationStatus,
    /// 原 run 的 terminal 序号。
    pub terminal_event_sequence: u64,
    /// 本页数据库 statement 时间。
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
    /// 该 run 当前 foreground 占用事实。
    pub foreground_blocked: bool,
    /// 本页正向历史回执。
    pub receipts: Vec<RunEffectReceipt>,
    /// 有更多记录时，本页最后一项的原二元位置。
    pub next: Option<RunReconciliationCursor>,
    /// 没有写证据、处置、解锁或重放入口。
    pub available_actions: [(); 0],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positive_receipt_wire_is_closed_and_does_not_expose_business_bindings() {
        let snapshot = RunEffectReceiptsSnapshot {
            thread_id: ThreadId::new("thread"),
            run_id: RunId::new("run"),
            status: RunReconciliationStatus::ReconciliationRequired,
            terminal_event_sequence: 7,
            observed_at: OffsetDateTime::UNIX_EPOCH,
            foreground_blocked: true,
            receipts: vec![RunEffectReceipt {
                receipt_id: "00000000-0000-4000-8000-000000000075".into(),
                tool_call_id: "call".into(),
                call_sequence: 2,
                attempt_id: "attempt".into(),
                attempt_sequence: 1,
                fact: RunEffectReceiptFact::MemoryCreated,
                recorded_at: OffsetDateTime::UNIX_EPOCH,
            }],
            next: None,
            available_actions: [],
        };
        let value = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 9);
        assert_eq!(value["receipts"][0].as_object().unwrap().len(), 7);
        assert_eq!(value["receipts"][0]["fact"], "memory_created");
        assert_eq!(value["receipts"][0]["recordedAt"], "1970-01-01T00:00:00Z");
        assert_eq!(value["availableActions"], serde_json::json!([]));
        assert_eq!(
            serde_json::from_value::<RunEffectReceiptsSnapshot>(value.clone()).unwrap(),
            snapshot
        );
        for field in [
            "memoryId",
            "targetId",
            "argsHash",
            "capabilityId",
            "content",
        ] {
            let mut unknown = value.clone();
            unknown["receipts"][0][field] = serde_json::json!("forbidden");
            assert!(serde_json::from_value::<RunEffectReceiptsSnapshot>(unknown).is_err());
        }
        let mut unknown = value.clone();
        unknown["receipts"][0]["fact"] = serde_json::json!("not_committed");
        assert!(serde_json::from_value::<RunEffectReceiptsSnapshot>(unknown).is_err());
        let mut unknown = value;
        unknown["availableActions"] = serde_json::json!([null]);
        assert!(serde_json::from_value::<RunEffectReceiptsSnapshot>(unknown).is_err());
    }

    #[test]
    fn query_requires_complete_nonnegative_cursor_and_bounded_limit() {
        assert_eq!(
            RunReconciliationQuery::default().into_parts().unwrap(),
            (None, None)
        );
        for query in [
            RunReconciliationQuery {
                after_call_sequence: Some(0),
                ..Default::default()
            },
            RunReconciliationQuery {
                after_attempt_sequence: Some(0),
                ..Default::default()
            },
            RunReconciliationQuery {
                after_call_sequence: Some(-1),
                after_attempt_sequence: Some(0),
                limit: None,
            },
            RunReconciliationQuery {
                limit: Some(0),
                ..Default::default()
            },
            RunReconciliationQuery {
                limit: Some(101),
                ..Default::default()
            },
        ] {
            assert!(query.into_parts().is_err());
        }
        let query = RunReconciliationQuery {
            after_call_sequence: Some(i64::MAX),
            after_attempt_sequence: Some(i64::MAX),
            limit: Some(100),
        };
        assert!(query.into_parts().is_ok());
        assert!(serde_json::from_str::<RunReconciliationQuery>(r#"{"actor":"admin"}"#).is_err());
        assert!(
            serde_json::from_str::<RunReconciliationQuery>(r#"{"limit":1,"limit":2}"#).is_err()
        );
    }

    #[test]
    fn opaque_ids_are_bounded_without_inventing_uuid_semantics() {
        assert!(valid_reconciliation_id("legacy-run-1"));
        assert!(valid_reconciliation_id(&"a".repeat(512)));
        for id in [
            "".to_owned(),
            "a".repeat(513),
            "line\nbreak".to_owned(),
            "null\0byte".to_owned(),
        ] {
            assert!(!valid_reconciliation_id(&id));
        }
        assert!(!valid_reconciliation_id(&"界".repeat(171)));
    }

    #[test]
    fn null_commit_is_preserved_and_action_surface_is_empty() {
        let attempt = RunReconciliationAttempt {
            tool_call_id: "call".into(),
            call_sequence: 0,
            attempt_id: "attempt".into(),
            attempt_sequence: 0,
            status: RunReconciliationAttemptStatus::Executing,
            recorded_commit_state: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            started_at: None,
            finished_at: None,
        };
        let snapshot = RunReconciliationSnapshot {
            thread_id: ThreadId::new("thread"),
            run_id: RunId::new("run"),
            status: RunReconciliationStatus::ReconciliationRequired,
            terminal_event_sequence: 3,
            observed_at: OffsetDateTime::UNIX_EPOCH,
            foreground_blocked: true,
            attempts: vec![attempt],
            next: None,
            available_actions: [],
        };
        let value = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(
            value["attempts"][0]["recordedCommitState"],
            serde_json::Value::Null
        );
        assert_eq!(value["attempts"][0]["status"], "executing");
        assert_eq!(value["observedAt"], "1970-01-01T00:00:00Z");
        assert_eq!(value["availableActions"], serde_json::json!([]));
        let mut tampered = value;
        tampered["availableActions"] = serde_json::json!([null]);
        assert!(serde_json::from_value::<RunReconciliationSnapshot>(tampered).is_err());
    }
}
