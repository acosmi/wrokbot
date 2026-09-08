//! Tool invocation 的跨 transport DTO；授权结论、metadata 与 capability 不在这里。

use core::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::ids::{BotId, RunId, ToolCallId};

/// Maximum actor-visible pending approval rows in one authoritative projection.
pub const MAX_PENDING_TOOL_APPROVALS: u32 = 100;

/// Agent 交给唯一 application 入口的一次工具调用。
///
/// `call_id` / `call_seq` 由 Rust Agent gateway 铸造；`run_id` / `bot_id` 仍须由 application
/// 的权威 scope resolver 复核。参数只是一份不可信 JSON 对象，不能携带 actor、policy、effect、
/// approval 或 target；这些字段刻意不存在，renderer/model 因而没有自报它们的入口。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolInvocation {
    /// Rust 铸造的本次调用 ID。
    pub call_id: ToolCallId,
    /// 声称所属 run；application 必须与权威 scope 逐字比对。
    pub run_id: RunId,
    /// 声称代表的 Bot；application 必须与权威 scope 逐字比对。
    pub bot_id: BotId,
    /// run 内严格递增的调用序号；由 Rust Agent gateway 铸造。
    pub call_seq: u64,
    /// catalog key。application 只拿它查权威 metadata，不采信任何外部 effect 声明。
    pub tool_name: String,
    /// 不可信参数；application 会要求顶层为 object 并走 schema/size/canonical hash。
    pub arguments: Value,
}

impl fmt::Debug for ToolInvocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolInvocation")
            .field("call_id", &self.call_id)
            .field("run_id", &self.run_id)
            .field("bot_id", &self.bot_id)
            .field("call_seq", &self.call_seq)
            .field("tool_name", &self.tool_name)
            .field("arguments", &"<redacted>")
            .finish()
    }
}

/// 已持久化 outcome 的线上提交状态。`unknown` 不可能成为成功 reply，而是 AppError 的
/// reconciliation 分支。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCommitState {
    /// 副作用已提交。
    Committed,
    /// 确知未提交。
    NotCommitted,
}

/// 给 Agent/model 的脱敏工具结果。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolResult {
    /// 对应调用。
    pub call_id: ToolCallId,
    /// 已经过 control plane 脱敏、再由 application 按 metadata 上限裁剪的 UTF-8 文本。
    pub content: String,
    /// 稳定错误码；`None` 表示工具成功。
    pub error_code: Option<String>,
    /// outcome 的确定提交状态。
    pub commit_state: ToolCommitState,
    /// 实际交给模型的 UTF-8 字节数。
    pub visible_bytes: u32,
    /// 完整脱敏输出是否更长。
    pub truncated: bool,
}

impl fmt::Debug for ToolResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolResult")
            .field("call_id", &self.call_id)
            .field("content", &"<redacted>")
            .field("error_code", &self.error_code)
            .field("commit_state", &self.commit_state)
            .field("visible_bytes", &self.visible_bytes)
            .field("truncated", &self.truncated)
            .finish()
    }
}

/// First-party acting effect shown by the approval UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolApprovalEffect {
    /// Mutates vendor/local state.
    Write,
    /// Executes a command/action.
    Execute,
    /// Opens an acting network effect.
    Network,
    /// Uses or changes a credential boundary.
    Credential,
}

/// Approval reuse class copied from authoritative tool metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolApprovalClass {
    /// Exact binding may be reused within this run.
    OncePerRun,
    /// Every distinct call requires a decision.
    EveryCall,
}

/// One pending approval visible only to its authoritative actor.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingToolApproval {
    /// Server-minted approval id.
    pub approval_id: String,
    /// Rust-minted tool call id.
    pub call_id: ToolCallId,
    /// Bound run.
    pub run_id: RunId,
    /// Bound Bot.
    pub bot_id: BotId,
    /// Human-readable/model catalog tool key.
    pub tool_name: String,
    /// First-party target kind.
    pub target_kind: String,
    /// First-party target id.
    pub target_id: String,
    /// First-party acting effect.
    pub effect: ToolApprovalEffect,
    /// Reuse class.
    pub approval_class: ToolApprovalClass,
    /// Redacted bounded argument summary. Secret-shaped fields are placeholders.
    pub arguments_summary: Value,
    /// Optional first-party change/diff summary.
    pub change_summary: Option<Value>,
    /// Database request time.
    pub requested_at: OffsetDateTime,
    /// Inclusive expiry boundary.
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for PendingToolApproval {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingToolApproval")
            .field("approval_id", &self.approval_id)
            .field("call_id", &self.call_id)
            .field("run_id", &self.run_id)
            .field("bot_id", &self.bot_id)
            .field("tool_name", &self.tool_name)
            .field("target_kind", &self.target_kind)
            .field("target_id", &self.target_id)
            .field("effect", &self.effect)
            .field("approval_class", &self.approval_class)
            .field("arguments_summary", &"<redacted>")
            .field("change_summary", &self.change_summary.is_some())
            .field("requested_at", &self.requested_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Pending approval page for the current actor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingToolApprovals {
    /// Oldest first; bounded by [`MAX_PENDING_TOOL_APPROVALS`].
    pub approvals: Vec<PendingToolApproval>,
}

/// Actor-scoped realtime hint that pending durable approval state changed.
///
/// It deliberately carries no approval id, tool name, target or argument summary. Consumers must
/// refetch [`PendingToolApprovals`] through the authoritative typed GET; the socket is not a second
/// state store and has no replay cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolApprovalActivityEvent {
    /// Current actor-visible pending count, bounded by [`MAX_PENDING_TOOL_APPROVALS`].
    pub pending_count: u32,
}

/// Human decision input. There is no caller-supplied binding or role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolApprovalDecision {
    /// Grant this exact stored binding.
    Grant,
    /// Deny it.
    Deny,
}

/// Successful durable resolution acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolApprovalResolved {
    /// Resolved approval id.
    pub approval_id: String,
    /// Exact committed human decision.
    pub decision: ToolApprovalDecision,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn invocation_wire_is_closed_and_debug_redacts_arguments() {
        let invocation = ToolInvocation {
            call_id: ToolCallId::new("call-1"),
            run_id: RunId::new("run-1"),
            bot_id: BotId::new("bot-1"),
            call_seq: 3,
            tool_name: "computer.click".to_owned(),
            arguments: json!({"secret":"SENTINEL-DO-NOT-LOG"}),
        };
        let rendered = format!("{invocation:?}");
        assert!(!rendered.contains("SENTINEL-DO-NOT-LOG"));
        assert!(rendered.contains("<redacted>"));

        let wire = serde_json::to_string(&invocation).unwrap();
        assert!(wire.contains(r#""callId":"call-1""#));
        assert!(wire.contains(r#""arguments":{"secret":"SENTINEL-DO-NOT-LOG"}"#));
        assert_eq!(
            serde_json::from_str::<ToolInvocation>(&wire).unwrap(),
            invocation
        );
        assert!(
            serde_json::from_str::<ToolInvocation>(
                r#"{"callId":"c","runId":"r","botId":"b","callSeq":0,"toolName":"t","arguments":{},"actor":"admin"}"#,
            )
            .is_err(),
            "外部自报 actor 必须被 deny_unknown_fields 拒绝",
        );
    }

    #[test]
    fn tool_result_debug_never_prints_model_visible_content() {
        let result = ToolResult {
            call_id: ToolCallId::new("call-1"),
            content: "SENTINEL-MODEL-OUTPUT".to_owned(),
            error_code: None,
            commit_state: ToolCommitState::Committed,
            visible_bytes: 21,
            truncated: false,
        };
        let rendered = format!("{result:?}");
        assert!(!rendered.contains("SENTINEL-MODEL-OUTPUT"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn pending_approval_wire_is_closed_and_debug_redacts_the_summary() {
        let pending = PendingToolApproval {
            approval_id: "approval-1".to_owned(),
            call_id: ToolCallId::new("call-1"),
            run_id: RunId::new("run-1"),
            bot_id: BotId::new("bot-1"),
            tool_name: "mcp__notes__delete_note".to_owned(),
            target_kind: "mcp_tool".to_owned(),
            target_id: "notes/delete_note".to_owned(),
            effect: ToolApprovalEffect::Write,
            approval_class: ToolApprovalClass::EveryCall,
            arguments_summary: serde_json::json!({"title":"SENTINEL-PRIVATE"}),
            change_summary: None,
            requested_at: OffsetDateTime::UNIX_EPOCH,
            expires_at: OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(5),
        };
        assert!(!format!("{pending:?}").contains("SENTINEL-PRIVATE"));
        let wire = serde_json::to_value(&pending).unwrap();
        assert_eq!(wire["effect"], "write");
        assert_eq!(wire["approvalClass"], "every_call");
        assert!(
            serde_json::from_value::<PendingToolApproval>(serde_json::json!({
                "approvalId":"a","callId":"c","runId":"r","botId":"b","toolName":"t",
                "targetKind":"mcp_tool","targetId":"x","effect":"write",
                "approvalClass":"every_call","argumentsSummary":{},"changeSummary":null,
                "requestedAt":"1970-01-01T00:00:00Z","expiresAt":"1970-01-01T00:05:00Z",
                "actor":"admin"
            }))
            .is_err()
        );
    }
}
