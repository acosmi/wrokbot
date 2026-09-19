//! Durable approval projection and the interactive Leptos page.
//!
//! The component consumes only the closed current-actor DTO and posts only a decision plus the
//! Server-minted id. It cannot mint or modify actor, Bot, run, target, effect, arguments, policy,
//! catalog generation or expiry bindings.

use core::fmt;

use openbot_contracts::tool::{PendingToolApproval, ToolApprovalClass, ToolApprovalEffect};

use crate::features::threads::tool_name::read_tool_name;

mod component;

pub use component::ApprovalPage;

/// Authority-only view model for one approval card.
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovalCardView {
    /// Durable approval id used by the typed decision command.
    pub approval_id: String,
    /// Humanized catalog tool name.
    pub tool_title: String,
    /// Optional server label for MCP/Drive tools.
    pub server: Option<String>,
    /// First-party effect; the component localizes this enum.
    pub effect: ToolApprovalEffect,
    /// First-party target kind.
    pub target_kind: String,
    /// First-party target id.
    pub target_id: String,
    /// Pretty, already-redacted bounded arguments.
    pub arguments: String,
    /// Optional first-party diff/change summary.
    pub change: Option<String>,
    /// Reuse class shown in details.
    pub approval_class: ToolApprovalClass,
    /// Inclusive expiry for the visible countdown.
    pub expires_at: time::OffsetDateTime,
}

impl ApprovalCardView {
    /// Project a server-authored pending DTO. No model reason/narrative field exists in either type.
    #[must_use]
    pub fn from_pending(pending: &PendingToolApproval) -> Self {
        let display = read_tool_name(&pending.tool_name);
        Self {
            approval_id: pending.approval_id.clone(),
            tool_title: display.label,
            server: display.detail,
            effect: pending.effect,
            target_kind: pending.target_kind.clone(),
            target_id: pending.target_id.clone(),
            arguments: pretty(&pending.arguments_summary),
            change: pending.change_summary.as_ref().map(pretty),
            approval_class: pending.approval_class,
            expires_at: pending.expires_at,
        }
    }
}

impl fmt::Debug for ApprovalCardView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalCardView")
            .field("approval_id", &self.approval_id)
            .field("tool_title", &self.tool_title)
            .field("server", &self.server)
            .field("effect", &self.effect)
            .field("target_kind", &self.target_kind)
            .field("target_id", &self.target_id)
            .field("arguments", &"<redacted>")
            .field("change", &self.change.is_some())
            .field("approval_class", &self.approval_class)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

fn pretty(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| "null".to_owned())
}

#[cfg(test)]
mod tests {
    use openbot_contracts::ids::{BotId, RunId, ToolCallId};
    use openbot_contracts::tool::PendingToolApproval;
    use time::{Duration, OffsetDateTime};

    use super::*;

    #[test]
    fn card_uses_authoritative_effect_target_and_redacted_summary_not_model_prose() {
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
            arguments_summary: serde_json::json!({"id":"note-1","token":"[redacted]"}),
            change_summary: Some(serde_json::json!({"kind":"delete","count":1})),
            requested_at: OffsetDateTime::UNIX_EPOCH,
            expires_at: OffsetDateTime::UNIX_EPOCH + Duration::minutes(5),
        };
        let card = ApprovalCardView::from_pending(&pending);
        assert_eq!(card.tool_title, "Delete note");
        assert_eq!(card.server.as_deref(), Some("notes"));
        assert_eq!(card.effect, ToolApprovalEffect::Write);
        assert_eq!(card.target_id, "notes/delete_note");
        assert!(card.arguments.contains("[redacted]"));
        assert!(card.change.as_ref().unwrap().contains("delete"));
        assert!(!format!("{card:?}").contains("note-1"));
    }
}
