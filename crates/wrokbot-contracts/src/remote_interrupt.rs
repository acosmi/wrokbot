//! Actor-scoped remote AG-UI interrupt presentation and answer wire.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Validate the canonical lowercase UUIDv7 handle minted by the Rust server.
#[must_use]
pub fn is_remote_interrupt_request_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| bytes[index] == b'-')
        && bytes[14] == b'7'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        && bytes.iter().enumerate().all(|(index, byte)| {
            [8, 13, 18, 23].contains(&index)
                || byte.is_ascii_digit()
                || (b'a'..=b'f').contains(byte)
        })
}

/// Closed human answer status accepted by the Rust authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteInterruptAnswerStatus {
    /// Supply an optional JSON payload to the next remote invocation.
    Resolved,
    /// Explicitly decline the interrupt; payload must be absent.
    Cancelled,
}

/// Untrusted answer body. Actor, run, Bot and remote pairing ids are not accepted here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoteInterruptAnswer {
    /// Closed resolution status.
    pub status: RemoteInterruptAnswerStatus,
    /// Optional bounded JSON value; cancelled answers cannot carry it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

/// One server-authorized pending remote interrupt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingRemoteInterrupt {
    /// Server-minted opaque handle used for the answer route.
    pub request_id: String,
    /// Authoritative durable run shown for correlation only.
    pub run_id: String,
    /// Authoritative Bot shown for correlation only.
    pub agent_id: String,
    /// Remote categorical reason, explicitly untrusted.
    pub untrusted_reason: String,
    /// Optional remote presentation message, explicitly untrusted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub untrusted_message: Option<String>,
    /// Optional remote response schema, explicitly untrusted and never executable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub untrusted_response_schema: Option<Value>,
    /// Database request time as JavaScript-safe Unix milliseconds.
    pub requested_at_ms: i64,
    /// Local authoritative expiry as JavaScript-safe Unix milliseconds.
    pub expires_at_ms: i64,
}

/// Current actor's bounded pending interrupt list.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingRemoteInterrupts {
    /// Ordered pending rows; empty is a successful result.
    pub interrupts: Vec<PendingRemoteInterrupt>,
}

/// Durable answer acknowledgement returned after its hash-chain audit commits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoteInterruptResolved {
    /// Server-minted opaque handle.
    pub request_id: String,
    /// Closed committed status.
    pub status: RemoteInterruptAnswerStatus,
    /// True only for an exact idempotent replay.
    pub replayed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answer_and_pending_wire_are_closed_and_mark_remote_content_untrusted() {
        let answer: RemoteInterruptAnswer = serde_json::from_value(serde_json::json!({
            "status":"resolved",
            "payload":{"choice":"yes"}
        }))
        .unwrap();
        assert_eq!(answer.status, RemoteInterruptAnswerStatus::Resolved);
        assert!(
            serde_json::from_value::<RemoteInterruptAnswer>(serde_json::json!({
                "status":"resolved","actorId":"forged"
            }))
            .is_err()
        );

        let pending = PendingRemoteInterrupt {
            request_id: "request-1".to_owned(),
            run_id: "run-1".to_owned(),
            agent_id: "bot-1".to_owned(),
            untrusted_reason: "human_input".to_owned(),
            untrusted_message: Some("Choose".to_owned()),
            untrusted_response_schema: Some(serde_json::json!({"type":"string"})),
            requested_at_ms: 1,
            expires_at_ms: 2,
        };
        let wire = serde_json::to_value(pending).unwrap();
        assert!(wire.get("untrustedReason").is_some());
        assert!(wire.get("reason").is_none());
        assert!(wire.get("interruptId").is_none());
        assert!(is_remote_interrupt_request_id(
            "018f6f8a-5f4b-7c2d-8a31-111111111111"
        ));
        assert!(!is_remote_interrupt_request_id(
            "018F6F8A-5F4B-7C2D-8A31-111111111111"
        ));
    }
}
