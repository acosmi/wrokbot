//! Typed ScreenSession request/ticket contracts (v4 §12.2–§12.4).

use core::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize as _;

use crate::ids::{ComputerGeneration, ComputerId, TabId};

/// Exact live screen identity requested by a transport.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScreenSessionTarget {
    /// Authority-minted computer identity.
    pub computer_id: ComputerId,
    /// Exact computer generation; stale generations are not visible.
    pub computer_generation: ComputerGeneration,
    /// Exact active tab/render-session identity.
    pub tab_id: TabId,
}

/// Host binding already derived by a trusted Rust transport boundary.
///
/// These values never grant screen visibility by themselves. The Computer port additionally
/// resolves the exact target under `AuthContext`; Server and Desktop must construct this value from
/// verified request/window state rather than accepting it in a request body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "host", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScreenViewerBindingRequest {
    /// Same-origin Server browser connection.
    Server {
        /// Exact trusted `Origin` header.
        origin: String,
    },
    /// Desktop loopback connection bound to one native window generation.
    Desktop {
        /// Exact trusted Tauri origin.
        origin: String,
        /// Rust-resolved native window label.
        window_label: String,
        /// Non-zero host binding generation.
        window_binding: u64,
    },
}

/// Application command payload assembled only after host authentication/origin verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScreenSessionRequest {
    /// Requested live target.
    pub target: ScreenSessionTarget,
    /// Trusted host binding, never copied from the JSON body by Server.
    pub binding: ScreenViewerBindingRequest,
}

/// One-time screen ticket returned to the already authenticated viewer.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScreenSessionTicket {
    base_protocol: String,
    ticket_protocol: String,
    expires_at_ms: i64,
}

impl ScreenSessionTicket {
    /// Construct a ticket from the Computer authority implementation.
    #[must_use]
    pub fn new(
        base_protocol: impl Into<String>,
        ticket_protocol: impl Into<String>,
        expires_at_ms: i64,
    ) -> Self {
        Self {
            base_protocol: base_protocol.into(),
            ticket_protocol: ticket_protocol.into(),
            expires_at_ms,
        }
    }

    /// Non-secret WebSocket protocol that the upgrade response must select.
    #[must_use]
    pub fn base_protocol(&self) -> &str {
        self.base_protocol.as_str()
    }

    /// Secret requested protocol. It must not enter URL/query/log or the upgrade response.
    #[must_use]
    pub fn ticket_protocol(&self) -> &str {
        self.ticket_protocol.as_str()
    }

    /// Ticket expiry as Unix milliseconds.
    #[must_use]
    pub const fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }
}

impl fmt::Debug for ScreenSessionTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScreenSessionTicket")
            .field("base_protocol", &self.base_protocol)
            .field("ticket_protocol", &"[REDACTED]")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

impl Drop for ScreenSessionTicket {
    fn drop(&mut self) {
        self.ticket_protocol.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_wire_contains_secret_but_debug_never_does() {
        let ticket = ScreenSessionTicket::new(
            "openbot.screen.v1",
            "obot_screen_00112233445566778899aabbccddeeff",
            1_788_499_230_000,
        );
        let wire = serde_json::to_string(&ticket).expect("ticket wire");
        assert!(wire.contains("obot_screen_00112233445566778899aabbccddeeff"));
        let debug = format!("{ticket:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("00112233445566778899aabbccddeeff"));
    }
}
