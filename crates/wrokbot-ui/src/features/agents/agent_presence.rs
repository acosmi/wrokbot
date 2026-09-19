//! Compact, accessible agent activity state.

use leptos::prelude::*;

use crate::i18n::{t_string, use_i18n};

/// Closed runtime state projected by the 20px status ring.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AgentPresenceState {
    /// Available and not currently running.
    #[default]
    Idle,
    /// Reasoning or waiting for a tool/provider result.
    Thinking,
    /// Producing a user-visible reply.
    Speaking,
    /// Terminal or recoverable error state.
    Error,
}

impl AgentPresenceState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Thinking => "thinking",
            Self::Speaking => "speaking",
            Self::Error => "error",
        }
    }
}

/// Render one reactive status ring with localized accessible state text.
#[component]
pub fn AgentPresence(
    /// Runtime state; constants and signals are both accepted.
    #[prop(into)]
    state: Signal<AgentPresenceState>,
) -> impl IntoView {
    let i18n = use_i18n();
    view! {
        <span
            class="ob-agent-presence"
            role="img"
            data-state=move || state.get().as_str()
            aria-label=move || state_label(i18n, state.get())
        >
            <span class="ob-agent-presence-track" aria-hidden="true"></span>
            <span
                class="ob-agent-presence-arc"
                data-arc="primary"
                aria-hidden="true"
            ></span>
            <span
                class="ob-agent-presence-arc"
                data-arc="secondary"
                aria-hidden="true"
            ></span>
        </span>
    }
}

fn state_label(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    state: AgentPresenceState,
) -> String {
    match state {
        AgentPresenceState::Idle => t_string!(i18n, agents.presence_idle).to_owned(),
        AgentPresenceState::Thinking => t_string!(i18n, agents.presence_thinking).to_owned(),
        AgentPresenceState::Speaking => t_string!(i18n, agents.presence_speaking).to_owned(),
        AgentPresenceState::Error => t_string!(i18n, agents.presence_error).to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_and_motion_tokens_are_closed_and_exact() {
        assert_eq!(AgentPresenceState::Idle.as_str(), "idle");
        assert_eq!(AgentPresenceState::Thinking.as_str(), "thinking");
        assert_eq!(AgentPresenceState::Speaking.as_str(), "speaking");
        assert_eq!(AgentPresenceState::Error.as_str(), "error");
        assert_eq!(crate::tokens::MOTION_AGENT_PRESENCE_CYCLE, "1200ms");
        assert_eq!(crate::tokens::MOTION_AGENT_PRESENCE_ERROR, "160ms");
    }
}
