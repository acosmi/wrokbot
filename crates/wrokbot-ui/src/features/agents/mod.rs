//! Agent-facing business projections.

/// Authenticated-shell invalidation after confirmed directory mutations, without polling.
#[derive(Clone, Copy)]
pub(crate) struct AgentDirectoryGeneration(pub leptos::prelude::RwSignal<u64>);

pub mod agent_card;
pub mod agent_editor;
pub mod agent_presence;
pub mod agent_profile;
pub mod callback_token_panel;
pub mod roster;

pub use agent_card::AgentCard;
pub use agent_editor::AgentEditor;
pub use agent_presence::{AgentPresence, AgentPresenceState};
pub use agent_profile::AgentProfilePanel;
pub use callback_token_panel::CallbackTokenPanel;
pub use roster::AgentsPage;
