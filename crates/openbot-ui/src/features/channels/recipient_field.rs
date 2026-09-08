//! One URL-owned single-recipient field backed by the shared Combobox primitive.

use core::fmt::Write as _;

use leptos::prelude::*;
use openbot_contracts::agent::AgentProfile;
use sha2::{Digest, Sha256};

use crate::primitives::{
    Avatar, AvatarSize, Combobox, ComboboxContent, ComboboxEmpty, ComboboxInput, ComboboxItem,
    ComboboxList,
};

/// Select exactly one Server-authorized Agent identity.
#[component]
pub fn RecipientField(
    /// Current Server-authorized choices; a URL-selected hidden Agent may be appended by the owner.
    agents: Signal<Vec<AgentProfile>>,
    /// URL-owned selected Agent identity.
    selected: RwSignal<Option<String>>,
    /// Accessible input name.
    #[prop(into)]
    aria_label: TextProp,
    /// Empty input hint.
    #[prop(into)]
    placeholder: TextProp,
    /// Feedback when filtering leaves no candidates.
    #[prop(into)]
    empty_label: TextProp,
    /// Locks recipient changes while create/begin is in flight or being replayed.
    #[prop(optional, into)]
    disabled: MaybeProp<bool>,
    /// Owner callback that commits the selection to the URL.
    on_select: UnsyncCallback<Option<String>>,
) -> impl IntoView {
    let open = RwSignal::new(false);
    view! {
        <div class="ob-recipient-field">
            <Combobox
                id="channel-new-recipient".to_owned()
                open
                value=selected
                disabled
                on_value_change=on_select
            >
                <ComboboxInput aria_label placeholder />
                <ComboboxContent>
                    <ComboboxEmpty>{move || empty_label.get()}</ComboboxEmpty>
                    <ComboboxList>
                        <For
                            each=move || agents.get()
                            key=|agent| agent.id.clone()
                            children=move |agent| {
                                let option_id = recipient_option_id(agent.id.as_str());
                                let value = agent.id.as_str().to_owned();
                                let label = agent.name.clone();
                                let avatar_seed = agent.avatar_seed.clone();
                                let avatar_name = agent.name.clone();
                                let name = agent.name;
                                let role = agent.role_description;
                                view! {
                                    <ComboboxItem id=option_id value label=label.clone()>
                                        <span class="ob-recipient-option-avatar" aria-hidden="true">
                                            <Avatar
                                                principal_id=avatar_seed
                                                name=avatar_name
                                                size=AvatarSize::Small
                                            />
                                        </span>
                                        <span class="ob-recipient-option-copy">
                                            <span>{name}</span>
                                            <small>{role}</small>
                                        </span>
                                    </ComboboxItem>
                                }
                            }
                        />
                    </ComboboxList>
                </ComboboxContent>
            </Combobox>
        </div>
    }
}

fn recipient_option_id(agent_id: &str) -> String {
    let mut id = String::from("recipient-option-");
    for byte in Sha256::digest(agent_id.as_bytes()) {
        write!(&mut id, "{byte:02x}").expect("writing to String cannot fail");
    }
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipient_option_identity_is_stable_bounded_and_selector_safe() {
        let id = recipient_option_id("agent/one?x=1");
        assert_eq!(id, recipient_option_id("agent/one?x=1"));
        assert_ne!(id, recipient_option_id("agent-two"));
        assert!(id.len() <= 128);
        assert!(
            id.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        );
    }
}
