//! Shared conversation presentation; intent freezing and requests stay with their existing owners.
use leptos::prelude::*;
use openbot_contracts::agent::AgentProfile;

use crate::{
    i18n::{t, t_string, use_i18n},
    icons::Icon,
    primitives::{Avatar, AvatarSize, IconSize, IconView},
};

/// Only an authorized, actually selected assistant receives an identity avatar.
#[component]
pub(crate) fn AssistantIdentity(
    profile: Signal<Option<AgentProfile>>,
    #[prop(into)] title: TextProp,
    #[prop(optional, into)] description: TextProp,
    #[prop(optional, into)] compact: MaybeProp<bool>,
) -> impl IntoView {
    let visible_title = title.clone();
    view! {
        <header class="ob-assistant-identity" data-size=move || if compact.get().unwrap_or(false) { "active" } else { "empty" }>
            <div class="ob-assistant-identity-avatar" aria-hidden="true">
                {move || profile.get().map_or_else(
                    || view! { <IconView icon=Icon::Brain size=IconSize::Navigation /> }.into_any(),
                    |agent| view! { <Avatar principal_id=agent.avatar_seed name=agent.name size=AvatarSize::Large /> }.into_any(),
                )}
            </div>
            <div class="ob-assistant-identity-copy">
                <h1>{move || profile.get().map_or_else(|| visible_title.get(), |agent| agent.name.into())}</h1>
                <p>{move || if compact.get().unwrap_or(false) { description.get() } else { profile.get().map_or_else(|| description.get(), |agent| agent.role_description.into()) }}</p>
            </div>
        </header>
    }
}

/// One visual composer frame used by all four existing submission surfaces.
#[component]
pub(crate) fn ComposerFrame(
    #[prop(into)] busy: Signal<bool>,
    #[prop(optional)] active: bool,
    children: Children,
) -> impl IntoView {
    view! {
        <div class="ob-chat-composer" data-kind=if active { "active" } else { "new" } aria-busy=move || busy.get().to_string()>
            {children()}
        </div>
    }
}

/// Suggestions only replace the local task draft through the caller's existing draft owner.
#[component]
pub(crate) fn DraftSuggestions(
    on_choose: UnsyncCallback<String>,
    disabled: Signal<bool>,
) -> impl IntoView {
    let i18n = use_i18n();
    view! {
        <div class="ob-draft-suggestions" aria-label=move || t_string!(i18n, home.suggestions_label).to_owned()>
            <button type="button" disabled=move || disabled.get() on:click=move |_| on_choose.run(t_string!(i18n, home.suggestion_examine).to_owned())>{move || t!(i18n, home.suggestion_examine)}</button>
            <button type="button" disabled=move || disabled.get() on:click=move |_| on_choose.run(t_string!(i18n, home.suggestion_plan).to_owned())>{move || t!(i18n, home.suggestion_plan)}</button>
            <button type="button" disabled=move || disabled.get() on:click=move |_| on_choose.run(t_string!(i18n, home.suggestion_review).to_owned())>{move || t!(i18n, home.suggestion_review)}</button>
        </div>
    }
}
