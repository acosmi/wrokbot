//! List-row primitive with closed link/button semantics.

use leptos::ev::KeyboardEvent;
use leptos::prelude::*;

use crate::icons::Icon;

use super::{IconSize, IconView};

/// An Item is either internal navigation or an action button; no free tag name is accepted.
pub enum ItemAction {
    /// Link destination.
    Link(String),
    /// Button callback.
    Button(UnsyncCallback<()>),
}

/// Structured list row. Compose content with ItemMedia/Title/Description/Actions.
#[component]
pub fn Item(
    action: ItemAction,
    #[prop(optional, into)] selected: MaybeProp<bool>,
    #[prop(optional, into)] disabled: MaybeProp<bool>,
    /// Force hover treatment in the compile-time design gallery.
    #[prop(optional)]
    preview_hover: bool,
    children: Children,
) -> AnyView {
    let content = children();
    let state = move || {
        item_state_tokens(
            preview_hover,
            selected.get().unwrap_or(false),
            disabled.get().unwrap_or(false),
        )
    };
    match action {
        ItemAction::Link(href) => {
            assert_internal_href(&href);
            view! {
            <a
                class="ob-item"
                href=href
                data-state=state
                aria-disabled=move || if disabled.get().unwrap_or(false) { "true" } else { "false" }
                tabindex=move || disabled.get().unwrap_or(false).then_some(-1)
                on:click=move |event| {
                    if disabled.get().unwrap_or(false) {
                        event.prevent_default();
                    }
                }
            >
                {content}
                <ItemSelection selected=selected />
            </a>
        }
        .into_any()
        }
        ItemAction::Button(on_activate) => view! {
            <button
                type="button"
                class="ob-item"
                data-state=state
                disabled=move || disabled.get().unwrap_or(false)
                on:click=move |event| {
                    if !disabled.get().unwrap_or(false) {
                        let _ = event;
                        on_activate.run(());
                    }
                }
                on:keydown=move |event: KeyboardEvent| {
                    if matches!(event.key().as_str(), "Enter" | " ")
                        && !disabled.get().unwrap_or(false)
                    {
                        event.prevent_default();
                        on_activate.run(());
                    }
                }
            >
                {content}
                <ItemSelection selected=selected />
            </button>
        }
        .into_any(),
    }
}

#[component]
fn ItemSelection(#[prop(into)] selected: MaybeProp<bool>) -> impl IntoView {
    view! {
        <Show when=move || selected.get().unwrap_or(false)>
            <span class="ob-item-selection" aria-hidden="true">
                <IconView icon=Icon::Check size=IconSize::Inline />
            </span>
        </Show>
    }
}

#[component]
pub fn ItemMedia(children: Children) -> impl IntoView {
    view! { <span class="ob-item-media">{children()}</span> }
}

#[component]
pub fn ItemTitle(children: Children) -> impl IntoView {
    view! { <span class="ob-item-title">{children()}</span> }
}

#[component]
pub fn ItemDescription(children: Children) -> impl IntoView {
    view! { <span class="ob-item-description">{children()}</span> }
}

#[component]
pub fn ItemActions(children: Children) -> impl IntoView {
    view! { <span class="ob-item-actions">{children()}</span> }
}

fn assert_internal_href(href: &str) {
    assert!(
        href.starts_with('/')
            && !href.starts_with("//")
            && href.len() <= 2048
            && !href
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b'\\'),
        "Item link must be one bounded same-origin absolute path"
    );
}

fn item_state_tokens(hover: bool, selected: bool, disabled: bool) -> Option<String> {
    let mut states = Vec::with_capacity(3);
    if hover {
        states.push("hover");
    }
    if selected {
        states.push("selected");
    }
    if disabled {
        states.push("disabled");
    }
    (!states.is_empty()).then(|| states.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_states_do_not_invent_a_third_action_shape() {
        assert_eq!(item_state_tokens(false, false, false), None);
        assert_eq!(
            item_state_tokens(true, true, true),
            Some("hover selected disabled".to_owned())
        );
        assert_internal_href("/settings?tab=general#theme");
    }

    #[test]
    #[should_panic(expected = "same-origin")]
    fn item_rejects_external_or_scheme_relative_links() {
        assert_internal_href("//attacker.example/path");
    }
}
