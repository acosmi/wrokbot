//! Select-only combobox backed by the shared listbox engine.

use leptos::ev::KeyboardEvent;
use leptos::prelude::*;

use crate::icons::Icon;

use super::listbox::{
    ListboxKind, ListboxRootOptions, described_by, handle_select_key, listbox_id, listbox_option,
    listbox_popup, listbox_root, owner_id, owner_state, toggle_current, trigger_ref,
    use_listbox_context,
};
use super::{IconSize, IconView};

/// Select-only single-value combobox root.
#[component]
pub fn Select(
    #[prop(into)] id: String,
    open: RwSignal<bool>,
    value: RwSignal<Option<String>>,
    #[prop(optional, into)] disabled: MaybeProp<bool>,
    #[prop(optional, into)] invalid: MaybeProp<bool>,
    #[prop(optional)] preview_focus: bool,
    #[prop(optional)] on_value_change: Option<UnsyncCallback<Option<String>>>,
    children: Children,
) -> impl IntoView {
    listbox_root(
        ListboxRootOptions {
            kind: ListboxKind::SelectOnly,
            id,
            open,
            value,
            disabled,
            invalid,
            preview_focus,
            on_value_change,
        },
        children,
    )
}

/// Button-like combobox owner; DOM focus stays here while AX focus uses active-descendant.
#[component]
pub fn SelectTrigger(
    #[prop(into)] aria_label: TextProp,
    #[prop(into)] placeholder: TextProp,
) -> impl IntoView {
    let context = use_listbox_context();
    assert!(
        !aria_label.get().is_empty(),
        "SelectTrigger label must be nonempty"
    );
    let label_context = context.clone();
    let owner_label = aria_label.clone();
    Effect::new(move |_| label_context.owner_label.set(owner_label.get().to_string()));
    let trigger_id = owner_id(&context);
    let popup_id = listbox_id(&context);
    let click_context = context.clone();
    let key_context = context.clone();
    let state_context = context.clone();
    let expanded_context = context.clone();
    let active_context = context.clone();
    let invalid_context = context.clone();
    let disabled_context = context.clone();
    let native_disabled_context = context.clone();
    let described_context = context.clone();
    let placeholder_context = context.clone();
    let value_context = context.clone();
    let trigger_node = trigger_ref(&context);
    view! {
        <button
            id=trigger_id
            type="button"
            class="ob-select-trigger"
            role="combobox"
            data-state=move || owner_state(&state_context)
            aria-label=move || aria_label.get()
            aria-haspopup="listbox"
            aria-expanded=move || explicit_bool(expanded_context.open.get())
            aria-controls=popup_id
            aria-activedescendant=move || active_context.open.get().then(|| active_context.active_id.get()).flatten()
            aria-invalid=move || explicit_bool(invalid_context.invalid.get())
            aria-disabled=move || explicit_bool(disabled_context.disabled.get())
            aria-describedby=move || described_by(&described_context)
            disabled=move || native_disabled_context.disabled.get()
            node_ref=trigger_node
            on:click=move |_| {
                if !click_context.disabled.get_untracked() {
                    toggle_current(click_context.clone());
                }
            }
            on:keydown=move |event: KeyboardEvent| {
                handle_select_key(event, key_context.clone());
            }
        >
            <span
                class="ob-select-value"
                data-placeholder=move || explicit_bool(placeholder_context.committed_label.get().is_none())
            >
                {move || value_context.committed_label.get().unwrap_or_else(|| placeholder.get().to_string())}
            </span>
            <span class="ob-select-icon" aria-hidden="true">
                <IconView icon=Icon::ChevronsUpDown size=IconSize::Inline />
            </span>
        </button>
    }
}

/// Popup/listbox surface.
#[component]
pub fn SelectContent(children: Children) -> impl IntoView {
    listbox_popup(children)
}

/// Semantic option group.
#[component]
pub fn SelectGroup(children: Children) -> impl IntoView {
    view! { <div class="ob-select-group" role="group">{children()}</div> }
}

/// Optional visual group label.
#[component]
pub fn SelectLabel(children: Children) -> impl IntoView {
    view! { <div class="ob-select-label">{children()}</div> }
}

/// One select option.
#[component]
pub fn SelectItem(
    #[prop(into)] id: String,
    #[prop(into)] value: String,
    #[prop(into)] label: TextProp,
    #[prop(optional, into)] disabled: MaybeProp<bool>,
    children: Children,
) -> impl IntoView {
    listbox_option(id, value, label, disabled, children)
}

/// Decorative separator between groups.
#[component]
pub fn SelectSeparator() -> impl IntoView {
    view! { <div class="ob-listbox-separator" role="separator"></div> }
}

const fn explicit_bool(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}
