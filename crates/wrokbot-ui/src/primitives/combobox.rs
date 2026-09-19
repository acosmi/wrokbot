//! Editable, single-value Combobox backed by the shared listbox engine.

use leptos::ev::KeyboardEvent;
use leptos::prelude::*;

use crate::icons::Icon;

use super::listbox::{
    ListboxKind, ListboxRootOptions, described_by, handle_editable_input, handle_editable_key,
    input_ref, listbox_id, listbox_option, listbox_popup, listbox_root, open_current, owner_id,
    owner_state, use_listbox_context,
};
use super::{IconSize, IconView};

/// Editable single-value combobox root.
#[component]
pub fn Combobox(
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
            kind: ListboxKind::Editable,
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

/// Native text input that filters the associated listbox without intercepting editing keys.
#[component]
pub fn ComboboxInput(
    #[prop(into)] aria_label: TextProp,
    #[prop(optional, into)] placeholder: TextProp,
) -> impl IntoView {
    let context = use_listbox_context();
    assert!(
        !aria_label.get().is_empty(),
        "ComboboxInput label must be nonempty"
    );
    let label_context = context.clone();
    let owner_label = aria_label.clone();
    Effect::new(move |_| label_context.owner_label.set(owner_label.get().to_string()));
    let input_id = owner_id(&context);
    let popup_id = listbox_id(&context);
    let input_context = context.clone();
    let key_context = context.clone();
    let click_context = context.clone();
    let value_context = context.clone();
    let state_context = context.clone();
    let expanded_context = context.clone();
    let active_context = context.clone();
    let invalid_context = context.clone();
    let disabled_context = context.clone();
    let native_disabled_context = context.clone();
    let described_context = context.clone();
    let input_node = input_ref(&context);
    view! {
        <div class="ob-combobox-control">
            <input
                id=input_id
                class="ob-combobox-input"
                type="text"
                role="combobox"
                autocomplete="off"
                spellcheck="false"
                placeholder=move || placeholder.get()
                prop:value=move || value_context.query.get()
                data-state=move || owner_state(&state_context)
                aria-label=move || aria_label.get()
                aria-haspopup="listbox"
                aria-autocomplete="list"
                aria-expanded=move || explicit_bool(expanded_context.open.get())
                aria-controls=popup_id
                aria-activedescendant=move || active_context.open.get().then(|| active_context.active_id.get()).flatten()
                aria-invalid=move || explicit_bool(invalid_context.invalid.get())
                aria-disabled=move || explicit_bool(disabled_context.disabled.get())
                aria-describedby=move || described_by(&described_context)
                disabled=move || native_disabled_context.disabled.get()
                node_ref=input_node
                on:input=move |event| {
                    if !input_context.disabled.get_untracked() {
                        handle_editable_input(input_context.clone(), event_target_value(&event));
                    }
                }
                on:keydown=move |event: KeyboardEvent| {
                    handle_editable_key(event, key_context.clone());
                }
                on:click=move |_| {
                    if !click_context.disabled.get_untracked()
                        && !click_context.open.get_untracked()
                    {
                        open_current(click_context.clone());
                    }
                }
            />
            <span class="ob-combobox-icon" aria-hidden="true">
                <IconView icon=Icon::ChevronDown size=IconSize::Inline />
            </span>
        </div>
    }
}

/// Popup/listbox surface.
#[component]
pub fn ComboboxContent(children: Children) -> impl IntoView {
    listbox_popup(children)
}

/// Scrollable options collection.
#[component]
pub fn ComboboxList(children: Children) -> impl IntoView {
    view! { <div class="ob-combobox-list" role="presentation">{children()}</div> }
}

/// One rich suggestion. `label` is the filter/typeahead/accessible text source.
#[component]
pub fn ComboboxItem(
    #[prop(into)] id: String,
    #[prop(into)] value: String,
    #[prop(into)] label: TextProp,
    #[prop(optional, into)] disabled: MaybeProp<bool>,
    children: Children,
) -> impl IntoView {
    listbox_option(id, value, label, disabled, children)
}

/// Empty-filter feedback tied to the shared visible-options count.
#[component]
pub fn ComboboxEmpty(children: Children) -> impl IntoView {
    let context = use_listbox_context();
    view! {
        <div
            class="ob-listbox-empty"
            role="status"
            hidden=move || !context.empty.get()
        >
            {children()}
        </div>
    }
}

/// Decorative separator between suggestion groups.
#[component]
pub fn ComboboxSeparator() -> impl IntoView {
    view! { <div class="ob-listbox-separator" role="separator"></div> }
}

const fn explicit_bool(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}
