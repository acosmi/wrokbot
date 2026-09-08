//! Controlled multiline textbox with Rust/WASM autosize capped by CSS at ten lines.

use leptos::ev::KeyboardEvent;
use leptos::html;
use leptos::prelude::*;

use super::field::{FieldContext, field_context};

/// Forced design-gallery state for Textarea.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextareaPreviewState {
    /// Render focus treatment without browser focus.
    Focus,
}

/// Controlled multiline textbox. Field context supplies ID and ARIA relationships automatically.
#[component]
pub fn Textarea(
    value: RwSignal<String>,
    #[prop(optional, into)] id: Option<String>,
    #[prop(optional, into)] name: Option<String>,
    #[prop(optional, into)] placeholder: TextProp,
    #[prop(optional, into)] aria_label: TextProp,
    /// Optional listbox id; when present this textarea is exposed as an editable combobox trigger.
    #[prop(optional, into)]
    combobox_controls: MaybeProp<String>,
    /// Current popup state for an opted-in combobox textarea.
    #[prop(optional, into)]
    combobox_open: MaybeProp<bool>,
    #[prop(optional, into)] active_descendant: MaybeProp<String>,
    /// An owning picker may consume keys before Enter submits. IME keys are never intercepted.
    #[prop(optional)]
    on_keydown: Option<UnsyncCallback<KeyboardEvent>>,
    #[prop(optional, into)] invalid: MaybeProp<bool>,
    #[prop(optional, into)] disabled: MaybeProp<bool>,
    /// Optional owner submit path: Enter submits, Shift+Enter and IME composition remain text input.
    #[prop(optional)]
    on_submit: Option<UnsyncCallback<()>>,
    #[prop(optional)] preview_state: Option<TextareaPreviewState>,
) -> impl IntoView {
    if let Some(controls) = combobox_controls.get() {
        assert_combobox_controls(&controls);
    }
    let is_combobox = Signal::derive(move || combobox_controls.get().is_some());
    let combobox_open = Signal::derive(move || combobox_open.get().unwrap_or(false));
    let field = field_context();
    let control_id = resolve_control_id(field.as_ref(), id);
    assert!(
        field.is_some() || control_id.is_some() || !aria_label.get().is_empty(),
        "standalone Textarea requires id or aria_label"
    );
    let field_invalid = field.clone();
    let field_disabled = field.clone();
    let described_by = field.clone();
    let aria_label_value = aria_label;
    let is_invalid = Signal::derive(move || {
        invalid.get().unwrap_or(false) || field_invalid.as_ref().is_some_and(FieldContext::invalid)
    });
    let is_disabled = Signal::derive(move || {
        disabled.get().unwrap_or(false)
            || field_disabled.as_ref().is_some_and(FieldContext::disabled)
    });
    let node_ref = NodeRef::<html::Textarea>::new();
    let composing = StoredValue::new(false);
    let submit = StoredValue::new(on_submit);
    Effect::new(move |_| {
        value.track();
        resize_textarea(node_ref);
    });

    view! {
        <textarea
            id=control_id
            class="ob-textarea"
            node_ref=node_ref
            name=name
            placeholder=move || placeholder.get()
            rows="1"
            prop:value=move || value.get()
            disabled=move || is_disabled.get()
            aria-label=move || {
                let label = aria_label_value.get();
                (!label.is_empty()).then_some(label)
            }
            role=move || is_combobox.get().then_some("combobox")
            aria-autocomplete=move || is_combobox.get().then_some("list")
            aria-controls=move || combobox_controls.get().inspect(|id| assert_combobox_controls(id))
            aria-expanded=move || is_combobox.get().then(|| {
                if combobox_open.get() { "true" } else { "false" }
            })
            aria-activedescendant=move || active_descendant.get()
            aria-invalid=move || if is_invalid.get() { "true" } else { "false" }
            aria-describedby=move || described_by.as_ref().and_then(FieldContext::described_by)
            data-state=move || textarea_state_tokens(
                preview_state,
                is_invalid.get(),
                is_disabled.get(),
            )
            on:input=move |event| {
                value.set(event_target_value(&event));
                resize_textarea(node_ref);
            }
            on:compositionstart=move |_| composing.set_value(true)
            on:compositionend=move |_| composing.set_value(false)
            on:keydown=move |event: KeyboardEvent| {
                if !composing.get_value() && !event.is_composing()
                    && let Some(callback) = on_keydown { callback.run(event.clone()); }
                if !event.default_prevented() && should_submit(&event.key(), event.shift_key(), composing.get_value() || event.is_composing())
                    && let Some(callback) = submit.get_value()
                {
                    event.prevent_default();
                    callback.run(());
                }
            }
        ></textarea>
    }
}

fn assert_combobox_controls(id: &str) {
    assert!(
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "Textarea combobox_controls must be one bounded DOM token"
    );
}

fn should_submit(key: &str, shift: bool, composing: bool) -> bool {
    key == "Enter" && !shift && !composing
}

fn resolve_control_id(field: Option<&FieldContext>, explicit: Option<String>) -> Option<String> {
    if let Some(field) = field {
        if let Some(explicit) = explicit {
            assert_eq!(
                explicit,
                field.control_id(),
                "Textarea id conflicts with Field"
            );
        }
        Some(field.control_id().to_owned())
    } else {
        explicit
    }
}

fn textarea_state_tokens(
    preview: Option<TextareaPreviewState>,
    invalid: bool,
    disabled: bool,
) -> Option<String> {
    let mut states = Vec::with_capacity(3);
    if preview == Some(TextareaPreviewState::Focus) {
        states.push("focus");
    }
    if invalid {
        states.push("invalid");
    }
    if disabled {
        states.push("disabled");
    }
    (!states.is_empty()).then(|| states.join(" "))
}

fn resize_textarea(node_ref: NodeRef<html::Textarea>) {
    #[cfg(target_arch = "wasm32")]
    if let Some(textarea) = node_ref.get() {
        let style = web_sys::HtmlElement::style(&textarea);
        _ = style.set_property("height", "auto");
        _ = style.set_property("height", &format!("{}px", textarea.scroll_height()));
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = node_ref;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn textarea_states_are_closed() {
        assert_eq!(textarea_state_tokens(None, false, false), None);
        assert_eq!(
            textarea_state_tokens(Some(TextareaPreviewState::Focus), true, true),
            Some("focus invalid disabled".to_owned())
        );
        assert_combobox_controls("home-mention-results");
    }

    #[test]
    #[should_panic(expected = "combobox_controls")]
    fn textarea_combobox_rejects_split_control_ids() {
        assert_combobox_controls("bad controls");
    }

    #[test]
    fn enter_submit_never_steals_shift_newline_or_ime_commit() {
        assert!(should_submit("Enter", false, false));
        assert!(!should_submit("Enter", true, false));
        assert!(!should_submit("Enter", false, true));
        assert!(!should_submit("a", false, false));
    }
}
