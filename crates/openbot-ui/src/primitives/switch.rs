//! Neutral APG switch primitive.

use leptos::ev::KeyboardEvent;
use leptos::prelude::*;

use super::field::{FieldContext, field_context};

/// Controlled `role=switch`; native button semantics provide Space activation.
#[component]
pub fn Switch(
    checked: RwSignal<bool>,
    #[prop(optional, into)] id: Option<String>,
    #[prop(optional, into)] aria_label: TextProp,
    #[prop(optional, into)] disabled: MaybeProp<bool>,
    #[prop(optional)] on_change: Option<UnsyncCallback<bool>>,
) -> impl IntoView {
    let field = field_context();
    let control_id = resolve_control_id(field.as_ref(), id);
    assert!(
        field.is_some() || control_id.is_some() || !aria_label.get().is_empty(),
        "standalone Switch requires id or aria_label"
    );
    let field_disabled = field.clone();
    let field_invalid = field.clone();
    let described_by = field.clone();
    let aria_label_value = aria_label;
    let is_disabled = Signal::derive(move || {
        disabled.get().unwrap_or(false)
            || field_disabled.as_ref().is_some_and(FieldContext::disabled)
    });
    let is_invalid =
        Signal::derive(move || field_invalid.as_ref().is_some_and(FieldContext::invalid));
    view! {
        <button
            id=control_id
            type="button"
            class="ob-switch"
            role="switch"
            aria-label=move || {
                let label = aria_label_value.get();
                (!label.is_empty()).then_some(label)
            }
            aria-checked=move || if checked.get() { "true" } else { "false" }
            aria-invalid=move || if is_invalid.get() { "true" } else { "false" }
            aria-describedby=move || described_by.as_ref().and_then(FieldContext::described_by)
            data-state=move || switch_state_tokens(checked.get(), is_disabled.get())
            disabled=move || is_disabled.get()
            on:click=move |_| {
                if !is_disabled.get() {
                    toggle(checked, on_change);
                }
            }
            on:keydown=move |event: KeyboardEvent| {
                if event.key() == " " && !is_disabled.get() {
                    event.prevent_default();
                    toggle(checked, on_change);
                }
            }
        >
            <span class="ob-switch-thumb" aria-hidden="true"></span>
        </button>
    }
}

fn toggle(checked: RwSignal<bool>, on_change: Option<UnsyncCallback<bool>>) {
    let next = !checked.get_untracked();
    checked.set(next);
    if let Some(callback) = on_change {
        callback.run(next);
    }
}

fn resolve_control_id(field: Option<&FieldContext>, explicit: Option<String>) -> Option<String> {
    if let Some(field) = field {
        if let Some(explicit) = explicit {
            assert_eq!(
                explicit,
                field.control_id(),
                "Switch id conflicts with Field"
            );
        }
        Some(field.control_id().to_owned())
    } else {
        explicit
    }
}

fn switch_state_tokens(checked: bool, disabled: bool) -> Option<&'static str> {
    match (checked, disabled) {
        (false, false) => None,
        (true, false) => Some("checked"),
        (false, true) => Some("disabled"),
        (true, true) => Some("checked disabled"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switch_states_are_closed_and_explicit() {
        assert_eq!(switch_state_tokens(false, false), None);
        assert_eq!(switch_state_tokens(true, true), Some("checked disabled"));
    }
}
