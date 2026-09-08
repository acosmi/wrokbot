//! Tokenized textbox primitive with Field-owned accessibility wiring.

use leptos::ev::KeyboardEvent;
use leptos::prelude::*;

use super::field::field_context;

/// Closed first-party input kinds used by current product forms.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum InputType {
    /// Ordinary text.
    #[default]
    Text,
    /// Email address.
    Email,
    /// Search field.
    Search,
    /// URL entry.
    Url,
}

impl InputType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Email => "email",
            Self::Search => "search",
            Self::Url => "url",
        }
    }
}

/// Forced design-gallery state for a textbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputPreviewState {
    /// Render the focus treatment without relying on browser focus.
    Focus,
}

/// Controlled semantic `<input>`; when nested in Field, all ARIA IDs are automatic.
#[component]
pub fn Input(
    /// Reactive controlled value.
    value: RwSignal<String>,
    /// Closed input type.
    #[prop(optional)]
    input_type: InputType,
    /// Optional standalone ID. Field's ID wins and conflicting values panic as a code bug.
    #[prop(optional, into)]
    id: Option<String>,
    /// Optional form name.
    #[prop(optional, into)]
    name: Option<String>,
    /// Optional reactive visible hint.
    #[prop(optional, into)]
    placeholder: TextProp,
    /// Required for a standalone control without an external `<label for>`.
    #[prop(optional, into)]
    aria_label: TextProp,
    /// Standalone invalid state, ORed with Field state.
    #[prop(optional, into)]
    invalid: MaybeProp<bool>,
    /// Standalone disabled state, ORed with Field state.
    #[prop(optional, into)]
    disabled: MaybeProp<bool>,
    /// Deterministic gallery state.
    #[prop(optional)]
    preview_state: Option<InputPreviewState>,
    /// Optional Enter activation owned by the surrounding use case; IME composition never submits.
    #[prop(optional)]
    on_submit: Option<UnsyncCallback<()>>,
) -> impl IntoView {
    let field = field_context();
    let control_id = resolve_control_id(field.as_ref(), id);
    assert!(
        field.is_some() || control_id.is_some() || !aria_label.get().is_empty(),
        "standalone Input requires id or aria_label"
    );
    let field_invalid = field.clone();
    let field_disabled = field.clone();
    let described_by = field.clone();
    let aria_label_value = aria_label;
    let composing = StoredValue::new(false);
    let submit = StoredValue::new(on_submit);
    let is_invalid = Signal::derive(move || {
        invalid.get().unwrap_or(false)
            || field_invalid
                .as_ref()
                .is_some_and(FieldContextView::invalid)
    });
    let is_disabled = Signal::derive(move || {
        disabled.get().unwrap_or(false)
            || field_disabled
                .as_ref()
                .is_some_and(FieldContextView::disabled)
    });

    view! {
        <input
            id=control_id
            class="ob-input"
            type=input_type.as_str()
            name=name
            autocomplete=(input_type == InputType::Email).then_some("email")
            placeholder=move || {
                let value = placeholder.get();
                (!value.is_empty()).then_some(value)
            }
            prop:value=move || value.get()
            disabled=move || is_disabled.get()
            aria-label=move || {
                let label = aria_label_value.get();
                (!label.is_empty()).then_some(label)
            }
            aria-invalid=move || if is_invalid.get() { "true" } else { "false" }
            aria-describedby=move || described_by.as_ref().and_then(FieldContextView::described_by)
            data-state=move || input_state_tokens(
                preview_state,
                is_invalid.get(),
                is_disabled.get(),
            )
            on:input=move |event| value.set(event_target_value(&event))
            on:compositionstart=move |_| composing.set_value(true)
            on:compositionend=move |_| composing.set_value(false)
            on:keydown=move |event: KeyboardEvent| {
                if event.key() == "Enter"
                    && !composing.get_value()
                    && !is_disabled.get()
                    && let Some(callback) = submit.get_value()
                {
                    event.prevent_default();
                    callback.run(());
                }
            }
        />
    }
}

trait FieldContextView {
    fn invalid(&self) -> bool;
    fn disabled(&self) -> bool;
    fn described_by(&self) -> Option<String>;
}

impl FieldContextView for super::field::FieldContext {
    fn invalid(&self) -> bool {
        self.invalid()
    }

    fn disabled(&self) -> bool {
        self.disabled()
    }

    fn described_by(&self) -> Option<String> {
        self.described_by()
    }
}

pub(super) fn resolve_control_id(
    field: Option<&super::field::FieldContext>,
    explicit: Option<String>,
) -> Option<String> {
    if let Some(field) = field {
        if let Some(explicit) = explicit {
            assert_eq!(
                explicit,
                field.control_id(),
                "Input id conflicts with Field"
            );
        }
        Some(field.control_id().to_owned())
    } else {
        explicit
    }
}

pub(super) fn input_state_tokens(
    preview: Option<InputPreviewState>,
    invalid: bool,
    disabled: bool,
) -> Option<String> {
    let mut states = Vec::with_capacity(3);
    if preview == Some(InputPreviewState::Focus) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_type_and_state_tokens_are_closed() {
        assert_eq!(InputType::Text.as_str(), "text");
        assert_eq!(InputType::Email.as_str(), "email");
        assert_eq!(input_state_tokens(None, false, false), None);
        assert_eq!(
            input_state_tokens(Some(InputPreviewState::Focus), true, true),
            Some("focus invalid disabled".to_owned())
        );
    }
}
