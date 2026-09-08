//! Field composition that owns label/control/description/error wiring.

use leptos::context::Provider;
use leptos::prelude::*;

use super::Label;

/// Context consumed by form controls nested in a [`Field`].
#[derive(Clone)]
pub(crate) struct FieldContext {
    control_id: String,
    description_id: String,
    error_id: String,
    description: TextProp,
    error: TextProp,
    invalid: Signal<bool>,
    disabled: Signal<bool>,
}

impl FieldContext {
    pub(crate) fn control_id(&self) -> &str {
        &self.control_id
    }

    pub(crate) fn invalid(&self) -> bool {
        self.invalid.get()
    }

    pub(crate) fn disabled(&self) -> bool {
        self.disabled.get()
    }

    pub(crate) fn described_by(&self) -> Option<String> {
        let mut ids = Vec::with_capacity(2);
        if !self.description.get().is_empty() {
            ids.push(self.description_id.as_str());
        }
        if self.invalid() && !self.error.get().is_empty() {
            ids.push(self.error_id.as_str());
        }
        (!ids.is_empty()).then(|| ids.join(" "))
    }
}

pub(crate) fn field_context() -> Option<FieldContext> {
    use_context::<FieldContext>()
}

/// Label, control slot, description and error with one stable ID source.
#[component]
pub fn Field(
    /// Stable control ID chosen by the first-party caller; Field derives all related IDs.
    #[prop(into)]
    control_id: String,
    /// Visible field label.
    #[prop(into)]
    label: TextProp,
    /// Optional explanatory text.
    #[prop(optional, into)]
    description: TextProp,
    /// Optional validation message; shown only while invalid.
    #[prop(optional, into)]
    error: TextProp,
    /// Reactive invalid state.
    #[prop(optional, into)]
    invalid: MaybeProp<bool>,
    /// Reactive disabled state propagated into nested controls.
    #[prop(optional, into)]
    disabled: MaybeProp<bool>,
    /// Exactly one first-party control or input group.
    children: Children,
) -> impl IntoView {
    assert_valid_control_id(&control_id);
    let invalid_signal = Signal::derive(move || invalid.get().unwrap_or(false));
    let disabled_signal = Signal::derive(move || disabled.get().unwrap_or(false));
    let description_id = format!("{control_id}-description");
    let error_id = format!("{control_id}-error");
    let context = FieldContext {
        control_id: control_id.clone(),
        description_id: description_id.clone(),
        error_id: error_id.clone(),
        description: description.clone(),
        error: error.clone(),
        invalid: invalid_signal,
        disabled: disabled_signal,
    };

    let description_visible = description.clone();
    let description_text = description;
    let error_visible = error.clone();
    let error_text = error;

    view! {
        <Provider value=context>
            <div
                class="ob-field"
                data-state=move || field_state_tokens(invalid_signal.get(), disabled_signal.get())
            >
                <Label for_id=control_id>{move || label.get()}</Label>
                {children()}
                <p
                    id=description_id
                    class="ob-field-description"
                    hidden=move || description_visible.get().is_empty()
                >
                    {move || description_text.get()}
                </p>
                <p
                    id=error_id
                    class="ob-field-error"
                    role="alert"
                    hidden=move || !invalid_signal.get() || error_visible.get().is_empty()
                >
                    {move || error_text.get()}
                </p>
            </div>
        </Provider>
    }
}

fn assert_valid_control_id(id: &str) {
    assert!(
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "Field control_id must be 1..=128 ASCII alphanumeric/hyphen/underscore bytes"
    );
}

fn field_state_tokens(invalid: bool, disabled: bool) -> Option<&'static str> {
    match (invalid, disabled) {
        (false, false) => None,
        (true, false) => Some("invalid"),
        (false, true) => Some("disabled"),
        (true, true) => Some("invalid disabled"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_ids_and_state_tokens_are_closed() {
        for id in ["email", "profile_email-1", "field_2"] {
            assert_valid_control_id(id);
        }
        assert_eq!(field_state_tokens(false, false), None);
        assert_eq!(field_state_tokens(true, true), Some("invalid disabled"));
    }

    #[test]
    #[should_panic(expected = "Field control_id")]
    fn field_rejects_ids_that_could_split_aria_tokens() {
        assert_valid_control_id("bad id");
    }
}
