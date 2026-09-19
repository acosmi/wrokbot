//! Password entry owns its value only in the DOM. Reactive state contains validation facts, never
//! plaintext; request copies are explicit, transient and zeroizing.

use leptos::prelude::*;
use zeroize::Zeroizing;

use super::field::field_context;
use super::input::{input_state_tokens, resolve_control_id};

/// Non-secret validation facts exposed to the form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretInputStatus {
    /// No effective secret was entered.
    Empty,
    /// The value meets the selected local framing bounds.
    Valid,
    /// The value exceeds bounds or contains forbidden control characters.
    Invalid,
}

/// Existing request semantics; this policy never validates a credential with a provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretInputPolicy {
    /// Preserve OAuth secret bytes; reject control characters.
    OpaqueToken,
    /// Preserve the Agent form's ECMAScript trim and Authorization CR/LF/NUL rejection.
    Authorization,
}

/// Copyable input handle holding a DOM reference and non-secret flags, never a Rust secret string.
#[derive(Clone, Copy)]
pub struct SecretInputController {
    node: NodeRef<leptos::html::Input>,
    status: RwSignal<SecretInputStatus>,
    revision: RwSignal<u64>,
    maximum_bytes: usize,
    policy: SecretInputPolicy,
}

impl SecretInputController {
    /// Allocate an empty field with the same maximum accepted by its typed request.
    pub fn new(maximum_bytes: usize, policy: SecretInputPolicy) -> Self {
        assert!((1..=64 * 1024).contains(&maximum_bytes));
        Self {
            node: NodeRef::new(),
            status: RwSignal::new(SecretInputStatus::Empty),
            revision: RwSignal::new(0),
            maximum_bytes,
            policy,
        }
    }

    /// Read-only validation state; never exposes bytes, prefixes or a hash of the value.
    pub fn status(self) -> ReadSignal<SecretInputStatus> {
        self.status.read_only()
    }

    /// User edit generation, for invalidating connection-test results without retaining a secret.
    pub fn revision(self) -> ReadSignal<u64> {
        self.revision.read_only()
    }

    /// Validate the current DOM value at explicit submit time, including browser autofill.
    pub fn validate(self) -> SecretInputStatus {
        let value = self.copy_for_request();
        let status = classify(&value, self.maximum_bytes, self.policy);
        self.status.try_set(status);
        status
    }

    /// Explicit temporary request copy. Connection probes may retain the editable DOM value until
    /// save/cancel; callers must immediately move this copy into a zeroizing request or drop it.
    pub fn copy_for_request(self) -> Zeroizing<String> {
        #[cfg(target_arch = "wasm32")]
        {
            Zeroizing::new(
                self.node
                    .get_untracked()
                    .map(|node| node.value())
                    .unwrap_or_default(),
            )
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            Zeroizing::new(String::new())
        }
    }

    /// Read once and clear the password control before sending the request. Failed writes require
    /// explicit re-entry; they never restore plaintext from request state into the DOM.
    pub fn take(self) -> Zeroizing<String> {
        let value = self.copy_for_request();
        self.clear();
        value
    }

    /// Clear the DOM and validation state on close, submit or scope change.
    pub fn clear(self) {
        #[cfg(target_arch = "wasm32")]
        if let Some(node) = self.node.get_untracked() {
            node.set_value("");
        }
        self.status.try_set(SecretInputStatus::Empty);
    }

    fn edited(self) {
        self.validate();
        self.revision.try_update(|generation| {
            if let Some(next) = generation.checked_add(1) {
                *generation = next;
            } else {
                self.status.try_set(SecretInputStatus::Invalid);
            }
        });
    }
}

fn classify(value: &str, maximum: usize, policy: SecretInputPolicy) -> SecretInputStatus {
    let value = match policy {
        SecretInputPolicy::OpaqueToken => value,
        SecretInputPolicy::Authorization => openbot_contracts::text::trim_ecmascript(value),
    };
    if value.is_empty() {
        return SecretInputStatus::Empty;
    }
    let controls = match policy {
        SecretInputPolicy::OpaqueToken => value.chars().any(char::is_control),
        SecretInputPolicy::Authorization => value.chars().any(|c| matches!(c, '\0' | '\r' | '\n')),
    };
    if value.len() > maximum || controls {
        SecretInputStatus::Invalid
    } else {
        SecretInputStatus::Valid
    }
}

/// Field-compatible password control. There is deliberately no reactive value prop or plaintext
/// change callback; only the owning controller can read an explicit temporary request copy.
#[component]
pub fn SecretInput(
    /// DOM owner and public validation metadata.
    controller: SecretInputController,
    /// Standalone ID; nested Field owns the ID and ARIA relationships.
    #[prop(optional, into)]
    id: Option<String>,
    /// Optional visible hint, never a secret default value.
    #[prop(optional, into)]
    placeholder: TextProp,
    /// Required accessible name for a standalone control.
    #[prop(optional, into)]
    aria_label: TextProp,
    /// Standalone invalid state, ORed with Field state.
    #[prop(optional, into)]
    invalid: MaybeProp<bool>,
    /// Standalone disabled state, ORed with Field state.
    #[prop(optional, into)]
    disabled: MaybeProp<bool>,
) -> impl IntoView {
    let field = field_context();
    let control_id = resolve_control_id(field.as_ref(), id);
    assert!(field.is_some() || control_id.is_some() || !aria_label.get().is_empty());
    let field_invalid = field.clone();
    let field_disabled = field.clone();
    let is_invalid = Signal::derive(move || {
        invalid.get().unwrap_or(false)
            || field_invalid.as_ref().is_some_and(|field| field.invalid())
    });
    let is_disabled = Signal::derive(move || {
        disabled.get().unwrap_or(false)
            || field_disabled
                .as_ref()
                .is_some_and(|field| field.disabled())
    });
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        if let Some(node) = controller.node.get() {
            // Capture this exact node so hiding/replacing a form cannot leave bytes in a detached
            // input, even when its controller's reactive owner is being disposed.
            on_cleanup(move || node.set_value(""));
        }
    });
    view! {
        <input id=control_id node_ref=controller.node class="ob-input" type="password"
            autocomplete="off" spellcheck="false" autocapitalize="off"
            placeholder=move || { let hint=placeholder.get(); (!hint.is_empty()).then_some(hint) }
            aria-label=move || { let label=aria_label.get(); (!label.is_empty()).then_some(label) }
            aria-invalid=move || if is_invalid.get() { "true" } else { "false" }
            aria-describedby=move || field.as_ref().and_then(|field| field.described_by())
            disabled=move || is_disabled.get()
            data-state=move || input_state_tokens(None, is_invalid.get(), is_disabled.get())
            on:input=move |_| controller.edited() on:change=move |_| controller.edited()
        />
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secret_validation_reports_only_facts_and_preserves_existing_trim_rules() {
        use SecretInputPolicy::{Authorization, OpaqueToken};
        use SecretInputStatus::{Empty, Invalid, Valid};
        assert_eq!(classify("", 16, OpaqueToken), Empty);
        assert_eq!(classify("\u{feff}  ", 16, Authorization), Empty);
        assert_eq!(classify("\u{feff} token \u{feff}", 5, Authorization), Valid);
        assert_eq!(classify("token", 4, OpaqueToken), Invalid);
        assert_eq!(classify("令牌", 5, OpaqueToken), Invalid);
        assert_eq!(classify("令牌", 6, OpaqueToken), Valid);
        assert_eq!(classify("a\tb", 16, Authorization), Valid);
        assert_eq!(classify("a\tb", 16, OpaqueToken), Invalid);
        for value in ["a\0b", "a\rb", "a\nb"] {
            assert_eq!(classify(value, 16, Authorization), Invalid);
        }
    }
}
