//! Non-blocking status toast with a five-second lifetime.

use leptos::prelude::*;

use crate::i18n::{t_string, use_i18n};

use super::timing::schedule_timeout;

/// First-source fixed toast lifetime.
pub const TOAST_TIMEOUT_MS: i32 = 5_000;

/// Forced compile-gallery state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToastPreviewState {
    /// Keep the toast visible without depending on wall time.
    Open,
}

/// Fixed polite-status viewport. Toast itself stays layout-agnostic for design/gallery embedding.
#[component]
pub fn ToastViewport(children: Children) -> impl IntoView {
    view! { <div class="ob-toast-viewport">{children()}</div> }
}

/// Visible, polite feedback. Business code owns the `visible` signal.
#[component]
pub fn Toast(
    #[prop(into)] id: String,
    visible: RwSignal<bool>,
    #[prop(into)] message: TextProp,
    #[prop(optional)] preview_state: Option<ToastPreviewState>,
    #[prop(optional)] on_dismiss: Option<UnsyncCallback<()>>,
) -> impl IntoView {
    assert!(
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "Toast id must be a bounded DOM token"
    );
    let i18n = use_i18n();
    let generation = RwSignal::new(0_u64);
    let forced = preview_state == Some(ToastPreviewState::Open);
    Effect::new(move |_| {
        if forced || !visible.get() {
            return;
        }
        let next = generation.get_untracked().saturating_add(1);
        generation.set(next);
        schedule_timeout(TOAST_TIMEOUT_MS, move || {
            if generation.get_untracked() == next {
                dismiss(visible, on_dismiss);
            }
        });
    });
    let is_open = Signal::derive(move || forced || visible.get());
    view! {
        <div
            id=id
            class="ob-toast"
            role="status"
            aria-live="polite"
            hidden=move || !is_open.get()
            data-state=move || if is_open.get() { "open" } else { "closed" }
        >
            <span>{move || message.get()}</span>
            <button
                type="button"
                class="ob-toast-dismiss"
                aria-label=move || t_string!(i18n, common.dismiss).to_owned()
                on:click=move |_| dismiss(visible, on_dismiss)
            >
                "×"
            </button>
        </div>
    }
}

fn dismiss(visible: RwSignal<bool>, on_dismiss: Option<UnsyncCallback<()>>) {
    visible.set(false);
    if let Some(callback) = on_dismiss {
        callback.run(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toast_lifetime_is_the_first_source_exact_value() {
        assert_eq!(TOAST_TIMEOUT_MS, 5_000);
    }
}
