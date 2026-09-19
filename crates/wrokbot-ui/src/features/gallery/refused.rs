//! Shared visible refusal for compiled and sandboxed component authorization failures.

use leptos::prelude::*;

use crate::i18n::{t_string, use_i18n};

/// Render a stable, non-interactive component refusal without exposing a tool name as a title.
#[component]
pub fn RefusedCard(title: String, reason: String) -> impl IntoView {
    let i18n = use_i18n();
    view! {
        <div class="ob-gallery-refused" data-testid="component-refused" role="status">
            <p>{move || t_string!(i18n, gallery.not_shown, title = title.as_str()).to_owned()}</p>
            <span>{reason}</span>
        </div>
    }
}
