//! Decorative waiting frame for a computer surface.

use leptos::prelude::*;

use crate::features::settings::ComputerPlaceholderArt;

/// Reuse the single neutral artwork inside the fixed computer-frame aspect ratio.
#[component]
pub fn ComputerPlaceholder() -> impl IntoView {
    view! {
        <div class="wrokbot-computer-placeholder" aria-hidden="true">
            <ComputerPlaceholderArt />
        </div>
    }
}
