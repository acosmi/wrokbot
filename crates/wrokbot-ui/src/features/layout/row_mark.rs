//! Neutral vendor mark tile for configuration rows.

use leptos::prelude::*;

/// A row-leading tile reserved for third-party/vendor identity.
#[component]
pub fn RowMark(children: Children) -> impl IntoView {
    view! { <span class="wrokbot-row-mark">{children()}</span> }
}
