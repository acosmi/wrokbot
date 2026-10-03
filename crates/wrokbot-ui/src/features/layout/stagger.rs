//! Stable library item grouping without the retired cascading page entrance.

use leptos::prelude::*;

/// Keep list identity and existing call sites while using the library's static appearance.
#[component]
pub fn StaggerItem(
    /// Retained caller index; static library rows have no stagger delay.
    index: usize,
    children: Children,
) -> impl IntoView {
    let _ = index;
    view! { <div class="ob-library-item">{children()}</div> }
}
