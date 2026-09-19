//! Empty-state primitive.

use leptos::prelude::*;

/// Render a titled empty state without inventing a disabled action.
#[component]
pub fn EmptyState(
    /// Caller-owned stable heading id; required so multiple empty states cannot share a hidden
    /// primitive-global id.
    heading_id: &'static str,
    /// Empty-state heading.
    #[prop(into)]
    title: TextProp,
    /// Explanatory body.
    #[prop(into)]
    body: TextProp,
) -> impl IntoView {
    view! {
        <section class="ob-empty-state" aria-labelledby=heading_id>
            <h2 id=heading_id class="ob-empty-title">{move || title.get()}</h2>
            <p class="ob-empty-body">{move || body.get()}</p>
        </section>
    }
}
