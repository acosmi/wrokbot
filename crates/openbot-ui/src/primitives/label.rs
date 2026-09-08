//! Explicit HTML label binding primitive.

use leptos::prelude::*;

/// A semantic label whose `for` value is supplied by Field's single ID source.
#[component]
pub fn Label(
    /// Target form-control ID.
    #[prop(into)]
    for_id: String,
    /// Visible label content.
    children: Children,
) -> impl IntoView {
    view! {
        <label class="ob-label" for=for_id>
            {children()}
        </label>
    }
}
