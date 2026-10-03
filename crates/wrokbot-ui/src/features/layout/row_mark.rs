//! Compact source-identity slot for library rows.

use leptos::prelude::*;

/// A row-leading tile reserved for third-party/vendor identity.
#[component]
pub fn RowMark(children: Children) -> impl IntoView {
    view! { <span class="ob-library-mark" aria-hidden="true">{children()}</span> }
}
