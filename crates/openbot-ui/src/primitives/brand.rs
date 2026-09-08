//! User-supplied animated brand with native reduced-motion image selection.
use leptos::prelude::*;

#[component]
pub(crate) fn BrandMark(#[prop(optional)] sign_in: bool) -> impl IntoView {
    view! {
        <picture class="contents">
            <source media="(prefers-reduced-motion: reduce)" srcset="/brand/wrok-bot-motion-still.png"/>
            {if sign_in {
                view! { <img class="ob-sign-logo" src="/brand/wrok-bot-motion.gif" alt="" width="64" height="64" decoding="async"/> }.into_any()
            } else {
                view! { <img class="ob-brand-mark" src="/brand/wrok-bot-motion.gif" alt="" width="40" height="40" decoding="async"/> }.into_any()
            }}
        </picture>
    }
}
