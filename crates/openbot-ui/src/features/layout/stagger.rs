//! Token-bound, CSS-only list entrance staggering.

use leptos::prelude::*;

const STAGGER_MAX_ITEMS: usize = 8;

/// One mount-only list item; delay is capped by the first-source token at eight steps.
#[component]
pub fn StaggerItem(
    /// Render index; values above eight share the capped final delay.
    index: usize,
    children: Children,
) -> impl IntoView {
    view! {
        <div class="ob-stagger-item" data-stagger=stagger_slot(index)>
            {children()}
        </div>
    }
}

fn stagger_slot(index: usize) -> &'static str {
    const SLOTS: [&str; STAGGER_MAX_ITEMS + 1] = ["0", "1", "2", "3", "4", "5", "6", "7", "8"];
    SLOTS[index.min(STAGGER_MAX_ITEMS)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stagger_uses_exact_token_cap() {
        assert_eq!(stagger_slot(0), "0");
        assert_eq!(stagger_slot(7), "7");
        assert_eq!(stagger_slot(8), "8");
        assert_eq!(stagger_slot(200), "8");
    }
}
