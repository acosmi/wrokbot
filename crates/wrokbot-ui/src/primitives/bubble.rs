//! Neutral user/assistant bubble shell.

use leptos::prelude::*;

/// The two first-party conversation sides.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BubbleKind {
    /// Assistant/coworker response.
    #[default]
    Assistant,
    /// Current-user message.
    User,
}

impl BubbleKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Assistant => "assistant",
            Self::User => "user",
        }
    }
}

/// Stack multiple bubbles on one message side.
#[component]
pub fn BubbleGroup(children: Children) -> impl IntoView {
    view! { <div class="ob-bubble-group">{children()}</div> }
}

/// Purely visual bubble with no independent accessibility role.
#[component]
pub fn Bubble(
    #[prop(optional)] kind: BubbleKind,
    /// Force hover state for deterministic design-gallery rendering.
    #[prop(optional)]
    preview_hover: bool,
    children: Children,
) -> impl IntoView {
    view! {
        <div
            class="ob-bubble"
            data-kind=kind.as_str()
            data-state=preview_hover.then_some("hover")
        >
            {children()}
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bubble_kind_is_only_user_or_assistant() {
        assert_eq!(BubbleKind::Assistant.as_str(), "assistant");
        assert_eq!(BubbleKind::User.as_str(), "user");
    }
}
