//! Semantic transcript message compound primitives.

use leptos::prelude::*;

/// Logical transcript alignment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MessageAlign {
    /// Assistant/system side.
    #[default]
    Start,
    /// Current-user side.
    End,
}

impl MessageAlign {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::End => "end",
        }
    }
}

/// Stack consecutive messages from one participant.
#[component]
pub fn MessageGroup(children: Children) -> impl IntoView {
    view! { <div class="ob-message-group">{children()}</div> }
}

/// One named transcript article.
#[component]
pub fn Message(
    #[prop(optional)] align: MessageAlign,
    #[prop(into)] aria_label: TextProp,
    children: Children,
) -> impl IntoView {
    assert!(
        !aria_label.get().is_empty(),
        "Message aria_label must be nonempty"
    );
    view! {
        <article
            class="ob-message"
            data-align=align.as_str()
            aria-label=move || aria_label.get()
        >
            {children()}
        </article>
    }
}

/// Avatar slot aligned with the message body.
#[component]
pub fn MessageAvatar(children: Children) -> impl IntoView {
    view! { <div class="ob-message-avatar">{children()}</div> }
}

/// Main body/bubble column.
#[component]
pub fn MessageContent(children: Children) -> impl IntoView {
    view! { <div class="ob-message-content">{children()}</div> }
}

/// Author/time metadata before content.
#[component]
pub fn MessageHeader(children: Children) -> impl IntoView {
    view! { <header class="ob-message-header">{children()}</header> }
}

/// Status/action metadata after content.
#[component]
pub fn MessageFooter(children: Children) -> impl IntoView {
    view! { <footer class="ob-message-footer">{children()}</footer> }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_alignment_is_closed() {
        assert_eq!(MessageAlign::Start.as_str(), "start");
        assert_eq!(MessageAlign::End.as_str(), "end");
    }
}
