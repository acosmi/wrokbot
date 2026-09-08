//! Text-and-dot status badge primitive.

use leptos::prelude::*;

/// Semantic badge tone. Color is never the only carrier because text is always present.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BadgeTone {
    /// Neutral status.
    #[default]
    Neutral,
    /// Caution status.
    Caution,
    /// Success status.
    Success,
    /// Informational status.
    Info,
    /// Danger status.
    Danger,
}

impl BadgeTone {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Neutral => "neutral",
            Self::Caution => "caution",
            Self::Success => "success",
            Self::Info => "info",
            Self::Danger => "danger",
        }
    }
}

/// Render a compact status badge with a decorative dot and visible text.
#[component]
pub fn Badge(
    /// Semantic tone.
    #[prop(optional)]
    tone: BadgeTone,
    /// Visible status text.
    children: Children,
) -> impl IntoView {
    view! {
        <span class="ob-badge" data-tone=tone.as_str()>
            <span class="ob-badge-dot" aria-hidden="true"></span>
            {children()}
        </span>
    }
}

#[cfg(test)]
mod tests {
    use super::BadgeTone;

    #[test]
    fn every_declared_semantic_tone_has_a_closed_css_value() {
        assert_eq!(
            [
                BadgeTone::Neutral.as_str(),
                BadgeTone::Caution.as_str(),
                BadgeTone::Success.as_str(),
                BadgeTone::Info.as_str(),
                BadgeTone::Danger.as_str(),
            ],
            ["neutral", "caution", "success", "info", "danger"]
        );
    }
}
