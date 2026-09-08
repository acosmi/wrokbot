//! Semantic or decorative separator.

use leptos::prelude::*;

/// Separator axis.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SeparatorOrientation {
    /// Horizontal rule between vertical sections.
    #[default]
    Horizontal,
    /// Vertical rule between inline regions.
    Vertical,
}

impl SeparatorOrientation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Horizontal => "horizontal",
            Self::Vertical => "vertical",
        }
    }
}

/// A neutral rule; decorative rules are removed from the accessibility tree.
#[component]
pub fn Separator(
    #[prop(optional)] orientation: SeparatorOrientation,
    #[prop(optional)] decorative: bool,
) -> impl IntoView {
    view! {
        <div
            class="ob-separator"
            data-orientation=orientation.as_str()
            role=(!decorative).then_some("separator")
            aria-hidden=decorative.then_some("true")
            aria-orientation=(!decorative).then_some(orientation.as_str())
        ></div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separator_orientation_is_closed() {
        assert_eq!(SeparatorOrientation::Horizontal.as_str(), "horizontal");
        assert_eq!(SeparatorOrientation::Vertical.as_str(), "vertical");
    }
}
