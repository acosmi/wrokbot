//! Loading placeholder excluded from the accessibility tree.

use leptos::prelude::*;

/// Bounded skeleton geometry; arbitrary inline sizes are intentionally absent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SkeletonShape {
    /// One text-like line.
    #[default]
    Line,
    /// Multi-line/card block.
    Block,
    /// Avatar-sized circle.
    Circle,
}

impl SkeletonShape {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Line => "line",
            Self::Block => "block",
            Self::Circle => "circle",
        }
    }
}

/// Purely visual loading placeholder.
#[component]
pub fn Skeleton(#[prop(optional)] shape: SkeletonShape) -> impl IntoView {
    view! {
        <span class="ob-skeleton" data-shape=shape.as_str() aria-hidden="true"></span>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skeleton_shape_is_closed() {
        assert_eq!(SkeletonShape::Line.as_str(), "line");
        assert_eq!(SkeletonShape::Block.as_str(), "block");
        assert_eq!(SkeletonShape::Circle.as_str(), "circle");
    }
}
