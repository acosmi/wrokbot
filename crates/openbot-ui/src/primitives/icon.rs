//! Trusted bundled SVG icon primitive.

use leptos::prelude::*;

use crate::icons::Icon;

/// The two icon sizes permitted by the GUI first source.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IconSize {
    /// 16px inline/adjacent icon.
    #[default]
    Inline,
    /// 20px navigation/button icon.
    Navigation,
}

impl IconSize {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::Navigation => "navigation",
        }
    }
}

/// Render one build-validated bundled SVG. It is decorative; the owning control supplies a name.
#[component]
pub fn IconView(
    /// Strongly typed allowlisted icon.
    icon: Icon,
    /// Permitted render size.
    #[prop(optional)]
    size: IconSize,
) -> impl IntoView {
    view! {
        <span
            class="ob-icon"
            data-size=size.as_str()
            aria-hidden="true"
            inner_html=icon.svg()
        ></span>
    }
}
