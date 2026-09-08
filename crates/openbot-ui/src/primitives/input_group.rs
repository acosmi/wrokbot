//! Input group container and prefix/suffix slots.

use leptos::prelude::*;

/// Prefix or suffix placement for a group affix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputGroupAffixPosition {
    /// Before the control in logical inline order.
    Prefix,
    /// After the control in logical inline order.
    Suffix,
}

impl InputGroupAffixPosition {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Prefix => "prefix",
            Self::Suffix => "suffix",
        }
    }
}

/// Shared focus-within surface. Keyboard focus remains on the nested control.
#[component]
pub fn InputGroup(
    /// Force the focus-within treatment in the design gallery.
    #[prop(optional)]
    preview_focus_within: bool,
    children: Children,
) -> impl IntoView {
    view! {
        <div
            class="ob-input-group"
            data-state=preview_focus_within.then_some("focus-within")
        >
            {children()}
        </div>
    }
}

/// Non-interactive content slot around an Input/Textarea.
#[component]
pub fn InputGroupAffix(position: InputGroupAffixPosition, children: Children) -> impl IntoView {
    view! {
        <span class="ob-input-group-affix" data-position=position.as_str()>
            {children()}
        </span>
    }
}
