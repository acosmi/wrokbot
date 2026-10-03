//! Edge sheet using the exact Dialog focus/security kernel.

use leptos::prelude::*;

use super::modal::modal_root_with_inline;
use super::modal::{ModalPresentation, SheetSide, modal_root};

/// One mounted tree changes from a focused edge sheet to an inline side panel.
#[component]
pub(crate) fn ResponsiveSheet(
    #[prop(into)] id: String,
    open: RwSignal<bool>,
    inline: Signal<bool>,
    #[prop(optional)] on_close: Option<UnsyncCallback<()>>,
    children: Children,
) -> impl IntoView {
    modal_root_with_inline(
        open,
        ModalPresentation::Sheet(SheetSide::Right),
        on_close,
        id,
        inline,
        children,
    )
}

/// Edge-aligned modal root. Use DialogTrigger/Content/Body/Footer/Close inside.
#[component]
pub fn Sheet(
    #[prop(into)] id: String,
    open: RwSignal<bool>,
    #[prop(optional)] side: SheetSide,
    #[prop(optional)] on_close: Option<UnsyncCallback<()>>,
    children: Children,
) -> impl IntoView {
    modal_root(open, ModalPresentation::Sheet(side), on_close, id, children)
}
