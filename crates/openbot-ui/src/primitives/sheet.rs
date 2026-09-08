//! Edge sheet using the exact Dialog focus/security kernel.

use leptos::prelude::*;

use super::modal::{ModalPresentation, SheetSide, modal_root};

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
