//! Centered modal dialog backed by the shared modal kernel.

use leptos::prelude::*;

use super::modal::{
    ModalPresentation, modal_body, modal_close, modal_content, modal_footer, modal_root,
    modal_trigger,
};

/// Centered modal root.
#[component]
pub fn Dialog(
    #[prop(into)] id: String,
    open: RwSignal<bool>,
    #[prop(optional)] on_close: Option<UnsyncCallback<()>>,
    children: Children,
) -> impl IntoView {
    modal_root(open, ModalPresentation::Dialog, on_close, id, children)
}

/// Button trigger for the nearest Dialog or Sheet.
#[component]
pub fn DialogTrigger(
    #[prop(optional, into)] id: Option<String>,
    #[prop(optional, into)] disabled: MaybeProp<bool>,
    children: Children,
) -> impl IntoView {
    modal_trigger(id, disabled, children)
}

/// Modal panel with generated title/description/close relationships.
#[component]
pub fn DialogContent(
    #[prop(into)] title: TextProp,
    #[prop(optional, into)] description: TextProp,
    #[prop(default = true)] show_close_button: bool,
    children: Children,
) -> impl IntoView {
    modal_content(title, description, show_close_button, children)
}

/// Independently placed close action.
#[component]
pub fn DialogClose(
    #[prop(optional, into)] id: Option<String>,
    children: Children,
) -> impl IntoView {
    modal_close(id, children)
}

/// Scrollable body between fixed header and footer.
#[component]
pub fn DialogBody(children: Children) -> impl IntoView {
    modal_body(children)
}

/// Fixed modal action row.
#[component]
pub fn DialogFooter(children: Children) -> impl IntoView {
    modal_footer(children)
}
