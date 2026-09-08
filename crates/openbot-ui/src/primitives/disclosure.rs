//! Keyboard dismissal for native, progressively disclosed shell controls.

/// Close the enclosing native details element on Escape and restore its trigger focus.
/// Other keys retain the browser's native summary/link/button semantics.
pub(crate) fn dismiss_disclosure(event: leptos::ev::KeyboardEvent) {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::JsCast as _;

        if event.key() != "Escape" {
            return;
        }
        let Some(details) = event
            .current_target()
            .and_then(|target| target.dyn_into::<web_sys::Element>().ok())
        else {
            return;
        };
        if !details.has_attribute("open") {
            return;
        }
        event.prevent_default();
        event.stop_propagation();
        _ = details.remove_attribute("open");
        if let Ok(Some(summary)) = details.query_selector(":scope > summary")
            && let Some(summary) = summary.dyn_ref::<web_sys::HtmlElement>()
        {
            _ = summary.focus();
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = event;
}

/// Dismiss a native disclosure after choosing a navigation link; navigation keeps its default action.
pub(crate) fn dismiss_disclosure_link(event: leptos::ev::MouseEvent) {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::JsCast as _;

        let link = event
            .target()
            .and_then(|target| target.dyn_into::<web_sys::Element>().ok())
            .and_then(|element| element.closest("a[href]").ok().flatten());
        if link.is_some()
            && let Some(details) = event
                .current_target()
                .and_then(|target| target.dyn_into::<web_sys::Element>().ok())
        {
            _ = details.remove_attribute("open");
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = event;
}
