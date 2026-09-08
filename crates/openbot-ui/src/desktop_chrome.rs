//! Presentation-only macOS titlebar gesture. Native host revalidates the invoking window.
use leptos::ev::MouseEvent;

/// Called only by titlebar surfaces. Controls, modified clicks, double clicks and the native
/// system-button area keep their own behavior; failures never schedule a retry.
pub(crate) fn start_drag(event: MouseEvent) {
    #[cfg(target_arch = "wasm32")]
    {
        use js_sys::{Function, Object, Promise, Reflect};
        use openbot_contracts::desktop::DESKTOP_WINDOW_CHROME_COMMAND;
        use wasm_bindgen::{JsCast, JsValue};
        if !plain_primary_down(
            event.is_trusted(),
            event.button(),
            event.buttons(),
            event.detail(),
            event.alt_key() || event.ctrl_key() || event.meta_key() || event.shift_key(),
        ) || event.default_prevented()
            || !super::desktop_transport::is_tauri_host()
        {
            return;
        }
        let Some(window) = web_sys::window() else {
            return;
        };
        if window
            .document()
            .and_then(|d| d.document_element())
            .and_then(|e| e.get_attribute("data-window-chrome"))
            .as_deref()
            != Some("macos-overlay")
        {
            return;
        }
        let Some(target) = event
            .target()
            .and_then(|e| e.dyn_into::<web_sys::Element>().ok())
        else {
            return;
        };
        // This is a UI affordance check, never evidence of authenticated hardware input.
        if !target.matches(".ob-shell-topbar,.ob-sidebar-header,.ob-shell-identity").unwrap_or(false)
            || target.closest("a,button,input,textarea,select,summary,[contenteditable],[role=button],[role=combobox]").ok().flatten().is_some()
            || event.client_x() < 88
        { return; }
        let invoke_once = || -> Result<Promise, JsValue> {
            let internals =
                Reflect::get(window.as_ref(), &JsValue::from_str("__TAURI_INTERNALS__"))?;
            let invoke =
                Reflect::get(&internals, &JsValue::from_str("invoke"))?.dyn_into::<Function>()?;
            let request = Object::new();
            Reflect::set(
                &request,
                &JsValue::from_str("action"),
                &JsValue::from_str("start_drag"),
            )?;
            let args = Object::new();
            Reflect::set(&args, &JsValue::from_str("request"), &request)?;
            invoke
                .call2(
                    &internals,
                    &JsValue::from_str(DESKTOP_WINDOW_CHROME_COMMAND),
                    &args,
                )?
                .dyn_into::<Promise>()
        };
        if let Ok(promise) = invoke_once() {
            event.prevent_default();
            // No success toast: accepted only means the native API accepted the request.
            leptos::task::spawn_local(async move {
                let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
            });
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = event;
}

#[cfg(any(target_arch = "wasm32", test))]
fn plain_primary_down(
    trusted: bool,
    button: i16,
    buttons: u16,
    detail: i32,
    modified: bool,
) -> bool {
    trusted && button == 0 && buttons == 1 && detail == 1 && !modified
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn titlebar_gesture_keeps_context_clicks_and_double_clicks_native() {
        assert!(plain_primary_down(true, 0, 1, 1, false));
        for (trusted, button, buttons, detail, modified) in [
            (false, 0, 1, 1, false),
            (true, 2, 2, 1, false),
            (true, 0, 3, 1, false),
            (true, 0, 1, 2, false),
            (true, 0, 1, 1, true),
        ] {
            assert!(!plain_primary_down(
                trusted, button, buttons, detail, modified
            ));
        }
    }
}
