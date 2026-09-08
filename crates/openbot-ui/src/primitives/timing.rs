//! Browser timeout helper shared by feedback primitives.

/// Schedule one same-thread callback. Non-WASM builds intentionally do not emulate wall time.
pub(crate) fn schedule_timeout(milliseconds: i32, callback: impl FnOnce() + 'static) {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::{JsCast, closure::Closure};

        let callback = Closure::once_into_js(callback);
        if let Some(window) = web_sys::window() {
            _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                callback.unchecked_ref(),
                milliseconds,
            );
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (milliseconds, callback);
}
