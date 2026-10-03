//! Same-thread browser timing for revision editors; no persisted draft or background retry.

pub(crate) fn now_ms() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::window()
            .and_then(|window| window.performance())
            .map(|performance| performance.now().max(0.0) as u64)
            .unwrap_or(0)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        0
    }
}

pub(crate) fn after(milliseconds: i32, callback: impl FnOnce() + 'static) {
    crate::primitives::timing::schedule_timeout(milliseconds, callback);
}
