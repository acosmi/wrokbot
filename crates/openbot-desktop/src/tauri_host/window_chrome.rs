//! A closed UI drag action on the invoking native window; no hardware-input authority.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use openbot_contracts::desktop::{
    DesktopWindowChromeAction, DesktopWindowChromeError, DesktopWindowChromeErrorCode as Code,
    DesktopWindowChromeReceipt, DesktopWindowChromeRequest,
};
use serde_json::Value;
use tauri::{State, Webview};

use super::{DesktopTauriProtocol, DesktopTauriProtocolSlot, WindowAuthority};

fn decode(request: Option<Value>) -> Result<DesktopWindowChromeRequest, DesktopWindowChromeError> {
    let request = request.ok_or(Code::Invalid)?;
    let valid = request.as_object().is_some_and(|object| {
        object.len() == 1 && object.get("action").and_then(Value::as_str) == Some("start_drag")
    });
    if !valid {
        return Err(Code::Invalid.into());
    }
    // Only the already bounded one-key/string shape reaches Serde; no clone or serialization of
    // arbitrary renderer JSON is performed to establish a size or authority boundary.
    serde_json::from_value(request).map_err(|_| Code::Invalid.into())
}

fn product_boundary() -> Option<(&'static str, &'static str)> {
    #[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
    {
        Some((
            crate::desktop_release::MAIN_WINDOW,
            crate::desktop_release::PROTOCOL_SCHEME,
        ))
    }
    #[cfg(not(all(feature = "desktop-launcher", target_os = "macos")))]
    {
        None
    }
}

fn validate_invoker(
    webview_label: &str,
    window_label: &str,
    url: &tauri::Url,
    main: &str,
    scheme: &str,
) -> Result<(), DesktopWindowChromeError> {
    if webview_label != main
        || window_label != main
        || url.scheme() != scheme
        || url.host_str() != Some("localhost")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
    {
        return Err(Code::Denied.into());
    }
    Ok(())
}

/// The pending bit belongs to one binding, so dropping an old request cannot clear a new one.
pub(super) struct PendingDrag {
    label: String,
    authority: WindowAuthority,
}

impl PendingDrag {
    pub(super) fn claim(
        protocol: &DesktopTauriProtocol,
        label: &str,
    ) -> Result<Self, DesktopWindowChromeError> {
        let authority = protocol
            .authority(label)
            .map_err(|_| Code::Unavailable)?
            .filter(|authority| !authority.closed.is_cancelled())
            .ok_or(Code::Stale)?;
        authority
            .chrome_pending
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Code::Busy)?;
        let pending = Self {
            label: label.to_owned(),
            authority,
        };
        pending.check(protocol)?;
        Ok(pending)
    }

    pub(super) fn check(
        &self,
        protocol: &DesktopTauriProtocol,
    ) -> Result<(), DesktopWindowChromeError> {
        let current = protocol
            .authority(&self.label)
            .map_err(|_| Code::Unavailable)?
            .ok_or(Code::Stale)?;
        if self.authority.closed.is_cancelled()
            || current.closed.is_cancelled()
            || current.binding_id != self.authority.binding_id
        {
            return Err(Code::Stale.into());
        }
        Ok(())
    }

    pub(super) fn run(
        self,
        protocol: &DesktopTauriProtocol,
        request: DesktopWindowChromeRequest,
        start_drag: impl FnOnce() -> Result<(), ()>,
    ) -> Result<DesktopWindowChromeReceipt, DesktopWindowChromeError> {
        self.check(protocol)?;
        // No authority/registry lock survives check(). AppKit drag may run a nested event loop.
        match request.action {
            DesktopWindowChromeAction::StartDrag => {
                start_drag().map_err(|()| Code::Unavailable)?;
            }
        }
        self.check(protocol)?;
        Ok(DesktopWindowChromeReceipt { accepted: true })
    }
}

impl Drop for PendingDrag {
    fn drop(&mut self) {
        self.authority
            .chrome_pending
            .store(false, Ordering::Release);
    }
}

#[tauri::command]
pub(super) async fn wrok_bot_window_chrome(
    webview: Webview,
    protocol: State<'_, Arc<DesktopTauriProtocolSlot>>,
    request: Option<Value>,
) -> Result<DesktopWindowChromeReceipt, DesktopWindowChromeError> {
    let request = decode(request)?;
    let (main, scheme) = product_boundary().ok_or(Code::Unsupported)?;
    let protocol = protocol.get().map_err(|_| Code::Unavailable)?;
    let window = webview.window();
    let url = webview.url().map_err(|_| Code::Unavailable)?;
    validate_invoker(webview.label(), window.label(), &url, main, scheme)?;
    let pending = PendingDrag::claim(&protocol, webview.label())?;
    let executing_webview = webview.clone();
    let (completed, completion) = tokio::sync::oneshot::channel();
    webview
        .run_on_main_thread(move || {
            let outcome = (|| {
                let current_url = executing_webview.url().map_err(|_| Code::Unavailable)?;
                let window = executing_webview.window();
                validate_invoker(
                    executing_webview.label(),
                    window.label(),
                    &current_url,
                    main,
                    scheme,
                )?;
                pending.run(&protocol, request, || {
                    window.start_dragging().map_err(|_| ())
                })
            })();
            // The consumed permit (including early refusal) drops before acknowledgement.
            let _ = completed.send(outcome);
        })
        .map_err(|_| Code::Unavailable)?;
    completion.await.map_err(|_| Code::Unavailable)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn window_chrome_decoder_rejects_every_non_drag_shape_with_fixed_code() {
        assert_eq!(
            decode(Some(json!({"action":"start_drag"}))).unwrap().action,
            DesktopWindowChromeAction::StartDrag
        );
        for input in [
            None,
            Some(Value::Null),
            Some(json!([])),
            Some(json!({})),
            Some(json!({"action":true})),
            Some(json!({"action":"toggle_maximize"})),
            Some(json!({"action":{"method":"start_drag"}})),
            Some(json!({"action":"start_drag","label":"other"})),
            Some(json!({"action":"start_drag","coordinates":[1,2]})),
            Some(json!({"action":"start_drag","auth":{"admin":true}})),
            Some(json!({"action":"x".repeat(100_000)})),
        ] {
            assert_eq!(decode(input), Err(Code::Invalid.into()));
        }
    }

    #[test]
    fn window_chrome_invoker_is_exactly_main_on_local_product_origin() {
        let local = tauri::Url::parse("wrokbot://localhost/settings?tab=one#top").unwrap();
        assert!(validate_invoker("main", "main", &local, "main", "wrokbot").is_ok());
        for (webview, window, url) in [
            ("child", "main", "wrokbot://localhost/"),
            ("main", "other", "wrokbot://localhost/"),
            ("other", "other", "wrokbot://localhost/"),
            ("main", "main", "https://localhost/"),
            ("main", "main", "wrokbot://elsewhere/"),
            ("main", "main", "wrokbot://user@localhost/"),
            ("main", "main", "wrokbot://localhost:1234/"),
        ] {
            assert_eq!(
                validate_invoker(
                    webview,
                    window,
                    &tauri::Url::parse(url).unwrap(),
                    "main",
                    "wrokbot"
                ),
                Err(Code::Denied.into())
            );
        }
    }
}
