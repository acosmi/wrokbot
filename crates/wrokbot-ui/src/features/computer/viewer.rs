//! Same-origin ScreenSession viewer. No frame queue, ticket URL, renderer-issued input, or authority guesses.
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
use crate::{
    features::computer::ComputerPlaceholder,
    i18n::{t, t_string, use_i18n},
    primitives::{Button, ButtonSize, ButtonVariant},
};
use leptos::prelude::*;
use openbot_contracts::screen::ScreenSessionTarget;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScreenStatus {
    Waiting,
    Connecting,
    Live,
    Disconnected,
    Stalled,
    Invalidated,
    Unavailable,
    Failed,
}
#[derive(Clone, Copy)]
struct ViewerState {
    status: RwSignal<ScreenStatus>,
    src: RwSignal<Option<String>>,
    decoding: RwSignal<bool>,
    generation: RwSignal<u64>,
    sequence: RwSignal<u64>,
    pending_sequence: RwSignal<u64>,
    paint_failed: RwSignal<Option<ScreenSessionTarget>>,
    decode_started: RwSignal<f64>,
}
impl ViewerState {
    fn clear(self, status: ScreenStatus) {
        self.status.set(status);
        self.src.set(None);
        self.decoding.set(false);
        self.sequence.set(0);
    }
}

#[component]
pub(crate) fn ScreenViewer(
    target: Signal<Option<ScreenSessionTarget>>,
    active: Signal<bool>,
) -> impl IntoView {
    let i18n = use_i18n();
    let state = ViewerState {
        status: RwSignal::new(ScreenStatus::Waiting),
        src: RwSignal::new(None),
        decoding: RwSignal::new(false),
        generation: RwSignal::new(0),
        sequence: RwSignal::new(0),
        pending_sequence: RwSignal::new(0),
        paint_failed: RwSignal::new(None),
        decode_started: RwSignal::new(0.0),
    };
    let reload = RwSignal::new(0_u64);
    install_viewer(target, active, reload, state);
    let can_retry = Signal::derive(move || {
        target.get().is_some()
            && matches!(
                state.status.get(),
                ScreenStatus::Failed
                    | ScreenStatus::Disconnected
                    | ScreenStatus::Invalidated
                    | ScreenStatus::Stalled
            )
    });
    view! {
        <Show when=move || state.src.get().is_some() fallback=move || view! { <ComputerPlaceholder/> }>
            <div class="ob-computer-placeholder" data-frame-generation=move || state.generation.get() data-frame-sequence=move || state.sequence.get()>
                <img class="ob-computer-placeholder-art object-contain" src=move || state.src.get() alt=move || t_string!(i18n, computer.screen).to_owned()
                    on:load=move |event| {
                        #[cfg(target_arch = "wasm32")]
                        if current_image_event(&event, state) { state.sequence.set(state.pending_sequence.get_untracked()); state.decoding.set(false); state.status.set(ScreenStatus::Live); }
                        #[cfg(not(target_arch = "wasm32"))] let _ = event;
                    }
                    on:error=move |event| {
                        #[cfg(target_arch = "wasm32")]
                        if current_image_event(&event, state) { state.paint_failed.set(target.get_untracked()); }
                        #[cfg(not(target_arch = "wasm32"))] let _ = event;
                    }/>
            </div>
        </Show>
        <p class="ob-page-intro" role="status">{move || match state.status.get() {
            ScreenStatus::Waiting => t_string!(i18n, computer.no_target_body).to_owned(),
            ScreenStatus::Connecting => t_string!(i18n, computer.screen_connecting).to_owned(),
            ScreenStatus::Live => t_string!(i18n, computer.screen_live).to_owned(),
            ScreenStatus::Stalled => t_string!(i18n, computer.screen_stalled).to_owned(),
            ScreenStatus::Disconnected => t_string!(i18n, computer.screen_disconnected).to_owned(),
            ScreenStatus::Invalidated => t_string!(i18n, computer.screen_invalidated).to_owned(),
            ScreenStatus::Unavailable => t_string!(i18n, computer.screen_unavailable).to_owned(),
            ScreenStatus::Failed => t_string!(i18n, computer.screen_failed).to_owned(),
        }}</p>
        <Show when=move || can_retry.get()><Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=move |_| { state.paint_failed.set(None); reload.update(|n| *n = n.saturating_add(1)); }>{move || t!(i18n, common.retry)}</Button></Show>
    }
}

fn screen_url(origin: &str) -> Option<String> {
    let mut url = url::Url::parse(origin).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return None;
    }
    let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
    url.set_scheme(scheme).ok()?;
    url.set_path("/api/screen");
    Some(url.to_string())
}

fn install_viewer(
    target: Signal<Option<ScreenSessionTarget>>,
    active: Signal<bool>,
    reload: RwSignal<u64>,
    state: ViewerState,
) {
    #[cfg(target_arch = "wasm32")]
    {
        let visible = RwSignal::new(true);
        let visibility = StoredValue::new_local(VisibilityListener::new(visible));
        on_cleanup(move || {
            visibility.update_value(|value| {
                value.take();
            })
        });
        Effect::new(move |_| {
            reload.track();
            let selected = target.get();
            let enabled = active.get() && visible.get();
            if selected.is_some() && state.paint_failed.get() == selected {
                state.clear(ScreenStatus::Failed);
                return;
            }
            state.clear(ScreenStatus::Waiting);
            if !enabled {
                return;
            }
            let Some(selected) = selected else {
                return;
            };
            if crate::api::desktop_transport::is_tauri_host() {
                state.clear(ScreenStatus::Unavailable);
                return;
            }
            let connection = StoredValue::new_local(None::<ScreenConnection>);
            on_cleanup(move || {
                connection.update_value(|value| {
                    value.take();
                })
            });
            state.status.set(ScreenStatus::Connecting);
            state.generation.set(selected.computer_generation.get());
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                match connect_screen(selected, state).await {
                    Ok(socket) => {
                        let last = socket.last_frame_at.clone();
                        connection.set_value(Some(socket));
                        loop {
                            let promise = js_sys::Promise::new(&mut |resolve, _| {
                                if let Some(window) = web_sys::window() {
                                    _ = window
                                        .set_timeout_with_callback_and_timeout_and_arguments_0(
                                            &resolve, 250,
                                        );
                                }
                            });
                            _ = wasm_bindgen_futures::JsFuture::from(promise).await;
                            if matches!(
                                state.status.get_untracked(),
                                ScreenStatus::Disconnected
                                    | ScreenStatus::Invalidated
                                    | ScreenStatus::Failed
                            ) {
                                connection.update_value(|value| {
                                    value.take();
                                });
                                break;
                            }
                            let now = monotonic_ms();
                            if now - last.get() > 2_000.0
                                || (state.decoding.get_untracked()
                                    && now - state.decode_started.get_untracked() > 2_000.0)
                            {
                                state.clear(ScreenStatus::Stalled);
                                connection.update_value(|value| {
                                    value.take();
                                });
                                break;
                            }
                        }
                    }
                    Err(status) => state.clear(status),
                }
            });
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (target, active, reload);
        state.clear(ScreenStatus::Unavailable);
    }
}

#[cfg(target_arch = "wasm32")]
struct VisibilityListener {
    document: web_sys::Document,
    callback: wasm_bindgen::closure::Closure<dyn FnMut(web_sys::Event)>,
}
#[cfg(target_arch = "wasm32")]
impl VisibilityListener {
    fn new(visible: RwSignal<bool>) -> Option<Self> {
        use wasm_bindgen::JsCast as _;
        let document = web_sys::window()?.document()?;
        visible.set(document.visibility_state() == web_sys::VisibilityState::Visible);
        let observed = document.clone();
        let callback = wasm_bindgen::closure::Closure::wrap(Box::new(move |_: web_sys::Event| {
            visible.set(observed.visibility_state() == web_sys::VisibilityState::Visible);
        }) as Box<dyn FnMut(_)>);
        document
            .add_event_listener_with_callback("visibilitychange", callback.as_ref().unchecked_ref())
            .ok()?;
        Some(Self { document, callback })
    }
}
#[cfg(target_arch = "wasm32")]
impl Drop for VisibilityListener {
    fn drop(&mut self) {
        use wasm_bindgen::JsCast as _;
        _ = self.document.remove_event_listener_with_callback(
            "visibilitychange",
            self.callback.as_ref().unchecked_ref(),
        );
    }
}

#[cfg(target_arch = "wasm32")]
struct ObjectUrls {
    current: Option<String>,
}
#[cfg(target_arch = "wasm32")]
impl ObjectUrls {
    fn replace(&mut self, next: Option<String>) {
        if let Some(old) = self.current.take() {
            _ = web_sys::Url::revoke_object_url(&old);
        }
        self.current = next;
    }
}
#[cfg(target_arch = "wasm32")]
impl Drop for ObjectUrls {
    fn drop(&mut self) {
        self.replace(None);
    }
}

#[cfg(target_arch = "wasm32")]
struct ScreenConnection {
    socket: web_sys::WebSocket,
    _message: wasm_bindgen::closure::Closure<dyn FnMut(web_sys::MessageEvent)>,
    _close: wasm_bindgen::closure::Closure<dyn FnMut(web_sys::CloseEvent)>,
    _error: wasm_bindgen::closure::Closure<dyn FnMut(web_sys::Event)>,
    urls: std::rc::Rc<std::cell::RefCell<ObjectUrls>>,
    last_frame_at: std::rc::Rc<std::cell::Cell<f64>>,
}
#[cfg(target_arch = "wasm32")]
impl Drop for ScreenConnection {
    fn drop(&mut self) {
        self.socket.set_onmessage(None);
        self.socket.set_onclose(None);
        self.socket.set_onerror(None);
        _ = self.socket.close();
        self.urls.borrow_mut().replace(None);
    }
}

#[cfg(target_arch = "wasm32")]
async fn connect_screen(
    target: ScreenSessionTarget,
    state: ViewerState,
) -> Result<ScreenConnection, ScreenStatus> {
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };
    use wasm_bindgen::{JsCast as _, closure::Closure};
    use web_sys::{RequestCache, RequestCredentials, RequestRedirect};
    let origin = web_sys::window()
        .ok_or(ScreenStatus::Unavailable)?
        .location()
        .origin()
        .map_err(|_| ScreenStatus::Unavailable)?;
    let url = screen_url(&origin).ok_or(ScreenStatus::Unavailable)?;
    let response = gloo_net::http::Request::post("/api/screen/sessions")
        .cache(RequestCache::NoStore)
        .credentials(RequestCredentials::SameOrigin)
        .redirect(RequestRedirect::Error)
        .json(&target)
        .map_err(|_| ScreenStatus::Failed)?
        .send()
        .await
        .map_err(|_| ScreenStatus::Failed)?;
    if response.status() != 200 {
        return Err(match response.status() {
            401 | 403 | 404 => ScreenStatus::Invalidated,
            503 => ScreenStatus::Unavailable,
            _ => ScreenStatus::Failed,
        });
    }
    let ticket = response
        .json::<openbot_contracts::screen::ScreenSessionTicket>()
        .await
        .map_err(|_| ScreenStatus::Failed)?;
    let Some(token) = ticket.ticket_protocol().strip_prefix("obot_screen_") else {
        return Err(ScreenStatus::Failed);
    };
    if ticket.base_protocol() != "openbot.screen.v1"
        || token.len() != 32
        || !token.bytes().all(|b| b.is_ascii_hexdigit())
        || (ticket.expires_at_ms() as f64) <= js_sys::Date::now()
    {
        return Err(ScreenStatus::Invalidated);
    }
    let protocols = js_sys::Array::new();
    protocols.push(&ticket.base_protocol().into());
    protocols.push(&ticket.ticket_protocol().into());
    let socket = web_sys::WebSocket::new_with_str_sequence(&url, &protocols)
        .map_err(|_| ScreenStatus::Failed)?;
    drop(ticket); // never retained in renderer signals, URL, logs, or retry state
    socket.set_binary_type(web_sys::BinaryType::Arraybuffer);
    let urls = Rc::new(RefCell::new(ObjectUrls { current: None }));
    let last = Rc::new(Cell::new(0_u64));
    let last_frame_at = Rc::new(Cell::new(monotonic_ms()));
    let message_time = last_frame_at.clone();
    let message_socket = socket.clone();
    let message_urls = urls.clone();
    let generation = target.computer_generation.get();
    let message = Closure::wrap(Box::new(move |event: web_sys::MessageEvent| {
        let reject = || {
            state.clear(ScreenStatus::Failed);
            message_urls.borrow_mut().replace(None);
            _ = message_socket.close_with_code(4000);
        };
        if message_socket.protocol() != "openbot.screen.v1" {
            reject();
            return;
        }
        let Ok(buffer) = event.data().dyn_into::<js_sys::ArrayBuffer>() else {
            reject();
            return;
        };
        if buffer.byte_length() as usize > openbot_contracts::engine::MAX_ENGINE_IMAGE_BYTES + 68 {
            reject();
            return;
        }
        let bytes = js_sys::Uint8Array::new(&buffer).to_vec();
        let Ok(frame) = super::frame::decode_frame(&bytes, generation, last.get()) else {
            reject();
            return;
        };
        last.set(frame.sequence);
        message_time.set(monotonic_ms());
        // Backpressure at the renderer boundary: no MPSC queue or retained pending frames.
        if state.decoding.get_untracked() {
            return;
        }
        let data = js_sys::Uint8Array::from(frame.jpeg);
        let parts = js_sys::Array::new();
        parts.push(&data);
        let options = web_sys::BlobPropertyBag::new();
        options.set_type("image/jpeg");
        let Ok(blob) = web_sys::Blob::new_with_u8_array_sequence_and_options(&parts, &options)
        else {
            reject();
            return;
        };
        let Ok(src) = web_sys::Url::create_object_url_with_blob(&blob) else {
            reject();
            return;
        };
        message_urls.borrow_mut().replace(Some(src.clone()));
        state.pending_sequence.set(frame.sequence);
        state.decode_started.set(monotonic_ms());
        state.decoding.set(true);
        state.src.set(Some(src));
    }) as Box<dyn FnMut(_)>);
    socket.set_onmessage(Some(message.as_ref().unchecked_ref()));
    let close_urls = urls.clone();
    let close = Closure::wrap(Box::new(move |event: web_sys::CloseEvent| {
        state.clear(if state.status.get_untracked() == ScreenStatus::Failed {
            ScreenStatus::Failed
        } else if event.code() == 1008 {
            ScreenStatus::Invalidated
        } else {
            ScreenStatus::Disconnected
        });
        close_urls.borrow_mut().replace(None);
    }) as Box<dyn FnMut(_)>);
    socket.set_onclose(Some(close.as_ref().unchecked_ref()));
    let error_urls = urls.clone();
    let error_socket = socket.clone();
    let error = Closure::wrap(Box::new(move |_: web_sys::Event| {
        state.clear(ScreenStatus::Failed);
        error_urls.borrow_mut().replace(None);
        _ = error_socket.close();
    }) as Box<dyn FnMut(_)>);
    socket.set_onerror(Some(error.as_ref().unchecked_ref()));
    Ok(ScreenConnection {
        socket,
        _message: message,
        _close: close,
        _error: error,
        urls,
        last_frame_at,
    })
}

#[cfg(target_arch = "wasm32")]
fn monotonic_ms() -> f64 {
    web_sys::window()
        .and_then(|w| w.performance())
        .map_or_else(js_sys::Date::now, |p| p.now())
}
#[cfg(target_arch = "wasm32")]
fn current_image_event(event: &web_sys::Event, state: ViewerState) -> bool {
    use wasm_bindgen::JsCast as _;
    event
        .target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlImageElement>().ok())
        .is_some_and(|img| state.src.get_untracked().as_deref() == Some(img.current_src().as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn screen_connection_url_never_contains_a_ticket_or_query() {
        assert_eq!(
            screen_url("https://example.test"),
            Some("wss://example.test/api/screen".into())
        );
        assert_eq!(
            screen_url("http://127.0.0.1:39027"),
            Some("ws://127.0.0.1:39027/api/screen".into())
        );
        for origin in [
            "https://user@example.test",
            "https://example.test/?ticket=secret",
            "https://example.test/#fragment",
            "file:///private/path",
            "https://example.test/path",
        ] {
            assert!(screen_url(origin).is_none());
        }
    }
}

#[cfg(feature = "design-gallery")]
#[component]
pub(crate) fn ScreenFixturePreview() -> impl IntoView {
    use openbot_contracts::ids::{ComputerGeneration, ComputerId, TabId};
    let mode = RwSignal::new("valid".to_owned());
    let enabled = RwSignal::new(false);
    let target = Signal::derive(move || {
        Some(ScreenSessionTarget {
            computer_id: ComputerId::new("screen-fixture"),
            computer_generation: ComputerGeneration::new(7),
            tab_id: TabId::new(mode.get()),
        })
    });
    view! { <section class="ob-page" id="screen-fixture-preview"><h2>"Screen transport fixture"</h2><p>"Development fixture only. No production computer is connected."</p>
        <Button on_activate=move |_| enabled.update(|v| *v = !*v)>{move || if enabled.get() {"Pause viewer"}else{"Start viewer"}}</Button>
        <div class="ob-skill-chips">{["valid","oversize","stale-generation","stall"].into_iter().map(|name|view! {<Button variant=ButtonVariant::Ghost on_activate=move |_| {mode.set(name.to_owned());enabled.set(true);}>{name}</Button>}).collect_view()}</div>
        <ScreenViewer target active=Signal::derive(move || enabled.get())/>
    </section> }
}
