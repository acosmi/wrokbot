//! Opaque-origin Web sandbox for browser-authored component source.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use leptos::html;
use leptos::prelude::*;
use openbot_contracts::sandboxed::{
    PublishedSandboxedComponent, SANDBOXED_COMPONENT_CONFIRMATION, is_sandboxed_component_name,
};
use serde_json::Value;

#[cfg(target_arch = "wasm32")]
use crate::api::load_published_sandboxed_components;
use crate::i18n::{t, t_string, use_i18n};

use super::RefusedCard;

/// The complete iframe sandbox token set; absence of every other token is security-relevant.
pub const SANDBOX_IFRAME_POLICY: &str = "allow-scripts";
const SANDBOX_RUNNER_PATH: &str = "/sandbox/runner";
const MAX_SANDBOX_FRAGMENT_BYTES: usize = 2 * 1024 * 1024;
#[cfg(target_arch = "wasm32")]
const CHANNEL_INIT_KIND: &str = "openbot_sandbox_init";
#[cfg(target_arch = "wasm32")]
const CHANNEL_READY_KIND: &str = "ready";
#[cfg(target_arch = "wasm32")]
const SANDBOX_START_TIMEOUT_MS: i32 = 2_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SandboxRenderState {
    #[default]
    Pending,
    Ready,
    Failed,
}

/// Render one published source/argument pair. Custom schemes never create an iframe.
#[component]
pub fn SandboxedComponentFrame(
    component: PublishedSandboxedComponent,
    arguments: Value,
    #[prop(into)] title: String,
) -> AnyView {
    let i18n = use_i18n();
    if !current_host_allows_web_sandbox() {
        let preview = argument_preview(&arguments);
        return view! {
            <div>
                <RefusedCard title reason=t_string!(i18n, gallery.sandbox_desktop_unavailable).to_owned()/>
                <details class="ob-workspace-event">
                    <summary>{move || t!(i18n, gallery.sandbox_readonly_arguments)}</summary>
                    <pre class="ob-transcript-text">{preview}</pre>
                </details>
            </div>
        }.into_any();
    }

    #[cfg(target_arch = "wasm32")]
    let (render_id, capability) = match (random_hex_token(), random_hex_token()) {
        (Ok(render_id), Ok(capability)) => (render_id, capability),
        _ => {
            return view! {
                <RefusedCard
                    title
                    reason=t_string!(i18n, gallery.sandbox_failed).to_owned()
                />
            }
            .into_any();
        }
    };
    #[cfg(not(target_arch = "wasm32"))]
    let (render_id, capability) = ("11".repeat(32), "00".repeat(32));

    let runner_url = match build_sandbox_url(&component, &arguments, &render_id, &capability) {
        Ok(url) => url,
        Err(()) => {
            return view! {
                <RefusedCard
                    title
                    reason=t_string!(i18n, gallery.sandbox_failed).to_owned()
                />
            }
            .into_any();
        }
    };
    let frame_ref = NodeRef::<html::Iframe>::new();
    let state = RwSignal::new(SandboxRenderState::Pending);
    let load_phase = StoredValue::new(0_u8);
    let runner_location = StoredValue::new(runner_url);
    let channel = StoredValue::new_local(None::<SandboxChannel>);
    #[cfg(target_arch = "wasm32")]
    let expected_capability = StoredValue::new(capability);
    on_cleanup(move || {
        channel.update_value(|channel| {
            if let Some(channel) = channel.take() {
                channel.close();
            }
        });
    });
    let on_load = move |_| {
        match load_phase.get_value() {
            0 => {
                load_phase.set_value(1);
                if let Some(frame) = frame_ref.get() {
                    frame.set_src(&runner_location.get_value());
                } else {
                    state.set(SandboxRenderState::Failed);
                }
                return;
            }
            1 => load_phase.set_value(2),
            _ => return,
        }
        #[cfg(target_arch = "wasm32")]
        match install_one_time_channel(frame_ref, expected_capability.get_value(), state) {
            Ok(installed_channel) => channel.set_value(Some(installed_channel)),
            Err(()) => state.set(SandboxRenderState::Failed),
        }
        #[cfg(not(target_arch = "wasm32"))]
        state.set(SandboxRenderState::Ready);
    };
    let failure_title = title.clone();

    view! {
        <div class="ob-sandbox-frame" data-state=move || match state.get() {
            SandboxRenderState::Pending => "pending",
            SandboxRenderState::Ready => "ready",
            SandboxRenderState::Failed => "failed",
        }>
            <Show when=move || state.get() == SandboxRenderState::Pending>
                <p class="ob-loading" role="status">{move || t!(i18n, gallery.sandbox_starting)}</p>
            </Show>
            <iframe
                node_ref=frame_ref
                class="ob-sandbox-iframe"
                sandbox=SANDBOX_IFRAME_POLICY
                src="about:blank"
                title=title.clone()
                referrerpolicy="no-referrer"
                hidden=move || state.get() == SandboxRenderState::Failed
                on:load=on_load
            ></iframe>
            <Show when=move || state.get() == SandboxRenderState::Failed>
                <RefusedCard
                    title=failure_title.clone()
                    reason=t_string!(i18n, gallery.sandbox_failed).to_owned()
                />
            </Show>
        </div>
    }
    .into_any()
}

/// Render one completed durable sandboxed provider call from current published source only.
#[component]
pub fn SandboxedConversationComponent(
    name: String,
    arguments: Value,
    result: Option<String>,
    error_code: Option<String>,
) -> AnyView {
    let i18n = use_i18n();
    if !is_sandboxed_component_name(&name)
        || !arguments.is_object()
        || error_code.is_some()
        || result.as_deref() != Some(SANDBOXED_COMPONENT_CONFIRMATION)
    {
        return view! {
            <RefusedCard
                title=name
                reason=t_string!(i18n, gallery.runtime_refused).to_owned()
            />
        }
        .into_any();
    }
    let source = RwSignal::new(None::<PublishedSandboxedComponent>);
    let loading = RwSignal::new(true);
    let failed = RwSignal::new(false);
    let frame_arguments = StoredValue::new(arguments);
    #[cfg(target_arch = "wasm32")]
    {
        let requested_name = name.clone();
        Effect::new(move |_| {
            let requested_name = requested_name.clone();
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                match load_published_sandboxed_components().await {
                    Ok(components) => {
                        let found = components
                            .components
                            .into_iter()
                            .find(|component| component.name == requested_name);
                        failed.set(found.is_none());
                        source.set(found);
                    }
                    Err(_) => failed.set(true),
                }
                loading.set(false);
            });
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        loading.set(false);
        failed.set(true);
    }
    let frame_name = name.clone();
    let frame_title = StoredValue::new(frame_name);
    let failure_name = name;
    view! {
        <Show when=move || loading.get()>
            <p class="ob-loading" role="status">{move || t!(i18n, gallery.sandbox_starting)}</p>
        </Show>
        <Show when=move || !loading.get() && !failed.get() && source.get().is_some()>
            {move || source.get().map(|component| view! {
                <SandboxedComponentFrame
                    component
                    arguments=frame_arguments.get_value()
                    title=frame_title.get_value()
                />
            })}
        </Show>
        <Show when=move || !loading.get() && failed.get()>
            <RefusedCard
                title=failure_name.clone()
                reason=t_string!(i18n, gallery.runtime_refused).to_owned()
            />
        </Show>
    }
    .into_any()
}

/// Static parameters remain inspectable while a host has no authorized render-session source.
fn argument_preview(arguments: &Value) -> String {
    let text = serde_json::to_string_pretty(arguments).unwrap_or_else(|_| "{}".to_owned());
    let mut end = text.len().min(8 * 1024);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    if end == text.len() {
        text
    } else {
        format!("{}\n…", &text[..end])
    }
}

fn build_sandbox_url(
    component: &PublishedSandboxedComponent,
    arguments: &Value,
    render_id: &str,
    capability: &str,
) -> Result<String, ()> {
    if render_id.len() != 64
        || capability.len() != 64
        || !render_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !capability.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !arguments.is_object()
    {
        return Err(());
    }
    let payload = serde_json::to_vec(&serde_json::json!({
        "capability": capability,
        "html": component.html,
        "css": component.css,
        "jsFunctions": component.js_functions,
        "arguments": arguments,
    }))
    .map_err(|_| ())?;
    let fragment = URL_SAFE_NO_PAD.encode(payload);
    if fragment.len() > MAX_SANDBOX_FRAGMENT_BYTES {
        return Err(());
    }
    Ok(format!(
        "{SANDBOX_RUNNER_PATH}?render={render_id}#{fragment}"
    ))
}

#[cfg(any(target_arch = "wasm32", test))]
fn host_protocol_allows_web_sandbox(protocol: &str) -> bool {
    matches!(protocol, "http:" | "https:")
}

fn current_host_allows_web_sandbox() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::window()
            .and_then(|window| window.location().protocol().ok())
            .is_some_and(|protocol| host_protocol_allows_web_sandbox(&protocol))
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        true
    }
}

#[cfg(target_arch = "wasm32")]
struct SandboxChannel {
    port: web_sys::MessagePort,
    timeout_id: i32,
    _message: wasm_bindgen::closure::Closure<dyn FnMut(web_sys::MessageEvent)>,
    _timeout: wasm_bindgen::closure::Closure<dyn FnMut()>,
}

#[cfg(not(target_arch = "wasm32"))]
struct SandboxChannel;

impl SandboxChannel {
    fn close(self) {
        #[cfg(target_arch = "wasm32")]
        {
            self.port.close();
            if let Some(window) = web_sys::window() {
                window.clear_timeout_with_handle(self.timeout_id);
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn random_hex_token() -> Result<String, ()> {
    let mut bytes = [0_u8; 32];
    web_sys::window()
        .ok_or(())?
        .crypto()
        .map_err(|_| ())?
        .get_random_values_with_u8_array(&mut bytes)
        .map_err(|_| ())?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(target_arch = "wasm32")]
fn install_one_time_channel(
    frame_ref: NodeRef<html::Iframe>,
    capability: String,
    state: RwSignal<SandboxRenderState>,
) -> Result<SandboxChannel, ()> {
    use wasm_bindgen::{JsCast, JsValue, closure::Closure};

    let frame = frame_ref.get().ok_or(())?;
    let target = frame.content_window().ok_or(())?;
    let channel = web_sys::MessageChannel::new().map_err(|_| ())?;
    let port = channel.port1();
    let settled_port = port.clone();
    let expected = format!("{CHANNEL_READY_KIND}:{capability}");
    let settled = StoredValue::new(false);
    let message =
        Closure::<dyn FnMut(web_sys::MessageEvent)>::new(move |event: web_sys::MessageEvent| {
            if settled.get_value() {
                return;
            }
            let response = event.data().as_string();
            settled.set_value(true);
            settled_port.close();
            state.set(if response.as_deref() == Some(expected.as_str()) {
                SandboxRenderState::Ready
            } else {
                SandboxRenderState::Failed
            });
        });
    port.set_onmessage(Some(message.as_ref().unchecked_ref()));
    port.start();
    let timeout_settled = settled;
    let timeout_port = port.clone();
    let timeout = Closure::<dyn FnMut()>::new(move || {
        if !timeout_settled.get_value() {
            timeout_settled.set_value(true);
            state.set(SandboxRenderState::Failed);
            timeout_port.close();
        }
    });
    let timeout_id = web_sys::window()
        .ok_or(())?
        .set_timeout_with_callback_and_timeout_and_arguments_0(
            timeout.as_ref().unchecked_ref(),
            SANDBOX_START_TIMEOUT_MS,
        )
        .map_err(|_| ())?;
    let init = JsValue::from_str(&format!("{CHANNEL_INIT_KIND}:{capability}"));
    let transfer = js_sys::Array::new();
    transfer.push(&channel.port2());
    target
        .post_message_with_transfer(&init, "*", &transfer)
        .map_err(|_| ())?;
    Ok(SandboxChannel {
        port,
        timeout_id,
        _message: message,
        _timeout: timeout,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn source(js: &str) -> PublishedSandboxedComponent {
        PublishedSandboxedComponent {
            name: "custom_delivery_eta".to_owned(),
            html: "<h3 id=\"title\"></h3>".to_owned(),
            css: "h3 { color: currentColor; }".to_owned(),
            js_functions: js.to_owned(),
            argument_schema: BTreeMap::new(),
        }
    }

    #[test]
    fn source_and_arguments_stay_in_a_local_fragment_not_the_network_request() {
        let url = build_sandbox_url(
            &source("document.body.dataset.value = '</script><script>escape</script>';"),
            &serde_json::json!({"value":"</script>\u{2028}"}),
            &"11".repeat(32),
            &"ff".repeat(32),
        )
        .unwrap();
        let fragment = url.split_once('#').unwrap().1;
        let payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(fragment).unwrap()).unwrap();
        assert_eq!(payload["capability"], "ff".repeat(32));
        assert_eq!(payload["arguments"]["value"], "</script>\u{2028}");
        assert!(
            payload["jsFunctions"]
                .as_str()
                .unwrap()
                .contains("<script>escape")
        );
        assert!(url.starts_with("/sandbox/runner?render="));
        assert!(!url.split('#').next().unwrap().contains("escape"));
    }

    #[test]
    fn capability_is_per_render_and_custom_schemes_are_refused() {
        let first = build_sandbox_url(
            &source("document.body.dataset.ok='1';"),
            &serde_json::json!({}),
            &"11".repeat(32),
            &"bb".repeat(32),
        )
        .unwrap();
        let second = build_sandbox_url(
            &source("document.body.dataset.ok='1';"),
            &serde_json::json!({}),
            &"22".repeat(32),
            &"dd".repeat(32),
        )
        .unwrap();
        assert_ne!(first, second);
        assert!(host_protocol_allows_web_sandbox("http:"));
        assert!(host_protocol_allows_web_sandbox("https:"));
        for protocol in ["openbot:", "tauri:", "file:", "data:", ""] {
            assert!(!host_protocol_allows_web_sandbox(protocol), "{protocol}");
        }
        assert_eq!(SANDBOX_IFRAME_POLICY.split_whitespace().count(), 1);
        assert_eq!(SANDBOX_IFRAME_POLICY, "allow-scripts");
    }
}
