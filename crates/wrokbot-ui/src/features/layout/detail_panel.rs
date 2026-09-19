//! URL-owned inline detail panel projection.

use leptos::{ev::KeyboardEvent, prelude::*};

use crate::i18n::{t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{IconSize, IconView};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PanelPhase {
    Closed,
    #[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
    Opening,
    Open,
    #[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
    Closing,
}

impl PanelPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Opening => "opening",
            Self::Open => "open",
            Self::Closing => "closing",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnimationPath {
    Idle,
    #[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
    Reduced,
    #[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
    Waapi,
    #[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
    CssFallback,
}

impl AnimationPath {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Reduced => "reduced",
            Self::Waapi => "waapi",
            Self::CssFallback => "css-fallback",
        }
    }
}

/// Flex row that owns a primary pane and an optional DetailPanel.
#[component]
pub fn DetailPanelLayout(children: Children) -> impl IntoView {
    view! { <div class="ob-detail-layout">{children()}</div> }
}

/// Flexible primary pane beside a DetailPanel.
#[component]
pub fn DetailPanelMain(children: Children) -> impl IntoView {
    view! { <div class="ob-detail-main">{children()}</div> }
}

/// Fixed 360px inline detail pane. The caller owns URL/search state through `open`.
#[component]
pub fn DetailPanel(
    /// Stable DOM token used to derive the heading relationship.
    #[prop(into)]
    id: String,
    /// Visible, localized panel title.
    #[prop(into)]
    title: TextProp,
    /// Caller-owned URL/search projection.
    #[prop(into)]
    open: MaybeProp<bool>,
    /// Stable element that receives focus after the close request is applied.
    #[prop(into)]
    return_focus_id: String,
    /// Close request; the caller updates URL/search state.
    #[prop(into)]
    on_close: UnsyncCallback<()>,
    children: ChildrenFn,
) -> impl IntoView {
    assert_dom_id(&id);
    assert_dom_id(&return_focus_id);
    assert!(
        !title.get().trim().is_empty(),
        "detail title must be nonempty"
    );
    let i18n = use_i18n();
    let heading_id = format!("{id}-title");
    let labelled_by = heading_id.clone();
    let title_text = title;
    let detail_children = children;
    let initially_open = open.get_untracked().unwrap_or(false);
    let present = RwSignal::new(initially_open);
    let phase = RwSignal::new(if initially_open {
        PanelPhase::Open
    } else {
        PanelPhase::Closed
    });
    let slot_ref = NodeRef::<leptos::html::Div>::new();
    let animation_path = RwSignal::new(AnimationPath::Idle);
    let animation_duration_ms = RwSignal::new(0_u32);
    install_panel_lifecycle(
        open,
        present,
        phase,
        animation_path,
        animation_duration_ms,
        slot_ref,
    );
    let click_focus_id = return_focus_id.clone();
    let key_focus_id = return_focus_id;
    let click_close = on_close;
    let key_close = on_close;
    view! {
        <div
            class="ob-detail-slot"
            data-state=move || phase.get().as_str()
            data-animation-path=move || animation_path.get().as_str()
            data-animation-duration-ms=move || animation_duration_ms.get().to_string()
            hidden=move || !present.get()
            node_ref=slot_ref
        >
            <aside
                id=id
                class="ob-detail-panel"
                data-state=move || phase.get().as_str()
                aria-labelledby=labelled_by
            >
                <header class="ob-detail-header">
                    <h2 id=heading_id>{move || title_text.get()}</h2>
                    <button
                        type="button"
                        class="ob-detail-close"
                        aria-label=move || t_string!(i18n, common.close).to_owned()
                        on:click=move |_| {
                            request_close(click_close, click_focus_id.clone());
                        }
                        on:keydown=move |event: KeyboardEvent| {
                            if matches!(event.key().as_str(), "Enter" | " ") {
                                event.prevent_default();
                                request_close(key_close, key_focus_id.clone());
                            }
                        }
                    >
                        <IconView icon=Icon::X size=IconSize::Navigation />
                    </button>
                </header>
                {move || {
                    if present.get() {
                        let children = detail_children.clone();
                        view! { <div class="ob-detail-body">{children()}</div> }.into_any()
                    } else {
                        ().into_any()
                    }
                }}
            </aside>
        </div>
    }
}

fn install_panel_lifecycle(
    open: MaybeProp<bool>,
    present: RwSignal<bool>,
    phase: RwSignal<PanelPhase>,
    animation_path: RwSignal<AnimationPath>,
    animation_duration_ms: RwSignal<u32>,
    slot_ref: NodeRef<leptos::html::Div>,
) {
    #[cfg(target_arch = "wasm32")]
    {
        let previous_open = StoredValue::new(open.get_untracked().unwrap_or(false));
        let generation = StoredValue::new(0_u64);
        Effect::new(move |_| {
            let desired_open = open.get().unwrap_or(false);
            if previous_open.get_value() == desired_open {
                return;
            }
            previous_open.set_value(desired_open);

            generation.update_value(|value| *value = value.wrapping_add(1));
            let transition_generation = generation.get_value();
            if desired_open {
                present.set(true);
                phase.set(PanelPhase::Opening);
                leptos::task::spawn_local_scoped_with_cancellation(async move {
                    leptos::task::tick().await;
                    if let Some(slot) = slot_ref.get() {
                        animate_slot(&slot, true, animation_path, animation_duration_ms).await;
                    }
                    if generation.get_value() == transition_generation
                        && open.get_untracked().unwrap_or(false)
                    {
                        phase.set(PanelPhase::Open);
                    }
                });
            } else if present.get_untracked() {
                phase.set(PanelPhase::Closing);
                leptos::task::spawn_local_scoped_with_cancellation(async move {
                    if let Some(slot) = slot_ref.get() {
                        animate_slot(&slot, false, animation_path, animation_duration_ms).await;
                    }
                    if generation.get_value() == transition_generation
                        && !open.get_untracked().unwrap_or(false)
                    {
                        present.set(false);
                        phase.set(PanelPhase::Closed);
                    }
                });
            } else {
                phase.set(PanelPhase::Closed);
            }
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    Effect::new(move |_| {
        let desired_open = open.get().unwrap_or(false);
        present.set(desired_open);
        phase.set(if desired_open {
            PanelPhase::Open
        } else {
            PanelPhase::Closed
        });
        animation_path.set(AnimationPath::Idle);
        animation_duration_ms.set(0);
        let _ = slot_ref;
    });
}

#[cfg(target_arch = "wasm32")]
async fn animate_slot(
    slot: &web_sys::HtmlElement,
    opening: bool,
    animation_path: RwSignal<AnimationPath>,
    animation_duration_ms: RwSignal<u32>,
) {
    cancel_animations(slot);
    let panel_width = format!("{}px", crate::tokens::SIZE_DETAIL_PANEL);
    let duration_token = if opening {
        crate::tokens::MOTION_DURATION_DIALOG_ENTER
    } else {
        crate::tokens::MOTION_DURATION_DIALOG_EXIT
    };
    let duration = if prefers_reduced_motion() {
        0.0
    } else {
        parse_css_duration_ms(duration_token)
            .expect("generated dialog motion duration token must be milliseconds or seconds")
    };
    animation_duration_ms.set(duration.round() as u32);
    if duration <= 0.0 {
        animation_path.set(AnimationPath::Reduced);
        return;
    }
    let easing = if opening {
        crate::tokens::MOTION_EASE_ENTER
    } else {
        crate::tokens::MOTION_EASE_EXIT
    };
    let (from_width, to_width, from_opacity, to_opacity) = if opening {
        ("0px", panel_width.as_str(), "0", "1")
    } else {
        (panel_width.as_str(), "0px", "1", "0")
    };
    let Ok((animation, finished)) = start_waapi_animation(
        slot,
        from_width,
        to_width,
        from_opacity,
        to_opacity,
        duration,
        easing,
    ) else {
        animation_path.set(AnimationPath::CssFallback);
        wait_for_duration(duration).await;
        return;
    };
    animation_path.set(AnimationPath::Waapi);
    let result = wasm_bindgen_futures::JsFuture::from(finished).await;
    cancel_animation(&animation);
    if result.is_err() {
        wait_for_duration(duration).await;
    }
}

#[cfg(target_arch = "wasm32")]
#[allow(clippy::too_many_arguments)]
fn start_waapi_animation(
    slot: &web_sys::HtmlElement,
    from_width: &str,
    to_width: &str,
    from_opacity: &str,
    to_opacity: &str,
    duration: f64,
    easing: &str,
) -> Result<(wasm_bindgen::JsValue, js_sys::Promise), wasm_bindgen::JsValue> {
    use wasm_bindgen::JsCast as _;

    let frames = js_sys::Array::new();
    frames.push(&animation_frame(from_width, from_opacity)?);
    frames.push(&animation_frame(to_width, to_opacity)?);
    let options = js_sys::Object::new();
    js_sys::Reflect::set(&options, &"duration".into(), &duration.into())?;
    js_sys::Reflect::set(&options, &"easing".into(), &easing.into())?;
    js_sys::Reflect::set(&options, &"fill".into(), &"both".into())?;

    let Ok(animate) = js_sys::Reflect::get(slot.as_ref(), &"animate".into())
        .and_then(|value| value.dyn_into::<js_sys::Function>())
    else {
        return Err(wasm_bindgen::JsValue::from_str(
            "Web Animations API unavailable",
        ));
    };
    let animation = animate.call2(slot.as_ref(), frames.as_ref(), options.as_ref())?;
    let finished =
        js_sys::Reflect::get(&animation, &"finished".into())?.dyn_into::<js_sys::Promise>()?;
    Ok((animation, finished))
}

#[cfg(target_arch = "wasm32")]
fn prefers_reduced_motion() -> bool {
    web_sys::window()
        .and_then(|window| {
            window
                .match_media(crate::tokens::MOTION_REDUCED_MEDIA)
                .ok()
                .flatten()
        })
        .is_some_and(|query| query.matches())
}

#[cfg(target_arch = "wasm32")]
async fn wait_for_duration(duration_ms: f64) {
    use wasm_bindgen::{JsCast as _, closure::Closure};

    if duration_ms <= 0.0 {
        return;
    }
    let Some(window) = web_sys::window() else {
        return;
    };
    let promise = js_sys::Promise::new(&mut |resolve, reject| {
        let callback = Closure::once_into_js(move || {
            _ = resolve.call0(&wasm_bindgen::JsValue::UNDEFINED);
        });
        if let Err(error) = window.set_timeout_with_callback_and_timeout_and_arguments_0(
            callback.unchecked_ref(),
            duration_ms.ceil().min(10_000.0) as i32,
        ) {
            _ = reject.call1(&wasm_bindgen::JsValue::UNDEFINED, &error);
        }
    });
    _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

#[cfg(target_arch = "wasm32")]
fn animation_frame(
    width: &str,
    opacity: &str,
) -> Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue> {
    let frame = js_sys::Object::new();
    js_sys::Reflect::set(&frame, &"width".into(), &width.into())?;
    js_sys::Reflect::set(&frame, &"flexBasis".into(), &width.into())?;
    js_sys::Reflect::set(&frame, &"opacity".into(), &opacity.into())?;
    Ok(frame.into())
}

#[cfg(target_arch = "wasm32")]
fn cancel_animations(slot: &web_sys::HtmlElement) {
    use wasm_bindgen::JsCast as _;

    let Ok(get_animations) = js_sys::Reflect::get(slot.as_ref(), &"getAnimations".into())
        .and_then(|value| value.dyn_into::<js_sys::Function>())
    else {
        return;
    };
    let Ok(animations) = get_animations
        .call0(slot.as_ref())
        .and_then(|value| value.dyn_into::<js_sys::Array>())
    else {
        return;
    };
    for animation in animations.iter() {
        cancel_animation(&animation);
    }
}

#[cfg(target_arch = "wasm32")]
fn cancel_animation(animation: &wasm_bindgen::JsValue) {
    use wasm_bindgen::JsCast as _;

    if let Ok(cancel) = js_sys::Reflect::get(animation, &"cancel".into())
        .and_then(|value| value.dyn_into::<js_sys::Function>())
    {
        _ = cancel.call0(animation);
    }
}

#[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
fn parse_css_duration_ms(value: &str) -> Option<f64> {
    let value = value.trim();
    if let Some(milliseconds) = value.strip_suffix("ms") {
        milliseconds.trim().parse().ok()
    } else if let Some(seconds) = value.strip_suffix('s') {
        seconds
            .trim()
            .parse::<f64>()
            .ok()
            .map(|value| value * 1000.0)
    } else {
        None
    }
}

fn request_close(on_close: UnsyncCallback<()>, return_focus_id: String) {
    on_close.run(());
    focus_later(return_focus_id);
}

fn focus_later(id: String) {
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        use wasm_bindgen::JsCast as _;

        leptos::task::tick().await;
        let target = web_sys::window()
            .and_then(|window| window.document())
            .and_then(|document| document.get_element_by_id(&id))
            .and_then(|element| element.dyn_into::<web_sys::HtmlElement>().ok());
        if let Some(target) = target {
            _ = target.focus();
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = id;
}

fn assert_dom_id(id: &str) {
    assert!(
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "DetailPanel id must be one bounded DOM token"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detail_panel_id_is_one_dom_token() {
        assert_dom_id("credential-detail");
        assert_eq!(PanelPhase::Opening.as_str(), "opening");
        assert_eq!(PanelPhase::Closing.as_str(), "closing");
        assert_eq!(AnimationPath::Reduced.as_str(), "reduced");
        assert_eq!(AnimationPath::Waapi.as_str(), "waapi");
        assert_eq!(AnimationPath::CssFallback.as_str(), "css-fallback");
        assert_eq!(parse_css_duration_ms("240ms"), Some(240.0));
        assert_eq!(parse_css_duration_ms("0.16s"), Some(160.0));
        assert_eq!(parse_css_duration_ms("forever"), None);
    }

    #[test]
    #[should_panic(expected = "bounded DOM token")]
    fn detail_panel_rejects_selector_injection() {
        assert_dom_id("detail'] *");
    }
}
