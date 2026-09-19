//! Streaming transcript scroller that follows the live edge without stealing reading position.

use std::collections::BTreeSet;

use leptos::context::Provider;
use leptos::ev::KeyboardEvent;
use leptos::html;
use leptos::prelude::*;

use crate::icons::Icon;

#[cfg(target_arch = "wasm32")]
use super::timing::schedule_timeout;
use super::{IconSize, IconView};

/// Distance from the natural content end that still counts as being at the live edge.
pub const MESSAGE_SCROLL_EDGE_THRESHOLD_PX: i32 = 8;
/// Amount of the preceding turn retained above a newly anchored user message.
pub const MESSAGE_SCROLL_PREVIOUS_ITEM_PEEK_PX: i32 = 48;
#[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
const AUTOSCROLL_SETTLE_MS: i32 = 180;

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ScrollMode {
    #[default]
    FollowingBottom,
    FreeScrolling,
    AnchoredToMessage,
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[derive(Clone)]
struct MessageScrollerContext {
    id: String,
    aria_label: TextProp,
    auto_scroll: bool,
    preserve_scroll_on_prepend: bool,
    edge_threshold: i32,
    previous_item_peek: i32,
    viewport_ref: NodeRef<html::Div>,
    content_ref: NodeRef<html::Div>,
    spacer_ref: NodeRef<html::Div>,
    can_scroll_end: RwSignal<bool>,
    mode: StoredValue<ScrollMode>,
    anchor_id: StoredValue<Option<String>>,
    handled_anchor_ids: StoredValue<BTreeSet<String>>,
    previous_ids: StoredValue<BTreeSet<String>>,
    previous_first_id: StoredValue<Option<String>>,
    reading_item_id: StoredValue<Option<String>>,
    reading_item_viewport_top: StoredValue<i32>,
    last_scroll_top: StoredValue<i32>,
    spacer_height: StoredValue<i32>,
    programmatic_scroll: StoredValue<bool>,
    programmatic_generation: StoredValue<u64>,
    content_change_pending: StoredValue<bool>,
    initialized: StoredValue<bool>,
    resize_scheduled: StoredValue<bool>,
}

/// Narrow imperative handle for the one production escape hatch used after queue submission.
#[derive(Clone)]
pub struct MessageScrollerController {
    context: MessageScrollerContext,
}

impl MessageScrollerController {
    /// Drop any reading anchor, move to the natural content end, and resume live following.
    pub fn scroll_to_end(&self) -> bool {
        scroll_to_end(self.context.clone())
    }
}

/// Read the nearest scroller controller. Must be called below [`MessageScroller`].
pub fn use_message_scroller() -> MessageScrollerController {
    MessageScrollerController {
        context: message_scroller_context(),
    }
}

/// Own the transcript scroll state and provide it to viewport/content/item/button compounds.
#[component]
pub fn MessageScroller(
    #[prop(into)] id: String,
    #[prop(into)] aria_label: TextProp,
    #[prop(default = true)] auto_scroll: bool,
    #[prop(default = true)] preserve_scroll_on_prepend: bool,
    #[prop(default = MESSAGE_SCROLL_EDGE_THRESHOLD_PX)] edge_threshold: i32,
    #[prop(default = MESSAGE_SCROLL_PREVIOUS_ITEM_PEEK_PX)] previous_item_peek: i32,
    children: Children,
) -> impl IntoView {
    assert_dom_id(&id);
    assert!(
        !aria_label.get().is_empty(),
        "MessageScroller label must be nonempty"
    );
    assert!(
        (0..=256).contains(&edge_threshold),
        "MessageScroller edge threshold must be 0..=256"
    );
    assert!(
        (0..=512).contains(&previous_item_peek),
        "MessageScroller previous item peek must be 0..=512"
    );
    let context = MessageScrollerContext {
        id,
        aria_label,
        auto_scroll,
        preserve_scroll_on_prepend,
        edge_threshold,
        previous_item_peek,
        viewport_ref: NodeRef::new(),
        content_ref: NodeRef::new(),
        spacer_ref: NodeRef::new(),
        can_scroll_end: RwSignal::new(false),
        mode: StoredValue::new(if auto_scroll {
            ScrollMode::FollowingBottom
        } else {
            ScrollMode::FreeScrolling
        }),
        anchor_id: StoredValue::new(None),
        handled_anchor_ids: StoredValue::new(BTreeSet::new()),
        previous_ids: StoredValue::new(BTreeSet::new()),
        previous_first_id: StoredValue::new(None),
        reading_item_id: StoredValue::new(None),
        reading_item_viewport_top: StoredValue::new(0),
        last_scroll_top: StoredValue::new(0),
        spacer_height: StoredValue::new(0),
        programmatic_scroll: StoredValue::new(false),
        programmatic_generation: StoredValue::new(0),
        content_change_pending: StoredValue::new(false),
        initialized: StoredValue::new(false),
        resize_scheduled: StoredValue::new(false),
    };
    install_resize_observer(context.clone());
    view! {
        <Provider value=context>
            <div class="ob-message-scroller">{children()}</div>
        </Provider>
    }
}

/// Focusable scrolling region. Native scrolling remains intact; handlers only observe intent.
#[component]
pub fn MessageScrollerViewport(children: Children) -> impl IntoView {
    let context = message_scroller_context();
    let viewport_id = format!("{}-viewport", context.id);
    let scroll_context = context.clone();
    let wheel_context = context.clone();
    let touch_context = context.clone();
    let key_context = context.clone();
    view! {
        <div
            id=viewport_id
            class="ob-message-scroller-viewport"
            role="region"
            aria-label=move || context.aria_label.get()
            tabindex="0"
            node_ref=context.viewport_ref
            on:scroll=move |_| handle_scroll(scroll_context.clone())
            on:wheel=move |_| handle_user_scroll_intent(wheel_context.clone())
            on:touchmove=move |_| handle_user_scroll_intent(touch_context.clone())
            on:keydown=move |event: KeyboardEvent| {
                if is_scroll_key(&event.key()) {
                    handle_user_scroll_intent(key_context.clone());
                }
            }
        >
            {children()}
        </div>
    }
}

/// Live transcript container. The spacer is layout-only and never enters the accessibility tree.
#[component]
pub fn MessageScrollerContent(
    #[prop(optional, into)] busy: MaybeProp<bool>,
    children: Children,
) -> impl IntoView {
    let context = message_scroller_context();
    let content_id = format!("{}-log", context.id);
    view! {
        <div
            id=content_id
            class="ob-message-scroller-content"
            role="log"
            aria-label=move || context.aria_label.get()
            aria-live="polite"
            aria-relevant="additions text"
            aria-atomic="false"
            aria-busy=move || busy.get().map(explicit_bool)
            node_ref=context.content_ref
        >
            {children()}
            <div
                class="ob-message-scroller-spacer"
                aria-hidden="true"
                hidden
                node_ref=context.spacer_ref
            ></div>
        </div>
    }
}

/// One measurable transcript row. User turns set `scroll_anchor=true`.
#[component]
pub fn MessageScrollerItem(
    #[prop(into)] message_id: String,
    #[prop(optional)] scroll_anchor: bool,
    children: Children,
) -> impl IntoView {
    assert_message_id(&message_id);
    view! {
        <div
            class="ob-message-scroller-item"
            data-message-scroller-item=""
            data-message-id=message_id
            data-scroll-anchor=explicit_bool(scroll_anchor)
        >
            {children()}
        </div>
    }
}

/// Self-managed jump-to-latest capsule. It is absent from focus/AX while already at the end.
#[component]
pub fn MessageScrollerButton(#[prop(into)] aria_label: TextProp) -> impl IntoView {
    assert!(
        !aria_label.get().is_empty(),
        "MessageScrollerButton label must be nonempty"
    );
    let context = message_scroller_context();
    let viewport_id = format!("{}-viewport", context.id);
    let click_context = context.clone();
    view! {
        <button
            type="button"
            class="ob-message-scroller-button"
            data-active=move || explicit_bool(context.can_scroll_end.get())
            aria-controls=viewport_id
            hidden=move || !context.can_scroll_end.get()
            on:click=move |_| {
                scroll_to_end(click_context.clone());
            }
        >
            <IconView icon=Icon::ArrowDown size=IconSize::Inline />
            <span class="ob-visually-hidden">{move || aria_label.get()}</span>
        </button>
    }
}

fn message_scroller_context() -> MessageScrollerContext {
    use_context::<MessageScrollerContext>()
        .expect("MessageScroller compound component must be nested in MessageScroller")
}

const fn explicit_bool(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn is_scroll_key(key: &str) -> bool {
    matches!(
        key,
        "ArrowDown" | "ArrowUp" | "End" | "Home" | "PageDown" | "PageUp" | " "
    )
}

fn assert_dom_id(id: &str) {
    assert!(
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "MessageScroller id must be one bounded DOM token"
    );
}

fn assert_message_id(id: &str) {
    assert!(
        !id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control),
        "MessageScroller message_id must be nonempty, bounded, and control-free"
    );
}

#[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
fn end_distance(
    scroll_height: i32,
    scroll_top: i32,
    client_height: i32,
    spacer_height: i32,
) -> i32 {
    (scroll_height - spacer_height - scroll_top - client_height).max(0)
}

#[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
fn required_spacer_height(target_scroll_top: i32, client_height: i32, natural_height: i32) -> i32 {
    (target_scroll_top + client_height - natural_height).max(0)
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone)]
struct MessageItemElement {
    id: String,
    anchor: bool,
    element: web_sys::Element,
}

#[cfg(target_arch = "wasm32")]
struct ResizeObserverState {
    resize_observer: web_sys::ResizeObserver,
    mutation_observer: Option<web_sys::MutationObserver>,
    _resize_callback:
        wasm_bindgen::closure::Closure<dyn FnMut(js_sys::Array, web_sys::ResizeObserver)>,
    _mutation_callback:
        Option<wasm_bindgen::closure::Closure<dyn FnMut(js_sys::Array, web_sys::MutationObserver)>>,
}

fn install_resize_observer(context: MessageScrollerContext) {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::{JsCast, closure::Closure};

        let installed = StoredValue::new(false);
        let observer_state = StoredValue::new_local(None::<ResizeObserverState>);
        let effect_context = context.clone();
        Effect::new(move |_| {
            if installed.get_value() {
                return;
            }
            let Some(content) = effect_context.content_ref.get() else {
                return;
            };
            let Some(viewport) = effect_context.viewport_ref.get() else {
                return;
            };
            installed.set_value(true);
            note_content_change(effect_context.clone());
            let resize_context = effect_context.clone();
            let resize_callback =
                Closure::<dyn FnMut(js_sys::Array, web_sys::ResizeObserver)>::new(move |_, _| {
                    note_content_change(resize_context.clone())
                });
            if let Ok(resize_observer) =
                web_sys::ResizeObserver::new(resize_callback.as_ref().unchecked_ref())
            {
                resize_observer.observe(&content);
                resize_observer.observe(&viewport);
                let mutation_context = effect_context.clone();
                let mutation_callback =
                    Closure::<dyn FnMut(js_sys::Array, web_sys::MutationObserver)>::new(
                        move |_, _| note_content_change(mutation_context.clone()),
                    );
                let mutation_observer =
                    web_sys::MutationObserver::new(mutation_callback.as_ref().unchecked_ref())
                        .ok()
                        .and_then(|observer| {
                            let options = web_sys::MutationObserverInit::new();
                            options.set_child_list(true);
                            observer
                                .observe_with_options(&content, &options)
                                .ok()
                                .map(|()| observer)
                        });
                observer_state.set_value(Some(ResizeObserverState {
                    resize_observer,
                    _resize_callback: resize_callback,
                    _mutation_callback: mutation_observer.as_ref().map(|_| mutation_callback),
                    mutation_observer,
                }));
            }
        });
        on_cleanup(move || {
            observer_state.update_value(|state| {
                if let Some(state) = state.take() {
                    state.resize_observer.disconnect();
                    if let Some(observer) = state.mutation_observer {
                        observer.disconnect();
                    }
                }
            });
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = context;
}

#[cfg(target_arch = "wasm32")]
fn note_content_change(context: MessageScrollerContext) {
    context.content_change_pending.set_value(true);
    schedule_content_sync(context);
}

#[cfg(target_arch = "wasm32")]
fn schedule_content_sync(context: MessageScrollerContext) {
    use wasm_bindgen::{JsCast, closure::Closure};

    if context.resize_scheduled.get_value() {
        return;
    }
    context.resize_scheduled.set_value(true);
    let callback_context = context.clone();
    let callback = Closure::once_into_js(move || {
        callback_context.resize_scheduled.set_value(false);
        sync_content(callback_context.clone());
        callback_context.content_change_pending.set_value(false);
    });
    let scheduled = web_sys::window().is_some_and(|window| {
        window
            .request_animation_frame(callback.unchecked_ref())
            .is_ok()
    });
    if !scheduled {
        context.resize_scheduled.set_value(false);
        sync_content(context.clone());
        context.content_change_pending.set_value(false);
    }
}

#[cfg(target_arch = "wasm32")]
fn sync_content(context: MessageScrollerContext) {
    let items = message_items(context.content_ref, context.spacer_ref);
    if items.is_empty() {
        context.initialized.set_value(false);
        context.handled_anchor_ids.set_value(BTreeSet::new());
        context.previous_ids.set_value(BTreeSet::new());
        context.previous_first_id.set_value(None);
        context.reading_item_id.set_value(None);
        context.anchor_id.set_value(None);
        set_spacer_height(context.clone(), 0);
        sync_scroll_state(context);
        return;
    }

    let current_ids = items
        .iter()
        .map(|item| item.id.clone())
        .collect::<BTreeSet<_>>();
    let first_id = items.first().map(|item| item.id.clone());
    if !context.initialized.get_value() {
        context.handled_anchor_ids.set_value(
            items
                .iter()
                .filter(|item| item.anchor)
                .map(|item| item.id.clone())
                .collect(),
        );
        context.previous_ids.set_value(current_ids);
        context.previous_first_id.set_value(first_id);
        context.initialized.set_value(true);
        scroll_to_end(context);
        return;
    }

    let previous_ids = context.previous_ids.get_value();
    let complete_replacement = !previous_ids.is_empty() && current_ids.is_disjoint(&previous_ids);
    if complete_replacement {
        context.handled_anchor_ids.set_value(
            items
                .iter()
                .filter(|item| item.anchor)
                .map(|item| item.id.clone())
                .collect(),
        );
        context.previous_ids.set_value(current_ids);
        context.previous_first_id.set_value(first_id);
        context.anchor_id.set_value(None);
        scroll_to_end(context);
        return;
    }

    let previous_first = context.previous_first_id.get_value();
    let prepended = previous_first.as_ref().is_some_and(|previous| {
        items
            .iter()
            .position(|item| &item.id == previous)
            .is_some_and(|index| index > 0)
    });
    if prepended && context.preserve_scroll_on_prepend {
        restore_reading_position(&context, &items);
        context.handled_anchor_ids.update_value(|handled| {
            handled.extend(
                items
                    .iter()
                    .filter(|item| item.anchor)
                    .map(|item| item.id.clone()),
            );
        });
    } else {
        let new_anchors = context.handled_anchor_ids.with_value(|handled| {
            items
                .iter()
                .filter(|item| item.anchor && !handled.contains(&item.id))
                .cloned()
                .collect::<Vec<_>>()
        });
        context.handled_anchor_ids.update_value(|handled| {
            handled.extend(new_anchors.iter().map(|item| item.id.clone()));
        });
        if let Some(anchor) = new_anchors.last() {
            if new_anchors.len() > 1 && context.mode.get_value() == ScrollMode::FollowingBottom {
                scroll_to_end(context.clone());
            } else {
                scroll_to_anchor(context.clone(), anchor);
            }
        } else {
            match context.mode.get_value() {
                ScrollMode::FollowingBottom => {
                    scroll_to_end(context.clone());
                }
                ScrollMode::AnchoredToMessage => {
                    reanchor(context.clone(), &items);
                }
                ScrollMode::FreeScrolling => {}
            }
        }
    }

    context.previous_ids.set_value(current_ids);
    context.previous_first_id.set_value(first_id);
    capture_reading_position(&context, &items);
    sync_scroll_state(context);
}

#[cfg(target_arch = "wasm32")]
fn message_items(
    content_ref: NodeRef<html::Div>,
    spacer_ref: NodeRef<html::Div>,
) -> Vec<MessageItemElement> {
    let Some(content) = content_ref.get() else {
        return Vec::new();
    };
    let spacer = spacer_ref.get();
    let children = web_sys::Element::children(&content);
    (0..children.length())
        .filter_map(|index| children.item(index))
        .filter(|element| {
            spacer
                .as_ref()
                .is_none_or(|spacer| !js_sys::Object::is(element.as_ref(), spacer.as_ref()))
        })
        .filter(|element| element.has_attribute("data-message-scroller-item"))
        .filter_map(|element| {
            let id = element.get_attribute("data-message-id")?;
            let anchor = element.get_attribute("data-scroll-anchor").as_deref() == Some("true");
            Some(MessageItemElement {
                id,
                anchor,
                element,
            })
        })
        .collect()
}

#[cfg(target_arch = "wasm32")]
fn capture_reading_position(context: &MessageScrollerContext, items: &[MessageItemElement]) {
    let Some(viewport) = context.viewport_ref.get() else {
        return;
    };
    let viewport_rect = web_sys::Element::get_bounding_client_rect(&viewport);
    if let Some(item) = items.iter().find(|item| {
        let rect = item.element.get_bounding_client_rect();
        rect.bottom() > viewport_rect.top() && rect.top() < viewport_rect.bottom()
    }) {
        context.reading_item_id.set_value(Some(item.id.clone()));
        context.reading_item_viewport_top.set_value(
            (item.element.get_bounding_client_rect().top() - viewport_rect.top()).round() as i32,
        );
    } else {
        context.reading_item_id.set_value(None);
    }
}

#[cfg(target_arch = "wasm32")]
fn restore_reading_position(context: &MessageScrollerContext, items: &[MessageItemElement]) {
    let Some(reading_id) = context.reading_item_id.get_value() else {
        return;
    };
    let Some(item) = items.iter().find(|item| item.id == reading_id) else {
        return;
    };
    let Some(viewport) = context.viewport_ref.get() else {
        return;
    };
    let current_top = (item.element.get_bounding_client_rect().top()
        - web_sys::Element::get_bounding_client_rect(&viewport).top())
    .round() as i32;
    let delta = current_top - context.reading_item_viewport_top.get_value();
    if delta != 0 {
        set_scroll_top(context, viewport.scroll_top() + delta);
    }
}

#[cfg(target_arch = "wasm32")]
fn scroll_to_anchor(context: MessageScrollerContext, anchor: &MessageItemElement) {
    let Some(viewport) = context.viewport_ref.get() else {
        return;
    };
    let Some(content) = context.content_ref.get() else {
        return;
    };
    let item_top = anchor.element.get_bounding_client_rect().top();
    let content_top = web_sys::Element::get_bounding_client_rect(&content).top();
    let target = ((item_top - content_top).round() as i32 - context.previous_item_peek).max(0);
    let natural_height = (viewport.scroll_height() - context.spacer_height.get_value()).max(0);
    let spacer = required_spacer_height(target, viewport.client_height(), natural_height);
    set_spacer_height(context.clone(), spacer);
    context.mode.set_value(ScrollMode::AnchoredToMessage);
    context.anchor_id.set_value(Some(anchor.id.clone()));
    set_scroll_top(&context, target);
    let items = message_items(context.content_ref, context.spacer_ref);
    capture_reading_position(&context, &items);
    sync_scroll_state(context);
}

#[cfg(target_arch = "wasm32")]
fn reanchor(context: MessageScrollerContext, items: &[MessageItemElement]) {
    let Some(anchor_id) = context.anchor_id.get_value() else {
        context.mode.set_value(ScrollMode::FreeScrolling);
        return;
    };
    if let Some(anchor) = items.iter().find(|item| item.id == anchor_id) {
        scroll_to_anchor(context, anchor);
    } else {
        context.anchor_id.set_value(None);
        context.mode.set_value(ScrollMode::FreeScrolling);
    }
}

fn scroll_to_end(context: MessageScrollerContext) -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        let Some(viewport) = context.viewport_ref.get() else {
            return false;
        };
        set_spacer_height(context.clone(), 0);
        context.anchor_id.set_value(None);
        context.mode.set_value(if context.auto_scroll {
            ScrollMode::FollowingBottom
        } else {
            ScrollMode::FreeScrolling
        });
        let target = (viewport.scroll_height() - viewport.client_height()).max(0);
        set_scroll_top(&context, target);
        let items = message_items(context.content_ref, context.spacer_ref);
        capture_reading_position(&context, &items);
        sync_scroll_state(context);
        true
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = context;
        false
    }
}

fn handle_user_scroll_intent(context: MessageScrollerContext) {
    context.programmatic_scroll.set_value(false);
    context.programmatic_generation.set_value(
        context
            .programmatic_generation
            .get_value()
            .saturating_add(1),
    );
    context.mode.set_value(ScrollMode::FreeScrolling);
    context.anchor_id.set_value(None);
}

fn handle_scroll(context: MessageScrollerContext) {
    #[cfg(target_arch = "wasm32")]
    if let Some(viewport) = context.viewport_ref.get() {
        let current = viewport.scroll_top();
        if (current - context.last_scroll_top.get_value()).abs() > 1
            && !context.programmatic_scroll.get_value()
            && !context.content_change_pending.get_value()
        {
            context.mode.set_value(ScrollMode::FreeScrolling);
            context.anchor_id.set_value(None);
        }
        context.last_scroll_top.set_value(current);
        let at_end = end_distance(
            viewport.scroll_height(),
            current,
            viewport.client_height(),
            context.spacer_height.get_value(),
        ) <= context.edge_threshold;
        if at_end && context.auto_scroll && context.mode.get_value() == ScrollMode::FreeScrolling {
            context.mode.set_value(ScrollMode::FollowingBottom);
        }
        let items = message_items(context.content_ref, context.spacer_ref);
        capture_reading_position(&context, &items);
        sync_scroll_state(context);
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = context;
}

#[cfg(target_arch = "wasm32")]
fn set_scroll_top(context: &MessageScrollerContext, target: i32) {
    if let Some(viewport) = context.viewport_ref.get() {
        mark_programmatic_scroll(context.clone());
        viewport.set_scroll_top(target.max(0));
        context.last_scroll_top.set_value(viewport.scroll_top());
    }
}

#[cfg(target_arch = "wasm32")]
fn mark_programmatic_scroll(context: MessageScrollerContext) {
    let generation = context
        .programmatic_generation
        .get_value()
        .saturating_add(1);
    context.programmatic_generation.set_value(generation);
    context.programmatic_scroll.set_value(true);
    schedule_timeout(AUTOSCROLL_SETTLE_MS, move || {
        if context.programmatic_generation.get_value() == generation {
            context.programmatic_scroll.set_value(false);
        }
    });
}

#[cfg(target_arch = "wasm32")]
fn set_spacer_height(context: MessageScrollerContext, height: i32) {
    let height = height.max(0);
    if context.spacer_height.get_value() == height {
        return;
    }
    context.spacer_height.set_value(height);
    if let Some(spacer) = context.spacer_ref.get() {
        spacer.set_hidden(height == 0);
        _ = web_sys::HtmlElement::style(&spacer).set_property("height", &format!("{height}px"));
    }
}

#[cfg(target_arch = "wasm32")]
fn sync_scroll_state(context: MessageScrollerContext) {
    let Some(viewport) = context.viewport_ref.get() else {
        return;
    };
    let distance = end_distance(
        viewport.scroll_height(),
        viewport.scroll_top(),
        viewport.client_height(),
        context.spacer_height.get_value(),
    );
    context
        .can_scroll_end
        .set(distance > context.edge_threshold);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scroller_constants_ids_and_geometry_are_closed() {
        assert_eq!(MESSAGE_SCROLL_EDGE_THRESHOLD_PX, 8);
        assert_eq!(MESSAGE_SCROLL_PREVIOUS_ITEM_PEEK_PX, 48);
        assert_eq!(AUTOSCROLL_SETTLE_MS, 180);
        assert_dom_id("thread-transcript");
        assert_message_id("thread:消息-1");
        assert_eq!(end_distance(1000, 690, 300, 0), 10);
        assert_eq!(end_distance(1000, 700, 300, 0), 0);
        assert_eq!(end_distance(1200, 700, 300, 200), 0);
        assert_eq!(required_spacer_height(900, 300, 1000), 200);
        assert_eq!(required_spacer_height(400, 300, 1000), 0);
        assert!(is_scroll_key("PageDown"));
        assert!(!is_scroll_key("Enter"));
    }

    #[test]
    #[should_panic(expected = "MessageScroller id")]
    fn scroller_dom_id_cannot_split_aria_tokens() {
        assert_dom_id("bad scroller");
    }

    #[test]
    #[should_panic(expected = "message_id")]
    fn scroller_message_id_rejects_control_characters() {
        assert_message_id("bad\nmessage");
    }
}
