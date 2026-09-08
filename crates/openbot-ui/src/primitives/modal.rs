//! Shared modal kernel for Dialog and Sheet.

use leptos::context::Provider;
use leptos::ev::KeyboardEvent;
use leptos::html;
use leptos::prelude::*;

use crate::i18n::{t_string, use_i18n};

/// Sheet edge; all four upstream placements remain available.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SheetSide {
    /// Inline end; default in LTR layouts.
    #[default]
    Right,
    /// Inline start.
    Left,
    /// Block start.
    Top,
    /// Block end.
    Bottom,
}

impl SheetSide {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Right => "right",
            Self::Left => "left",
            Self::Top => "top",
            Self::Bottom => "bottom",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ModalPresentation {
    Dialog,
    Sheet(SheetSide),
}

impl ModalPresentation {
    const fn kind(self) -> &'static str {
        match self {
            Self::Dialog => "dialog",
            Self::Sheet(_) => "sheet",
        }
    }

    const fn side(self) -> Option<&'static str> {
        match self {
            Self::Dialog => None,
            Self::Sheet(side) => Some(side.as_str()),
        }
    }
}

#[derive(Clone)]
struct ModalContext {
    id: String,
    open: RwSignal<bool>,
    trigger_ref: NodeRef<html::Button>,
    panel_ref: NodeRef<html::Div>,
    presentation: ModalPresentation,
    on_close: Option<UnsyncCallback<()>>,
}

pub(crate) fn modal_root(
    open: RwSignal<bool>,
    presentation: ModalPresentation,
    on_close: Option<UnsyncCallback<()>>,
    id: String,
    children: Children,
) -> impl IntoView {
    assert_dom_id(&id);
    let context = ModalContext {
        id,
        open,
        trigger_ref: NodeRef::new(),
        panel_ref: NodeRef::new(),
        presentation,
        on_close,
    };
    install_modal_lifecycle(context.clone());
    view! { <Provider value=context>{children()}</Provider> }
}

pub(crate) fn modal_trigger(
    id: Option<String>,
    disabled: MaybeProp<bool>,
    children: Children,
) -> impl IntoView {
    if let Some(id) = &id {
        assert_dom_id(id);
    }
    let context = modal_context();
    let controls = format!("{}-panel", context.id);
    let open = context.open;
    let trigger_ref = context.trigger_ref;
    let click_context = context.clone();
    let key_context = context.clone();
    view! {
        <button
            id=id
            type="button"
            class="ob-modal-trigger"
            node_ref=trigger_ref
            aria-haspopup="dialog"
            aria-expanded=move || if open.get() { "true" } else { "false" }
            aria-controls=controls
            disabled=move || disabled.get().unwrap_or(false)
            on:click=move |_| {
                if !disabled.get().unwrap_or(false) {
                    click_context.open.set(true);
                }
            }
            on:keydown=move |event: KeyboardEvent| {
                if matches!(event.key().as_str(), "Enter" | " ")
                    && !disabled.get().unwrap_or(false)
                {
                    event.prevent_default();
                    key_context.open.set(true);
                }
            }
        >
            {children()}
        </button>
    }
}

pub(crate) fn modal_content(
    title: TextProp,
    description: TextProp,
    show_close_button: bool,
    children: Children,
) -> impl IntoView {
    let context = modal_context();
    let panel_id = format!("{}-panel", context.id);
    let title_id = format!("{}-title", context.id);
    let description_id = format!("{}-description", context.id);
    let title_aria_id = title_id.clone();
    let description_aria_id = description_id.clone();
    let close_id = format!("{}-close", context.id);
    let open = context.open;
    let panel_ref = context.panel_ref;
    let presentation = context.presentation;
    let layer_close = context.clone();
    let key_context = context.clone();
    let description_visible = description.clone();
    let description_hidden = description.clone();
    let description_text = description;
    view! {
        <div
                class="ob-modal-layer"
                hidden=move || !open.get()
                data-presentation=presentation.kind()
                data-side=presentation.side()
            >
                <div
                    class="ob-modal-backdrop"
                    on:click=move |_| close(layer_close.clone())
                ></div>
                <div
                    id=panel_id
                    class="ob-modal-panel"
                    role="dialog"
                    aria-modal="true"
                    aria-labelledby=title_aria_id
                    aria-describedby=move || {
                        (!description_visible.get().is_empty()).then(|| description_aria_id.clone())
                    }
                    tabindex="-1"
                    node_ref=panel_ref
                    data-presentation=presentation.kind()
                    data-side=presentation.side()
                    on:keydown=move |event| handle_panel_key(event, key_context.clone())
                >
                    <header class="ob-modal-header">
                        <h2 id=title_id>{move || title.get()}</h2>
                        <p
                            id=description_id
                            hidden=move || description_hidden.get().is_empty()
                        >
                            {move || description_text.get()}
                        </p>
                    </header>
                    {show_close_button.then(|| view! {
                        <ModalCloseButton id=close_id />
                    })}
                    {children()}
                </div>
        </div>
    }
}

#[component]
fn ModalCloseButton(id: String) -> impl IntoView {
    let i18n = use_i18n();
    let context = modal_context();
    view! {
        <button
            id=id
            type="button"
            class="ob-modal-close"
            aria-label=move || t_string!(i18n, common.close).to_owned()
            on:click=move |_| close(context.clone())
        >
            "×"
        </button>
    }
}

pub(crate) fn modal_close(id: Option<String>, children: Children) -> impl IntoView {
    if let Some(id) = &id {
        assert_dom_id(id);
    }
    let context = modal_context();
    let click_context = context.clone();
    let key_context = context;
    view! {
        <button
            id=id
            type="button"
            class="ob-button"
            data-variant="chip"
            data-size="md"
            on:click=move |_| close(click_context.clone())
            on:keydown=move |event: KeyboardEvent| {
                if matches!(event.key().as_str(), "Enter" | " ") {
                    event.prevent_default();
                    close(key_context.clone());
                }
            }
        >{children()}</button>
    }
}

pub(crate) fn modal_body(children: Children) -> impl IntoView {
    view! { <div class="ob-modal-body">{children()}</div> }
}

pub(crate) fn modal_footer(children: Children) -> impl IntoView {
    view! { <footer class="ob-modal-footer">{children()}</footer> }
}

fn modal_context() -> ModalContext {
    use_context::<ModalContext>().expect("modal compound component must be nested in Dialog/Sheet")
}

fn install_modal_lifecycle(context: ModalContext) {
    let was_open = StoredValue::new(false);
    let previous_overflow = StoredValue::new(None::<String>);
    let effect_context = context.clone();
    Effect::new(move |_| {
        let open = effect_context.open.get();
        let previous = was_open.get_value();
        if open == previous {
            return;
        }
        was_open.set_value(open);
        if open {
            lock_body(previous_overflow);
            set_background_inert(&effect_context.id, true);
            let focus_context = effect_context.clone();
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                leptos::task::tick().await;
                focus_first_or_panel(focus_context.panel_ref);
            });
        } else {
            unlock_body(previous_overflow);
            set_background_inert(&effect_context.id, false);
            let trigger_ref = effect_context.trigger_ref;
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                leptos::task::tick().await;
                focus_trigger(trigger_ref);
            });
        }
    });
    on_cleanup(move || {
        unlock_body(previous_overflow);
        set_background_inert(&context.id, false);
    });
}

fn close(context: ModalContext) {
    if context.open.get_untracked() {
        context.open.set(false);
        if let Some(callback) = context.on_close {
            callback.run(());
        }
    }
}

fn handle_panel_key(event: KeyboardEvent, context: ModalContext) {
    match event.key().as_str() {
        "Escape" => {
            event.prevent_default();
            close(context);
        }
        "Tab" => trap_tab(event, context.panel_ref),
        _ => {}
    }
}

fn assert_dom_id(id: &str) {
    assert!(
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "modal id must be one bounded DOM token"
    );
}

#[cfg(target_arch = "wasm32")]
fn focusables(panel_ref: NodeRef<html::Div>) -> Vec<web_sys::HtmlElement> {
    use wasm_bindgen::JsCast;

    let Some(panel) = panel_ref.get() else {
        return Vec::new();
    };
    let selector = "a[href],button:not([disabled]),input:not([disabled]),textarea:not([disabled]),select:not([disabled]),[tabindex]:not([tabindex='-1'])";
    let Ok(nodes) = web_sys::Element::query_selector_all(&panel, selector) else {
        return Vec::new();
    };
    (0..nodes.length())
        .filter_map(|index| nodes.item(index))
        .filter_map(|node| node.dyn_into::<web_sys::HtmlElement>().ok())
        .filter(|element| !element.hidden())
        .collect()
}

#[cfg(target_arch = "wasm32")]
fn focus_first_or_panel(panel_ref: NodeRef<html::Div>) {
    if let Some(first) = focusables(panel_ref).first() {
        _ = first.focus();
    } else if let Some(panel) = panel_ref.get() {
        _ = web_sys::HtmlElement::focus(&panel);
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn focus_first_or_panel(_panel_ref: NodeRef<html::Div>) {}

#[cfg(target_arch = "wasm32")]
fn focus_trigger(trigger_ref: NodeRef<html::Button>) {
    if let Some(trigger) = trigger_ref.get() {
        _ = web_sys::HtmlElement::focus(&trigger);
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn focus_trigger(_trigger_ref: NodeRef<html::Button>) {}

fn trap_tab(event: KeyboardEvent, panel_ref: NodeRef<html::Div>) {
    #[cfg(target_arch = "wasm32")]
    {
        let focusables = focusables(panel_ref);
        let Some(first) = focusables.first() else {
            event.prevent_default();
            focus_first_or_panel(panel_ref);
            return;
        };
        let last = focusables.last().expect("first implies last");
        let active = web_sys::window()
            .and_then(|window| window.document())
            .and_then(|document| document.active_element());
        let is_first = active
            .as_ref()
            .is_some_and(|active| js_sys::Object::is(active.as_ref(), first.as_ref()));
        let is_last = active
            .as_ref()
            .is_some_and(|active| js_sys::Object::is(active.as_ref(), last.as_ref()));
        if event.shift_key() && is_first {
            event.prevent_default();
            _ = last.focus();
        } else if !event.shift_key() && is_last {
            event.prevent_default();
            _ = first.focus();
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (event, panel_ref);
}

fn lock_body(previous: StoredValue<Option<String>>) {
    #[cfg(target_arch = "wasm32")]
    if let Some(body) = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.body())
    {
        let style = web_sys::HtmlElement::style(&body);
        previous.set_value(style.get_property_value("overflow").ok());
        _ = style.set_property("overflow", "hidden");
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = previous;
}

fn unlock_body(previous: StoredValue<Option<String>>) {
    #[cfg(target_arch = "wasm32")]
    if let Some(value) = previous.get_value()
        && let Some(body) = web_sys::window()
            .and_then(|window| window.document())
            .and_then(|document| document.body())
    {
        let style = web_sys::HtmlElement::style(&body);
        if value.is_empty() {
            _ = style.remove_property("overflow");
        } else {
            _ = style.set_property("overflow", &value);
        }
        previous.set_value(None);
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = previous;
}

fn set_background_inert(modal_id: &str, inert: bool) {
    #[cfg(target_arch = "wasm32")]
    if let Some(document) = web_sys::window().and_then(|window| window.document()) {
        if inert {
            let Some(mut current) = document
                .get_element_by_id(&format!("{modal_id}-panel"))
                .and_then(|panel| panel.parent_element())
            else {
                return;
            };
            while let Some(parent) = current.parent_element() {
                if current.tag_name() == "BODY" {
                    break;
                }
                let children = parent.children();
                for index in 0..children.length() {
                    if let Some(child) = children.item(index)
                        && !js_sys::Object::is(child.as_ref(), current.as_ref())
                    {
                        _ = child.set_attribute("inert", "");
                        _ = child.set_attribute("aria-hidden", "true");
                        _ = child.set_attribute("data-openbot-modal-inert", modal_id);
                    }
                }
                current = parent;
            }
        } else {
            let selector = format!("[data-openbot-modal-inert='{modal_id}']");
            if let Ok(nodes) = document.query_selector_all(&selector) {
                for index in 0..nodes.length() {
                    if let Some(node) = nodes.item(index) {
                        use wasm_bindgen::JsCast;
                        if let Ok(element) = node.dyn_into::<web_sys::Element>() {
                            _ = element.remove_attribute("inert");
                            _ = element.remove_attribute("aria-hidden");
                            _ = element.remove_attribute("data-openbot-modal-inert");
                        }
                    }
                }
            }
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (modal_id, inert);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sheet_sides_and_modal_ids_are_closed() {
        assert_eq!(SheetSide::Right.as_str(), "right");
        assert_eq!(SheetSide::Left.as_str(), "left");
        assert_eq!(SheetSide::Top.as_str(), "top");
        assert_eq!(SheetSide::Bottom.as_str(), "bottom");
        assert_dom_id("credential-dialog");
    }

    #[test]
    #[should_panic(expected = "modal id")]
    fn modal_id_cannot_split_aria_tokens() {
        assert_dom_id("bad dialog");
    }
}
