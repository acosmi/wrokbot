//! Responsive application sidebar with large, rail, and mobile-Sheet presentations.

use leptos::context::Provider;
use leptos::html;
use leptos::prelude::*;

use crate::icons::Icon;

use super::{DialogContent, IconSize, IconView, Sheet, SheetSide};

/// First-source breakpoint where the full desktop layout begins.
pub const SIDEBAR_LARGE_BREAKPOINT_PX: u32 = 1024;
/// First-source breakpoint where the automatic rail begins.
pub const SIDEBAR_MEDIUM_BREAKPOINT_PX: u32 = 768;

/// Responsive presentation selected from the real viewport width.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SidebarViewport {
    /// 1024px and wider: user-controlled expanded/rail state.
    #[default]
    Large,
    /// 768–1023px: forced 64px rail.
    Medium,
    /// Below 768px: navigation moves into the shared Sheet modal.
    Compact,
}

impl SidebarViewport {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Large => "large",
            Self::Medium => "medium",
            Self::Compact => "compact",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SidebarState {
    Expanded,
    Rail,
    MobileOpen,
    MobileClosed,
}

impl SidebarState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Expanded => "expanded",
            Self::Rail => "rail",
            Self::MobileOpen => "mobile-open",
            Self::MobileClosed => "mobile-closed",
        }
    }
}

#[derive(Clone)]
struct SidebarContext {
    id: String,
    collapsed: RwSignal<bool>,
    mobile_open: RwSignal<bool>,
    viewport: RwSignal<SidebarViewport>,
    aria_label: TextProp,
    mobile_title: TextProp,
    mobile_description: TextProp,
    on_collapsed_change: Option<UnsyncCallback<bool>>,
    trigger_ref: NodeRef<html::Button>,
}

/// Read-only/control handle for shell composition below [`SidebarProvider`].
#[derive(Clone)]
pub struct SidebarController {
    context: SidebarContext,
}

impl SidebarController {
    /// Current responsive presentation.
    pub fn viewport(&self) -> SidebarViewport {
        self.context.viewport.get()
    }

    /// Current semantic state after responsive rules are applied.
    pub fn state(&self) -> &'static str {
        effective_state(&self.context).as_str()
    }

    /// Toggle the allowed state for the current viewport.
    pub fn toggle(&self) {
        toggle_sidebar(self.context.clone());
    }
}

/// Read the nearest sidebar controller.
pub fn use_sidebar() -> SidebarController {
    SidebarController {
        context: sidebar_context(),
    }
}

/// Provide one responsive/collapse/mobile/shortcut state to Sidebar and its shell trigger.
#[component]
pub fn SidebarProvider(
    #[prop(into)] id: String,
    collapsed: RwSignal<bool>,
    #[prop(into)] aria_label: TextProp,
    #[prop(into)] mobile_title: TextProp,
    #[prop(into)] mobile_description: TextProp,
    #[prop(optional)] on_collapsed_change: Option<UnsyncCallback<bool>>,
    children: Children,
) -> impl IntoView {
    assert_dom_id(&id);
    assert!(
        !aria_label.get().is_empty(),
        "Sidebar label must be nonempty"
    );
    assert!(
        !mobile_title.get().is_empty(),
        "Sidebar mobile title must be nonempty"
    );
    let context = SidebarContext {
        id,
        collapsed,
        mobile_open: RwSignal::new(false),
        viewport: RwSignal::new(SidebarViewport::Large),
        aria_label,
        mobile_title,
        mobile_description,
        on_collapsed_change,
        trigger_ref: NodeRef::new(),
    };
    install_viewport_observer(context.clone());
    install_shortcut(context.clone());
    let state_context = context.clone();
    view! {
        <Provider value=context>
            <div
                class="ob-sidebar-provider"
                data-viewport=move || state_context.viewport.get().as_str()
                data-state=move || effective_state(&state_context).as_str()
            >
                {children()}
            </div>
        </Provider>
    }
}

/// Render one nav tree as an aside on desktop/rail or inside the shared Sheet on compact widths.
#[component]
pub fn Sidebar(children: ChildrenFn) -> impl IntoView {
    let context = sidebar_context();
    let desktop_context = StoredValue::new(context.clone());
    let desktop_children = StoredValue::new(children.clone());
    let mobile_context = StoredValue::new(context.clone());
    let mobile_children = StoredValue::new(children);
    view! {
        <Show
            when=move || context.viewport.get() == SidebarViewport::Compact
            fallback=move || desktop_sidebar_view(
                desktop_context.get_value(),
                desktop_children.get_value(),
            )
        >
            {move || mobile_sidebar_view(
                mobile_context.get_value(),
                mobile_children.get_value(),
            )}
        </Show>
    }
}

fn desktop_sidebar_view(context: SidebarContext, children: ChildrenFn) -> impl IntoView {
    let aside_id = format!("{}-desktop", context.id);
    let state_context = context.clone();
    let aria_label = context.aria_label;
    view! {
        <aside
            id=aside_id
            class="ob-sidebar"
            data-state=move || effective_state(&state_context).as_str()
        >
            <nav class="ob-sidebar-nav" aria-label=move || aria_label.get()>
                {children()}
            </nav>
        </aside>
    }
}

fn mobile_sidebar_view(context: SidebarContext, children: ChildrenFn) -> impl IntoView {
    let close_context = context.clone();
    let sheet_id = format!("{}-mobile", context.id);
    let mobile_open = context.mobile_open;
    let title = context.mobile_title;
    let description = context.mobile_description;
    let aria_label = context.aria_label;
    view! {
        <Sheet
            id=sheet_id
            open=mobile_open
            side=SheetSide::Left
            on_close=UnsyncCallback::new(move |_| focus_sidebar_trigger_later(close_context.clone()))
        >
            <DialogContent
                title=move || title.get()
                description=move || description.get()
            >
                <nav
                    class="ob-sidebar-nav ob-sidebar-mobile-nav"
                    data-mobile="true"
                    on:click=move |event| close_mobile_on_navigation(event, mobile_open)
                    aria-label=move || aria_label.get()
                >
                    {children()}
                </nav>
            </DialogContent>
        </Sheet>
    }
}

// Handle every real link in the mobile nav, including custom account and history links.
fn close_mobile_on_navigation(event: leptos::ev::MouseEvent, open: RwSignal<bool>) {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::JsCast as _;
        if event.button() != 0
            || event.ctrl_key()
            || event.meta_key()
            || event.shift_key()
            || event.alt_key()
        {
            return;
        }
        let navigates = event
            .target()
            .and_then(|target| target.dyn_into::<web_sys::Element>().ok())
            .and_then(|element| element.closest("a[href]").ok().flatten())
            .is_some();
        if navigates {
            open.set(false);
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (event, open);
}

/// Toggle button intended for the topbar. Medium mode hides/disables it because rail is automatic.
#[component]
pub fn SidebarTrigger(
    #[prop(optional, into)] id: Option<String>,
    #[prop(into)] aria_label: TextProp,
) -> impl IntoView {
    if let Some(id) = &id {
        assert_dom_id(id);
    }
    assert!(
        !aria_label.get().is_empty(),
        "SidebarTrigger label must be nonempty"
    );
    let context = sidebar_context();
    let controls_context = context.clone();
    let expanded_context = context.clone();
    let disabled_context = context.clone();
    let click_context = context.clone();
    let trigger_node = context.trigger_ref;
    view! {
        <button
            id=id
            type="button"
            class="ob-sidebar-trigger"
            data-state=move || effective_state(&context).as_str()
            aria-label=move || aria_label.get()
            aria-controls=move || controls_id(&controls_context)
            aria-expanded=move || explicit_bool(sidebar_expanded(&expanded_context))
            aria-disabled=move || explicit_bool(disabled_context.viewport.get() == SidebarViewport::Medium)
            disabled=move || disabled_context.viewport.get() == SidebarViewport::Medium
            node_ref=trigger_node
            on:click=move |_| toggle_sidebar(click_context.clone())
        >
            <IconView icon=Icon::PanelLeft size=IconSize::Navigation />
        </button>
    }
}

/// Brand/top controls slot.
#[component]
pub fn SidebarHeader(children: Children) -> impl IntoView {
    view! { <header class="ob-sidebar-header" on:mousedown=crate::api::desktop_chrome::start_drag>{children()}</header> }
}

/// Scrollable primary groups slot.
#[component]
pub fn SidebarContent(children: Children) -> impl IntoView {
    view! { <div class="ob-sidebar-content">{children()}</div> }
}

/// Bottom-pinned user/settings slot.
#[component]
pub fn SidebarFooter(children: Children) -> impl IntoView {
    view! { <footer class="ob-sidebar-footer">{children()}</footer> }
}

/// Navigation group.
#[component]
pub fn SidebarGroup(children: Children) -> impl IntoView {
    view! { <div class="ob-sidebar-group">{children()}</div> }
}

/// Group heading hidden visually in rail state.
#[component]
pub fn SidebarGroupLabel(children: Children) -> impl IntoView {
    view! { <div class="ob-sidebar-group-label">{children()}</div> }
}

/// Semantic navigation list.
#[component]
pub fn SidebarNavList(children: Children) -> impl IntoView {
    view! { <ul class="ob-sidebar-list">{children()}</ul> }
}

/// Same-origin navigation item with explicit current-page semantics.
#[component]
pub fn SidebarNavLink(
    #[prop(into)] href: String,
    icon: Icon,
    #[prop(into)] label: TextProp,
    #[prop(optional, into)] current: MaybeProp<bool>,
) -> impl IntoView {
    assert_same_origin_href(&href);
    assert!(
        !label.get().is_empty(),
        "SidebarNavLink label must be nonempty"
    );
    let context = sidebar_context();
    let click_context = context.clone();
    let visible_label = label.clone();
    let aria_label = label.clone();
    let title_label = label;
    view! {
        <li class="ob-sidebar-list-item">
            <a
                class="ob-sidebar-link"
                href=href
                aria-label=move || aria_label.get()
                aria-current=move || current.get().unwrap_or(false).then_some("page")
                data-state=move || current.get().unwrap_or(false).then_some("current")
                title=move || title_label.get()
                on:click=move |_| {
                    if click_context.viewport.get_untracked() == SidebarViewport::Compact {
                        click_context.mobile_open.set(false);
                    }
                }
            >
                <IconView icon size=IconSize::Navigation />
                <span class="ob-sidebar-link-label">{move || visible_label.get()}</span>
                <Show when=move || current.get().unwrap_or(false)>
                    <span class="ob-sidebar-current" aria-hidden="true">
                        <IconView icon=Icon::Check size=IconSize::Inline />
                    </span>
                </Show>
            </a>
        </li>
    }
}

fn sidebar_context() -> SidebarContext {
    use_context::<SidebarContext>()
        .expect("Sidebar compound component must be nested in SidebarProvider")
}

fn effective_state(context: &SidebarContext) -> SidebarState {
    match context.viewport.get() {
        SidebarViewport::Large if context.collapsed.get() => SidebarState::Rail,
        SidebarViewport::Large => SidebarState::Expanded,
        SidebarViewport::Medium => SidebarState::Rail,
        SidebarViewport::Compact if context.mobile_open.get() => SidebarState::MobileOpen,
        SidebarViewport::Compact => SidebarState::MobileClosed,
    }
}

fn sidebar_expanded(context: &SidebarContext) -> bool {
    matches!(
        effective_state(context),
        SidebarState::Expanded | SidebarState::MobileOpen
    )
}

fn controls_id(context: &SidebarContext) -> String {
    match context.viewport.get() {
        SidebarViewport::Compact => format!("{}-mobile-panel", context.id),
        SidebarViewport::Large | SidebarViewport::Medium => format!("{}-desktop", context.id),
    }
}

fn toggle_sidebar(context: SidebarContext) {
    match context.viewport.get_untracked() {
        SidebarViewport::Large => {
            let collapsed = !context.collapsed.get_untracked();
            context.collapsed.set(collapsed);
            if let Some(callback) = context.on_collapsed_change {
                callback.run(collapsed);
            }
        }
        SidebarViewport::Medium => {}
        SidebarViewport::Compact => {
            let closing = context.mobile_open.get_untracked();
            context.mobile_open.set(!closing);
            if closing {
                focus_sidebar_trigger_later(context);
            }
        }
    }
}

fn install_viewport_observer(context: SidebarContext) {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::{JsCast, closure::Closure};

        struct ObserverState {
            observer: web_sys::ResizeObserver,
            _callback:
                wasm_bindgen::closure::Closure<dyn FnMut(js_sys::Array, web_sys::ResizeObserver)>,
        }

        let observer_state = StoredValue::new_local(None::<ObserverState>);
        let effect_context = context.clone();
        Effect::new(move |_| {
            if observer_state.with_value(Option::is_some) {
                return;
            }
            update_viewport(effect_context.clone());
            let callback_context = effect_context.clone();
            let callback =
                Closure::<dyn FnMut(js_sys::Array, web_sys::ResizeObserver)>::new(move |_, _| {
                    update_viewport(callback_context.clone());
                });
            let Some(root) = web_sys::window()
                .and_then(|window| window.document())
                .and_then(|document| document.document_element())
            else {
                return;
            };
            if let Ok(observer) = web_sys::ResizeObserver::new(callback.as_ref().unchecked_ref()) {
                observer.observe(&root);
                observer_state.set_value(Some(ObserverState {
                    observer,
                    _callback: callback,
                }));
            }
        });
        on_cleanup(move || {
            observer_state.update_value(|state| {
                if let Some(state) = state.take() {
                    state.observer.disconnect();
                }
            });
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = context;
}

#[cfg(target_arch = "wasm32")]
fn update_viewport(context: SidebarContext) {
    let Some(width) = web_sys::window()
        .and_then(|window| window.inner_width().ok())
        .and_then(|width| width.as_f64())
    else {
        return;
    };
    let viewport = viewport_for_width(width);
    context.viewport.set(viewport);
    if viewport != SidebarViewport::Compact {
        let was_open = context.mobile_open.get_untracked();
        context.mobile_open.set(false);
        if was_open {
            focus_sidebar_trigger_later(context);
        }
    }
}

fn focus_sidebar_trigger_later(context: SidebarContext) {
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        leptos::task::tick().await;
        if let Some(trigger) = context.trigger_ref.get() {
            _ = web_sys::HtmlElement::focus(&trigger);
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = context;
}

#[cfg(target_arch = "wasm32")]
struct ShortcutState {
    window: web_sys::Window,
    callback: wasm_bindgen::closure::Closure<dyn FnMut(web_sys::KeyboardEvent)>,
}

fn install_shortcut(context: SidebarContext) {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::{JsCast, closure::Closure};

        let shortcut_state = StoredValue::new_local(None::<ShortcutState>);
        let shortcut_context = context.clone();
        if let Some(window) = web_sys::window() {
            let callback = Closure::<dyn FnMut(web_sys::KeyboardEvent)>::new(
                move |event: web_sys::KeyboardEvent| {
                    let shortcut = event.key().eq_ignore_ascii_case("b")
                        && (event.meta_key() || event.ctrl_key())
                        && !event.alt_key();
                    if shortcut
                        && shortcut_context.viewport.get_untracked() != SidebarViewport::Medium
                    {
                        event.prevent_default();
                        toggle_sidebar(shortcut_context.clone());
                    }
                },
            );
            if window
                .add_event_listener_with_callback("keydown", callback.as_ref().unchecked_ref())
                .is_ok()
            {
                shortcut_state.set_value(Some(ShortcutState { window, callback }));
            }
        }
        on_cleanup(move || {
            shortcut_state.update_value(|state| {
                if let Some(state) = state.take() {
                    _ = state.window.remove_event_listener_with_callback(
                        "keydown",
                        state.callback.as_ref().unchecked_ref(),
                    );
                }
            });
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = context;
}

#[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
fn viewport_for_width(width: f64) -> SidebarViewport {
    if width >= f64::from(SIDEBAR_LARGE_BREAKPOINT_PX) {
        SidebarViewport::Large
    } else if width >= f64::from(SIDEBAR_MEDIUM_BREAKPOINT_PX) {
        SidebarViewport::Medium
    } else {
        SidebarViewport::Compact
    }
}

fn assert_dom_id(id: &str) {
    assert!(
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "Sidebar id must be one bounded DOM token"
    );
}

fn assert_same_origin_href(href: &str) {
    assert!(
        href.starts_with('/')
            && !href.starts_with("//")
            && href.len() <= 2048
            && !href.chars().any(char::is_control),
        "SidebarNavLink href must be one bounded same-origin absolute path"
    );
}

const fn explicit_bool(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidebar_breakpoints_states_and_links_are_closed() {
        assert_eq!(viewport_for_width(1024.0), SidebarViewport::Large);
        assert_eq!(viewport_for_width(768.0), SidebarViewport::Medium);
        assert_eq!(viewport_for_width(767.0), SidebarViewport::Compact);
        assert_eq!(SidebarViewport::Large.as_str(), "large");
        assert_eq!(SidebarState::Expanded.as_str(), "expanded");
        assert_dom_id("app-sidebar");
        assert_same_origin_href("/settings/profile");
    }

    #[test]
    #[should_panic(expected = "same-origin")]
    fn sidebar_rejects_external_links() {
        assert_same_origin_href("https://example.com/settings");
    }
}
