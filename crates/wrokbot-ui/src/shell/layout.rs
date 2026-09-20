//! Pathless root and authenticated application layouts.
//!
//! The fixed upstream root providers are preserved by mechanism, not by React-shaped names:
//! theme/locale first paint is host-authored on `<html>`, authenticated preference persistence is
//! installed only inside [`AppLayout`], and each first-party Tooltip owns the same closed compound
//! context. This layout therefore owns only their common full-height placement.

use leptos::prelude::*;

use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::preferences::provide_ui_preferences;
use crate::primitives::{IconSize, IconView};
use crate::primitives::{Sidebar, SidebarProvider, SidebarTrigger};
use crate::shell::AppSidebar;

/// Root layout shared by sign-in and every authenticated route.
#[component]
pub fn RootLayout(children: Children) -> impl IntoView {
    view! {
        <div class="ob-root-layout" data-layout="root">
            {children()}
        </div>
    }
}

/// One-viewport authenticated application shell with independently scrolling panes.
#[component]
pub fn AppLayout(children: Children) -> impl IntoView {
    let i18n = use_i18n();
    provide_ui_preferences(i18n);
    let collapsed = RwSignal::new(false);
    view! {
        <a class="ob-skip-link" href="#main-content" on:click=move |_| focus_main_content()>
            {move || t!(i18n, shell.skip_to_content)}
        </a>
        <SidebarProvider
            id="app-sidebar".to_owned()
            collapsed
            aria_label=move || t_string!(i18n, shell.nav_channels).to_owned()
            mobile_title=move || t_string!(i18n, shell.sidebar_mobile_title).to_owned()
            mobile_description=move || t_string!(i18n, shell.sidebar_mobile_description).to_owned()
        >
            <div class="ob-app-shell" data-layout="app">
                <Sidebar>
                    <AppSidebar />
                </Sidebar>
                <div class="ob-app-stage">
                    <header class="ob-shell-topbar" on:mousedown=crate::api::desktop_chrome::start_drag>
                        <SidebarTrigger aria_label=move || t_string!(i18n, shell.sidebar_toggle).to_owned() />
                        <div class="ob-shell-identity">
                            <a class="ob-shell-product" href="/" aria-label=move || t_string!(i18n, common.app_name).to_owned()>
                                <crate::primitives::BrandMark/>
                                <span class="ob-brand-wordmark" aria-hidden="true"></span>
                            </a>
                            <div class="ob-shell-context"
                                role="status"
                                aria-label=move || t_string!(i18n, shell.env_tooltip).to_owned()
                                title=move || t_string!(i18n, shell.env_tooltip).to_owned()
                            >
                                <IconView icon=Icon::Monitor size=IconSize::Navigation />
                                <span class="ob-shell-context-label">
                                    {move || format!("{}: {}", t_string!(i18n, shell.env_summary), t_string!(i18n, shell.env_unassigned))}
                                </span>
                            </div>
                        </div>
                    </header>
                    <main id="main-content" class="ob-main" tabindex="-1">
                        {children()}
                    </main>
                </div>
            </div>
        </SidebarProvider>
    }
}

/// Explicitly move focus to `#main-content` after the skip-link's native hash navigation.
///
/// A `href="#main-content"` anchor jump does not reliably move keyboard focus to a
/// `tabindex="-1"` target in every browser (notably WebKit); without this, a keyboard user who
/// activates the skip link gets the scroll jump but keeps tabbing from the link's own DOM
/// position, defeating the link's purpose. Mirrors the established `restore_focus` idiom used
/// elsewhere in this crate (e.g. `features/settings/connected_accounts.rs`).
fn focus_main_content() {
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        use wasm_bindgen::JsCast as _;

        leptos::task::tick().await;
        if let Some(element) = web_sys::window()
            .and_then(|window| window.document())
            .and_then(|document| document.get_element_by_id("main-content"))
            .and_then(|element| element.dyn_into::<web_sys::HtmlElement>().ok())
        {
            _ = element.focus();
        }
    });
}
