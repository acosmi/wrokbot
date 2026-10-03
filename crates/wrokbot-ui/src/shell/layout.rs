//! Pathless root and authenticated application layouts.
//!
//! The fixed upstream root providers are preserved by mechanism, not by React-shaped names:
//! theme/locale first paint is host-authored on `<html>`, authenticated preference persistence is
//! installed only inside [`AppLayout`], and each first-party Tooltip owns the same closed compound
//! context. This layout therefore owns only their common full-height placement.

use leptos::prelude::*;
use leptos_router::hooks::use_location;

use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::preferences::provide_ui_preferences;
use crate::primitives::{IconSize, IconView};
use crate::primitives::{Sidebar, SidebarProvider, SidebarTrigger, use_sidebar};
use crate::shell::AppSidebar;

#[derive(Clone, Copy)]
pub(crate) struct WorkspaceToolbarMount(pub NodeRef<leptos::html::Div>);

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
    provide_context(crate::features::agents::AgentDirectoryGeneration(
        RwSignal::new(0),
    ));
    let collapsed = RwSignal::new(false);
    let workspace_toolbar = NodeRef::<leptos::html::Div>::new();
    provide_context(WorkspaceToolbarMount(workspace_toolbar));
    view! {
        <a class="ob-skip-link" href="#main-content">
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
                <IconRail />
                <Sidebar>
                    <AppSidebar />
                </Sidebar>
                <div class="ob-app-stage">
                    <header class="ob-shell-topbar" on:mousedown=crate::api::desktop_chrome::start_drag>
                        <SidebarTrigger aria_label=move || t_string!(i18n, shell.sidebar_toggle).to_owned() />
                        <ShellContext />
                        <div id="workspace-toolbar-slot" class="ob-workspace-tools" node_ref=workspace_toolbar></div>
                    </header>
                    <main id="main-content" class="ob-main" tabindex="-1">
                        {children()}
                    </main>
                </div>
            </div>
        </SidebarProvider>
    }
}

/// Presentation-only navigation. No task counts, device identity or unopened result controls.
#[component]
fn IconRail() -> impl IntoView {
    let i18n = use_i18n();
    let sidebar = use_sidebar();
    let rail_trigger = sidebar.rail_trigger_ref();
    let toggle = sidebar.clone();
    let history = sidebar.clone();
    view! {
        <nav class="ob-icon-rail" aria-label=move || t_string!(i18n, shell.tier_daily_work).to_owned()>
            <a class="ob-rail-brand" href="/" aria-label=move || t_string!(i18n, common.app_name).to_owned()>
                <crate::primitives::BrandMark />
            </a>
            <button id="app-sidebar-rail-toggle" class="ob-rail-control" type="button" node_ref=rail_trigger
                aria-label=move || t_string!(i18n, shell.sidebar_toggle).to_owned()
                aria-controls="app-sidebar-panel"
                aria-expanded=move || (sidebar.state() == "expanded").to_string()
                on:click=move |_| toggle.toggle()>
                <IconView icon=Icon::PanelLeft size=IconSize::Navigation />
            </button>
            <a class="ob-rail-control" href="/" aria-label=move || t_string!(i18n, shell.nav_chat).to_owned()>
                <IconView icon=Icon::Pencil size=IconSize::Navigation />
            </a>
            <button class="ob-rail-control" type="button"
                aria-label=move || t_string!(i18n, shell.chats).to_owned()
                aria-controls="sidebar-history"
                on:click=move |_| history.show_history()>
                <IconView icon=Icon::Clock size=IconSize::Navigation />
            </button>
            <a class="ob-rail-control ob-rail-settings" href="/settings" aria-label=move || t_string!(i18n, shell.nav_settings).to_owned()>
                <IconView icon=Icon::Settings size=IconSize::Navigation />
            </a>
        </nav>
    }
}

#[component]
fn ShellContext() -> impl IntoView {
    let i18n = use_i18n();
    let location = use_location();
    let context = move || {
        let path = location.pathname.get();
        if path.starts_with("/admin") {
            t_string!(i18n, shell.nav_admin).to_owned()
        } else if path.starts_with("/settings/memory") {
            t_string!(i18n, shell.nav_memory).to_owned()
        } else if path.starts_with("/settings") {
            t_string!(i18n, shell.nav_settings).to_owned()
        } else if path.starts_with("/agents") {
            t_string!(i18n, shell.nav_agents).to_owned()
        } else if path.starts_with("/approvals") {
            t_string!(i18n, admin.nav_approvals).to_owned()
        } else if path.starts_with("/skills") {
            t_string!(i18n, shell.nav_skills).to_owned()
        } else if path.starts_with("/channel") {
            t_string!(i18n, shell.chats).to_owned()
        } else if path == "/bot" {
            t_string!(i18n, shell.nav_bot).to_owned()
        } else {
            t_string!(i18n, shell.nav_chat).to_owned()
        }
    };
    view! {
        <div class="ob-shell-identity">
            <span class="ob-shell-breadcrumb">{context}</span>
        </div>
    }
}
