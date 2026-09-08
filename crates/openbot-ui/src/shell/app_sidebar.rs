//! Authenticated channel roster and account controls inside the shared Sidebar primitive.

#[cfg(any(target_arch = "wasm32", test))]
use std::collections::HashSet;

use leptos::prelude::*;
use leptos_router::hooks::use_location;
#[cfg(any(target_arch = "wasm32", test))]
use openbot_contracts::command::ChannelPage;
use openbot_contracts::command::ChannelSummary;
#[cfg(target_arch = "wasm32")]
use openbot_contracts::command::{AppEvent, SubscriptionRequest};
use openbot_contracts::people::CurrentUser;

use crate::api::channel_route_href;
#[cfg(target_arch = "wasm32")]
use crate::api::desktop_transport::{
    DesktopStructuredHandlers, is_tauri_host, open_desktop_structured,
};
#[cfg(target_arch = "wasm32")]
use crate::api::{
    list_channels, load_current_user, load_session_status, require_admin_status,
    sign_out_current_session,
};
use crate::features::app_sidebar::ChannelRow;
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::preferences::PreferenceSaveStatus;
use crate::primitives::{
    Avatar, AvatarSize, Button, ButtonSize, ButtonVariant, IconSize, IconView, Input, InputType,
    LocaleSwitch, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupLabel, SidebarHeader,
    SidebarNavLink, SidebarNavList, ThemeToggle,
};

#[cfg(any(target_arch = "wasm32", test))]
const FIRST_RETRY_MS: u32 = 500;
#[cfg(any(target_arch = "wasm32", test))]
const MAX_RETRY_MS: u32 = 30_000;

/// Production AppSidebar content. The responsive container itself is the shared Sidebar primitive.
#[component]
pub fn AppSidebar() -> impl IntoView {
    let i18n = use_i18n();
    let location = use_location();
    let channels = RwSignal::new(Vec::<ChannelSummary>::new());
    let next_cursor = RwSignal::new(None::<String>);
    let search = RwSignal::new(String::new());
    let loading = RwSignal::new(true);
    let loading_more = RwSignal::new(false);
    let load_error = RwSignal::new(false);
    let reload_generation = RwSignal::new(0_u64);
    let current_user = RwSignal::new(None::<CurrentUser>);
    let revocable = RwSignal::new(false);
    let account_error = RwSignal::new(false);
    let admin_visible = RwSignal::new(false);
    let sign_out_pending = RwSignal::new(false);
    let sign_out_error = RwSignal::new(false);

    install_roster_loader(
        reload_generation,
        channels,
        next_cursor,
        loading,
        load_error,
    );
    install_channel_socket(reload_generation);
    load_identity(current_user, revocable, account_error);
    load_admin_visibility(admin_visible);

    let visible_channels = Memo::new(move |_| filter_channels(&channels.get(), &search.get()));
    let retry =
        move |_| reload_generation.update(|generation| *generation = generation.saturating_add(1));
    let load_more = move |_| {
        let Some(cursor) = next_cursor.get_untracked() else {
            return;
        };
        if loading_more.get_untracked() {
            return;
        }
        loading_more.set(true);
        load_error.set(false);
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            match list_channels(Some(&cursor)).await {
                Ok(page) => match append_page(&channels.get_untracked(), page) {
                    Ok((merged, cursor)) => {
                        channels.set(merged);
                        next_cursor.set(cursor);
                    }
                    Err(()) => {
                        // Activity can reorder a row across a keyset boundary while paging.
                        // Recover from the authoritative first page instead of showing duplicates.
                        reload_generation
                            .update(|generation| *generation = generation.saturating_add(1));
                    }
                },
                Err(_) => load_error.set(true),
            }
            loading_more.set(false);
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = cursor;
            loading_more.set(false);
        }
    };
    let sign_out = move |_| {
        if sign_out_pending.get_untracked() {
            return;
        }
        sign_out_pending.set(true);
        sign_out_error.set(false);
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            match sign_out_current_session().await {
                Ok(()) => {
                    if let Some(window) = web_sys::window() {
                        _ = window.location().set_href("/sign");
                    }
                }
                Err(_) => {
                    sign_out_pending.set(false);
                    sign_out_error.set(true);
                }
            }
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            sign_out_pending.set(false);
            sign_out_error.set(true);
        }
    };

    let chat_location = location.clone();
    let roster_location = location.clone();
    let agents_location = location.clone();
    let library_location = location.clone();
    let approvals_location = location.clone();
    let plugins_location = location.clone();
    let admin_location = location;
    let search_open = RwSignal::new(false);
    view! {
        <span hidden aria-hidden="true" data-roster-generation=move || reload_generation.get().to_string()></span>
        <SidebarHeader>
            <a class="ob-sidebar-brand" href="/" aria-label=move || t_string!(i18n, common.app_name).to_owned()>
                <crate::primitives::BrandMark/>
            </a>
            <button class="ob-sidebar-search-toggle" type="button"
                aria-label=move || t_string!(i18n, shell.search_toggle).to_owned()
                aria-expanded=move || search_open.get().to_string()
                aria-controls="sidebar-search-panel"
                on:click=move |_| search_open.update(|open| *open = !*open)>
                <IconView icon=Icon::Search size=IconSize::Navigation />
            </button>
        </SidebarHeader>
        <SidebarContent>
            <SidebarNavList>
                <SidebarNavLink href="/".to_owned() icon=Icon::Pencil
                    label=move || t_string!(i18n, shell.nav_chat).to_owned()
                    current=Signal::derive(move || chat_location.pathname.get() == "/") />
                <SidebarNavLink href="/agents".to_owned() icon=Icon::Bot
                    label=move || t_string!(i18n, shell.nav_agents).to_owned()
                    current=Signal::derive(move || agents_location.pathname.get() == "/agents") />
                <SidebarNavLink href="/settings/components-gallery".to_owned() icon=Icon::Archive
                    label=move || t_string!(i18n, shell.nav_library).to_owned()
                    current=Signal::derive(move || library_location.pathname.get().starts_with("/settings/components-gallery")) />
                <SidebarNavLink href="/approvals".to_owned() icon=Icon::Clock
                    label=move || t_string!(i18n, admin.nav_approvals).to_owned()
                    current=Signal::derive(move || approvals_location.pathname.get() == "/approvals") />
            </SidebarNavList>
            <details class="ob-workspace-disclosure" on:keydown=crate::primitives::dismiss_disclosure on:click=crate::primitives::dismiss_disclosure_link>
                <summary>{move || t!(i18n, shell.workspace)}<IconView icon=Icon::ChevronDown size=IconSize::Inline /></summary>
                <a class="ob-sidebar-secondary-link" href="/bot"><IconView icon=Icon::Globe size=IconSize::Inline />{move || t!(i18n, shell.nav_bot)}</a>
                <a class="ob-sidebar-secondary-link" href="/skills"><IconView icon=Icon::FileText size=IconSize::Inline />{move || t!(i18n, shell.nav_skills)}</a>
                <a class="ob-sidebar-secondary-link" href="/settings/memory"><IconView icon=Icon::Brain size=IconSize::Inline />{move || t!(i18n, shell.nav_memory)}</a>
                <a class="ob-sidebar-secondary-link" href="/channel/new"><IconView icon=Icon::Plus size=IconSize::Inline />{move || t!(i18n, shell.new_channel)}</a>
            </details>
            <SidebarGroup>
                <div class="ob-sidebar-chats-heading">
                    <SidebarGroupLabel>{move || t!(i18n, shell.chats)}</SidebarGroupLabel>
                    <a href="/channel/new" aria-label=move || t_string!(i18n, shell.new_channel).to_owned()>
                        <IconView icon=Icon::Plus size=IconSize::Inline />
                    </a>
                </div>
                <div id="sidebar-search-panel" hidden=move || !search_open.get()>
                    <Input value=search input_type=InputType::Search
                        aria_label=move || t_string!(i18n, channels.search_label).to_owned()
                        placeholder=move || t_string!(i18n, channels.search_placeholder) />
                </div>
                <Show when=move || loading.get()>
                    <div class="ob-sidebar-loading" role="status">{move || t!(i18n, common.loading)}</div>
                </Show>
                <Show when=move || load_error.get()>
                    <div class="ob-sidebar-alert" role="alert">
                        <span>{move || t!(i18n, channels.load_error)}</span>
                        <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=retry>{move || t!(i18n, common.retry)}</Button>
                    </div>
                </Show>
                <Show when=move || !search.get().trim().is_empty() && !loading.get() && visible_channels.get().is_empty()>
                    <p class="ob-sidebar-search-empty" role="status">{move || t!(i18n, channels.no_match_title)}</p>
                </Show>
                <SidebarNavList>
                    <For each=move || visible_channels.get() key=|channel| channel.id.clone()
                        children=move |channel| {
                            let href = channel_route_href(channel.id.as_str()).expect("server channel id is route-safe");
                            let row_location = roster_location.clone();
                            let current = Signal::derive(move || row_location.pathname.get() == href);
                            view! { <ChannelRow channel current=current /> }
                        } />
                </SidebarNavList>
                <Show when=move || next_cursor.get().is_some() && search.get().trim().is_empty()>
                    <Button variant=ButtonVariant::Ghost size=ButtonSize::Medium loading=loading_more on_activate=load_more>{move || t!(i18n, channels.load_more)}</Button>
                </Show>
            </SidebarGroup>
        </SidebarContent>
        <SidebarFooter>
            <SidebarNavList>
                <SidebarNavLink href="/settings/connected-accounts".to_owned() icon=Icon::Puzzle
                    label=move || t_string!(i18n, plugins.title).to_owned()
                    current=Signal::derive(move || plugins_location.pathname.get().starts_with("/settings/connected-accounts")) />
            </SidebarNavList>
            <details class="ob-account-disclosure" on:keydown=crate::primitives::dismiss_disclosure on:click=crate::primitives::dismiss_disclosure_link>
                <summary aria-label=move || t_string!(i18n, shell.account_menu).to_owned()>
                    <Show when=move || current_user.get().is_some()
                        fallback=move || view! { <IconView icon=Icon::User size=IconSize::Navigation /><span class="ob-sidebar-link-label">{move || t!(i18n, shell.account)}</span> }>
                        {move || current_user.get().map(|user| {
                            let display = user.name.clone().unwrap_or_else(|| user.email.clone());
                            view! {
                                <Avatar principal_id=user.id.as_str().to_owned() name=display.clone() size=AvatarSize::Medium />
                                <span class="ob-sidebar-link-label">{display}</span>
                            }
                        })}
                    </Show>
                    <span class="ob-account-chevron"><IconView icon=Icon::ChevronsUpDown size=IconSize::Inline /></span>
                </summary>
                <div class="ob-account-panel">
                    <a class="ob-sidebar-secondary-link" href="/settings"><IconView icon=Icon::Settings size=IconSize::Inline />{move || t!(i18n, shell.nav_settings)}</a>
                    <Show when=move || admin_visible.get()>
                        <a class="ob-sidebar-secondary-link" href="/admin" aria-current=move || is_admin_path(&admin_location.pathname.get()).then_some("page")>
                            <IconView icon=Icon::ShieldLock size=IconSize::Inline />{move || t!(i18n, shell.nav_admin)}
                        </a>
                    </Show>
                    <div class="ob-sidebar-preferences"><ThemeToggle /><LocaleSwitch id="sidebar-locale-switch" /><PreferenceSaveStatus /></div>
                    <Show when=move || revocable.get()>
                        <Button variant=ButtonVariant::DangerText size=ButtonSize::Medium loading=sign_out_pending on_activate=sign_out>
                            <IconView icon=Icon::LogOut size=IconSize::Inline /><span>{move || t!(i18n, auth.sign_out)}</span>
                        </Button>
                    </Show>
                </div>
            </details>
            <Show when=move || sign_out_error.get()><p class="ob-sidebar-alert" role="alert">{move || t!(i18n, auth.sign_out_error)}</p></Show>
            <Show when=move || account_error.get()><p class="ob-sidebar-alert" role="alert">{move || t!(i18n, account.load_failed)}</p></Show>
        </SidebarFooter>
    }
}

fn load_admin_visibility(admin_visible: RwSignal<bool>) {
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        admin_visible.set(require_admin_status().await.is_ok());
    });
    #[cfg(not(target_arch = "wasm32"))]
    admin_visible.set(false);
}

fn is_admin_path(pathname: &str) -> bool {
    pathname == "/admin"
        || pathname
            .strip_prefix("/admin/")
            .is_some_and(|suffix| !suffix.is_empty())
}

fn filter_channels(channels: &[ChannelSummary], query: &str) -> Vec<ChannelSummary> {
    let needle = query.trim().to_lowercase();
    if needle.is_empty() {
        return channels.to_vec();
    }
    channels
        .iter()
        .filter(|channel| {
            channel.name.to_lowercase().contains(&needle)
                || channel
                    .last_message
                    .as_deref()
                    .is_some_and(|message| message.to_lowercase().contains(&needle))
        })
        .cloned()
        .collect()
}

#[cfg(any(target_arch = "wasm32", test))]
fn append_page(
    existing: &[ChannelSummary],
    page: ChannelPage,
) -> Result<(Vec<ChannelSummary>, Option<String>), ()> {
    let mut ids = HashSet::with_capacity(existing.len() + page.channels.len());
    let mut merged = Vec::with_capacity(existing.len() + page.channels.len());
    for channel in existing.iter().chain(&page.channels) {
        if !ids.insert(channel.id.clone()) {
            return Err(());
        }
        merged.push(channel.clone());
    }
    Ok((merged, page.next_cursor))
}

fn install_roster_loader(
    reload_generation: RwSignal<u64>,
    channels: RwSignal<Vec<ChannelSummary>>,
    next_cursor: RwSignal<Option<String>>,
    loading: RwSignal<bool>,
    load_error: RwSignal<bool>,
) {
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        let generation = reload_generation.get();
        loading.set(true);
        load_error.set(false);
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let outcome = list_channels(None).await;
            if reload_generation.get_untracked() != generation {
                return;
            }
            match outcome {
                Ok(page) => match append_page(&[], page) {
                    Ok((loaded, cursor)) => {
                        channels.set(loaded);
                        next_cursor.set(cursor);
                    }
                    Err(()) => {
                        channels.set(Vec::new());
                        next_cursor.set(None);
                        load_error.set(true);
                    }
                },
                Err(_) => {
                    channels.set(Vec::new());
                    next_cursor.set(None);
                    load_error.set(true);
                }
            }
            loading.set(false);
        });
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (
        reload_generation,
        channels,
        next_cursor,
        loading,
        load_error,
    );
}

fn load_identity(
    current_user: RwSignal<Option<CurrentUser>>,
    revocable: RwSignal<bool>,
    account_error: RwSignal<bool>,
) {
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        let (user, session) = futures_util::join!(load_current_user(), load_session_status());
        match user {
            Ok(user) => current_user.set(Some(user)),
            Err(_) => account_error.set(true),
        }
        match session {
            Ok(session) => revocable.set(session.revocable),
            Err(_) => account_error.set(true),
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (current_user, revocable, account_error);
}

fn install_channel_socket(reload_generation: RwSignal<u64>) {
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        use futures_util::StreamExt as _;
        use gloo_net::websocket::{Message, futures::WebSocket};
        use openbot_contracts::command::ChannelActivityEvent;

        let mut retry = FIRST_RETRY_MS;
        loop {
            // Refetch first: the socket is an optimisation and has no replay cursor.
            reload_generation.update(|generation| *generation = generation.saturating_add(1));
            if is_tauri_host() {
                let handlers = DesktopStructuredHandlers::new(
                    move |event| match event {
                        AppEvent::ChannelActivity(_) => {
                            reload_generation
                                .update(|generation| *generation = generation.saturating_add(1));
                            true
                        }
                        AppEvent::ChannelStreamError { .. } => {
                            reload_generation
                                .update(|generation| *generation = generation.saturating_add(1));
                            false
                        }
                        AppEvent::Heartbeat { .. }
                        | AppEvent::ThreadRunEvent(_)
                        | AppEvent::ThreadStreamError { .. }
                        | AppEvent::ToolApprovalActivity(_)
                        | AppEvent::ToolApprovalStreamError { .. } => false,
                    },
                    move |_| {
                        reload_generation
                            .update(|generation| *generation = generation.saturating_add(1));
                    },
                    move || {
                        reload_generation
                            .update(|generation| *generation = generation.saturating_add(1));
                    },
                );
                match open_desktop_structured(SubscriptionRequest::ChannelActivity, handlers) {
                    Ok(connection) => {
                        retry = FIRST_RETRY_MS;
                        connection.finished().await;
                    }
                    Err(()) => {
                        wait_ms(retry).await;
                        retry = next_retry(retry);
                        continue;
                    }
                }
                wait_ms(retry).await;
                retry = next_retry(retry);
                continue;
            }
            let Some(url) = channel_socket_url() else {
                wait_ms(retry).await;
                retry = next_retry(retry);
                continue;
            };
            let Ok(mut socket) = WebSocket::open_with_protocol(&url, "openbot.channel-activity.v1")
            else {
                wait_ms(retry).await;
                retry = next_retry(retry);
                continue;
            };
            while let Some(message) = socket.next().await {
                match message {
                    Ok(Message::Text(text))
                        if serde_json::from_str::<ChannelActivityEvent>(&text).is_ok() =>
                    {
                        retry = FIRST_RETRY_MS;
                        reload_generation
                            .update(|generation| *generation = generation.saturating_add(1));
                    }
                    Ok(Message::Text(_) | Message::Bytes(_)) | Err(_) => {
                        reload_generation
                            .update(|generation| *generation = generation.saturating_add(1));
                        break;
                    }
                }
            }
            wait_ms(retry).await;
            retry = next_retry(retry);
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = reload_generation;
}

#[cfg(target_arch = "wasm32")]
fn channel_socket_url() -> Option<String> {
    let location = web_sys::window()?.location();
    let protocol = match location.protocol().ok()?.as_str() {
        "https:" => "wss:",
        "http:" => "ws:",
        _ => return None,
    };
    Some(format!(
        "{protocol}//{}/api/channels/events",
        location.host().ok()?
    ))
}

#[cfg(target_arch = "wasm32")]
async fn wait_ms(milliseconds: u32) {
    use wasm_bindgen_futures::JsFuture;

    let promise = js_sys::Promise::new(&mut |resolve, _| {
        if let Some(window) = web_sys::window() {
            _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                &resolve,
                i32::try_from(milliseconds).unwrap_or(i32::MAX),
            );
        } else {
            _ = resolve.call0(&wasm_bindgen::JsValue::NULL);
        }
    });
    _ = JsFuture::from(promise).await;
}

#[cfg(any(target_arch = "wasm32", test))]
fn next_retry(current: u32) -> u32 {
    current.saturating_mul(2).min(MAX_RETRY_MS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::ids::ChannelId;
    use time::macros::datetime;

    fn channel(id: &str, name: &str, message: Option<&str>) -> ChannelSummary {
        ChannelSummary {
            id: ChannelId::new(id),
            name: name.to_owned(),
            agent_ids: Vec::new(),
            last_message: message.map(str::to_owned),
            last_message_at: None,
            last_message_agent_id: None,
            created_at: datetime!(2026-08-26 00:00 UTC),
            thread_id: None,
            active: true,
        }
    }

    #[test]
    fn search_only_matches_visible_name_or_preview_and_empty_keeps_order() {
        let rows = vec![
            channel("a", "Finance", Some("Categorized expenses")),
            channel("b", "Research", Some("Read the report")),
        ];
        assert_eq!(filter_channels(&rows, " "), rows);
        assert_eq!(filter_channels(&rows, "FIN")[0].id.as_str(), "a");
        assert_eq!(filter_channels(&rows, "report")[0].id.as_str(), "b");
        assert!(filter_channels(&rows, "hidden history").is_empty());
    }

    #[test]
    fn page_append_rejects_duplicate_ids_and_retry_is_bounded() {
        let first = channel("a", "A", None);
        let second = channel("b", "B", None);
        let (merged, cursor) = append_page(
            std::slice::from_ref(&first),
            ChannelPage {
                channels: vec![second],
                next_cursor: Some("next".to_owned()),
            },
        )
        .unwrap();
        assert_eq!(merged.len(), 2);
        assert_eq!(cursor.as_deref(), Some("next"));
        assert!(
            append_page(
                std::slice::from_ref(&first),
                ChannelPage {
                    channels: vec![first.clone()],
                    next_cursor: None,
                }
            )
            .is_err()
        );
        assert_eq!(FIRST_RETRY_MS, 500);
        assert_eq!(next_retry(500), 1_000);
        assert_eq!(next_retry(20_000), MAX_RETRY_MS);
        assert_eq!(next_retry(MAX_RETRY_MS), MAX_RETRY_MS);
        assert!(is_admin_path("/admin"));
        assert!(is_admin_path("/admin/audit"));
        assert!(!is_admin_path("/admin-old"));
        assert!(!is_admin_path("/settings"));
    }
}
