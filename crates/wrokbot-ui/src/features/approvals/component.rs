//! Interactive current-actor approval page.

use std::collections::BTreeSet;

use leptos::prelude::*;
#[cfg(target_arch = "wasm32")]
use openbot_contracts::command::{AppEvent, SubscriptionRequest};
#[cfg(target_arch = "wasm32")]
use openbot_contracts::tool::MAX_PENDING_TOOL_APPROVALS;
use openbot_contracts::tool::{ToolApprovalClass, ToolApprovalDecision, ToolApprovalEffect};
use time::format_description::well_known::Rfc3339;

use super::ApprovalCardView;
use crate::api::ApiError;
#[cfg(target_arch = "wasm32")]
use crate::api::decide_tool_approval;
#[cfg(target_arch = "wasm32")]
use crate::api::desktop_transport::{
    DesktopStructuredHandlers, is_tauri_host, open_desktop_structured,
};
#[cfg(target_arch = "wasm32")]
use crate::api::list_pending_tool_approvals;
use crate::features::layout::{PageHeader, PageShell, PageTopbar, PageWidth};
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{
    Badge, BadgeTone, Button, ButtonSize, ButtonVariant, EmptyState, IconSize, IconView,
};

#[cfg(target_arch = "wasm32")]
const APPROVAL_ACTIVITY_PROTOCOL: &str = "openbot.tool-approvals.v1";
#[cfg(any(target_arch = "wasm32", test))]
const FIRST_RETRY_MS: u32 = 500;
#[cfg(any(target_arch = "wasm32", test))]
const MAX_RETRY_MS: u32 = 5_000;
#[cfg(target_arch = "wasm32")]
const FALLBACK_REFRESH_SECONDS: u32 = 30;

#[derive(Clone, Copy)]
struct ApprovalRefresh {
    approvals: RwSignal<Vec<ApprovalCardView>>,
    loading: RwSignal<bool>,
    load_error: RwSignal<Option<ApiError>>,
    epoch: RwSignal<u64>,
    #[cfg(target_arch = "wasm32")]
    worker_owner: StoredValue<Option<Owner>>,
}

impl ApprovalRefresh {
    fn request(self) {
        request_refresh(self);
    }
}

/// Current-actor list page for pending durable tool approvals.
#[component]
pub fn ApprovalPage() -> impl IntoView {
    let i18n = use_i18n();
    let approvals = RwSignal::new(Vec::<ApprovalCardView>::new());
    let loading = RwSignal::new(true);
    let load_error = RwSignal::new(None::<ApiError>);
    let decision_error = RwSignal::new(false);
    let notice = RwSignal::new(None::<ToolApprovalDecision>);
    let in_flight = RwSignal::new(BTreeSet::<String>::new());
    let now = RwSignal::new(now_epoch_seconds());
    let refresh = ApprovalRefresh {
        approvals,
        loading,
        load_error,
        epoch: RwSignal::new(0_u64),
        #[cfg(target_arch = "wasm32")]
        worker_owner: StoredValue::new(Owner::current()),
    };

    start_realtime(refresh, now);

    let refresh_page = move |_| {
        refresh.request();
    };

    view! {
        <PageShell width=PageWidth::Content>
            <PageTopbar>
                <p class="ob-eyebrow">{move || t!(i18n, admin.approval_pending)}</p>
                <Button
                    variant=ButtonVariant::Chip
                    size=ButtonSize::Medium
                    disabled=loading
                    loading=loading
                    on_activate=refresh_page
                >
                    <IconView icon=Icon::RefreshCw size=IconSize::Inline />
                    {move || t!(i18n, common.refresh)}
                </Button>
            </PageTopbar>
            <PageHeader
                heading_id="approvals-title"
                title=move || t_string!(i18n, admin.approvals_title).to_owned()
                description=move || t_string!(i18n, admin.approvals_intro).to_owned()
            />

            <Show when=move || load_error.get().is_some()>
                <div class="ob-alert" role="alert">
                    <IconView icon=Icon::TriangleAlert size=IconSize::Inline />
                    <span>{move || t!(i18n, admin.approval_load_error)}</span>
                </div>
            </Show>
            <Show when=move || decision_error.get()>
                <div class="ob-alert" role="alert">
                    <IconView icon=Icon::TriangleAlert size=IconSize::Inline />
                    <span>{move || t!(i18n, admin.approval_decision_error)}</span>
                    <button
                        type="button"
                        class="ob-alert-dismiss"
                        aria-label=move || t_string!(i18n, common.dismiss).to_owned()
                        on:click=move |_| decision_error.set(false)
                    >
                        <IconView icon=Icon::X size=IconSize::Inline />
                    </button>
                </div>
            </Show>
            <Show when=move || notice.get().is_some()>
                <div class="ob-status" role="status">
                    <IconView icon=Icon::CircleCheck size=IconSize::Inline />
                    <span>{move || match notice.get() {
                        Some(ToolApprovalDecision::Grant) => {
                            t_string!(i18n, admin.approval_granted).to_owned()
                        }
                        Some(ToolApprovalDecision::Deny) => {
                            t_string!(i18n, admin.approval_denied).to_owned()
                        }
                        None => String::new(),
                    }}</span>
                </div>
            </Show>

            {move || {
                if loading.get() && approvals.with(Vec::is_empty) {
                    view! {
                        <div class="ob-loading" role="status">
                            <IconView icon=Icon::LoaderCircle size=IconSize::Navigation />
                            <span>{t!(i18n, common.loading)}</span>
                        </div>
                    }
                    .into_any()
                } else if approvals.with(Vec::is_empty) {
                    view! {
                        <EmptyState
                            heading_id="approval-empty-title"
                            title=move || t_string!(i18n, admin.approval_empty_title)
                            body=move || t_string!(i18n, admin.approval_empty_body)
                        />
                    }
                    .into_any()
                } else {
                    view! {
                        <div class="ob-approval-list">
                            <For
                                each=move || approvals.get()
                                key=|card| card.approval_id.clone()
                                children=move |card| {
                                    view! {
                                        <ApprovalCard
                                            card
                                            now
                                            in_flight
                                            approvals
                                            decision_error
                                            notice
                                            refresh
                                        />
                                    }
                                }
                            />
                        </div>
                    }
                    .into_any()
                }
            }}
        </PageShell>
    }
}

#[component]
fn ApprovalCard(
    card: ApprovalCardView,
    now: RwSignal<i64>,
    in_flight: RwSignal<BTreeSet<String>>,
    approvals: RwSignal<Vec<ApprovalCardView>>,
    decision_error: RwSignal<bool>,
    notice: RwSignal<Option<ToolApprovalDecision>>,
    refresh: ApprovalRefresh,
) -> impl IntoView {
    let i18n = use_i18n();
    let heading_id = approval_heading_id(&card.approval_id);
    let arguments_id = format!("{heading_id}-arguments");
    let article_heading_id = heading_id.clone();
    let payload_heading_id = arguments_id.clone();
    let approval_id = card.approval_id.clone();
    let grant_id = approval_id.clone();
    let deny_id = approval_id.clone();
    let expires_at = card.expires_at;
    let expires_datetime = card
        .expires_at
        .format(&Rfc3339)
        .unwrap_or_else(|_| card.expires_at.unix_timestamp().to_string());
    let pending_id = approval_id.clone();
    let is_loading = Signal::derive(move || in_flight.with(|ids| ids.contains(&pending_id)));
    let is_expired =
        Signal::derive(move || remaining_seconds(expires_at.unix_timestamp(), now.get()) == 0);
    let unavailable = Signal::derive(move || is_loading.get() || is_expired.get());

    let grant = move |_| {
        dispatch_decision(
            grant_id.clone(),
            ToolApprovalDecision::Grant,
            approvals,
            in_flight,
            decision_error,
            notice,
            refresh,
        );
    };
    let deny = move |_| {
        dispatch_decision(
            deny_id.clone(),
            ToolApprovalDecision::Deny,
            approvals,
            in_flight,
            decision_error,
            notice,
            refresh,
        );
    };
    let effect = card.effect;
    let approval_class = card.approval_class;
    let server = card.server.clone();
    let change = card.change.clone();

    view! {
        <article class="ob-approval-card" aria-labelledby=article_heading_id>
            <header class="ob-approval-card-header">
                <div class="ob-approval-title-group">
                    <IconView icon=Icon::ShieldCheck size=IconSize::Navigation />
                    <div>
                        <h2 id=heading_id class="ob-approval-title">{card.tool_title}</h2>
                        {server.map(|server| view! { <p class="ob-approval-server">{server}</p> })}
                    </div>
                </div>
                <Badge tone=BadgeTone::Caution>
                    {move || effect_label(i18n, effect)}
                </Badge>
            </header>

            <dl class="ob-approval-facts">
                <div class="ob-approval-fact">
                    <dt>{move || t!(i18n, admin.approval_effect)}</dt>
                    <dd>{move || effect_label(i18n, effect)}</dd>
                </div>
                <div class="ob-approval-fact">
                    <dt>{move || t!(i18n, admin.approval_target)}</dt>
                    <dd>
                        <span class="ob-target-kind">{card.target_kind}</span>
                        <code class="ob-target-id">{card.target_id}</code>
                    </dd>
                </div>
                <div class="ob-approval-fact">
                    <dt>{move || t!(i18n, admin.approval_reuse)}</dt>
                    <dd>{move || approval_class_label(i18n, approval_class)}</dd>
                </div>
                <div class="ob-approval-fact">
                    <dt>
                        <IconView icon=Icon::Clock size=IconSize::Inline />
                        <span class="ob-visually-hidden">{move || t!(i18n, admin.approval_expiry)}</span>
                    </dt>
                    <dd>
                        <time datetime=expires_datetime>
                            {move || {
                                let seconds = remaining_seconds(expires_at.unix_timestamp(), now.get());
                                if seconds == 0 {
                                    t_string!(i18n, admin.approval_expired).to_owned()
                                } else {
                                    t_string!(i18n, admin.approval_expires, seconds = seconds)
                                }
                            }}
                        </time>
                    </dd>
                </div>
            </dl>

            <section class="ob-approval-payload" aria-labelledby=payload_heading_id>
                <h3 id=arguments_id>
                    {move || t!(i18n, admin.approval_arguments)}
                </h3>
                <pre><code>{card.arguments}</code></pre>
            </section>
            {change.map(|change| view! {
                <section class="ob-approval-payload">
                    <h3>{move || t!(i18n, admin.approval_change)}</h3>
                    <pre><code>{change}</code></pre>
                </section>
            })}

            <footer class="ob-approval-actions">
                <Button
                    variant=ButtonVariant::DangerText
                    size=ButtonSize::Medium
                    disabled=unavailable
                    loading=is_loading
                    on_activate=deny
                >
                    <IconView icon=Icon::X size=IconSize::Inline />
                    {move || t!(i18n, admin.approval_reject)}
                </Button>
                <Button
                    variant=ButtonVariant::Primary
                    size=ButtonSize::Medium
                    disabled=unavailable
                    loading=is_loading
                    on_activate=grant
                >
                    <IconView icon=Icon::Check size=IconSize::Inline />
                    {move || t!(i18n, admin.approval_approve)}
                </Button>
            </footer>
        </article>
    }
}

fn dispatch_decision(
    approval_id: String,
    decision: ToolApprovalDecision,
    approvals: RwSignal<Vec<ApprovalCardView>>,
    in_flight: RwSignal<BTreeSet<String>>,
    decision_error: RwSignal<bool>,
    notice: RwSignal<Option<ToolApprovalDecision>>,
    refresh: ApprovalRefresh,
) {
    if in_flight.with(|ids| ids.contains(&approval_id)) {
        return;
    }
    in_flight.update(|ids| {
        ids.insert(approval_id.clone());
    });
    decision_error.set(false);
    notice.set(None);

    #[cfg(target_arch = "wasm32")]
    {
        let start_worker = || {
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                match decide_tool_approval(&approval_id, decision).await {
                    Ok(_) => {
                        notice.set(Some(decision));
                        approvals
                            .update(|cards| cards.retain(|card| card.approval_id != approval_id));
                        refresh.request();
                    }
                    Err(_) => decision_error.set(true),
                }
                in_flight.update(|ids| {
                    ids.remove(&approval_id);
                });
            });
        };
        match refresh.worker_owner.get_value() {
            Some(owner) => owner.with(start_worker),
            None => start_worker(),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (decision, approvals, refresh);
        in_flight.update(|ids| {
            ids.remove(&approval_id);
        });
        decision_error.set(true);
    }
}

fn request_refresh(refresh: ApprovalRefresh) {
    let Some(request_epoch) = next_refresh_epoch(refresh.epoch.get_untracked()) else {
        refresh.loading.set(false);
        refresh.load_error.set(Some(ApiError::Unavailable));
        return;
    };
    refresh.epoch.set(request_epoch);
    refresh.loading.set(true);
    #[cfg(target_arch = "wasm32")]
    {
        let start_worker = || {
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                refresh_page(refresh, request_epoch).await;
            });
        };
        match refresh.worker_owner.get_value() {
            Some(owner) => owner.with(start_worker),
            None => start_worker(),
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = refresh.approvals;
        refresh.loading.set(false);
        refresh.load_error.set(Some(ApiError::Unavailable));
    }
}

fn start_realtime(refresh: ApprovalRefresh, now: RwSignal<i64>) {
    refresh.request();
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        let mut elapsed_seconds = 0_u32;
        loop {
            delay_ms(1_000).await;
            now.set(now_epoch_seconds());
            elapsed_seconds = elapsed_seconds.saturating_add(1);
            if elapsed_seconds >= FALLBACK_REFRESH_SECONDS {
                elapsed_seconds = 0;
                refresh.request();
            }
        }
    });
    #[cfg(target_arch = "wasm32")]
    install_approval_socket(refresh);
    #[cfg(not(target_arch = "wasm32"))]
    {
        refresh.loading.set(false);
        refresh.load_error.set(Some(ApiError::Unavailable));
        let _ = (refresh.approvals, now, refresh.epoch);
    }
}

#[cfg(target_arch = "wasm32")]
async fn delay_ms(milliseconds: u32) {
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        web_sys::window()
            .expect("CSR approval realtime requires Window")
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                &resolve,
                i32::try_from(milliseconds).unwrap_or(i32::MAX),
            )
            .expect("browser rejected approval realtime timer");
    });
    _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

#[cfg(target_arch = "wasm32")]
fn install_approval_socket(refresh: ApprovalRefresh) {
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        use futures_util::StreamExt as _;
        use gloo_net::websocket::{Message, futures::WebSocket};
        use openbot_contracts::tool::ToolApprovalActivityEvent;

        let mut retry = FIRST_RETRY_MS;
        loop {
            // The socket has no replay cursor. Refetch before every connection/reconnection.
            refresh.request();
            if is_tauri_host() {
                let handlers = DesktopStructuredHandlers::new(
                    move |event| match event {
                        AppEvent::ToolApprovalActivity(event)
                            if event.pending_count <= MAX_PENDING_TOOL_APPROVALS =>
                        {
                            refresh.request();
                            true
                        }
                        AppEvent::ToolApprovalActivity(_)
                        | AppEvent::ToolApprovalStreamError { .. } => {
                            refresh.request();
                            false
                        }
                        AppEvent::Heartbeat { .. }
                        | AppEvent::ThreadRunEvent(_)
                        | AppEvent::ThreadStreamError { .. }
                        | AppEvent::ChannelActivity(_)
                        | AppEvent::ChannelStreamError { .. } => false,
                    },
                    move |_| refresh.request(),
                    move || refresh.request(),
                );
                match open_desktop_structured(SubscriptionRequest::ToolApprovalActivity, handlers) {
                    Ok(connection) => {
                        retry = FIRST_RETRY_MS;
                        connection.finished().await;
                    }
                    Err(()) => {
                        delay_ms(retry).await;
                        retry = next_retry(retry);
                        continue;
                    }
                }
                delay_ms(retry).await;
                retry = next_retry(retry);
                continue;
            }
            let Some(url) = approval_socket_url() else {
                delay_ms(retry).await;
                retry = next_retry(retry);
                continue;
            };
            let Ok(mut socket) = WebSocket::open_with_protocol(&url, APPROVAL_ACTIVITY_PROTOCOL)
            else {
                delay_ms(retry).await;
                retry = next_retry(retry);
                continue;
            };
            while let Some(message) = socket.next().await {
                match message {
                    Ok(Message::Text(text)) => {
                        let event = serde_json::from_str::<ToolApprovalActivityEvent>(&text);
                        if !matches!(event, Ok(event) if event.pending_count <= MAX_PENDING_TOOL_APPROVALS)
                        {
                            refresh.request();
                            break;
                        }
                        retry = FIRST_RETRY_MS;
                        refresh.request();
                    }
                    Ok(Message::Bytes(_)) | Err(_) => {
                        refresh.request();
                        break;
                    }
                }
            }
            delay_ms(retry).await;
            retry = next_retry(retry);
        }
    });
}

#[cfg(target_arch = "wasm32")]
fn approval_socket_url() -> Option<String> {
    let location = web_sys::window()?.location();
    let protocol = match location.protocol().ok()?.as_str() {
        "https:" => "wss:",
        "http:" => "ws:",
        _ => return None,
    };
    Some(format!(
        "{protocol}//{}/api/tool-approvals/events",
        location.host().ok()?
    ))
}

#[cfg(any(target_arch = "wasm32", test))]
fn next_retry(current: u32) -> u32 {
    current.saturating_mul(2).min(MAX_RETRY_MS)
}

fn next_refresh_epoch(current: u64) -> Option<u64> {
    current.checked_add(1)
}

#[cfg(target_arch = "wasm32")]
async fn refresh_page(refresh: ApprovalRefresh, request_epoch: u64) {
    let result = list_pending_tool_approvals().await;
    if refresh.epoch.get_untracked() != request_epoch {
        return;
    }
    match result {
        Ok(page) => {
            refresh.approvals.set(
                page.approvals
                    .iter()
                    .map(ApprovalCardView::from_pending)
                    .collect(),
            );
            refresh.load_error.set(None);
        }
        Err(error) => refresh.load_error.set(Some(error)),
    }
    refresh.loading.set(false);
}

fn effect_label(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    effect: ToolApprovalEffect,
) -> String {
    match effect {
        ToolApprovalEffect::Write => t_string!(i18n, admin.approval_effect_write).to_owned(),
        ToolApprovalEffect::Execute => t_string!(i18n, admin.approval_effect_execute).to_owned(),
        ToolApprovalEffect::Network => t_string!(i18n, admin.approval_effect_network).to_owned(),
        ToolApprovalEffect::Credential => {
            t_string!(i18n, admin.approval_effect_credential).to_owned()
        }
    }
}

fn approval_class_label(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    class: ToolApprovalClass,
) -> String {
    match class {
        ToolApprovalClass::OncePerRun => t_string!(i18n, admin.approval_once_per_run).to_owned(),
        ToolApprovalClass::EveryCall => t_string!(i18n, admin.approval_every_call).to_owned(),
    }
}

fn remaining_seconds(expires_at: i64, now: i64) -> i64 {
    expires_at.saturating_sub(now).max(0)
}

fn approval_heading_id(approval_id: &str) -> String {
    use core::fmt::Write as _;

    let mut id = String::from("approval-");
    for byte in approval_id.bytes() {
        write!(&mut id, "{byte:02x}").expect("writing to String cannot fail");
    }
    id
}

#[cfg(target_arch = "wasm32")]
fn now_epoch_seconds() -> i64 {
    (js_sys::Date::now() / 1_000.0).floor() as i64
}

#[cfg(not(target_arch = "wasm32"))]
fn now_epoch_seconds() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_is_inclusive_and_dom_ids_are_closed() {
        assert_eq!(remaining_seconds(101, 100), 1);
        assert_eq!(remaining_seconds(100, 100), 0);
        assert_eq!(remaining_seconds(99, 100), 0);
        let id = approval_heading_id("a / b");
        assert_eq!(id, "approval-61202f2062");
        assert!(
            id.chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
        );
        assert_eq!(next_retry(FIRST_RETRY_MS), 1_000);
        assert_eq!(next_retry(MAX_RETRY_MS), MAX_RETRY_MS);
        assert_eq!(next_refresh_epoch(0), Some(1));
        assert_eq!(next_refresh_epoch(u64::MAX), None);
    }
}
