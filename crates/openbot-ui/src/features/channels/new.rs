//! Real `/channel/new` first-message journey without a fake full-chat runtime.

use leptos::prelude::*;
use leptos_router::hooks::{use_navigate, use_query_map};
use openbot_contracts::agent::AgentProfile;
use openbot_contracts::command::ChannelDetail;
use openbot_contracts::ids::{BotId, RunId};
use openbot_contracts::text::trim_ecmascript;

use crate::api::channel_new_href;
#[cfg(target_arch = "wasm32")]
use crate::api::channel_route_href;
#[cfg(target_arch = "wasm32")]
use crate::api::{
    ApiError, begin_thread_run_with_skills, create_channel, list_agents, load_agent, mint_run_id,
};
use crate::features::layout::{PageBackLink, PageHeader, PageShell, PageTopbar, PageWidth};
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{Button, ButtonSize, ButtonVariant, IconSize, IconView, Textarea};

use super::RecipientField;
use super::composer::skills::{SkillComposer, SkillPicker};

/// One recipient/message/run identity retained across a recoverable first-message retry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StartAttempt {
    pub(crate) agent_id: BotId,
    pub(crate) message: String,
    pub(crate) run_id: RunId,
    pub(crate) channel: Option<ChannelDetail>,
    pub(crate) selected_skill_slugs: Vec<String>,
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StartFailureKind {
    CreateDefinite,
    CreateUncertain,
    Begin,
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StartFailure {
    pub(crate) attempt: StartAttempt,
    pub(crate) kind: StartFailureKind,
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StartedChannel {
    pub(crate) attempt: StartAttempt,
    pub(crate) channel: ChannelDetail,
}

/// Execute the single shared create → BeginRun ordering.
#[cfg(target_arch = "wasm32")]
pub(crate) async fn execute_start_attempt(
    mut attempt: StartAttempt,
) -> Result<StartedChannel, StartFailure> {
    let channel = match attempt.channel.clone() {
        Some(channel) => channel,
        None => match create_channel(&attempt.agent_id).await {
            Ok(channel) => {
                attempt.channel = Some(channel.clone());
                channel
            }
            Err(error) => {
                return Err(StartFailure {
                    attempt,
                    kind: if error == ApiError::Network {
                        StartFailureKind::CreateUncertain
                    } else {
                        StartFailureKind::CreateDefinite
                    },
                });
            }
        },
    };
    let Some(thread_id) = channel.thread_id.as_ref() else {
        return Err(StartFailure {
            attempt,
            kind: StartFailureKind::Begin,
        });
    };
    if begin_thread_run_with_skills(
        thread_id,
        &attempt.agent_id,
        &attempt.run_id,
        openbot_contracts::command::ThreadRunAnchor::Channel {
            channel_id: channel.id.clone(),
        },
        &attempt.message,
        &attempt.selected_skill_slugs,
    )
    .await
    .is_err()
    {
        return Err(StartFailure {
            attempt,
            kind: StartFailureKind::Begin,
        });
    }
    Ok(StartedChannel { attempt, channel })
}

/// Select one visible coworker, then atomically create a channel and begin its native first run.
#[component]
pub fn ChannelNewPage() -> impl IntoView {
    let i18n = use_i18n();
    let query = use_query_map();
    let navigate = use_navigate();
    let agents = RwSignal::new(Vec::<AgentProfile>::new());
    let selected = RwSignal::new(None::<String>);
    let selected_profile = RwSignal::new(None::<AgentProfile>);
    let loading = RwSignal::new(true);
    let load_error = RwSignal::new(false);
    let load_generation = RwSignal::new(0_u64);
    let draft = RwSignal::new(String::new());
    let skill_composer = SkillComposer::new(
        draft,
        Signal::derive(move || selected_profile.get().map(|p| p.id)),
        "channel-new-message",
    );
    let submitting = RwSignal::new(false);
    let start_error = RwSignal::new(false);
    let uncertain_create = RwSignal::new(false);
    let resumable = RwSignal::new(None::<StartAttempt>);

    install_recipient_loader(
        query,
        agents,
        selected,
        selected_profile,
        loading,
        load_error,
        load_generation,
    );

    let select_navigate = navigate.clone();
    let select = UnsyncCallback::new(move |agent_id: Option<String>| {
        let Some(agent_id) = agent_id else {
            return;
        };
        if let Ok(href) = channel_new_href(&agent_id) {
            select_navigate(&href, Default::default());
        }
    });
    let inputs_locked = Signal::derive(move || submitting.get() || resumable.get().is_some());
    let send_disabled = Signal::derive(move || {
        submitting.get()
            || uncertain_create.get()
            || selected_profile.get().is_none()
            || trim_ecmascript(&draft.get()).is_empty()
            || (resumable.get().is_none() && skill_composer.invalid.get())
    });
    #[cfg(target_arch = "wasm32")]
    let send_navigate = navigate;
    #[cfg(not(target_arch = "wasm32"))]
    let _ = navigate;
    let send = move |_| {
        if send_disabled.get_untracked() {
            return;
        }
        let Some(profile) = selected_profile.get_untracked() else {
            return;
        };
        let message = draft.get_untracked();
        if trim_ecmascript(&message).is_empty() {
            return;
        }
        submitting.set(true);
        start_error.set(false);
        #[cfg(target_arch = "wasm32")]
        let navigate_after_send = send_navigate.clone();
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let attempt = resumable.get_untracked().unwrap_or_else(|| StartAttempt {
                agent_id: profile.id.clone(),
                message: message.clone(),
                run_id: mint_run_id(),
                channel: None,
                selected_skill_slugs: skill_composer.selected.get_untracked(),
            });
            match execute_start_attempt(attempt).await {
                Ok(started) => {
                    resumable.set(Some(started.attempt));
                    match channel_route_href(started.channel.id.as_str()) {
                        Ok(href) => navigate_after_send(&href, Default::default()),
                        Err(_) => start_error.set(true),
                    }
                }
                Err(failure) => {
                    match failure.kind {
                        StartFailureKind::CreateUncertain => uncertain_create.set(true),
                        StartFailureKind::CreateDefinite => resumable.set(None),
                        StartFailureKind::Begin => resumable.set(Some(failure.attempt)),
                    }
                    start_error.set(true);
                }
            }
            submitting.set(false);
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (profile, message);
            submitting.set(false);
            start_error.set(true);
        }
    };

    view! {
        <PageShell width=PageWidth::Chat>
            <PageTopbar>
                <PageBackLink href="/agents".to_owned() label=move || t_string!(i18n, common.back).to_owned() />
            </PageTopbar>
            <div class="ob-channel-new">
                <PageHeader
                    heading_id="channel-new-title"
                    title=move || t_string!(i18n, channels.new_channel).to_owned()
                    description=move || t_string!(i18n, channels.new_intro).to_owned()
                />
                <Show when=move || loading.get()>
                    <div class="ob-loading" role="status">{move || t!(i18n, common.loading)}</div>
                </Show>
                <Show when=move || load_error.get()>
                    <p class="ob-alert" role="alert">{move || t!(i18n, channels.recipient_load_error)}</p>
                </Show>
                <div class="ob-channel-new-recipient">
                    <label for="channel-new-recipient">{move || t!(i18n, channels.recipient_label)}</label>
                    <RecipientField
                        agents=Signal::derive(move || agents.get())
                        selected
                        aria_label=move || t_string!(i18n, channels.recipient_label).to_owned()
                        placeholder=move || t_string!(i18n, channels.recipient_placeholder).to_owned()
                        empty_label=move || t_string!(i18n, channels.recipient_empty).to_owned()
                        disabled=inputs_locked
                        on_select=select
                    />
                </div>
                <div class="ob-first-message-composer">
                    <SkillPicker state=skill_composer disabled=inputs_locked/>
                    <Textarea
                        value=draft
                        id="channel-new-message"
                        aria_label=move || t_string!(i18n, channels.composer_placeholder).to_owned()
                        placeholder=move || t_string!(i18n, channels.composer_placeholder).to_owned()
                        disabled=inputs_locked
                        combobox_controls="channel-skill-results"
                        combobox_open=skill_composer.open
                        active_descendant=skill_composer.active_descendant
                        on_keydown=UnsyncCallback::new(move |event| skill_composer.keyboard(event))
                    />
                    <div class="ob-first-message-actions">
                        <Button
                            variant=ButtonVariant::Primary
                            size=ButtonSize::Medium
                            disabled=send_disabled
                            loading=submitting
                            on_activate=send
                        >
                            <IconView icon=Icon::Send size=IconSize::Inline />
                            <span>{move || if resumable.get().is_some() {
                                t_string!(i18n, common.retry).to_owned()
                            } else {
                                t_string!(i18n, channels.composer_send).to_owned()
                            }}</span>
                        </Button>
                    </div>
                </div>
                <Show when=move || start_error.get()>
                    <p class="ob-alert" role="alert">{move || t!(i18n, channels.start_error)}</p>
                </Show>
                <Show when=move || uncertain_create.get()>
                    <p class="ob-alert" role="alert">{move || t!(i18n, channels.create_uncertain)}</p>
                </Show>
            </div>
        </PageShell>
    }
}

#[allow(clippy::too_many_arguments)]
fn install_recipient_loader(
    query: Memo<leptos_router::params::ParamsMap>,
    agents: RwSignal<Vec<AgentProfile>>,
    selected: RwSignal<Option<String>>,
    selected_profile: RwSignal<Option<AgentProfile>>,
    loading: RwSignal<bool>,
    load_error: RwSignal<bool>,
    generation: RwSignal<u64>,
) {
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        let requested = query.get().get("agent");
        let current = generation.get_untracked().saturating_add(1);
        generation.set(current);
        selected.set(requested.clone());
        selected_profile.set(None);
        loading.set(true);
        load_error.set(false);
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let roster = list_agents(false).await;
            let direct = match requested.as_deref() {
                Some(agent_id) => Some(load_agent(agent_id).await),
                None => None,
            };
            if generation.get_untracked() != current {
                return;
            }
            let roster_failed = roster.is_err();
            let mut loaded = roster.unwrap_or_default();
            match direct {
                Some(Ok(profile)) => {
                    if !loaded.iter().any(|agent| agent.id == profile.id) {
                        loaded.push(profile.clone());
                        loaded.sort_by(|left, right| left.id.cmp(&right.id));
                    }
                    selected_profile.set(Some(profile));
                }
                Some(Err(_)) => load_error.set(true),
                None if roster_failed => load_error.set(true),
                None => {}
            }
            agents.set(loaded);
            loading.set(false);
        });
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (
        query,
        agents,
        selected,
        selected_profile,
        loading,
        load_error,
        generation,
    );
}

#[cfg(test)]
mod tests {
    use openbot_contracts::ids::{ChannelId, ThreadId};

    use super::*;

    #[test]
    fn retry_identity_is_unchanged_when_the_channel_becomes_known() {
        let original = StartAttempt {
            selected_skill_slugs: vec!["review".to_owned()],
            agent_id: BotId::new("agent-1"),
            message: "hello".to_owned(),
            run_id: RunId::new("run-1"),
            channel: None,
        };
        let mut resumed = original.clone();
        resumed.channel = Some(ChannelDetail {
            id: ChannelId::new("channel-1"),
            name: "Agent One".to_owned(),
            agent_ids: vec![BotId::new("agent-1")],
            thread_id: Some(ThreadId::new("thread-1")),
            active: true,
        });
        assert_eq!(resumed.agent_id, original.agent_id);
        assert_eq!(resumed.message, original.message);
        assert_eq!(resumed.run_id, original.run_id);
    }
}
