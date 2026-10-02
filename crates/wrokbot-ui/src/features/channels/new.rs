//! Real `/channel/new` first-message journey without a fake full-chat runtime.

use leptos::prelude::*;
use leptos_router::hooks::{use_navigate, use_query_map};
use openbot_contracts::agent::AgentProfile;
use openbot_contracts::command::ChannelDetail;
use openbot_contracts::ids::{BotId, RunId};
use openbot_contracts::model_connections::RunModelSelection;
use openbot_contracts::text::trim_ecmascript;

#[cfg(any(target_arch = "wasm32", test))]
use crate::api::ApiError;
use crate::api::channel_new_href;
#[cfg(target_arch = "wasm32")]
use crate::api::channel_route_href;
#[cfg(target_arch = "wasm32")]
use crate::api::{
    begin_thread_run_with_skills_and_model, create_channel, list_agents, load_agent, mint_run_id,
};
use crate::features::layout::{PageBackLink, PageHeader, PageShell, PageTopbar, PageWidth};
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{Button, ButtonSize, ButtonVariant, IconSize, IconView, Textarea};

use super::RecipientField;
#[cfg(target_arch = "wasm32")]
use super::composer::model_intents::{CreateIntent, RunIntent, RunRecovery, is_definite_rejection};
use super::composer::model_intents::{RunSubmissionActions, SubmissionSource};
use super::composer::models::{ModelComposer, ModelPicker, ModelSelectionStatus};
use super::composer::skills::{SkillComposer, SkillPicker};

/// One recipient/message/run identity retained across a recoverable first-message retry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StartAttempt {
    pub(crate) source: SubmissionSource,
    pub(crate) agent_id: BotId,
    pub(crate) message: String,
    pub(crate) run_id: RunId,
    pub(crate) channel: Option<ChannelDetail>,
    pub(crate) selected_skill_slugs: Vec<String>,
    pub(crate) model_selection: Option<RunModelSelection>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SubmissionNotice {
    ModelAgentConflict,
    ModelSelectionUnavailable,
    Conflict,
    Rejected,
    NavigationFailed,
}

pub(crate) const fn model_notice(status: ModelSelectionStatus) -> Option<SubmissionNotice> {
    match status {
        ModelSelectionStatus::AgentDefault | ModelSelectionStatus::Ready => None,
        ModelSelectionStatus::AgentConflict => Some(SubmissionNotice::ModelAgentConflict),
        ModelSelectionStatus::Loading
        | ModelSelectionStatus::DirectoryFailed
        | ModelSelectionStatus::Unavailable => Some(SubmissionNotice::ModelSelectionUnavailable),
    }
}

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn definite_notice(error: Option<ApiError>) -> SubmissionNotice {
    if error == Some(ApiError::Conflict) {
        SubmissionNotice::Conflict
    } else {
        SubmissionNotice::Rejected
    }
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StartFailureKind {
    CreateDefinite,
    CreateUncertain,
    BeginDefinite,
    BeginUnknown,
    Blocked,
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StartFailure {
    pub(crate) attempt: StartAttempt,
    pub(crate) kind: StartFailureKind,
    pub(crate) error: Option<ApiError>,
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
    retry_unknown: bool,
) -> Result<StartedChannel, Box<StartFailure>> {
    let submissions = expect_context::<RunSubmissionActions>();
    let channel = match attempt.channel.clone() {
        Some(channel) => channel,
        None => {
            let create_intent = CreateIntent {
                source: attempt.source,
                run_id: attempt.run_id.clone(),
                agent_id: attempt.agent_id.clone(),
                message: attempt.message.clone(),
                selected_skill_slugs: attempt.selected_skill_slugs.clone(),
                model_selection: attempt.model_selection.clone(),
            };
            let Some(ticket) = submissions.start_create(&create_intent) else {
                return Err(Box::new(StartFailure {
                    attempt,
                    kind: StartFailureKind::Blocked,
                    error: None,
                }));
            };
            match create_channel(&attempt.agent_id).await {
                Ok(channel) => {
                    ticket.accepted();
                    attempt.channel = Some(channel.clone());
                    channel
                }
                Err(error) => {
                    ticket.failed(error);
                    return Err(Box::new(StartFailure {
                        attempt,
                        kind: if is_definite_rejection(error) {
                            StartFailureKind::CreateDefinite
                        } else {
                            StartFailureKind::CreateUncertain
                        },
                        error: Some(error),
                    }));
                }
            }
        }
    };
    let Some(thread_id) = channel.thread_id.as_ref() else {
        return Err(Box::new(StartFailure {
            attempt,
            kind: StartFailureKind::BeginDefinite,
            error: None,
        }));
    };
    let anchor = openbot_contracts::command::ThreadRunAnchor::Channel {
        channel_id: channel.id.clone(),
    };
    let intent = RunIntent {
        thread_id: Some(thread_id.clone()),
        run_id: attempt.run_id.clone(),
        agent_id: attempt.agent_id.clone(),
        anchor: anchor.clone(),
        message: attempt.message.clone(),
        selected_skill_slugs: attempt.selected_skill_slugs.clone(),
        model_selection: attempt.model_selection.clone(),
    };
    let recovery = RunRecovery {
        source: attempt.source,
        intent,
        channel: Some(channel.clone()),
    };
    let Some(ticket) = submissions.start_run(&recovery, retry_unknown) else {
        return Err(Box::new(StartFailure {
            attempt,
            kind: StartFailureKind::Blocked,
            error: None,
        }));
    };
    match begin_thread_run_with_skills_and_model(
        thread_id,
        &attempt.agent_id,
        &attempt.run_id,
        anchor,
        &attempt.message,
        &attempt.selected_skill_slugs,
        attempt.model_selection.as_ref(),
    )
    .await
    {
        Ok(_) => ticket.accepted(),
        Err(error) => {
            ticket.failed(error);
            return Err(Box::new(StartFailure {
                attempt,
                kind: if is_definite_rejection(error) {
                    StartFailureKind::BeginDefinite
                } else {
                    StartFailureKind::BeginUnknown
                },
                error: Some(error),
            }));
        }
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
    let recipient_restore_missing = RwSignal::new(false);
    let load_generation = RwSignal::new(0_u64);
    let draft = RwSignal::new(String::new());
    let frozen_model_agent = RwSignal::new(None::<BotId>);
    let skill_composer = SkillComposer::new(
        draft,
        Signal::derive(move || selected_profile.get().map(|p| p.id)),
        "channel-new-message",
    );
    let model_composer = ModelComposer::new(
        Signal::derive(move || {
            let agent_id = frozen_model_agent
                .get()
                .or_else(|| selected_profile.get().map(|profile| profile.id));
            let Some(agent_id) = agent_id else {
                return false;
            };
            selected_profile
                .get()
                .filter(|profile| profile.id == agent_id)
                .or_else(|| {
                    agents
                        .get()
                        .into_iter()
                        .find(|profile| profile.id == agent_id)
                })
                .is_some_and(|profile| profile.endpoint.is_none())
        }),
        Signal::derive(move || {
            frozen_model_agent
                .get()
                .or_else(|| selected_profile.get().map(|profile| profile.id))
        }),
    );
    let submitting = RwSignal::new(false);
    let notice = RwSignal::new(None::<SubmissionNotice>);
    let uncertain_create = RwSignal::new(false);
    let begin_unknown = RwSignal::new(false);
    let submission_blocked = RwSignal::new(false);
    let resumable = RwSignal::new(None::<StartAttempt>);
    let submissions = expect_context::<RunSubmissionActions>();

    Effect::new(move |_| {
        if let Some(intent) = submissions.create_unknown(SubmissionSource::ChannelNew) {
            uncertain_create.set(true);
            frozen_model_agent.set(Some(intent.agent_id.clone()));
            draft.set(intent.message);
            skill_composer.selected.set(intent.selected_skill_slugs);
            model_composer.restore_selection(intent.model_selection, Some(intent.agent_id));
        }
        if resumable.get_untracked().is_none()
            && let Some(recovery) = submissions.run_unknown_for_source(SubmissionSource::ChannelNew)
            && let Some(channel) = recovery.channel
        {
            let intent = recovery.intent;
            frozen_model_agent.set(Some(intent.agent_id.clone()));
            draft.set(intent.message.clone());
            skill_composer
                .selected
                .set(intent.selected_skill_slugs.clone());
            model_composer.restore_selection(
                intent.model_selection.clone(),
                Some(intent.agent_id.clone()),
            );
            resumable.set(Some(StartAttempt {
                source: SubmissionSource::ChannelNew,
                agent_id: intent.agent_id,
                message: intent.message,
                run_id: intent.run_id,
                channel: Some(channel),
                selected_skill_slugs: intent.selected_skill_slugs,
                model_selection: intent.model_selection,
            }));
            begin_unknown.set(true);
            notice.set(None);
        }
    });
    Effect::new(move |_| {
        if submitting.get() {
            return;
        }
        let owns_barrier = submissions
            .create_unknown(SubmissionSource::ChannelNew)
            .is_some()
            || submissions
                .run_unknown_for_source(SubmissionSource::ChannelNew)
                .is_some();
        submission_blocked.set(!owns_barrier && submissions.has_barrier());
    });

    install_recipient_loader(
        query,
        agents,
        selected,
        selected_profile,
        loading,
        load_error,
        load_generation,
    );
    Effect::new(move |_| {
        if selected.get().is_some() || loading.get() {
            return;
        }
        let frozen_agent = resumable.get().map(|attempt| attempt.agent_id).or_else(|| {
            submissions
                .create_unknown(SubmissionSource::ChannelNew)
                .map(|intent| intent.agent_id)
        });
        let Some(frozen_agent) = frozen_agent else {
            recipient_restore_missing.set(false);
            return;
        };
        if agents
            .get()
            .iter()
            .any(|profile| profile.id == frozen_agent)
        {
            recipient_restore_missing.set(false);
            selected.set(Some(frozen_agent.as_str().to_owned()));
        } else {
            recipient_restore_missing.set(true);
        }
    });

    let select_navigate = navigate.clone();
    let select = UnsyncCallback::new(move |agent_id: Option<String>| {
        let Some(agent_id) = agent_id else {
            return;
        };
        if let Ok(href) = channel_new_href(&agent_id) {
            select_navigate(&href, Default::default());
        }
    });
    let inputs_locked = Signal::derive(move || {
        submitting.get()
            || resumable.get().is_some()
            || uncertain_create.get()
            || submission_blocked.get()
    });
    let send_disabled = Signal::derive(move || {
        submitting.get()
            || uncertain_create.get()
            || submission_blocked.get()
            || (resumable.get().is_none()
                && (selected_profile.get().is_none()
                    || trim_ecmascript(&draft.get()).is_empty()
                    || skill_composer.invalid.get()))
    });
    #[cfg(target_arch = "wasm32")]
    let send_navigate = navigate;
    #[cfg(not(target_arch = "wasm32"))]
    let _ = navigate;
    let send = move |_| {
        if send_disabled.get_untracked() {
            return;
        }
        let prior_attempt = resumable.get_untracked();
        if prior_attempt.is_none() {
            frozen_model_agent.set(None);
        }
        let fresh = if prior_attempt.is_none() {
            let Some(profile) = selected_profile.get_untracked() else {
                return;
            };
            let message = draft.get_untracked();
            if trim_ecmascript(&message).is_empty() {
                return;
            }
            if let Some(model_notice) = model_notice(model_composer.selection_status()) {
                notice.set(Some(model_notice));
                return;
            }
            let model_selection = match model_composer.freeze() {
                Ok(selection) => selection,
                Err(_) => {
                    notice.set(Some(SubmissionNotice::ModelSelectionUnavailable));
                    return;
                }
            };
            Some((
                profile,
                message,
                skill_composer.selected.get_untracked(),
                model_selection,
            ))
        } else {
            None
        };
        submitting.set(true);
        notice.set(None);
        begin_unknown.set(false);
        submission_blocked.set(false);
        #[cfg(target_arch = "wasm32")]
        let navigate_after_send = send_navigate.clone();
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let retry_unknown = prior_attempt.is_some();
            let attempt = prior_attempt.unwrap_or_else(|| {
                let (profile, message, selected_skill_slugs, model_selection) =
                    fresh.expect("fresh attempt");
                StartAttempt {
                    source: SubmissionSource::ChannelNew,
                    agent_id: profile.id,
                    message,
                    run_id: mint_run_id(),
                    channel: None,
                    selected_skill_slugs,
                    model_selection,
                }
            });
            match execute_start_attempt(attempt, retry_unknown).await {
                Ok(started) => {
                    resumable.set(Some(started.attempt));
                    match channel_route_href(started.channel.id.as_str()) {
                        Ok(href) => navigate_after_send(&href, Default::default()),
                        Err(_) => notice.set(Some(SubmissionNotice::NavigationFailed)),
                    }
                }
                Err(failure) => {
                    let StartFailure {
                        attempt,
                        kind,
                        error,
                    } = *failure;
                    match kind {
                        StartFailureKind::CreateUncertain => {
                            uncertain_create.set(true);
                            notice.set(None);
                        }
                        StartFailureKind::CreateDefinite | StartFailureKind::BeginDefinite => {
                            resumable.set(None);
                            frozen_model_agent.set(None);
                            let rejected = definite_notice(error);
                            if rejected == SubmissionNotice::Conflict {
                                model_composer.directory_reload();
                            }
                            notice.set(Some(rejected));
                        }
                        StartFailureKind::BeginUnknown => {
                            resumable.set(Some(attempt));
                            begin_unknown.set(true);
                            notice.set(None);
                        }
                        StartFailureKind::Blocked => submission_blocked.set(true),
                    }
                }
            }
            submitting.set(false);
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (prior_attempt, fresh);
            submitting.set(false);
            notice.set(Some(SubmissionNotice::Rejected));
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
                <Show when=move || load_error.get() || recipient_restore_missing.get()>
                    <p class="ob-alert" role="alert">{move || t!(i18n, channels.recipient_load_error)}</p>
                </Show>
                <div class="ob-channel-new-recipient">
                    <label for="channel-new-recipient">{move || t!(i18n, channels.recipient_label)}</label>
                    <RecipientField
                        agents=Signal::derive(move || {
                            let restoring = resumable.get().is_some() || uncertain_create.get();
                            if restoring && (loading.get() || load_error.get() || recipient_restore_missing.get()) {
                                Vec::new()
                            } else {
                                agents.get()
                            }
                        })
                        selected
                        aria_label=move || t_string!(i18n, channels.recipient_label).to_owned()
                        placeholder=move || t_string!(i18n, channels.recipient_placeholder).to_owned()
                        empty_label=move || t_string!(i18n, channels.recipient_empty).to_owned()
                        disabled=inputs_locked
                        on_select=select
                    />
                    <Show when=move || resumable.get().is_some() || uncertain_create.get()>
                        <p class="ob-page-empty" role="note">
                            <strong>{move || t!(i18n, channels.recipient_label)}</strong>
                            {move || {
                                if loading.get() {
                                    return t_string!(i18n, common.loading).to_owned();
                                }
                                let frozen_agent = resumable.get().map(|attempt| attempt.agent_id).or_else(|| submissions.create_unknown(SubmissionSource::ChannelNew).map(|intent| intent.agent_id));
                                frozen_agent.and_then(|id| agents.get().into_iter().find(|profile| profile.id == id).map(|profile| profile.name)).unwrap_or_else(|| t_string!(i18n, common.unknown).to_owned())
                            }}
                        </p>
                    </Show>
                </div>
                <div class="ob-first-message-composer">
                    <ModelPicker state=model_composer disabled=inputs_locked/>
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
                            <span>{move || if begin_unknown.get() {
                                t_string!(i18n, common.retry).to_owned()
                            } else {
                                t_string!(i18n, channels.composer_send).to_owned()
                            }}</span>
                        </Button>
                    </div>
                </div>
                <Show when=move || notice.get()==Some(SubmissionNotice::ModelAgentConflict) && model_notice(model_composer.selection_status())==Some(SubmissionNotice::ModelAgentConflict)><p class="ob-alert" role="alert">{move || t!(i18n, channels.model_agent_conflict)}</p></Show>
                <Show when=move || notice.get()==Some(SubmissionNotice::ModelSelectionUnavailable) && model_notice(model_composer.selection_status())==Some(SubmissionNotice::ModelSelectionUnavailable)><p class="ob-alert" role="alert">{move || t!(i18n, channels.model_selection_unavailable)}</p></Show>
                <Show when=move || notice.get()==Some(SubmissionNotice::Conflict)><p class="ob-alert" role="alert">{move || t!(i18n, channels.submit_conflict)}</p></Show>
                <Show when=move || notice.get()==Some(SubmissionNotice::Rejected)><p class="ob-alert" role="alert">{move || t!(i18n, channels.submit_rejected)}</p></Show>
                <Show when=move || notice.get()==Some(SubmissionNotice::NavigationFailed)><p class="ob-alert" role="alert">{move || t!(i18n, channels.navigation_failed)}</p></Show>
                <Show when=move || uncertain_create.get()>
                    <div class="ob-alert" role="alert">
                        <p>{move || t!(i18n, channels.create_uncertain)}</p>
                        <a href="/">{move || t!(i18n, home.title)}</a>
                    </div>
                </Show>
                <Show when=move || begin_unknown.get()>
                    <p class="ob-alert" role="alert">{move || t!(i18n, channels.begin_unknown)}</p>
                </Show>
                <Show when=move || submission_blocked.get()>
                    <a class="ob-alert" role="alert" href=move || submissions.barrier().and_then(|barrier| barrier.href()).unwrap_or_else(|| "/".to_owned())>
                        {move || t!(i18n, channels.submission_blocked)}
                    </a>
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
    fn display_classification_never_labels_known_rejections_as_unknown() {
        assert_eq!(
            definite_notice(Some(ApiError::Conflict)),
            SubmissionNotice::Conflict
        );
        for error in [
            None,
            Some(ApiError::Unauthorized),
            Some(ApiError::Forbidden),
            Some(ApiError::NotFound),
        ] {
            assert_eq!(definite_notice(error), SubmissionNotice::Rejected);
        }
        assert_eq!(
            model_notice(ModelSelectionStatus::AgentConflict),
            Some(SubmissionNotice::ModelAgentConflict)
        );
        for status in [
            ModelSelectionStatus::Loading,
            ModelSelectionStatus::DirectoryFailed,
            ModelSelectionStatus::Unavailable,
        ] {
            assert_eq!(
                model_notice(status),
                Some(SubmissionNotice::ModelSelectionUnavailable)
            );
        }
        assert_eq!(model_notice(ModelSelectionStatus::AgentDefault), None);
        assert_eq!(model_notice(ModelSelectionStatus::Ready), None);
    }

    #[test]
    fn retry_identity_is_unchanged_when_the_channel_becomes_known() {
        let original = StartAttempt {
            source: SubmissionSource::ChannelNew,
            selected_skill_slugs: vec!["review".to_owned()],
            model_selection: Some(RunModelSelection {
                connection_id: "01991389-7380-7000-8000-000000000001".into(),
                expected_revision: 1,
            }),
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
        assert_eq!(resumed.model_selection, original.model_selection);
    }
}
