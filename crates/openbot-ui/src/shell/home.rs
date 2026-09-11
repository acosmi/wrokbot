//! Root Home Composer: structured mention, routing fallback, and durable first message.

use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use openbot_contracts::agent::{AgentProfile, AgentVisibility};
use openbot_contracts::ids::BotId;
use openbot_contracts::text::trim_ecmascript;

use crate::api::channel_new_href;
#[cfg(target_arch = "wasm32")]
use crate::api::{channel_route_href, list_agents, mint_run_id, route_channel_message};
use crate::features::channels::composer::skills::{SkillComposer, SkillPicker};
use crate::features::channels::new::StartAttempt;
#[cfg(target_arch = "wasm32")]
use crate::features::channels::new::{StartFailureKind, execute_start_attempt};
use crate::features::layout::{PageShell, PageWidth};
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{
    Avatar, AvatarSize, Button, ButtonSize, ButtonVariant, IconSize, IconView, Textarea,
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct MentionSelection {
    agent_id: BotId,
    display_text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ActiveMention {
    start: usize,
    query: String,
}

/// First-message Home route with fixed-upstream automatic routing and explicit `@` choice.
#[component]
pub fn HomePage() -> impl IntoView {
    let i18n = use_i18n();
    let navigate = use_navigate();
    let agents = RwSignal::new(Vec::<AgentProfile>::new());
    let loading = RwSignal::new(true);
    let load_error = RwSignal::new(false);
    let load_generation = RwSignal::new(0_u64);
    let draft = RwSignal::new(String::new());
    let agent_picker_open = RwSignal::new(false);
    let selected_mention = RwSignal::new(None::<MentionSelection>);
    let skill_composer = SkillComposer::new(
        draft,
        Signal::derive(move || selected_mention.get().map(|s| s.agent_id)),
        "home-message",
    );
    let submitting = RwSignal::new(false);
    let start_error = RwSignal::new(false);
    let uncertain_create = RwSignal::new(false);
    let resumable = RwSignal::new(None::<StartAttempt>);

    install_home_agent_loader(load_generation, agents, loading, load_error);

    let fallback = Memo::new(move |_| fallback_agent(&agents.get()));
    let active =
        Memo::new(move |_| unselected_mention(&draft.get(), selected_mention.get().as_ref()));
    let suggestions = Memo::new(move |_| {
        active.get().map_or_else(Vec::new, |active| {
            mention_candidates(&agents.get(), &active.query)
        })
    });
    Effect::new(move |_| {
        let text = draft.get();
        if selected_mention
            .get_untracked()
            .as_ref()
            .is_some_and(|selection| !selection_is_present(&text, selection))
        {
            selected_mention.set(None);
        }
    });

    let choose_mention = UnsyncCallback::new(move |agent: AgentProfile| {
        let current = draft.get_untracked();
        let previous = selected_mention.get_untracked();
        if let Some(updated) = insert_mention(&current, previous.as_ref(), &agent) {
            draft.set(updated);
            selected_mention.set(Some(MentionSelection {
                agent_id: agent.id,
                display_text: agent.name,
            }));
        }
    });

    let inputs_locked = Signal::derive(move || submitting.get() || resumable.get().is_some());
    let send_disabled = Signal::derive(move || {
        submitting.get()
            || uncertain_create.get()
            || fallback.get().is_none()
            || trim_ecmascript(&draft.get()).is_empty()
            || (resumable.get().is_none() && skill_composer.invalid.get())
    });
    let mention_open = Signal::derive(move || active.get().is_some() && !inputs_locked.get());

    #[cfg(target_arch = "wasm32")]
    let send_navigate = navigate;
    #[cfg(not(target_arch = "wasm32"))]
    let _ = navigate;
    let send = UnsyncCallback::new(move |_| {
        if send_disabled.get_untracked() {
            return;
        }
        let Some(default_agent) = fallback.get_untracked() else {
            return;
        };
        let message = draft.get_untracked();
        if message.is_empty() {
            return;
        }
        let prior_attempt = resumable.get_untracked();
        let explicit = selected_agent_id(&message, selected_mention.get_untracked().as_ref());
        let roster = agents.get_untracked();
        submitting.set(true);
        start_error.set(false);
        #[cfg(target_arch = "wasm32")]
        {
            let navigate_after_send = send_navigate.clone();
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let attempt = match prior_attempt {
                    Some(attempt) => attempt,
                    None => {
                        let agent_id = resolve_home_recipient(
                            &message,
                            explicit.as_ref(),
                            &default_agent,
                            &roster,
                        )
                        .await;
                        let attempt = StartAttempt {
                            agent_id,
                            message,
                            run_id: mint_run_id(),
                            channel: None,
                            selected_skill_slugs: skill_composer.selected.get_untracked(),
                        };
                        // Route selection and run identity are now fixed. Retries never reroute.
                        resumable.set(Some(attempt.clone()));
                        attempt
                    }
                };
                match execute_start_attempt(attempt).await {
                    Ok(started) => {
                        let href = channel_route_href(started.channel.id.as_str());
                        resumable.set(Some(started.attempt));
                        submitting.set(false);
                        match href {
                            Ok(href) => navigate_after_send(&href, Default::default()),
                            Err(_) => start_error.set(true),
                        }
                    }
                    Err(failure) => {
                        if failure.kind == StartFailureKind::CreateUncertain {
                            uncertain_create.set(true);
                        }
                        resumable.set(Some(failure.attempt));
                        start_error.set(true);
                        submitting.set(false);
                    }
                }
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (prior_attempt, explicit, roster, default_agent, message);
            submitting.set(false);
            start_error.set(true);
        }
    });
    let submit_or_choose = UnsyncCallback::new(move |_| {
        if active.get_untracked().is_some()
            && let Some(agent) = suggestions.get_untracked().into_iter().next()
        {
            choose_mention.run(agent);
            return;
        }
        send.run(());
    });
    let retry_agents = move |_| {
        if let Some(next) = load_generation.get_untracked().checked_add(1) {
            load_generation.set(next);
        } else {
            load_error.set(true);
        }
    };

    view! {
        <PageShell width=PageWidth::Chat>
            <div class="ob-home">
                <header class="ob-home-header">

                    <h1>{move || t!(i18n, home.title)}</h1>
                </header>
                <Show when=move || loading.get()>
                    <div class="ob-loading" role="status">{move || t!(i18n, common.loading)}</div>
                </Show>
                <Show when=move || load_error.get()>
                    <div class="ob-alert" role="alert">
                        <span>{move || t!(i18n, home.agents_load_error)}</span>
                        <Button
                            size=ButtonSize::Small
                            variant=ButtonVariant::Ghost
                            on_activate=retry_agents
                        >
                            {move || t!(i18n, common.retry)}
                        </Button>
                    </div>
                </Show>
                <div class="ob-home-composer" aria-busy=move || submitting.get().to_string()>
                    <Textarea
                        value=draft
                        id="home-message"
                        aria_label=move || t_string!(i18n, channels.composer_placeholder).to_owned()
                        placeholder=move || t_string!(i18n, home.placeholder).to_owned()
                        disabled=inputs_locked
                        combobox_controls=Signal::derive(move || if skill_composer.open.get() { "channel-skill-results".to_owned() } else { "home-mention-results".to_owned() })
                        combobox_open=Signal::derive(move || mention_open.get() || skill_composer.open.get())
                        active_descendant=skill_composer.active_descendant
                        on_keydown=UnsyncCallback::new(move |event| skill_composer.keyboard(event))
                        on_submit=submit_or_choose
                    />
                    <Show when=move || mention_open.get()>
                        <div
                            id="home-mention-results"
                            class="ob-home-mention-results"
                            role="listbox"
                            aria-label=move || t_string!(i18n, home.mention_results).to_owned()
                        >
                            <Show
                                when=move || !suggestions.get().is_empty()
                                fallback=move || view! {
                                    <p>{move || t!(i18n, home.mention_empty)}</p>
                                }
                            >
                                <For
                                    each=move || suggestions.get()
                                    key=|agent| agent.id.clone()
                                    children=move |agent| {
                                        let selected_id = agent.id.clone();
                                        let activate_agent = agent.clone();
                                        let avatar_seed = agent.avatar_seed.clone();
                                        let avatar_name = agent.name.clone();
                                        let name = agent.name;
                                        let role = agent.role_description;
                                        view! {
                                            <button
                                                type="button"
                                                role="option"
                                                aria-selected=move || selected_mention.get().as_ref().is_some_and(|selection| {
                                                    selection.agent_id == selected_id
                                                }).to_string()
                                                on:click=move |_| choose_mention.run(activate_agent.clone())
                                            >
                                                <span aria-hidden="true">
                                                    <Avatar
                                                        principal_id=avatar_seed.clone()
                                                        name=avatar_name.clone()
                                                        size=AvatarSize::Small
                                                    />
                                                </span>
                                                <span>
                                                    <strong>{name.clone()}</strong>
                                                    <small>{role.clone()}</small>
                                                </span>
                                            </button>
                                        }
                                    }
                                />
                            </Show>
                        </div>
                    </Show>
                    <SkillPicker state=skill_composer disabled=inputs_locked/>
                    <div class="ob-home-composer-actions">
                        <details class="ob-composer-options" on:keydown=crate::primitives::dismiss_disclosure on:click=crate::primitives::dismiss_disclosure_link>
                            <summary aria-label=move || t_string!(i18n, home.actions).to_owned()>
                                <IconView icon=Icon::Plus size=IconSize::Navigation />
                            </summary>
                            <div class="ob-composer-options-panel">
                                <a href="/channel/new"><IconView icon=Icon::Pencil size=IconSize::Inline />{move || t!(i18n, shell.new_channel)}</a>
                                <a href="/settings/components-gallery"><IconView icon=Icon::Archive size=IconSize::Inline />{move || t!(i18n, shell.nav_library)}</a>
                            </div>
                        </details>
                        <div class="ob-composer-spacer"></div>
                        <button class="ob-composer-mode" type="button"
                            aria-label=move || t_string!(i18n, home.choose_agent).to_owned()
                            aria-expanded=move || agent_picker_open.get().to_string()
                            aria-controls="home-agent-picker"
                            on:click=move |_| agent_picker_open.update(|open| *open = !*open)>
                            <span>{move || selected_mention.get().map_or_else(|| t_string!(i18n, home.auto).to_owned(), |selected| selected.display_text)}</span>
                            <IconView icon=Icon::Brain size=IconSize::Inline />
                            <IconView icon=Icon::ChevronDown size=IconSize::Inline />
                        </button>
                        <Button
                            id="home-send"
                            variant=ButtonVariant::Primary
                            size=ButtonSize::Medium
                            disabled=send_disabled
                            loading=submitting
                            on_activate=move |_| send.run(())
                        >
                            <IconView icon=Icon::ArrowUp size=IconSize::Navigation />
                            <span class="ob-visually-hidden">{move || if resumable.get().is_some() {
                                t_string!(i18n, common.retry).to_owned()
                            } else {
                                t_string!(i18n, channels.composer_send).to_owned()
                            }}</span>
                        </Button>
                    </div>
                </div>
                <p class="ob-home-model-preset-note" role="note">{move || t!(i18n, home.model_preset_note)}</p>
                <Show when=move || !loading.get() && !load_error.get() && fallback.get().is_none()>
                    <p class="ob-home-routing-hint" role="status">
                        <a href="/agents">{move || t!(i18n, home.no_agents)}</a>
                    </p>
                </Show>
                <Show when=move || start_error.get()>
                    <p class="ob-alert" role="alert">{move || t!(i18n, channels.start_error)}</p>
                </Show>
                <Show when=move || uncertain_create.get()>
                    <p class="ob-alert" role="alert">{move || t!(i18n, channels.create_uncertain)}</p>
                </Show>
                <section id="home-agent-picker" class="ob-home-explore" hidden=move || !agent_picker_open.get() aria-labelledby="home-explore-title">
                    <h2 id="home-explore-title">{move || t!(i18n, home.choose_agent)}</h2>
                    <p class="ob-home-routing-hint">{move || t!(i18n, home.routing_hint)}</p>
                    <div class="ob-home-agent-list">
                        <For each=move || { agents.get().into_iter().filter(valid_home_agent).collect::<Vec<_>>() } key=|agent| agent.id.clone()
                            children=move |agent| {
                                let selected_agent = agent.clone();
                                view! {
                                    <button type="button" disabled=inputs_locked
                                        on:click=move |_| {
                                            let text = draft.get_untracked();
                                            if active_mention(&text).is_none() {
                                                draft.set(format!("{text} @"));
                                            }
                                            choose_mention.run(selected_agent.clone());
                                            agent_picker_open.set(false);
                                        }>
                                        <Avatar principal_id=agent.avatar_seed name=agent.name.clone() size=AvatarSize::Small />
                                        <span><strong>{agent.name}</strong><small>{agent.role_description}</small></span>
                                    </button>
                                }
                            } />
                    </div>
                    <Show when=move || agents.get().is_empty()><p class="ob-page-empty">{move || t!(i18n, home.explore_empty)}</p></Show>
                    <a class="ob-home-agent-manage" href="/agents">{move || t!(i18n, home.explore_agents)}<IconView icon=Icon::ArrowUpRight size=IconSize::Inline /></a>
                </section>
            </div>
        </PageShell>
    }
}

fn install_home_agent_loader(
    generation: RwSignal<u64>,
    agents: RwSignal<Vec<AgentProfile>>,
    loading: RwSignal<bool>,
    error: RwSignal<bool>,
) {
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        let current = generation.get();
        loading.set(true);
        error.set(false);
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            match list_agents(false).await {
                Ok(loaded) if generation.get_untracked() == current => agents.set(loaded),
                Err(_) if generation.get_untracked() == current => {
                    agents.set(Vec::new());
                    error.set(true);
                }
                _ => return,
            }
            loading.set(false);
        });
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (generation, agents, loading, error);
}

#[cfg(target_arch = "wasm32")]
async fn resolve_home_recipient(
    message: &str,
    explicit: Option<&BotId>,
    fallback: &AgentProfile,
    roster: &[AgentProfile],
) -> BotId {
    if let Some(explicit) = explicit {
        // The person already chose. The request exists only to record that fact; fixed-upstream
        // behavior does not let an audit transport failure overturn their recipient choice.
        _ = route_channel_message(message, Some(explicit)).await;
        return explicit.clone();
    }
    match route_channel_message(message, None).await {
        Ok(decision) if roster.iter().any(|agent| agent.id == decision.agent_id) => {
            decision.agent_id
        }
        _ => fallback.id.clone(),
    }
}

fn valid_home_agent(agent: &AgentProfile) -> bool {
    !agent.name.is_empty()
        && agent.name.len() <= 512
        && !agent.name.chars().any(char::is_control)
        && channel_new_href(agent.id.as_str()).is_ok()
}

fn explore_agents(agents: &[AgentProfile]) -> Vec<AgentProfile> {
    agents
        .iter()
        .filter(|agent| {
            valid_home_agent(agent) && !agent.mine && agent.visibility == AgentVisibility::Public
        })
        .cloned()
        .collect()
}

fn fallback_agent(agents: &[AgentProfile]) -> Option<AgentProfile> {
    explore_agents(agents)
        .into_iter()
        .next()
        .or_else(|| agents.iter().find(|agent| valid_home_agent(agent)).cloned())
}

fn active_mention(value: &str) -> Option<ActiveMention> {
    let start = value.rfind('@')?;
    if value[..start]
        .chars()
        .next_back()
        .is_some_and(|character| !character.is_whitespace())
    {
        return None;
    }
    let query = &value[start + 1..];
    if query.contains('\n')
        || query.contains('\r')
        || query.chars().last().is_some_and(char::is_whitespace)
        || query.len() > 512
    {
        return None;
    }
    Some(ActiveMention {
        start,
        query: query.to_owned(),
    })
}

fn unselected_mention(value: &str, selected: Option<&MentionSelection>) -> Option<ActiveMention> {
    let active = active_mention(value)?;
    if let Some(selection) = selected {
        let marker = selection_marker(selection);
        if let Some(remainder) = value[active.start..].strip_prefix(&marker)
            && (remainder.is_empty() || remainder.chars().next().is_some_and(char::is_whitespace))
        {
            return None;
        }
    }
    Some(active)
}

fn mention_candidates(agents: &[AgentProfile], query: &str) -> Vec<AgentProfile> {
    let query = query.to_lowercase();
    agents
        .iter()
        .filter(|agent| {
            valid_home_agent(agent)
                && (query.is_empty()
                    || agent.name.to_lowercase().contains(&query)
                    || agent.id.as_str().to_lowercase().contains(&query))
        })
        .cloned()
        .collect()
}

fn selection_marker(selection: &MentionSelection) -> String {
    format!("@{}", selection.display_text)
}

fn selection_is_present(value: &str, selection: &MentionSelection) -> bool {
    value.contains(&selection_marker(selection))
}

fn selected_agent_id(value: &str, selection: Option<&MentionSelection>) -> Option<BotId> {
    selection
        .filter(|selection| selection_is_present(value, selection))
        .map(|selection| selection.agent_id.clone())
}

fn insert_mention(
    value: &str,
    previous: Option<&MentionSelection>,
    agent: &AgentProfile,
) -> Option<String> {
    if !valid_home_agent(agent) {
        return None;
    }
    let mut updated = value.to_owned();
    if let Some(previous) = previous {
        let marker = selection_marker(previous);
        if let Some(position) = updated.find(&marker) {
            updated.replace_range(position..position + marker.len(), "");
        }
    }
    let active = active_mention(&updated)?;
    updated.replace_range(active.start.., &format!("@{} ", agent.name));
    Some(updated)
}

#[cfg(test)]
mod tests {
    use openbot_contracts::ids::BotId;

    use super::*;

    fn agent(id: &str, name: &str, mine: bool, visibility: AgentVisibility) -> AgentProfile {
        AgentProfile {
            id: BotId::new(id),
            name: name.to_owned(),
            title: "Title".to_owned(),
            role_description: format!("{name} role"),
            avatar_seed: id.to_owned(),
            visibility,
            endpoint: None,
            has_auth: false,
            has_callback_token: false,
            hidden: false,
            system_owned: false,
            can_manage: mine,
            mine,
        }
    }

    #[test]
    fn a_selected_mention_does_not_reopen_when_typing_a_task_or_skill() {
        let selected = MentionSelection {
            agent_id: BotId::new("bot"),
            display_text: "Wrok Bot".into(),
        };
        assert!(unselected_mention("@Wrok Bot /review", Some(&selected)).is_none());
        assert!(unselected_mention("@Wrok Bot keep this task", Some(&selected)).is_none());
        assert_eq!(
            unselected_mention("@Wrok Bot ask @Ada", Some(&selected))
                .unwrap()
                .query,
            "Ada"
        );
    }

    #[test]
    fn fallback_and_explore_match_the_fixed_upstream_order() {
        let roster = [
            agent("mine", "Mine", true, AgentVisibility::Public),
            agent("private", "Private", false, AgentVisibility::Private),
            agent("explore-one", "Explore One", false, AgentVisibility::Public),
            agent("explore-two", "Explore Two", false, AgentVisibility::Public),
        ];
        assert_eq!(
            explore_agents(&roster)
                .iter()
                .map(|agent| agent.id.as_str())
                .collect::<Vec<_>>(),
            ["explore-one", "explore-two"]
        );
        assert_eq!(fallback_agent(&roster).unwrap().id.as_str(), "explore-one");
        assert_eq!(fallback_agent(&roster[..2]).unwrap().id.as_str(), "mine");
    }

    #[test]
    fn at_trigger_is_structured_and_replacing_it_keeps_only_the_latest_agent() {
        assert_eq!(
            active_mention("Please ask @know"),
            Some(ActiveMention {
                start: 11,
                query: "know".to_owned(),
            })
        );
        assert_eq!(active_mention("mail@example.test"), None);
        assert_eq!(active_mention("@Knowledge Desk "), None);

        let knowledge = agent(
            "knowledge",
            "Knowledge Desk",
            false,
            AgentVisibility::Public,
        );
        let risk = agent("risk", "Risk Analyst", false, AgentVisibility::Public);
        let first = insert_mention("Please ask @know", None, &knowledge).unwrap();
        let selected = MentionSelection {
            agent_id: knowledge.id.clone(),
            display_text: knowledge.name.clone(),
        };
        assert_eq!(first, "Please ask @Knowledge Desk ");
        assert_eq!(
            selected_agent_id(&first, Some(&selected)),
            Some(knowledge.id)
        );

        let second = insert_mention(&format!("{first}then @risk"), Some(&selected), &risk).unwrap();
        assert!(!second.contains("@Knowledge Desk"));
        assert!(second.contains("@Risk Analyst "));
    }

    #[test]
    fn mention_filter_matches_name_or_stable_id_and_rejects_bad_rows() {
        let candidates = [
            agent(
                "knowledge",
                "Knowledge Desk",
                false,
                AgentVisibility::Public,
            ),
            agent(
                "risk-analyst",
                "Risk Analyst",
                false,
                AgentVisibility::Public,
            ),
            agent("bad\nidentity", "Bad", false, AgentVisibility::Public),
        ];
        assert_eq!(
            mention_candidates(&candidates, "risk")
                .iter()
                .map(|agent| agent.id.as_str())
                .collect::<Vec<_>>(),
            ["risk-analyst"]
        );
        assert_eq!(mention_candidates(&candidates, "desk").len(), 1);
        assert_eq!(mention_candidates(&candidates, "").len(), 2);
    }
}
