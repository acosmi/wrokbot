//! `/agents` roster destination with URL-owned read-only detail state.

use leptos::prelude::*;
use leptos_router::hooks::{use_navigate, use_query_map};
use openbot_contracts::agent::{AgentProfile, AgentVisibility};

#[cfg(target_arch = "wasm32")]
use crate::api::list_agents;
use crate::features::layout::{
    DetailPanel, DetailPanelLayout, DetailPanelMain, PageEmpty, PageHeader, PageSection, PageShell,
    PageWidth, StaggerItem,
};
use crate::i18n::{t, t_string, use_i18n};
use crate::primitives::{Button, ButtonSize, ButtonVariant};

use super::{AgentCard, AgentEditor, AgentProfilePanel};

/// Current-user coworker roster with URL-owned create/detail state and a recoverable hidden list.
#[component]
pub fn AgentsPage() -> impl IntoView {
    let i18n = use_i18n();
    let query = use_query_map();
    let navigate = use_navigate();
    let creating = Memo::new(move |_| query.get().get("new").as_deref() == Some("true"));
    let selected_agent_id = Memo::new(move |_| {
        (!creating.get())
            .then(|| query.get().get("agent"))
            .flatten()
    });
    let agents = RwSignal::new(Vec::<AgentProfile>::new());
    let hidden_agents = RwSignal::new(Vec::<AgentProfile>::new());
    let loading = RwSignal::new(true);
    let load_error = RwSignal::new(false);
    let reload_generation = RwSignal::new(0_u64);
    install_agent_loader(
        reload_generation,
        agents,
        hidden_agents,
        loading,
        load_error,
    );

    let mine = Memo::new(move |_| {
        split_agents(&agents.get())
            .0
            .into_iter()
            .enumerate()
            .collect::<Vec<_>>()
    });
    let explore = Memo::new(move |_| {
        split_agents(&agents.get())
            .1
            .into_iter()
            .enumerate()
            .collect::<Vec<_>>()
    });
    let hidden = Memo::new(move |_| {
        hidden_agents
            .get()
            .into_iter()
            .enumerate()
            .collect::<Vec<_>>()
    });
    let retry =
        move |_| reload_generation.update(|generation| *generation = generation.saturating_add(1));
    let close_navigate = navigate.clone();
    let close = move |_| close_navigate("/agents", Default::default());
    let cancel_navigate = use_navigate();
    let create_cancel = UnsyncCallback::new(move |_| {
        cancel_navigate("/agents", Default::default());
    });
    let create_navigate = navigate.clone();
    let open_create = move |_| create_navigate("/agents?new=true", Default::default());
    let changed_navigate = navigate.clone();
    let changed = UnsyncCallback::new(move |agent: AgentProfile| {
        reload_generation.update(|generation| *generation = generation.saturating_add(1));
        let href = crate::api::agent_profile_href(agent.id.as_str())
            .expect("server Agent id must be route-safe");
        changed_navigate(&href, Default::default());
    });
    let closed_navigate = navigate;
    let closed = UnsyncCallback::new(move |_| {
        reload_generation.update(|generation| *generation = generation.saturating_add(1));
        closed_navigate("/agents", Default::default());
    });
    let detail_agent = Signal::derive(move || selected_agent_id.get());
    let panel_open = Signal::derive(move || creating.get() || selected_agent_id.get().is_some());

    view! {
        <DetailPanelLayout>
            <DetailPanelMain>
                <div id="agents-roster-focus" class="ob-agent-roster-focus" tabindex="-1">
                    <PageShell width=PageWidth::Content>
                        <div class="ob-agent-roster-content">
                            <div class="ob-agent-roster-toolbar">
                                <PageHeader
                                    heading_id="agents-page-title"
                                    title=move || t_string!(i18n, agents.title).to_owned()
                                />
                                <Button
                                    variant=ButtonVariant::Primary
                                    size=ButtonSize::Small
                                    on_activate=open_create
                                >{move || t!(i18n, agents.new_coworker)}</Button>
                            </div>
                            <Show when=move || loading.get()>
                                <div class="ob-loading" role="status">
                                    {move || t!(i18n, common.loading)}
                                </div>
                            </Show>
                            <Show when=move || load_error.get()>
                                <div class="ob-alert" role="alert">
                                    <span>{move || t!(i18n, agents.load_error)}</span>
                                    <Button
                                        variant=ButtonVariant::Ghost
                                        size=ButtonSize::Small
                                        on_activate=retry
                                    >
                                        {move || t!(i18n, common.retry)}
                                    </Button>
                                </div>
                            </Show>
                            <Show when=move || !loading.get() && !load_error.get()>
                                <PageSection
                                    heading_id="agents-mine-title"
                                    title=move || t_string!(i18n, agents.your_agents).to_owned()
                                >
                                    <Show
                                        when=move || !mine.get().is_empty()
                                        fallback=move || view! {
                                            <PageEmpty>{move || t!(i18n, agents.mine_empty)}</PageEmpty>
                                        }
                                    >
                                        <div class="ob-agent-grid">
                                            <For
                                                each=move || mine.get()
                                                key=|(_, agent)| agent.id.clone()
                                                children=move |(index, agent)| {
                                                    view! {
                                                        <StaggerItem index=index>
                                                            <AgentCard agent />
                                                        </StaggerItem>
                                                    }
                                                }
                                            />
                                        </div>
                                    </Show>
                                </PageSection>
                                <Show when=move || !hidden.get().is_empty()>
                                    <PageSection
                                        heading_id="agents-hidden-title"
                                        title=move || t_string!(i18n, agents.hidden_agents).to_owned()
                                        description=move || t_string!(i18n, agents.hidden_help).to_owned()
                                    >
                                        <div class="ob-agent-grid">
                                            <For
                                                each=move || hidden.get()
                                                key=|(_, agent)| agent.id.clone()
                                                children=move |(index, agent)| view! {
                                                    <StaggerItem index=index>
                                                        <AgentCard agent />
                                                    </StaggerItem>
                                                }
                                            />
                                        </div>
                                    </PageSection>
                                </Show>
                                <PageSection
                                    heading_id="agents-explore-title"
                                    title=move || t_string!(i18n, agents.explore_agents).to_owned()
                                >
                                    <Show
                                        when=move || !explore.get().is_empty()
                                        fallback=move || view! {
                                            <PageEmpty>{move || t!(i18n, agents.explore_empty)}</PageEmpty>
                                        }
                                    >
                                        <div class="ob-agent-grid">
                                            <For
                                                each=move || explore.get()
                                                key=|(_, agent)| agent.id.clone()
                                                children=move |(index, agent)| {
                                                    view! {
                                                        <StaggerItem index=index>
                                                            <AgentCard agent />
                                                        </StaggerItem>
                                                    }
                                                }
                                            />
                                        </div>
                                    </Show>
                                </PageSection>
                            </Show>
                        </div>
                    </PageShell>
                </div>
            </DetailPanelMain>
            <DetailPanel
                id="agent-profile-panel"
                title=move || if creating.get() {
                    t_string!(i18n, agents.new_coworker).to_owned()
                } else {
                    t_string!(i18n, agents.profile).to_owned()
                }
                open=panel_open
                return_focus_id="agents-roster-focus"
                on_close=close
            >
                <Show
                    when=move || creating.get()
                    fallback=move || view! {
                        <AgentProfilePanel
                            agent_id=detail_agent
                            on_changed=changed
                            on_closed=closed
                        />
                    }
                >
                    <AgentEditor
                        profile=None
                        on_saved=changed
                        on_cancel=create_cancel
                    />
                </Show>
            </DetailPanel>
        </DetailPanelLayout>
    }
}

fn split_agents(agents: &[AgentProfile]) -> (Vec<AgentProfile>, Vec<AgentProfile>) {
    let mine = agents.iter().filter(|agent| agent.mine).cloned().collect();
    let explore = agents
        .iter()
        .filter(|agent| !agent.mine && agent.visibility == AgentVisibility::Public)
        .cloned()
        .collect();
    (mine, explore)
}

fn install_agent_loader(
    reload_generation: RwSignal<u64>,
    agents: RwSignal<Vec<AgentProfile>>,
    hidden_agents: RwSignal<Vec<AgentProfile>>,
    loading: RwSignal<bool>,
    load_error: RwSignal<bool>,
) {
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        let generation = reload_generation.get();
        loading.set(true);
        load_error.set(false);
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let outcome = list_agents(false).await;
            let hidden_outcome = list_agents(true).await;
            if reload_generation.get_untracked() != generation {
                return;
            }
            match (outcome, hidden_outcome) {
                (Ok(loaded), Ok(hidden)) => {
                    agents.set(loaded);
                    hidden_agents.set(hidden);
                }
                _ => {
                    agents.set(Vec::new());
                    hidden_agents.set(Vec::new());
                    load_error.set(true);
                }
            }
            loading.set(false);
        });
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (
        reload_generation,
        agents,
        hidden_agents,
        loading,
        load_error,
    );
}

#[cfg(test)]
mod tests {
    use openbot_contracts::ids::BotId;

    use super::*;

    fn profile(id: &str, mine: bool, visibility: AgentVisibility) -> AgentProfile {
        AgentProfile {
            id: BotId::new(id),
            name: id.to_owned(),
            title: "Title".to_owned(),
            role_description: "Role".to_owned(),
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
    fn roster_groups_follow_upstream_mine_and_public_explore_predicates() {
        let agents = [
            profile("mine-private", true, AgentVisibility::Private),
            profile("mine-public", true, AgentVisibility::Public),
            profile("explore-public", false, AgentVisibility::Public),
            profile("admin-visible-private", false, AgentVisibility::Private),
        ];
        let (mine, explore) = split_agents(&agents);
        assert_eq!(
            mine.iter()
                .map(|agent| agent.id.as_str())
                .collect::<Vec<_>>(),
            ["mine-private", "mine-public"]
        );
        assert_eq!(
            explore
                .iter()
                .map(|agent| agent.id.as_str())
                .collect::<Vec<_>>(),
            ["explore-public"]
        );
    }
}
