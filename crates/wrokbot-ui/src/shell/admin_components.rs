//! Administrator compiled-component governance index and detail routes.

#![cfg_attr(
    not(any(test, target_arch = "wasm32")),
    allow(dead_code, unused_variables)
)]

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use openbot_contracts::agent::AgentProfile;
use openbot_contracts::components::{
    CompiledComponentKind, ComponentDataFunctionSummary, ComponentRecord, ComponentRecords,
};

use crate::api::admin_component_href;
#[cfg(target_arch = "wasm32")]
use crate::api::{
    announce_component_catalogue, list_agents, load_component_data_functions, load_components,
    save_component_draft, set_component_agent_grant, set_component_function_grant,
    set_component_publication,
};
use crate::features::gallery::ComponentPreview;
use crate::features::layout::{
    PageBackLink, PageEmpty, PageHeader, PageRows, PageSection, PageShell, PageTopbar, PageWidth,
};
use crate::i18n::{t, t_string, use_i18n};
use crate::primitives::{
    Button, ButtonSize, ButtonVariant, Dialog, DialogBody, DialogContent, DialogFooter, Switch,
    Textarea,
};

#[derive(Clone)]
struct ComponentDetailData {
    component: ComponentRecord,
    agents: Vec<AgentProfile>,
    functions: Vec<ComponentDataFunctionSummary>,
}

#[derive(Clone, Copy)]
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
enum DetailLoadError {
    NotFound,
    Failed,
}

#[derive(Clone)]
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
enum UiMutation {
    Agent {
        name: String,
        agent_id: String,
        granted: bool,
    },
    Function {
        name: String,
        function: String,
        granted: bool,
    },
    Publication {
        name: String,
        published: bool,
    },
    Draft {
        name: String,
        description: String,
    },
}

#[derive(Clone, Copy)]
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
struct MutationState {
    data: RwSignal<Option<ComponentDetailData>>,
    pending: RwSignal<Option<String>>,
    error: RwSignal<bool>,
    worker_owner: StoredValue<Option<Owner>>,
}

/// Administrator list of every durable compiled/sandboxed governance row.
#[component]
pub fn AdminComponentsPage() -> impl IntoView {
    let i18n = use_i18n();
    let records = RwSignal::new(None::<ComponentRecords>);
    let loading = RwSignal::new(true);
    let load_error = RwSignal::new(false);
    let generation = RwSignal::new(0_u64);
    install_component_index_loader(generation, records, loading, load_error);
    let retry = move |_| generation.update(|value| *value = value.saturating_add(1));

    view! {
        <PageShell width=PageWidth::Content>
            <PageHeader
                heading_id="admin-components-title"
                title=move || t_string!(i18n, admin.components_title).to_owned()
                description=move || t_string!(i18n, admin.components_intro).to_owned()
            />
            <Show when=move || loading.get()>
                <div class="ob-loading" role="status">{move || t!(i18n, common.loading)}</div>
            </Show>
            <Show when=move || load_error.get()>
                <div class="ob-alert" role="alert">
                    <span>{move || t!(i18n, admin.components_load_error)}</span>
                    <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=retry>
                        {move || t!(i18n, common.retry)}
                    </Button>
                </div>
            </Show>
            <Show when=move || {
                !loading.get()
                    && !load_error.get()
                    && records.get().is_some_and(|records| records.components.is_empty())
            }>
                <PageEmpty>{move || t!(i18n, admin.components_empty)}</PageEmpty>
            </Show>
            <Show when=move || records.get().is_some_and(|records| !records.components.is_empty())>
                <div class="ob-admin-components-grid">
                    <For
                        each=move || records.get().map_or_else(Vec::new, |records| records.components)
                        key=|component| component.name.clone()
                        children=move |component| {
                            let href = admin_component_href(&component.name)
                                .unwrap_or_else(|_| "/admin/components".to_owned());
                            let preview_name = component.name.clone();
                            let status = component.published;
                            let changed = component.has_unpublished_changes;
                            view! {
                                <article class="ob-admin-component-card">
                                    <a class="ob-admin-component-copy" href=href>
                                        <span class="ob-admin-component-heading">
                                            <span class="ob-admin-component-status" data-state=if status { "published" } else { "draft" }></span>
                                            <strong>{component.title}</strong>
                                        </span>
                                        <span>{component.draft_description}</span>
                                        <small>{move || if status {
                                            t_string!(i18n, admin.component_published).to_owned()
                                        } else {
                                            t_string!(i18n, admin.component_unpublished).to_owned()
                                        }}</small>
                                        <Show when=move || changed>
                                            <small>{move || t!(i18n, admin.component_draft_changes)}</small>
                                        </Show>
                                    </a>
                                    <div class="ob-admin-component-preview" aria-hidden="true" inert=true>
                                        <ComponentPreview name=preview_name />
                                    </div>
                                </article>
                            }
                        }
                    />
                </div>
            </Show>
        </PageShell>
    }
}

/// Administrator governance for one exact component name.
#[component]
pub fn AdminComponentDetailPage() -> impl IntoView {
    let i18n = use_i18n();
    let params = use_params_map();
    let data = RwSignal::new(None::<ComponentDetailData>);
    let loading = RwSignal::new(true);
    let load_error = RwSignal::new(false);
    let not_found = RwSignal::new(false);
    let generation = RwSignal::new(0_u64);
    let pending = RwSignal::new(None::<String>);
    let mutation_error = RwSignal::new(false);
    let worker_owner = StoredValue::new(Owner::current());
    install_component_detail_loader(params, generation, data, loading, load_error, not_found);
    let retry = move |_| generation.update(|value| *value = value.saturating_add(1));
    let state = MutationState {
        data,
        pending,
        error: mutation_error,
        worker_owner,
    };

    view! {
        <PageShell width=PageWidth::Content>
            <PageTopbar>
                <PageBackLink
                    href="/admin/components".to_owned()
                    label=move || t_string!(i18n, admin.component_back).to_owned()
                />
            </PageTopbar>
            <Show when=move || loading.get()>
                <div class="ob-loading" role="status">{move || t!(i18n, common.loading)}</div>
            </Show>
            <Show when=move || load_error.get()>
                <div class="ob-alert" role="alert">
                    <span>{move || t!(i18n, admin.components_load_error)}</span>
                    <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=retry>
                        {move || t!(i18n, common.retry)}
                    </Button>
                </div>
            </Show>
            <Show when=move || not_found.get()>
                <PageHeader
                    heading_id="admin-component-not-found"
                    title=move || t_string!(i18n, admin.component_not_found).to_owned()
                    description=move || t_string!(i18n, admin.component_not_found_intro).to_owned()
                />
            </Show>
            <Show when=move || mutation_error.get()>
                <p class="ob-alert" role="alert">{move || t!(i18n, admin.component_mutation_error)}</p>
            </Show>
            <For
                each=move || data.get().into_iter()
                key=detail_key
                children=move |detail| view! { <ComponentDetail detail state /> }
            />
        </PageShell>
    }
}

#[component]
fn ComponentDetail(detail: ComponentDetailData, state: MutationState) -> impl IntoView {
    let i18n = use_i18n();
    let component = detail.component;
    let name = StoredValue::new(component.name.clone());
    let title = component.title.clone();
    let preview_name = component.name.clone();
    let called_as = component.name.clone();
    let kind = component.kind;
    let last_changed = component.updated_at.to_string();
    let initial_draft = StoredValue::new(component.draft_description.clone());
    let withheld = StoredValue::new(component.withheld_from.clone());
    let granted_functions = StoredValue::new(component.functions.clone());
    let agents_empty = detail.agents.is_empty();
    let agents = StoredValue::new(detail.agents);
    let functions_empty = detail.functions.is_empty();
    let functions = StoredValue::new(detail.functions);
    let sandboxed = component.kind == CompiledComponentKind::Sandboxed;
    let description_open = RwSignal::new(false);
    let draft = RwSignal::new(component.draft_description.clone());
    let published = RwSignal::new(component.published);
    let publication_pending = Signal::derive(move || state.pending.get().is_some());
    let publication_change = UnsyncCallback::new(move |next: bool| {
        let prior = !next;
        dispatch_mutation(
            UiMutation::Publication {
                name: name.get_value(),
                published: next,
            },
            "publication".to_owned(),
            state,
            Some((published, prior)),
            None,
        );
    });
    let open_description = move |_| {
        draft.set(initial_draft.get_value());
        description_open.set(true);
    };
    let close_description = UnsyncCallback::new(move |_| {
        draft.set(initial_draft.get_value());
        description_open.set(false);
    });
    let save_description = move |_| {
        dispatch_mutation(
            UiMutation::Draft {
                name: name.get_value(),
                description: draft.get_untracked(),
            },
            "draft".to_owned(),
            state,
            None,
            Some(description_open),
        );
    };
    let available = agents
        .get_value()
        .iter()
        .filter(|agent| {
            !withheld
                .get_value()
                .iter()
                .any(|id| id == agent.id.as_str())
        })
        .count();
    let agent_count = agents.get_value().len();
    let available_summary = if agents_empty {
        t_string!(i18n, admin.component_available_none).to_owned()
    } else if available == agent_count {
        t_string!(i18n, admin.component_available_all, count = available).to_owned()
    } else if available == 0 {
        t_string!(i18n, admin.component_available_none).to_owned()
    } else {
        t_string!(
            i18n,
            admin.component_available_some,
            count = available,
            total = agent_count,
        )
        .to_owned()
    };
    let published_description = component
        .published_description
        .clone()
        .unwrap_or_else(|| t_string!(i18n, admin.component_publication_off).to_owned());

    view! {
        <PageHeader
            heading_id="admin-component-title"
            title
            description=published_description
        />
        <div class="ob-admin-component-detail-preview">
            <ComponentPreview name=preview_name />
        </div>
        <PageSection
            heading_id="admin-component-configuration"
            title=move || t_string!(i18n, admin.component_configuration).to_owned()
            description=move || t_string!(i18n, admin.component_configuration_intro).to_owned()
        >
            <PageRows>
                <div class="ob-component-governance-row">
                    <span>
                        <strong>{move || t!(i18n, admin.component_publication)}</strong>
                        <small>{move || if sandboxed {
                            t_string!(i18n, admin.component_sandboxed_atomic).to_owned()
                        } else if published.get() {
                            t_string!(i18n, admin.component_publication_on).to_owned()
                        } else {
                            t_string!(i18n, admin.component_publication_off).to_owned()
                        }}</small>
                    </span>
                    <Switch
                        id="component-publication"
                        aria_label=move || t_string!(i18n, admin.component_publication).to_owned()
                        checked=published
                        disabled=Signal::derive(move || sandboxed || publication_pending.get())
                        on_change=publication_change
                    />
                </div>
                <div class="ob-component-governance-row">
                    <span>
                        <strong>{move || t!(i18n, admin.component_description)}</strong>
                        <small>{initial_draft.get_value()}</small>
                    </span>
                    <Button
                        variant=ButtonVariant::Ghost
                        size=ButtonSize::Small
                        disabled=Signal::derive(move || sandboxed || state.pending.get().is_some())
                        on_activate=open_description
                    >{move || t!(i18n, common.edit)}</Button>
                </div>
                <Show when=move || sandboxed>
                    <div class="ob-component-governance-row">
                        <span>{move || t!(i18n, admin.component_sandboxed_atomic)}</span>
                        <a href="/admin/playground">{move || t!(i18n, admin.component_manage_playground)}</a>
                    </div>
                </Show>
            </PageRows>
        </PageSection>
        <PageSection
            heading_id="admin-component-agents"
            title=move || t_string!(i18n, admin.component_available_to).to_owned()
            description=available_summary
        >
            <Show when=move || agents_empty>
                <PageEmpty>{move || t!(i18n, admin.component_no_bots)}</PageEmpty>
            </Show>
            <PageRows>
                <For
                    each=move || agents.get_value()
                    key=|agent| agent.id.clone()
                    children=move |agent| {
                        let agent_id = agent.id.as_str().to_owned();
                        let operation_id = format!("agent:{agent_id}");
                        let checked = RwSignal::new(!withheld.get_value().contains(&agent_id));
                        let callback_agent = agent_id.clone();
                        let aria_name = agent.name.clone();
                        let on_change = UnsyncCallback::new(move |next: bool| {
                            dispatch_mutation(
                                UiMutation::Agent {
                                    name: name.get_value(),
                                    agent_id: callback_agent.clone(),
                                    granted: next,
                                },
                                operation_id.clone(),
                                state,
                                Some((checked, !next)),
                                None,
                            );
                        });
                        view! {
                            <div class="ob-component-governance-row">
                                <span><strong>{agent.name}</strong><small>{agent.role_description}</small></span>
                                <Switch
                                    aria_label=aria_name
                                    checked
                                    disabled=Signal::derive(move || state.pending.get().is_some())
                                    on_change
                                />
                            </div>
                        }
                    }
                />
            </PageRows>
        </PageSection>
        <PageSection
            heading_id="admin-component-functions"
            title=move || t_string!(i18n, admin.component_may_read).to_owned()
            description=move || if granted_functions.get_value().is_empty() {
                t_string!(i18n, admin.component_no_function_grants).to_owned()
            } else {
                granted_functions.get_value().join(", ")
            }
        >
            <Show when=move || functions_empty>
                <PageEmpty>{move || t!(i18n, admin.component_no_functions)}</PageEmpty>
            </Show>
            <PageRows>
                <For
                    each=move || functions.get_value()
                    key=|function| function.name.clone()
                    children=move |function| {
                        let function_name = function.name.clone();
                        let operation_id = format!("function:{function_name}");
                        let checked = RwSignal::new(granted_functions.get_value().contains(&function_name));
                        let callback_function = function_name.clone();
                        let aria_name = function_name.clone();
                        let on_change = UnsyncCallback::new(move |next: bool| {
                            dispatch_mutation(
                                UiMutation::Function {
                                    name: name.get_value(),
                                    function: callback_function.clone(),
                                    granted: next,
                                },
                                operation_id.clone(),
                                state,
                                Some((checked, !next)),
                                None,
                            );
                        });
                        view! {
                            <div class="ob-component-governance-row">
                                <span><strong>{function_name}</strong><small>{function.description}</small></span>
                                <Switch
                                    aria_label=aria_name
                                    checked
                                    disabled=Signal::derive(move || sandboxed || state.pending.get().is_some())
                                    on_change
                                />
                            </div>
                        }
                    }
                />
            </PageRows>
        </PageSection>
        <PageSection
            heading_id="admin-component-details"
            title=move || t_string!(i18n, admin.component_details).to_owned()
        >
            <dl class="ob-gallery-facts">
                <div><dt>{move || t!(i18n, admin.component_kind)}</dt><dd>{move || component_kind_text(i18n, kind)}</dd></div>
                <div><dt>{move || t!(i18n, admin.component_called_as)}</dt><dd><code>{called_as}</code></dd></div>
                <div><dt>{move || t!(i18n, admin.component_last_changed)}</dt><dd>{last_changed}</dd></div>
            </dl>
        </PageSection>

        <Dialog id="component-description-dialog" open=description_open on_close=close_description>
            <DialogContent
                title=move || t_string!(i18n, admin.component_description).to_owned()
                description=move || t_string!(i18n, admin.component_description_intro).to_owned()
            >
                <DialogBody>
                    <Textarea
                        id="component-description-draft"
                        aria_label=move || t_string!(i18n, admin.component_description).to_owned()
                        value=draft
                        disabled=Signal::derive(move || state.pending.get().is_some())
                    />
                </DialogBody>
                <DialogFooter>
                    <Button
                        variant=ButtonVariant::Ghost
                        size=ButtonSize::Small
                        disabled=Signal::derive(move || state.pending.get().is_some())
                        on_activate=move |_| {
                            draft.set(initial_draft.get_value());
                            description_open.set(false);
                        }
                    >{move || t!(i18n, common.cancel)}</Button>
                    <Button
                        variant=ButtonVariant::Primary
                        size=ButtonSize::Small
                        loading=Signal::derive(move || state.pending.get().as_deref() == Some("draft"))
                        on_activate=save_description
                    >{move || t!(i18n, common.save)}</Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    }
}

fn install_component_index_loader(
    generation: RwSignal<u64>,
    records: RwSignal<Option<ComponentRecords>>,
    loading: RwSignal<bool>,
    error: RwSignal<bool>,
) {
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        let expected = generation.get();
        loading.set(true);
        error.set(false);
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let _ = announce_component_catalogue().await;
            let outcome = load_components().await;
            if generation.get_untracked() != expected {
                return;
            }
            match outcome {
                Ok(loaded) => records.set(Some(loaded)),
                Err(_) => error.set(true),
            }
            loading.set(false);
        });
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (generation, records, loading, error);
}

fn install_component_detail_loader(
    params: Memo<leptos_router::params::ParamsMap>,
    generation: RwSignal<u64>,
    data: RwSignal<Option<ComponentDetailData>>,
    loading: RwSignal<bool>,
    error: RwSignal<bool>,
    not_found: RwSignal<bool>,
) {
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        let expected = generation.get();
        let name = params.get().get("name");
        loading.set(true);
        error.set(false);
        not_found.set(false);
        data.set(None);
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let outcome = async {
                let name = name.ok_or(DetailLoadError::Failed)?;
                let _ = announce_component_catalogue().await;
                let records = load_components()
                    .await
                    .map_err(|_| DetailLoadError::Failed)?;
                let component = records
                    .components
                    .into_iter()
                    .find(|component| component.name == name)
                    .ok_or(DetailLoadError::NotFound)?;
                let agents = list_agents(false)
                    .await
                    .map_err(|_| DetailLoadError::Failed)?;
                let functions = load_component_data_functions()
                    .await
                    .map_err(|_| DetailLoadError::Failed)?
                    .functions;
                Ok::<_, DetailLoadError>(ComponentDetailData {
                    component,
                    agents,
                    functions,
                })
            }
            .await;
            if generation.get_untracked() != expected {
                return;
            }
            match outcome {
                Ok(loaded) => data.set(Some(loaded)),
                Err(DetailLoadError::NotFound) => not_found.set(true),
                Err(DetailLoadError::Failed) => error.set(true),
            }
            loading.set(false);
        });
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (params, generation, data, loading, error, not_found);
}

fn dispatch_mutation(
    mutation: UiMutation,
    operation_id: String,
    state: MutationState,
    rollback: Option<(RwSignal<bool>, bool)>,
    close_on_success: Option<RwSignal<bool>>,
) {
    if state.pending.get_untracked().is_some() {
        if let Some((signal, value)) = rollback {
            signal.set(value);
        }
        return;
    }
    state.pending.set(Some(operation_id));
    state.error.set(false);
    #[cfg(target_arch = "wasm32")]
    {
        let start_worker = move || {
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let outcome = execute_mutation(mutation).await;
                match outcome {
                    Ok(component) => {
                        state.data.update(|data| {
                            if let Some(data) = data {
                                data.component = component;
                            }
                        });
                        if let Some(open) = close_on_success {
                            open.set(false);
                        }
                    }
                    Err(()) => {
                        if let Some((signal, value)) = rollback {
                            signal.set(value);
                        }
                        state.error.set(true);
                    }
                }
                state.pending.set(None);
            });
        };
        match state.worker_owner.get_value() {
            Some(owner) => owner.with(start_worker),
            None => start_worker(),
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (mutation, close_on_success, state.worker_owner);
        if let Some((signal, value)) = rollback {
            signal.set(value);
        }
        state.pending.set(None);
        state.error.set(true);
    }
}

#[cfg(target_arch = "wasm32")]
async fn execute_mutation(mutation: UiMutation) -> Result<ComponentRecord, ()> {
    match mutation {
        UiMutation::Agent {
            name,
            agent_id,
            granted,
        } => set_component_agent_grant(&name, &agent_id, granted).await,
        UiMutation::Function {
            name,
            function,
            granted,
        } => set_component_function_grant(&name, &function, granted).await,
        UiMutation::Publication { name, published } => {
            set_component_publication(&name, published).await
        }
        UiMutation::Draft { name, description } => save_component_draft(&name, &description).await,
    }
    .map_err(|_| ())
}

fn detail_key(detail: &ComponentDetailData) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        detail.component.name,
        detail.component.published,
        detail.component.draft_description,
        detail.component.withheld_from.join(","),
        detail.component.functions.join(",")
    )
}

fn component_kind_text(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    kind: CompiledComponentKind,
) -> String {
    match kind {
        CompiledComponentKind::Chart => t_string!(i18n, gallery.kind_chart).to_owned(),
        CompiledComponentKind::Card => t_string!(i18n, gallery.kind_card).to_owned(),
        CompiledComponentKind::Decision => t_string!(i18n, gallery.kind_decision).to_owned(),
        CompiledComponentKind::Sandboxed => t_string!(i18n, gallery.kind_sandboxed).to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use super::*;

    fn detail() -> ComponentDetailData {
        ComponentDetailData {
            component: ComponentRecord {
                name: "showQuote".to_owned(),
                title: "Quotation".to_owned(),
                kind: CompiledComponentKind::Card,
                draft_description: "quote".to_owned(),
                published_description: Some("quote".to_owned()),
                published: true,
                published_at: Some(OffsetDateTime::UNIX_EPOCH),
                updated_by: Some("admin".to_owned()),
                updated_at: OffsetDateTime::UNIX_EPOCH,
                has_unpublished_changes: false,
                withheld_from: Vec::new(),
                functions: Vec::new(),
            },
            agents: Vec::new(),
            functions: Vec::new(),
        }
    }

    #[test]
    fn authoritative_detail_key_changes_for_every_mutable_governance_surface() {
        let baseline = detail();
        let baseline_key = detail_key(&baseline);
        let mut publication = baseline.clone();
        publication.component.published = false;
        assert_ne!(detail_key(&publication), baseline_key);
        let mut draft = baseline.clone();
        draft.component.draft_description = "edited".to_owned();
        assert_ne!(detail_key(&draft), baseline_key);
        let mut withheld = baseline.clone();
        withheld
            .component
            .withheld_from
            .push("agent-one".to_owned());
        assert_ne!(detail_key(&withheld), baseline_key);
        let mut function = baseline;
        function.component.functions.push("botActivity".to_owned());
        assert_ne!(detail_key(&function), baseline_key);
    }
}
