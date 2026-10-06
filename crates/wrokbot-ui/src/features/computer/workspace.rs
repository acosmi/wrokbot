//! One responsive Results / Computer tree; closing changes only presentation.
use crate::{
    features::{
        channels::{
            markdown::MarkdownBody,
            run_observation::{OutputPhase, RunObservation},
        },
        computer::viewer::ScreenViewer,
    },
    i18n::{t, t_string, use_i18n},
    primitives::{DialogBody, DialogClose, DialogContent, DialogTrigger, ResponsiveSheet},
};
use leptos::html;
use leptos::prelude::*;
use openbot_contracts::ids::ThreadId;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WorkspaceActivity {
    pub id: String,
    pub label: String,
    pub output: String,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkspaceTab {
    Results,
    Computer,
}
#[derive(Clone, Copy)]
pub(crate) struct WorkspaceControls {
    pub open: RwSignal<bool>,
    pub tab: RwSignal<WorkspaceTab>,
    pub wide: RwSignal<bool>,
}
impl WorkspaceControls {
    pub(crate) fn show(self, tab: WorkspaceTab) {
        self.tab.set(tab);
        self.open.set(true);
    }
}

#[component]
pub(crate) fn ConversationWorkspace(children: Children) -> impl IntoView {
    let controls = WorkspaceControls {
        open: RwSignal::new(false),
        tab: RwSignal::new(WorkspaceTab::Results),
        wide: RwSignal::new(false),
    };
    provide_context(controls);
    let root = NodeRef::<html::Div>::new();
    install_geometry(root, controls);
    view! { <div class="ob-workspace" data-panel-inline=move || (controls.open.get() && controls.wide.get()).then_some("true") node_ref=root>{children()}</div> }
}

#[component]
pub(crate) fn ComputerWorkspace(
    activity: Signal<Vec<WorkspaceActivity>>,
    observation: Signal<Option<RunObservation>>,
    thread: Signal<Option<ThreadId>>,
    #[prop(optional, into)] target: MaybeProp<openbot_contracts::screen::ScreenSessionTarget>,
) -> impl IntoView {
    let i18n = use_i18n();
    let controls = expect_context::<WorkspaceControls>();
    view! { <div class="ob-pane">
        <ResponsiveSheet id="run-workspace" open=controls.open inline=Signal::derive(move || controls.wide.get() && controls.open.get()) on_close=UnsyncCallback::new(move |()| { if controls.wide.get_untracked() { focus_workspace_control("workspace-open"); } })>
            <WorkspaceTrigger/>
            <DialogContent title=move || t_string!(i18n, computer.workspace).to_owned() show_close_button=false>
                <header class="ob-pane-header"><div role="tablist" aria-label=move || t_string!(i18n, computer.workspace).to_owned() on:keydown=move |event| { let tab = match event.key().as_str() { "ArrowLeft" | "ArrowRight" => Some(if controls.tab.get_untracked()==WorkspaceTab::Results { WorkspaceTab::Computer } else { WorkspaceTab::Results }), "Home" => Some(WorkspaceTab::Results), "End" => Some(WorkspaceTab::Computer), _=>None }; if let Some(tab)=tab { event.prevent_default(); controls.tab.set(tab); focus_workspace_control(if tab==WorkspaceTab::Results { "workspace-results-tab" } else { "workspace-computer-tab" }); } }>
                    <button type="button" role="tab" id="workspace-results-tab" aria-controls="workspace-results" tabindex=move || if controls.tab.get()==WorkspaceTab::Results {0} else {-1} aria-selected=move || (controls.tab.get()==WorkspaceTab::Results).to_string() on:click=move |_| controls.tab.set(WorkspaceTab::Results)>{move || t!(i18n, computer.results)}</button>
                    <button type="button" role="tab" id="workspace-computer-tab" aria-controls="workspace-computer" tabindex=move || if controls.tab.get()==WorkspaceTab::Computer {0} else {-1} aria-selected=move || (controls.tab.get()==WorkspaceTab::Computer).to_string() on:click=move |_| controls.tab.set(WorkspaceTab::Computer)>{move || t!(i18n, computer.tab)}</button>
                </div><DialogClose>{move || t!(i18n, common.close)}</DialogClose></header>
                <DialogBody>
                    <section id="workspace-results" role="tabpanel" aria-labelledby="workspace-results-tab" hidden=move || controls.tab.get()!=WorkspaceTab::Results>
                        <h3>{move || t!(i18n, computer.run_result)}</h3>
                        <Show when=move || observation.get().is_none()><p>{move || t!(i18n, computer.no_current_output)}</p></Show>
                        <For each={move || observation.get().map(|row|row.run).into_iter().collect::<Vec<_>>()} key=|run|run.clone() children=move |run| view! { <CurrentRunResult run observation thread/> }/>
                        <h3>{move || t!(i18n, computer.activity_title)}</h3>
                        <p class="ob-page-intro">{move || t!(i18n, computer.activity_description)}</p>
                        <For each=move || activity.get() key=|item| (item.id.clone(), item.label.clone(), item.output.clone()) children=move |item| view! { <details class="ob-workspace-event"><summary>{item.label}</summary><pre>{item.output}</pre></details> }/>
                        <h3>{move || t!(i18n, computer.artifacts)}</h3><p>{move || t!(i18n, computer.artifacts_unavailable)}</p>
                    </section>
                    <section id="workspace-computer" role="tabpanel" aria-labelledby="workspace-computer-tab" hidden=move || controls.tab.get()!=WorkspaceTab::Computer>
                        <ScreenViewer target=Signal::derive(move || target.get()) active=Signal::derive(move || controls.open.get() && controls.tab.get()==WorkspaceTab::Computer)/>
                        <Show when=move || target.get().is_none()><h3>{move || t!(i18n, computer.no_target_title)}</h3></Show>
                        <p>{move || t!(i18n, computer.no_control_contract)}</p>
                    </section>
                </DialogBody>
            </DialogContent>
        </ResponsiveSheet>
    </div> }
}

#[component]
fn CurrentRunResult(
    run: openbot_contracts::ids::RunId,
    observation: Signal<Option<RunObservation>>,
    thread: Signal<Option<ThreadId>>,
) -> impl IntoView {
    let i18n = use_i18n();
    let identity = StoredValue::new(run.clone());
    let current = Signal::derive(move || {
        observation
            .get()
            .filter(|row| row.run == identity.get_value())
    });
    let phase = Signal::derive(move || {
        current
            .get()
            .map_or(OutputPhase::UnobservedTerminal, |row| row.phase)
    });
    let text = Signal::derive(move || current.get().map_or_else(String::new, |row| row.text));
    view! {
        <code data-result-run=run.as_str().to_owned()>{run.as_str().to_owned()}</code>
        <p class="ob-page-intro" data-run-phase=move || format!("{:?}",phase.get())>{move ||phase_label(phase.get())}</p>
        <p>{move || t!(i18n, computer.goal_boundary)}</p>
        <Show when=move || !text.get().trim().is_empty() fallback=move || view! { <p>{t!(i18n, computer.no_current_output)}</p> }>
            <div data-current-run-output="">{move || view! { <MarkdownBody content=text.get()/> }}</div>
        </Show>
        <Show when=move ||phase.get()==OutputPhase::Unknown>{move ||thread.get().map(|thread|view! { <crate::features::approvals::unknown::UnknownFacts thread run=identity.get_value()/> })}</Show>
    }
}

#[component]
fn WorkspaceTrigger() -> impl IntoView {
    let i18n = use_i18n();
    let slot = expect_context::<crate::shell::layout::WorkspaceToolbarMount>().0;
    #[cfg(target_arch = "wasm32")]
    {
        return view! { {move || slot.get().map(|slot| { let mount: web_sys::Element=(*slot).clone().into(); view! { <leptos::portal::Portal mount><DialogTrigger id="workspace-open">{move || t!(i18n, computer.results)} " / " {move || t!(i18n, computer.tab)}</DialogTrigger></leptos::portal::Portal> } })} }.into_any();
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = slot;
    #[cfg(not(target_arch = "wasm32"))]
    view! { <DialogTrigger id="workspace-open">{move || t!(i18n, computer.results)} " / " {move || t!(i18n, computer.tab)}</DialogTrigger> }.into_any()
}
fn focus_workspace_control(id: &str) {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::JsCast as _;
        if let Some(element) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.get_element_by_id(id))
            .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok())
        {
            let _ = element.focus();
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = id;
}
fn phase_label(phase: OutputPhase) -> String {
    let i18n = use_i18n();
    match phase {
        OutputPhase::Running => t_string!(i18n, computer.run_active).to_owned(),
        OutputPhase::UnobservedTerminal => {
            t_string!(i18n, computer.run_terminal_unobserved).to_owned()
        }
        OutputPhase::Succeeded => t_string!(i18n, computer.run_ended).to_owned(),
        OutputPhase::Failed => t_string!(i18n, computer.run_failed).to_owned(),
        OutputPhase::Cancelled => t_string!(i18n, computer.run_cancelled).to_owned(),
        OutputPhase::Unknown => t_string!(i18n, admin.unknown_title).to_owned(),
    }
}
fn fits_inline(viewport: f64, available: f64) -> bool {
    viewport > 1100.0 && available - (viewport * 0.4).clamp(390.0, 660.0) >= 560.0
}
fn install_geometry(root: NodeRef<html::Div>, controls: WorkspaceControls) {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::{JsCast as _, closure::Closure};
        Effect::new(move |_| {
            let Some(element) = root.get() else {
                return;
            };
            let update = move || {
                if controls.wide.try_get_untracked().is_none() {
                    return;
                }
                let viewport = web_sys::window()
                    .and_then(|window| window.inner_width().ok())
                    .and_then(|value| value.as_f64())
                    .unwrap_or(0.0);
                if let Some(element) = root.try_get().flatten() {
                    controls.wide.set(fits_inline(
                        viewport,
                        element.get_bounding_client_rect().width(),
                    ));
                }
            };
            update();
            let callback =
                Closure::<dyn FnMut(js_sys::Array, web_sys::ResizeObserver)>::new(move |_, _| {
                    update()
                });
            if let Ok(observer) = web_sys::ResizeObserver::new(callback.as_ref().unchecked_ref()) {
                observer.observe(&element);
                if let Some(document) = web_sys::window()
                    .and_then(|window| window.document())
                    .and_then(|document| document.document_element())
                {
                    observer.observe(&document);
                }
                let observer_state = StoredValue::new_local(Some((observer, callback)));
                on_cleanup(move || {
                    observer_state.update_value(|state| {
                        if let Some((observer, _callback)) = state.take() {
                            observer.disconnect();
                        }
                    })
                });
            }
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (root, controls, fits_inline);
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn side_panel_requires_frozen_breakpoint_and_real_main_width() {
        assert!(!fits_inline(1100.0, 1100.0));
        assert!(!fits_inline(1101.0, 833.0));
        assert!(fits_inline(1440.0, 1172.0));
        assert!(!fits_inline(1440.0, 1135.0));
        assert!(!fits_inline(1440.0, 1135.9));
        assert!(fits_inline(1440.0, 1136.0));
        assert!(fits_inline(1800.0, 1532.0));
    }
}
