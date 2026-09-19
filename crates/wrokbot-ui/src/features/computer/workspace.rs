//! Read-only conversation workspace until the authority supplies a live computer target.
use crate::{
    features::computer::viewer::ScreenViewer,
    i18n::{t, t_string, use_i18n},
    primitives::{Button, ButtonVariant},
};
use leptos::prelude::*;

/// Sanitized durable activity; it is display data, never an executable command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WorkspaceActivity {
    pub id: String,
    pub label: String,
    pub output: String,
}

#[component]
pub(crate) fn ComputerWorkspace(
    activity: Signal<Vec<WorkspaceActivity>>,
    running: Signal<bool>,
    #[prop(optional, into)] target: MaybeProp<openbot_contracts::screen::ScreenSessionTarget>,
) -> impl IntoView {
    let i18n = use_i18n();
    let open = RwSignal::new(false);
    view! {
        <details class="ob-computer-workspace" on:keydown=crate::primitives::dismiss_disclosure on:toggle=move |event| {
                #[cfg(target_arch = "wasm32")]
                { use wasm_bindgen::JsCast as _; if let Some(element) = event.target().and_then(|t| t.dyn_into::<web_sys::Element>().ok()) { open.set(element.has_attribute("open")); } }
                #[cfg(not(target_arch = "wasm32"))] let _ = event;
            }>
            <summary>{move || t!(i18n, computer.workspace)}<span>{move || if running.get() { t_string!(i18n, computer.run_active).to_owned() } else { t_string!(i18n, computer.read_only).to_owned() }}</span></summary>
            <section aria-label=move || t_string!(i18n, computer.screen).to_owned()>
                <ScreenViewer target=Signal::derive(move || target.get()) active=Signal::derive(move || open.get())/>
                <Show when=move || target.get().is_none()><h2>{move || t!(i18n, computer.no_target_title)}</h2></Show>

                <div class="ob-skill-chips">
                    <Button variant=ButtonVariant::Chip disabled=true on_activate=move |_| {}>{move || t!(i18n, computer.take_over)}</Button>
                    <Button variant=ButtonVariant::Ghost disabled=true on_activate=move |_| {}>{move || t!(i18n, computer.return_control)}</Button>
                </div>
            </section>
            <section aria-label=move || t_string!(i18n, computer.activity_title).to_owned()>
                <h2>{move || t!(i18n, computer.activity_title)}</h2>
                <p class="ob-page-intro">{move || t!(i18n, computer.activity_description)}</p>
                <Show when=move || activity.get().is_empty()><p class="ob-page-empty">{move || t!(i18n, computer.activity_empty)}</p></Show>
                <For each=move || activity.get() key=|item| (item.id.clone(), item.label.clone(), item.output.clone()) children=move |item| view! {
                    <details class="ob-workspace-event"><summary>{item.label}</summary><pre class="ob-transcript-text">{item.output}</pre></details>
                }/>
            </section>
            <a class="ob-plugin-link" href="/approvals">{move || t!(i18n, computer.review_approvals)}</a>
        </details>
    }
}
