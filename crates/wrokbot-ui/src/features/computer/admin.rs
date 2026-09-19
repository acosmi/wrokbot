//! Administrator resource destination. Missing manager support is distinct from an empty inventory.
use crate::{
    features::{
        computer::ComputerPlaceholder,
        layout::{PageHeader, PageSection, PageShell},
    },
    i18n::{t, t_string, use_i18n},
};
use leptos::prelude::*;

#[component]
pub(crate) fn AdminComputersPage() -> impl IntoView {
    let i18n = use_i18n();
    view! {
        <PageShell>
            <PageHeader heading_id="computers-title" title=move || t_string!(i18n, computer.admin_title).to_owned() description=move || t_string!(i18n, computer.admin_description).to_owned()/>
            <PageSection heading_id="computers-inventory" title=move || t_string!(i18n, computer.inventory).to_owned()>
                <ComputerPlaceholder/>
                <h2>{move || t!(i18n, computer.manager_pending)}</h2>
                <p class="ob-page-intro">{move || t!(i18n, computer.manager_pending_body)}</p>
            </PageSection>
            <PageSection heading_id="computers-controls" title=move || t_string!(i18n, computer.control_boundary).to_owned()>
                <p class="ob-page-intro">{move || t!(i18n, computer.control_boundary_body)}</p>
                <a class="ob-plugin-link" href="/admin/boundaries">{move || t!(i18n, computer.configure_policy)}</a>
                <a class="ob-plugin-link" href="/admin/audit">{move || t!(i18n, computer.review_audit)}</a>
            </PageSection>
        </PageShell>
    }
}
