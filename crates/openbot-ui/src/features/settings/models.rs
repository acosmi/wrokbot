//! Model-service settings. Personal custom inventory uses the authoritative management API.
mod form;
mod state;
use crate::api::model_connections::{self as api, WriteError};
use crate::{
    features::layout::{PageHeader, PageSection, PageShell},
    i18n::{t, t_string, use_i18n},
    primitives::{Button, ButtonVariant},
};
use form::{EditTarget, ModelDialog};
use leptos::prelude::*;
pub(crate) use state::ModelActions;
use state::Status;

/// Personal custom-model management and first-release gateway/account integration status.
#[component]
pub fn ModelServicesPage() -> impl IntoView {
    let i18n = use_i18n();
    view! {
        <PageShell>
            <PageHeader heading_id="model-services-title" title=move || t_string!(i18n, models.title).to_owned() description=move || t_string!(i18n, models.description).to_owned()/>
            <PageSection heading_id="model-gateway" title=move || t_string!(i18n, models.gateway).to_owned()>
                <p class="ob-page-intro">{move || t!(i18n, models.gateway_description)}</p>
                <p class="ob-preference-saving" role="status">{move || t!(i18n, models.gateway_pending)}</p>
                <Button variant=ButtonVariant::Chip disabled=true on_activate=move |_| {}>{move || t!(i18n, models.gateway_connect)}</Button>
            </PageSection>
            <PageSection heading_id="model-custom" title=move || t_string!(i18n, models.custom).to_owned()>
                <p class="ob-page-intro">{move || t!(i18n, models.custom_description)}</p>
                <CustomConnections/>
            </PageSection>
            <PageSection heading_id="model-accounts" title=move || t_string!(i18n, models.bridge).to_owned()>
                <p class="ob-page-intro">{move || t!(i18n, models.bridge_description)}</p>
                <p class="ob-preference-saving" role="status">{move || t!(i18n, models.bridge_pending)}</p>
                <Button variant=ButtonVariant::Chip disabled=true on_activate=move |_| {}>{move || t!(i18n, models.bridge_connect)}</Button>
            </PageSection>
        </PageShell>
    }
}

#[component]
fn CustomConnections() -> impl IntoView {
    let i18n = use_i18n();
    let actions = expect_context::<ModelActions>();
    let target = RwSignal::new(None::<EditTarget>);
    let cursor = RwSignal::new(None::<String>);
    let refresh = RwSignal::new(0_u64);
    let reading = RwSignal::new(true);
    let inventory = LocalResource::new(move || {
        let cursor = cursor.get();
        refresh.get();
        actions.revision.get();
        reading.set(true);
        async move {
            let result = api::list(cursor.as_deref()).await;
            reading.try_set(false);
            result
        }
    });
    let locked = Signal::derive(move || reading.get() || actions.status.get().locked());
    let open = UnsyncCallback::new(move |selection| {
        if locked.get_untracked() {
            return;
        }
        actions.status.set(Status::Idle);
        target.set(Some(selection));
    });
    let close = UnsyncCallback::new(move |_| {
        target.try_set(None);
    });
    view! {
        <p class="ob-page-intro">{move ||t!(i18n, models.saved_boundary)}</p>
        <Show when=move || actions.status.get()==Status::Pending><p role="status">{move ||t!(i18n, models.saving)}</p></Show>
        <Show when=move || actions.status.get()==Status::Saved><p role="status">{move ||t!(i18n, models.saved)}</p></Show>
        <Show when=move || matches!(actions.status.get(),Status::Failed(WriteError::Unknown))><p class="ob-alert" role="alert">{move ||t!(i18n, models.unknown)}</p></Show>
        <Button disabled=Signal::derive(move || reading.get() || actions.status.get()==Status::Pending) on_activate=move |_| refresh.update(|v|*v=v.saturating_add(1))>{move ||t!(i18n, models.refresh)}</Button>
        <Suspense fallback=move ||view! {<p role="status">{move ||t!(i18n, common.loading)}</p>}>
            {move || inventory.get().map(|result| match result {
                Err(_) => view! {<p class="ob-alert" role="alert">{move ||t!(i18n, models.load_failed)}</p>}.into_any(),
                Ok(page) => {
                    let next = StoredValue::new(page.next_cursor);
                    let empty = page.connections.is_empty();
                    view! {
                        <Button id="model-create" disabled=locked on_activate=move |_|open.run(EditTarget::Create)>{move ||t!(i18n, models.custom_add)}</Button>
                        <Show when=move ||empty><p class="ob-page-empty">{move ||t!(i18n, models.empty)}</p></Show>
                        <div class="ob-page-rows">
                            {page.connections.into_iter().map(|row| {
                                let edit_id=row.id.clone();let delete_id=row.id;
                                let label=match row.protocol {openbot_contracts::model_connections::CustomModelProtocol::OpenaiChatCompletions=>"OpenAI · Chat Completions",openbot_contracts::model_connections::CustomModelProtocol::OpenaiResponses=>"OpenAI · Responses",openbot_contracts::model_connections::CustomModelProtocol::AnthropicMessages=>"Anthropic · Messages"};
                                view! {<div class="ob-plugin-grant"><div class="ob-plugin-copy">
                                    <strong>{row.name}</strong><span>{row.model}</span><span class="text-fg-secondary">{label}</span><span class="text-fg-muted">{row.endpoint}</span>
                                    <span class="text-fg-secondary">{move || if row.enabled {t_string!(i18n,models.enabled).to_owned()} else {t_string!(i18n,models.disabled).to_owned()}}</span>
                                    <span class="text-fg-muted">{move || if row.has_credential {t_string!(i18n,models.key_stored).to_owned()} else {t_string!(i18n,models.key_missing).to_owned()}}</span>
                                    <div><Button disabled=locked on_activate=move |_|open.run(EditTarget::Edit(edit_id.clone()))>{move ||t!(i18n,models.edit)}</Button><Button variant=ButtonVariant::DangerText disabled=locked on_activate=move |_|open.run(EditTarget::Delete(delete_id.clone()))>{move ||t!(i18n,models.remove)}</Button></div>
                                </div></div>}
                            }).collect_view()}
                        </div>
                        <Show when=move ||cursor.get().is_some()><Button disabled=locked on_activate=move |_|cursor.set(None)>{move ||t!(i18n,credentials.first_page)}</Button></Show>
                        <Show when=move ||next.with_value(Option::is_some)><Button disabled=locked on_activate=move |_|cursor.set(next.get_value())>{move ||t!(i18n,credentials.next_page)}</Button></Show>
                    }.into_any()
                }
            })}
        </Suspense>
        {move ||target.get().map(|target|view!{<ModelDialog target close/>})}
    }
}
