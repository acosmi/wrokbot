//! Shared, localized revision status and explicit choices; owners retain all object data.

use crate::{
    i18n::{t, t_string, use_i18n},
    primitives::{Button, ButtonVariant},
    revision_editor::Phase,
};
use leptos::prelude::*;

#[component]
pub(crate) fn EditorNotice(
    phase: Signal<Phase>,
    busy: Signal<bool>,
    #[prop(into)] id_prefix: String,
    #[prop(optional)] on_compare: Option<UnsyncCallback<()>>,
    #[prop(optional)] on_load: Option<UnsyncCallback<()>>,
    #[prop(optional)] on_retry: Option<UnsyncCallback<()>>,
    #[prop(default = Signal::stored(true))] can_retry: Signal<bool>,
    #[prop(optional)] on_reapply: Option<UnsyncCallback<()>>,
) -> impl IntoView {
    let i18n = use_i18n();
    let confirm_load = RwSignal::new(false);
    let confirm_reapply = RwSignal::new(false);
    let compare_id = StoredValue::new(format!("{id_prefix}-compare"));
    let load_id = StoredValue::new(format!("{id_prefix}-load"));
    let retry_id = StoredValue::new(format!("{id_prefix}-retry"));
    let reapply_id = StoredValue::new(format!("{id_prefix}-reapply"));
    let load_confirm_id = StoredValue::new(format!("{id_prefix}-confirm-load"));
    let reapply_confirm_id = StoredValue::new(format!("{id_prefix}-confirm-reapply"));
    let paused = move || matches!(phase.get(), Phase::Error | Phase::Conflict);
    view! {
        <div class="ob-library-form" class:ob-revision-notice=paused>
            <p class="ob-preference-saving" role="status" aria-live="polite" data-editor-state=move || match phase.get() {
                Phase::Saved => "saved", Phase::Dirty => "dirty", Phase::Saving => "saving",
                Phase::Error => "error", Phase::Conflict => "conflict",
            }>
                {move || match phase.get() {
                    Phase::Saved => t_string!(i18n, revision_editor.saved).to_owned(),
                    Phase::Dirty => t_string!(i18n, revision_editor.dirty).to_owned(),
                    Phase::Saving => t_string!(i18n, revision_editor.saving).to_owned(),
                    Phase::Error => t_string!(i18n, revision_editor.error).to_owned(),
                    Phase::Conflict => t_string!(i18n, revision_editor.conflict).to_owned(),
                }}
            </p>
            <Show when=paused>
                <p class="ob-page-intro">{move || t!(i18n, revision_editor.paused)}</p>
                <div class="ob-library-form-actions">
                    {on_compare.map(|callback| view! {<Button id=compare_id.get_value() disabled=busy on_activate=move |_| { let _ = callback.try_run(()); }>{move || t!(i18n, revision_editor.compare)}</Button>})}
                    {on_load.map(|_| view! {<Button id=load_id.get_value() disabled=busy on_activate=move |_| {confirm_reapply.set(false);confirm_load.set(true);}>{move || t!(i18n, revision_editor.load)}</Button>})}
                    <Show when=move ||can_retry.get()>{on_retry.map(|callback| view! {<Button id=retry_id.get_value() disabled=busy on_activate=move |_| {let _ = callback.try_run(());}>{move || t!(i18n, revision_editor.retry)}</Button>})}</Show>
                    {on_reapply.map(|_| view! {<Button id=reapply_id.get_value() disabled=busy on_activate=move |_| {confirm_load.set(false);confirm_reapply.set(true);}>{move || t!(i18n, revision_editor.reapply)}</Button>})}
                </div>
                <Show when=move || confirm_load.get()>
                    <p role="alert">{move || t!(i18n, revision_editor.discard_confirm)}</p>
                    <div class="ob-library-form-actions">
                        <Button id=load_confirm_id.get_value() variant=ButtonVariant::DangerText disabled=busy on_activate=move |_| {
                            confirm_load.set(false); if let Some(callback)=on_load {let _=callback.try_run(());}
                        }>{move || t!(i18n, revision_editor.confirm_load)}</Button>
                        <Button disabled=busy on_activate=move |_|confirm_load.set(false)>{move ||t!(i18n, common.cancel)}</Button>
                    </div>
                </Show>
                <Show when=move || confirm_reapply.get()>
                    <p role="alert">{move ||t!(i18n, revision_editor.reapply_confirm)}</p>
                    <div class="ob-library-form-actions">
                        <Button id=reapply_confirm_id.get_value() variant=ButtonVariant::Primary disabled=busy on_activate=move |_| {
                            confirm_reapply.set(false);if let Some(callback)=on_reapply {let _=callback.try_run(());}
                        }>{move ||t!(i18n, revision_editor.confirm_reapply)}</Button>
                        <Button disabled=busy on_activate=move |_|confirm_reapply.set(false)>{move ||t!(i18n, common.cancel)}</Button>
                    </div>
                </Show>
            </Show>
        </div>
    }
}
