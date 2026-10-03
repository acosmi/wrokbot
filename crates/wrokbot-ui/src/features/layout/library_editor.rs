//! One form body, shown as a route editor or a short confirmation.

use super::DetailPanel;
use crate::primitives::{Dialog, DialogContent};
use leptos::prelude::*;

#[component]
pub(crate) fn LibraryEditorFrame(
    #[prop(into)] id: String,
    #[prop(into)] title: TextProp,
    open: Signal<bool>,
    confirm: Signal<bool>,
    #[prop(into)] return_focus_id: TextProp,
    #[prop(into)] on_close: UnsyncCallback<()>,
    children: ChildrenFn,
) -> impl IntoView {
    let full = Signal::derive(move || open.get() && !confirm.get());
    let modal = Signal::derive(move || open.get() && confirm.get());
    let confirm_id = StoredValue::new(format!("{id}-confirm"));
    let caption = StoredValue::new(title.clone());
    let form = StoredValue::new(children.clone());
    let return_focus = StoredValue::new(return_focus_id.clone());
    // The focus effect must not keep its own route alive after navigation.
    let owner = Owner::current().expect("library route owner").downgrade();
    let focus_generation = RwSignal::new(0_u64);
    Effect::new(move |previous: Option<bool>| {
        let visible = modal.get();
        focus_generation.update(|value| *value = value.wrapping_add(1));
        if previous == Some(true) && !visible {
            let id = return_focus.get_value().get().to_string();
            let generation = focus_generation.get_untracked();
            if let Some(owner) = owner.upgrade() {
                owner.with(|| super::detail_panel::focus_later(id, focus_generation, generation));
            }
        }
        visible
    });
    view! {
        <DetailPanel id title open=full return_focus_id on_close>
            {children()}
        </DetailPanel>
        <Show when=move || modal.get()>
            <Dialog id=confirm_id.get_value() open=RwSignal::new(true) on_close>
                <DialogContent title=move || caption.get_value().get()>{form.get_value()()}</DialogContent>
            </Dialog>
        </Show>
    }
}
