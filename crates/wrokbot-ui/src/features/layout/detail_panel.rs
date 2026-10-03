//! A URL-owned library detail page. Selection and writes remain with the caller.

#[cfg(target_arch = "wasm32")]
use leptos::ev::KeyboardEvent;
use leptos::prelude::*;

use crate::i18n::{t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{Button, ButtonSize, ButtonVariant, IconSize, IconView};

#[derive(Clone, Copy)]
struct DetailPageVisibility(MaybeProp<bool>);

/// One route frame; the existing URL selects its library or its detail view.
#[component]
pub fn DetailPanelLayout(
    /// Existing URL-owned detail selection.
    #[prop(into)]
    open: MaybeProp<bool>,
    children: Children,
) -> impl IntoView {
    provide_context(DetailPageVisibility(open));
    view! { <div class="ob-library-route">{children()}</div> }
}

/// Keep the list's read state, but exclude its controls and heading while inspecting a detail.
#[component]
pub fn DetailPanelMain(children: Children) -> impl IntoView {
    let open = expect_context::<DetailPageVisibility>().0;
    view! {
        <div class="ob-library-main" hidden=move || open.get().unwrap_or(false)>
            {children()}
        </div>
    }
}

/// Full route detail for the existing Agent selection and configuration queries.
#[component]
pub fn DetailPanel(
    /// Bounded, stable DOM token.
    #[prop(into)]
    id: String,
    /// Localized route heading.
    #[prop(into)]
    title: TextProp,
    /// Existing URL-owned detail selection.
    #[prop(into)]
    open: MaybeProp<bool>,
    /// Existing list focus anchor.
    #[prop(into)]
    return_focus_id: TextProp,
    /// The caller changes the URL without cancelling accepted writes.
    #[prop(into)]
    on_close: UnsyncCallback<()>,
    children: ChildrenFn,
) -> impl IntoView {
    assert_dom_id(&id);
    assert_dom_id(&return_focus_id.get());
    assert!(
        !title.get().trim().is_empty(),
        "detail title must be nonempty"
    );
    let i18n = use_i18n();
    let heading_id = format!("{id}-title");
    let focus_heading_id = heading_id.clone();
    let labelled_by = heading_id.clone();
    let title = StoredValue::new(title);
    let return_focus_id = StoredValue::new(return_focus_id);
    // The focus effect must not keep its own route alive after navigation.
    let route_owner = Owner::current().expect("detail route owner").downgrade();
    let focus_generation = RwSignal::new(0_u64);
    let composing = StoredValue::new(false);
    #[cfg(target_arch = "wasm32")]
    {
        let listener = leptos::leptos_dom::helpers::window_event_listener(
            leptos::ev::keydown,
            move |event: KeyboardEvent| {
                if open.get().unwrap_or(false) && editor_escape(&event, composing.get_value()) {
                    event.prevent_default();
                    on_close.run(());
                }
            },
        );
        on_cleanup(move || listener.remove());
    }
    Effect::new(move |previous: Option<bool>| {
        let visible = open.get().unwrap_or(false);
        if previous != Some(visible) {
            composing.set_value(false);
        }
        focus_generation.update(|generation| *generation = generation.wrapping_add(1));
        let generation = focus_generation.get_untracked();
        if visible || previous == Some(true) {
            let id = if visible {
                focus_heading_id.clone()
            } else {
                return_focus_id.get_value().get().to_string()
            };
            if let Some(route_owner) = route_owner.upgrade() {
                route_owner.with(|| focus_later(id, focus_generation, generation));
            }
        }
        visible
    });
    view! {
        <Show when=move || open.get().unwrap_or(false)>
            <section
                id=id.clone()
                class="ob-page-shell"
                data-width="content"
                aria-labelledby=labelled_by.clone()
                on:compositionstart=move |_| composing.set_value(true)
                on:compositionend=move |_| composing.set_value(false)
            >
                <header class="ob-library-detail-heading">
                    <h1 id=heading_id.clone() class="ob-page-title" tabindex="-1">
                        {move || title.get_value().get()}
                    </h1>
                    <Button
                        variant=ButtonVariant::Ghost
                        size=ButtonSize::Small
                        aria_label=move || t_string!(i18n, common.close).to_owned()
                        on_activate=move |_| on_close.run(())
                    >
                        <IconView icon=Icon::X size=IconSize::Navigation />
                    </Button>
                </header>
                <div class="ob-library-detail-body">{children()}</div>
            </section>
        </Show>
    }
}

#[cfg(target_arch = "wasm32")]
fn editor_escape(event: &KeyboardEvent, composing: bool) -> bool {
    event.key() == "Escape" && !event.default_prevented() && !event.is_composing() && !composing
}

pub(super) fn focus_later(id: String, focus_generation: RwSignal<u64>, generation: u64) {
    assert_dom_id(&id);
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        use wasm_bindgen::JsCast as _;
        leptos::task::tick().await;
        if focus_generation.try_get_untracked() != Some(generation) {
            return;
        }
        let document = web_sys::window().and_then(|window| window.document());
        let target = document
            .as_ref()
            .and_then(|document| document.get_element_by_id(&id))
            .filter(|element| !element.has_attribute("disabled"))
            .and_then(|element| element.dyn_into::<web_sys::HtmlElement>().ok());
        let target = target
            .filter(|target| target.offset_parent().is_some())
            .or_else(|| {
                let element = document?
                    .query_selector(".ob-library-main:not([hidden]) .ob-page-title")
                    .ok()??;
                let target = element.dyn_into::<web_sys::HtmlElement>().ok()?;
                target.set_tab_index(-1);
                Some(target)
            });
        if let Some(target) = target {
            _ = target.focus();
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (id, focus_generation, generation);
}

fn assert_dom_id(id: &str) {
    assert!(
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "DetailPanel id must be one bounded DOM token"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detail_panel_id_is_one_dom_token() {
        assert_dom_id("credential-detail");
    }
    #[test]
    #[should_panic(expected = "bounded DOM token")]
    fn detail_panel_rejects_selector_injection() {
        assert_dom_id("detail'] *");
    }
}
