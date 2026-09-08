//! Shared single-value listbox engine for editable Combobox and select-only Select.

use leptos::context::Provider;
use leptos::ev::KeyboardEvent;
use leptos::html;
use leptos::prelude::*;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;

use crate::icons::Icon;

use super::field::{FieldContext, field_context};
use super::{IconSize, IconView, timing::schedule_timeout};

pub(crate) const LISTBOX_TYPEAHEAD_RESET_MS: i32 = 500;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ListboxKind {
    Editable,
    SelectOnly,
}

impl ListboxKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Editable => "editable",
            Self::SelectOnly => "select-only",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum InitialActive {
    First,
    Last,
    #[default]
    CommittedOrFirst,
}

#[derive(Clone)]
pub(crate) struct ListboxContext {
    id: String,
    kind: ListboxKind,
    pub(crate) open: RwSignal<bool>,
    pub(crate) value: RwSignal<Option<String>>,
    pub(crate) query: RwSignal<String>,
    pub(crate) committed_label: RwSignal<Option<String>>,
    pub(crate) owner_label: RwSignal<String>,
    pub(crate) active_id: RwSignal<Option<String>>,
    pub(crate) empty: RwSignal<bool>,
    pub(crate) disabled: Signal<bool>,
    pub(crate) invalid: Signal<bool>,
    pub(crate) preview_focus: bool,
    pub(crate) field_context: Option<FieldContext>,
    input_ref: NodeRef<html::Input>,
    trigger_ref: NodeRef<html::Button>,
    content_ref: NodeRef<html::Div>,
    on_value_change: Option<UnsyncCallback<Option<String>>>,
    query_dirty: StoredValue<bool>,
    pending_initial: StoredValue<InitialActive>,
    typeahead: RwSignal<String>,
    typeahead_generation: RwSignal<u64>,
}

pub(crate) struct ListboxRootOptions {
    pub(crate) kind: ListboxKind,
    pub(crate) id: String,
    pub(crate) open: RwSignal<bool>,
    pub(crate) value: RwSignal<Option<String>>,
    pub(crate) disabled: MaybeProp<bool>,
    pub(crate) invalid: MaybeProp<bool>,
    pub(crate) preview_focus: bool,
    pub(crate) on_value_change: Option<UnsyncCallback<Option<String>>>,
}

pub(crate) fn listbox_root(options: ListboxRootOptions, children: Children) -> impl IntoView {
    let ListboxRootOptions {
        kind,
        id,
        open,
        value,
        disabled,
        invalid,
        preview_focus,
        on_value_change,
    } = options;
    assert_dom_id(&id);
    let kind_token = kind.as_str();
    let field_context = field_context();
    if let Some(field) = &field_context {
        assert_eq!(
            field.control_id(),
            id,
            "Combobox/Select id must equal the enclosing Field control_id"
        );
    }
    let disabled_field = field_context.clone();
    let invalid_field = field_context.clone();
    let disabled = Signal::derive(move || {
        disabled.get().unwrap_or(false)
            || disabled_field.as_ref().is_some_and(FieldContext::disabled)
    });
    let invalid = Signal::derive(move || {
        invalid.get().unwrap_or(false) || invalid_field.as_ref().is_some_and(FieldContext::invalid)
    });
    let context = ListboxContext {
        id,
        kind,
        open,
        value,
        query: RwSignal::new(String::new()),
        committed_label: RwSignal::new(None),
        owner_label: RwSignal::new(String::new()),
        active_id: RwSignal::new(None),
        empty: RwSignal::new(false),
        disabled,
        invalid,
        preview_focus,
        field_context,
        input_ref: NodeRef::new(),
        trigger_ref: NodeRef::new(),
        content_ref: NodeRef::new(),
        on_value_change,
        query_dirty: StoredValue::new(false),
        pending_initial: StoredValue::new(InitialActive::CommittedOrFirst),
        typeahead: RwSignal::new(String::new()),
        typeahead_generation: RwSignal::new(0),
    };
    install_lifecycle(context.clone());
    view! {
        <Provider value=context>
            <div class="ob-listbox-root" data-kind=kind_token>{children()}</div>
        </Provider>
    }
}

pub(crate) fn listbox_popup(children: Children) -> impl IntoView {
    let context = use_listbox_context();
    let listbox_id = listbox_id(&context);
    let dismiss_context = context.clone();
    view! {
        <div
            class="ob-listbox-dismiss"
            hidden=move || !context.open.get()
            on:click=move |_| close_cancel(dismiss_context.clone(), true)
        ></div>
        <div
            id=listbox_id
            class="ob-listbox-popup"
            role="listbox"
            aria-label=move || context.owner_label.get()
            data-state=move || if context.open.get() { "open" } else { "closed" }
            hidden=move || !context.open.get()
            node_ref=context.content_ref
        >
            {children()}
        </div>
    }
}

pub(crate) fn listbox_option(
    id: String,
    value: String,
    label: TextProp,
    disabled: MaybeProp<bool>,
    children: Children,
) -> impl IntoView {
    assert_dom_id(&id);
    assert_value(&value);
    assert!(
        !label.get().is_empty(),
        "listbox option label must be nonempty"
    );
    let context = use_listbox_context();
    let sync_context = context.clone();
    let sync_value = value.clone();
    let sync_label = label.clone();
    Effect::new(move |_| {
        if sync_context.value.get().as_ref() == Some(&sync_value) {
            let label = sync_label.get().to_string();
            sync_context.committed_label.set(Some(label.clone()));
            if !sync_context.open.get() || !sync_context.query_dirty.get_value() {
                sync_context.query.set(label);
            }
        }
    });
    let hidden_context = context.clone();
    let hidden_label = label.clone();
    let source_label = label.clone();
    let click_context = context.clone();
    let click_id = id.clone();
    let click_value = value.clone();
    let click_label = label.clone();
    let hover_context = context.clone();
    let hover_id = id.clone();
    let highlighted_context = context.clone();
    let highlighted_id = id.clone();
    let state_context = context.clone();
    let state_id = id.clone();
    let state_value = value.clone();
    let selected_context = context.clone();
    let selected_id = id.clone();
    let selected_value = value.clone();
    let indicator_context = context.clone();
    let indicator_value = value.clone();
    view! {
        <button
            id=id
            type="button"
            class="ob-listbox-option"
            role="option"
            tabindex="-1"
            data-value=value
            data-label=move || label.get().to_lowercase()
            data-label-source=move || source_label.get()
            data-highlighted=move || explicit_bool(highlighted_context.active_id.get().as_ref() == Some(&highlighted_id))
            data-state=move || option_state_tokens(
                state_context.active_id.get().as_ref() == Some(&state_id),
                state_context.value.get().as_ref() == Some(&state_value),
                disabled.get().unwrap_or(false),
            )
            aria-selected=move || explicit_bool(if selected_context.open.get() {
                selected_context.active_id.get().as_ref() == Some(&selected_id)
            } else {
                selected_context.value.get().as_ref() == Some(&selected_value)
            })
            aria-disabled=move || explicit_bool(disabled.get().unwrap_or(false))
            disabled=move || disabled.get().unwrap_or(false)
            hidden=move || hidden_context.kind == ListboxKind::Editable
                && !matches_query(&hidden_label.get(), &hidden_context.query.get())
            on:mousemove=move |_| {
                if !disabled.get().unwrap_or(false) {
                    hover_context.active_id.set(Some(hover_id.clone()));
                }
            }
            on:click=move |_| {
                if !disabled.get().unwrap_or(false) {
                    select_value(
                        click_context.clone(),
                        click_id.clone(),
                        click_value.clone(),
                        click_label.get().to_string(),
                        true,
                    );
                }
            }
        >
            <span class="ob-listbox-option-content">{children()}</span>
            <Show when=move || indicator_context.value.get().as_ref() == Some(&indicator_value)>
                <span class="ob-listbox-indicator" aria-hidden="true">
                    <IconView icon=Icon::Check size=IconSize::Inline />
                </span>
            </Show>
        </button>
    }
}

pub(crate) fn use_listbox_context() -> ListboxContext {
    use_context::<ListboxContext>()
        .expect("Combobox/Select compound component must be nested in its root")
}

pub(crate) fn input_ref(context: &ListboxContext) -> NodeRef<html::Input> {
    context.input_ref
}

pub(crate) fn trigger_ref(context: &ListboxContext) -> NodeRef<html::Button> {
    context.trigger_ref
}

pub(crate) fn owner_id(context: &ListboxContext) -> String {
    context.id.clone()
}

pub(crate) fn listbox_id(context: &ListboxContext) -> String {
    format!("{}-listbox", context.id)
}

pub(crate) fn owner_state(context: &ListboxContext) -> Option<String> {
    owner_state_tokens(
        context.preview_focus,
        context.open.get(),
        context.disabled.get(),
        context.invalid.get(),
    )
}

pub(crate) fn described_by(context: &ListboxContext) -> Option<String> {
    context
        .field_context
        .as_ref()
        .and_then(FieldContext::described_by)
}

pub(crate) fn open_first(context: ListboxContext) {
    open_with(context, InitialActive::First);
}

pub(crate) fn open_last(context: ListboxContext) {
    open_with(context, InitialActive::Last);
}

pub(crate) fn open_current(context: ListboxContext) {
    open_with(context, InitialActive::CommittedOrFirst);
}

pub(crate) fn toggle_current(context: ListboxContext) {
    if context.open.get_untracked() {
        close_cancel(context, true);
    } else {
        open_current(context);
    }
}

pub(crate) fn handle_editable_key(event: KeyboardEvent, context: ListboxContext) {
    if context.disabled.get_untracked() {
        return;
    }
    match event.key().as_str() {
        "ArrowDown" => {
            event.prevent_default();
            if context.open.get_untracked() {
                move_active(context, 1);
            } else {
                open_first(context);
            }
        }
        "ArrowUp" => {
            event.prevent_default();
            if context.open.get_untracked() {
                move_active(context, -1);
            } else {
                open_last(context);
            }
        }
        "Home" if context.open.get_untracked() => {
            event.prevent_default();
            set_active_edge(context, false);
        }
        "End" if context.open.get_untracked() => {
            event.prevent_default();
            set_active_edge(context, true);
        }
        "Enter" if context.open.get_untracked() => {
            event.prevent_default();
            _ = select_active(context, true);
        }
        "Escape" if context.open.get_untracked() => {
            event.prevent_default();
            close_cancel(context, true);
        }
        "Tab" if context.open.get_untracked() => close_cancel(context, false),
        _ => {}
    }
}

pub(crate) fn handle_select_key(event: KeyboardEvent, context: ListboxContext) {
    if context.disabled.get_untracked() {
        return;
    }
    let key = event.key();
    match key.as_str() {
        "ArrowDown" => {
            event.prevent_default();
            if context.open.get_untracked() {
                move_active(context, 1);
            } else {
                open_first(context);
            }
        }
        "ArrowUp" => {
            event.prevent_default();
            if context.open.get_untracked() {
                move_active(context, -1);
            } else {
                open_last(context);
            }
        }
        "Home" if context.open.get_untracked() => {
            event.prevent_default();
            set_active_edge(context, false);
        }
        "End" if context.open.get_untracked() => {
            event.prevent_default();
            set_active_edge(context, true);
        }
        "Enter" | " " => {
            event.prevent_default();
            if context.open.get_untracked() {
                _ = select_active(context, true);
            } else {
                open_current(context);
            }
        }
        "Escape" if context.open.get_untracked() => {
            event.prevent_default();
            close_cancel(context, true);
        }
        "Tab" if context.open.get_untracked() => {
            if !select_active(context.clone(), false) {
                close_cancel(context, false);
            }
        }
        key if is_typeahead_key(&event, key) => {
            event.prevent_default();
            push_typeahead(context, key);
        }
        _ => {}
    }
}

pub(crate) fn handle_editable_input(context: ListboxContext, next: String) {
    context.query_dirty.set_value(true);
    context.query.set(next);
    context.pending_initial.set_value(InitialActive::First);
    if !context.open.get_untracked() {
        context.open.set(true);
    }
    schedule_refresh(context, InitialActive::First);
}

pub(crate) fn close_cancel(context: ListboxContext, return_focus: bool) {
    context.open.set(false);
    context.active_id.set(None);
    context.typeahead.set(String::new());
    if context.kind == ListboxKind::Editable {
        context
            .query
            .set(context.committed_label.get_untracked().unwrap_or_default());
        context.query_dirty.set_value(false);
    }
    if return_focus {
        focus_owner_later(context);
    }
}

fn install_lifecycle(context: ListboxContext) {
    let was_open = StoredValue::new(false);
    let open_context = context.clone();
    Effect::new(move |_| {
        let open = open_context.open.get();
        let previous = was_open.get_value();
        if open && !previous {
            let initial = open_context.pending_initial.get_value();
            schedule_refresh(open_context.clone(), initial);
        } else if !open && previous {
            open_context.active_id.set(None);
        }
        if open_context.value.get().is_none() && !open {
            open_context.committed_label.set(None);
            if open_context.kind == ListboxKind::Editable {
                open_context.query.set(String::new());
                open_context.query_dirty.set_value(false);
            }
        }
        was_open.set_value(open);
    });
}

fn open_with(context: ListboxContext, initial: InitialActive) {
    context.pending_initial.set_value(initial);
    if context.open.get_untracked() {
        schedule_refresh(context, initial);
    } else {
        context.open.set(true);
    }
}

fn schedule_refresh(context: ListboxContext, initial: InitialActive) {
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        leptos::task::tick().await;
        refresh_options(context, initial);
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (context, initial);
}

fn move_active(context: ListboxContext, delta: i32) {
    #[cfg(target_arch = "wasm32")]
    {
        let options = enabled_options(context.content_ref);
        if options.is_empty() {
            context.active_id.set(None);
            return;
        }
        let current = context.active_id.get_untracked();
        let index = current
            .as_ref()
            .and_then(|id| option_index(&options, id))
            .unwrap_or(if delta > 0 { options.len() - 1 } else { 0 });
        let next = (i32::try_from(index).expect("option index fits i32") + delta)
            .rem_euclid(i32::try_from(options.len()).expect("option count fits i32"));
        set_active_element(
            &context,
            &options[usize::try_from(next).expect("nonnegative option index")],
        );
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (context, delta);
}

fn set_active_edge(context: ListboxContext, last: bool) {
    #[cfg(target_arch = "wasm32")]
    {
        let options = enabled_options(context.content_ref);
        let target = if last {
            options.last()
        } else {
            options.first()
        };
        if let Some(target) = target {
            set_active_element(&context, target);
        } else {
            context.active_id.set(None);
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (context, last);
}

#[cfg(target_arch = "wasm32")]
fn refresh_options(context: ListboxContext, initial: InitialActive) {
    let visible = visible_options(context.content_ref);
    let enabled = visible
        .iter()
        .filter(|option| option.get_attribute("aria-disabled").as_deref() != Some("true"))
        .cloned()
        .collect::<Vec<_>>();
    context.empty.set(visible.is_empty());
    if enabled.is_empty() {
        context.active_id.set(None);
        return;
    }
    let target = match initial {
        InitialActive::First => enabled.first(),
        InitialActive::Last => enabled.last(),
        InitialActive::CommittedOrFirst => context
            .value
            .get_untracked()
            .as_ref()
            .and_then(|value| {
                enabled
                    .iter()
                    .find(|option| option.get_attribute("data-value").as_ref() == Some(value))
            })
            .or_else(|| enabled.first()),
    };
    if let Some(target) = target {
        set_active_element(&context, target);
    }
}

fn select_active(context: ListboxContext, return_focus: bool) -> bool {
    #[cfg(target_arch = "wasm32")]
    if let Some(active) = context.active_id.get_untracked()
        && let Some(element) = visible_options(context.content_ref)
            .into_iter()
            .find(|option| option.get_attribute("id").as_ref() == Some(&active))
        && element.get_attribute("aria-disabled").as_deref() != Some("true")
        && let (Some(value), Some(label)) = (
            element.get_attribute("data-value"),
            element.get_attribute("data-label-source"),
        )
    {
        select_value(context, active, value, label, return_focus);
        return true;
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (context, return_focus);
    false
}

fn select_value(
    context: ListboxContext,
    _id: String,
    value: String,
    label: String,
    return_focus: bool,
) {
    let changed = context.value.get_untracked().as_ref() != Some(&value);
    context.value.set(Some(value.clone()));
    context.committed_label.set(Some(label.clone()));
    context.query.set(label);
    context.query_dirty.set_value(false);
    context.open.set(false);
    context.active_id.set(None);
    context.typeahead.set(String::new());
    if changed && let Some(callback) = context.on_value_change {
        callback.run(Some(value));
    }
    if return_focus {
        focus_owner_later(context);
    }
}

fn push_typeahead(context: ListboxContext, key: &str) {
    context
        .typeahead
        .update(|buffer| buffer.extend(key.chars().flat_map(char::to_lowercase)));
    if !context.open.get_untracked() {
        context.pending_initial.set_value(InitialActive::First);
        context.open.set(true);
    }
    let prefix = context.typeahead.get_untracked();
    let focus_context = context.clone();
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        leptos::task::tick().await;
        focus_prefix(focus_context, &prefix);
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (focus_context, prefix);
    let generation = context
        .typeahead_generation
        .get_untracked()
        .saturating_add(1);
    context.typeahead_generation.set(generation);
    schedule_timeout(LISTBOX_TYPEAHEAD_RESET_MS, move || {
        if context.typeahead_generation.get_untracked() == generation {
            context.typeahead.set(String::new());
        }
    });
}

#[cfg(target_arch = "wasm32")]
fn focus_prefix(context: ListboxContext, prefix: &str) {
    if let Some(option) = enabled_options(context.content_ref)
        .into_iter()
        .find(|option| {
            matches_prefix(
                &option.get_attribute("data-label").unwrap_or_default(),
                prefix,
            )
        })
    {
        set_active_element(&context, &option);
    }
}

#[cfg(target_arch = "wasm32")]
fn visible_options(content_ref: NodeRef<html::Div>) -> Vec<web_sys::Element> {
    let Some(content) = content_ref.get() else {
        return Vec::new();
    };
    let Ok(nodes) = web_sys::Element::query_selector_all(&content, "[role='option']") else {
        return Vec::new();
    };
    (0..nodes.length())
        .filter_map(|index| nodes.item(index))
        .filter_map(|node| node.dyn_into::<web_sys::Element>().ok())
        .filter(|option| !option.has_attribute("hidden"))
        .collect()
}

#[cfg(target_arch = "wasm32")]
fn enabled_options(content_ref: NodeRef<html::Div>) -> Vec<web_sys::Element> {
    visible_options(content_ref)
        .into_iter()
        .filter(|option| option.get_attribute("aria-disabled").as_deref() != Some("true"))
        .collect()
}

#[cfg(target_arch = "wasm32")]
fn option_index(options: &[web_sys::Element], id: &str) -> Option<usize> {
    options
        .iter()
        .position(|option| option.get_attribute("id").as_deref() == Some(id))
}

#[cfg(target_arch = "wasm32")]
fn set_active_element(context: &ListboxContext, option: &web_sys::Element) {
    if let Some(id) = option.get_attribute("id") {
        context.active_id.set(Some(id));
        if let Some(content) = context.content_ref.get() {
            let option_rect = option.get_bounding_client_rect();
            let content_rect = web_sys::Element::get_bounding_client_rect(&content);
            if option_rect.top() < content_rect.top() {
                content.set_scroll_top(
                    content.scroll_top() - (content_rect.top() - option_rect.top()).ceil() as i32,
                );
            } else if option_rect.bottom() > content_rect.bottom() {
                content.set_scroll_top(
                    content.scroll_top()
                        + (option_rect.bottom() - content_rect.bottom()).ceil() as i32,
                );
            }
        }
    }
}

fn focus_owner_later(context: ListboxContext) {
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        leptos::task::tick().await;
        match context.kind {
            ListboxKind::Editable => {
                if let Some(input) = context.input_ref.get() {
                    _ = web_sys::HtmlElement::focus(&input);
                }
            }
            ListboxKind::SelectOnly => {
                if let Some(trigger) = context.trigger_ref.get() {
                    _ = web_sys::HtmlElement::focus(&trigger);
                }
            }
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = context;
}

fn matches_query(label: &str, query: &str) -> bool {
    query.is_empty() || label.to_lowercase().contains(&query.to_lowercase())
}

#[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
fn matches_prefix(label: &str, prefix: &str) -> bool {
    label.to_lowercase().starts_with(&prefix.to_lowercase())
}

fn is_typeahead_key(event: &KeyboardEvent, key: &str) -> bool {
    key.chars().count() == 1
        && key != " "
        && !event.alt_key()
        && !event.ctrl_key()
        && !event.meta_key()
}

fn owner_state_tokens(
    preview_focus: bool,
    open: bool,
    disabled: bool,
    invalid: bool,
) -> Option<String> {
    let mut states = Vec::with_capacity(4);
    if preview_focus {
        states.push("focus");
    }
    if open {
        states.push("open");
    }
    if disabled {
        states.push("disabled");
    }
    if invalid {
        states.push("invalid");
    }
    (!states.is_empty()).then(|| states.join(" "))
}

fn option_state_tokens(active: bool, selected: bool, disabled: bool) -> Option<String> {
    let mut states = Vec::with_capacity(3);
    if active {
        states.push("active");
    }
    if selected {
        states.push("selected");
    }
    if disabled {
        states.push("disabled");
    }
    (!states.is_empty()).then(|| states.join(" "))
}

fn assert_dom_id(id: &str) {
    assert!(
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "listbox id must be one bounded DOM token"
    );
}

fn assert_value(value: &str) {
    assert!(
        !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control),
        "listbox value must be nonempty, bounded, and control-free"
    );
}

const fn explicit_bool(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listbox_states_filter_and_ids_are_closed() {
        assert_eq!(LISTBOX_TYPEAHEAD_RESET_MS, 500);
        assert_eq!(ListboxKind::Editable.as_str(), "editable");
        assert_eq!(ListboxKind::SelectOnly.as_str(), "select-only");
        assert_dom_id("agent-picker");
        assert_value("agent:张三");
        assert!(matches_query("Ada Lovelace", "love"));
        assert!(matches_query("张三", "张"));
        assert!(!matches_query("Ada Lovelace", "grace"));
        assert!(matches_prefix("Public", "pu"));
        assert!(matches_prefix("所有人可见", "所有"));
        assert_eq!(
            owner_state_tokens(true, true, true, true),
            Some("focus open disabled invalid".to_owned())
        );
        assert_eq!(
            option_state_tokens(true, true, true),
            Some("active selected disabled".to_owned())
        );
    }

    #[test]
    #[should_panic(expected = "listbox id")]
    fn listbox_id_rejects_split_tokens() {
        assert_dom_id("bad id");
    }
}
