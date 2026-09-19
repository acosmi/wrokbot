//! Compound tooltip with delayed hover/focus disclosure.

use leptos::context::Provider;
use leptos::ev::KeyboardEvent;
use leptos::prelude::*;

use super::timing::schedule_timeout;

/// First-source fixed tooltip delay.
pub const TOOLTIP_DELAY_MS: i32 = 400;

/// Trigger action is closed to a same-origin link or unit-callback button.
pub enum TooltipTriggerAction {
    /// Same-origin link.
    Link(String),
    /// Button action.
    Button(UnsyncCallback<()>),
}

#[derive(Clone)]
struct TooltipContext {
    tooltip_id: String,
    open: RwSignal<bool>,
    generation: RwSignal<u64>,
    hovered: RwSignal<bool>,
    focused: RwSignal<bool>,
    forced: bool,
}

/// Provide one tooltip popup and one or more nested triggers.
#[component]
pub fn Tooltip(
    #[prop(into)] id: String,
    #[prop(into)] content: TextProp,
    /// Compile-gallery forced state; production callers leave false.
    #[prop(optional)]
    preview_open: bool,
    children: Children,
) -> impl IntoView {
    assert_dom_id(&id);
    let context = TooltipContext {
        tooltip_id: id.clone(),
        open: RwSignal::new(false),
        generation: RwSignal::new(0),
        hovered: RwSignal::new(false),
        focused: RwSignal::new(false),
        forced: preview_open,
    };
    let popup_hidden = context.clone();
    let popup_state = context.clone();
    view! {
        <Provider value=context>
            <span class="ob-tooltip-root">
                {children()}
                <span
                    id=id
                    class="ob-tooltip"
                    role="tooltip"
                    hidden=move || !is_open(&popup_hidden)
                    data-state=move || if is_open(&popup_state) { "open" } else { "closed" }
                >
                    {move || content.get()}
                </span>
            </span>
        </Provider>
    }
}

/// Button/link trigger wired to its nearest Tooltip provider.
#[component]
pub fn TooltipTrigger(
    #[prop(optional, into)] id: Option<String>,
    action: TooltipTriggerAction,
    children: Children,
) -> AnyView {
    if let Some(id) = &id {
        assert_dom_id(id);
    }
    let context =
        use_context::<TooltipContext>().expect("TooltipTrigger must be nested in Tooltip");
    let content = children();
    match action {
        TooltipTriggerAction::Link(href) => {
            assert_internal_href(&href);
            let described = context.clone();
            let enter = context.clone();
            let focus = context.clone();
            let leave = context.clone();
            let blur = context.clone();
            let key = context;
            view! {
                <a
                    id=id
                    class="ob-tooltip-trigger"
                    href=href
                    aria-describedby=move || is_open(&described).then(|| described.tooltip_id.clone())
                    on:mouseenter=move |_| pointer_enter(enter.clone())
                    on:focus=move |_| focus_enter(focus.clone())
                    on:mouseleave=move |_| pointer_leave(leave.clone())
                    on:blur=move |_| focus_leave(blur.clone())
                    on:keydown=move |event: KeyboardEvent| {
                        if event.key() == "Escape" {
                            event.prevent_default();
                            escape_close(key.clone());
                        }
                    }
                >{content}</a>
            }
            .into_any()
        }
        TooltipTriggerAction::Button(on_activate) => {
            let described = context.clone();
            let enter = context.clone();
            let focus = context.clone();
            let leave = context.clone();
            let blur = context.clone();
            let key = context;
            view! {
                <button
                    id=id
                    type="button"
                    class="ob-tooltip-trigger"
                    aria-describedby=move || is_open(&described).then(|| described.tooltip_id.clone())
                    on:mouseenter=move |_| pointer_enter(enter.clone())
                    on:focus=move |_| focus_enter(focus.clone())
                    on:mouseleave=move |_| pointer_leave(leave.clone())
                    on:blur=move |_| focus_leave(blur.clone())
                    on:click=move |_| on_activate.run(())
                    on:keydown=move |event: KeyboardEvent| {
                        match event.key().as_str() {
                            "Escape" => {
                                event.prevent_default();
                                escape_close(key.clone());
                            }
                            "Enter" | " " => {
                                event.prevent_default();
                                on_activate.run(());
                            }
                            _ => {}
                        }
                    }
                >{content}</button>
            }
            .into_any()
        }
    }
}

fn request_open(context: TooltipContext) {
    if context.forced {
        return;
    }
    let next = context.generation.get_untracked().saturating_add(1);
    context.generation.set(next);
    schedule_timeout(TOOLTIP_DELAY_MS, move || {
        if context.generation.get_untracked() == next {
            context.open.set(true);
        }
    });
}

fn pointer_enter(context: TooltipContext) {
    context.hovered.set(true);
    request_open(context);
}

fn focus_enter(context: TooltipContext) {
    context.focused.set(true);
    request_open(context);
}

fn pointer_leave(context: TooltipContext) {
    context.hovered.set(false);
    close_if_inactive(context);
}

fn focus_leave(context: TooltipContext) {
    context.focused.set(false);
    close_if_inactive(context);
}

fn close_if_inactive(context: TooltipContext) {
    if context.hovered.get_untracked() || context.focused.get_untracked() {
        return;
    }
    escape_close(context);
}

fn escape_close(context: TooltipContext) {
    if context.forced {
        return;
    }
    context
        .generation
        .set(context.generation.get_untracked().saturating_add(1));
    context.open.set(false);
}

fn is_open(context: &TooltipContext) -> bool {
    context.forced || context.open.get()
}

fn assert_dom_id(id: &str) {
    assert!(
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "Tooltip id must be one bounded DOM token"
    );
}

fn assert_internal_href(href: &str) {
    assert!(
        href.starts_with('/')
            && !href.starts_with("//")
            && href.len() <= 2048
            && !href
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b'\\'),
        "Tooltip link must be one bounded same-origin absolute path"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tooltip_delay_and_ids_are_closed() {
        assert_eq!(TOOLTIP_DELAY_MS, 400);
        assert_dom_id("tooltip-settings");
        assert_internal_href("/settings");
    }

    #[test]
    #[should_panic(expected = "same-origin")]
    fn tooltip_rejects_external_links() {
        assert_internal_href("javascript:alert(1)");
    }
}
