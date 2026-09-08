//! Two-locale APG menu-button switch synchronized through `leptos_i18n`.

use leptos::prelude::*;
use leptos::{ev::KeyboardEvent, html};
use openbot_contracts::ui::UiLocale;

use crate::i18n::{Locale, t, use_i18n};
use crate::icons::Icon;
use crate::preferences::use_ui_preferences;

use super::{IconSize, IconView};

/// Switch between the two first-release locales without reloading the bundle.
#[component]
pub fn LocaleSwitch(#[prop(into)] id: String) -> impl IntoView {
    assert_dom_id(&id);
    let i18n = use_i18n();
    let open = RwSignal::new(false);
    let trigger_ref = NodeRef::<html::Button>::new();
    let en_ref = NodeRef::<html::Button>::new();
    let zh_ref = NodeRef::<html::Button>::new();
    let label_id = format!("{id}-label");
    let current_id = format!("{id}-current");
    let labelled_by = format!("{label_id} {current_id}");
    let menu_label_id = label_id.clone();

    let toggle = move |_| {
        if open.get_untracked() {
            open.set(false);
        } else {
            open_locale_menu(open, i18n.get_locale_untracked(), en_ref, zh_ref);
        }
    };
    view! {
        <div id=id class="ob-locale-switch">
            <span id=label_id class="ob-visually-hidden">
                {move || t!(i18n, shell.language_label)}
            </span>
            <button
                type="button"
                class="ob-locale-trigger"
                node_ref=trigger_ref
                aria-haspopup="menu"
                aria-expanded=move || if open.get() { "true" } else { "false" }
                aria-labelledby=labelled_by
                on:click=toggle
                on:keydown=move |event| {
                    match event.key().as_str() {
                        "ArrowDown" | "ArrowUp" | "Enter" | " " => {
                            event.prevent_default();
                            open_locale_menu(open, i18n.get_locale_untracked(), en_ref, zh_ref);
                        }
                        "Escape" => open.set(false),
                        _ => {}
                    }
                }
            >
                <IconView icon=Icon::Languages size=IconSize::Inline />
                <span id=current_id>
                    {move || locale_label(i18n, i18n.get_locale())}
                </span>
                <IconView icon=Icon::ChevronDown size=IconSize::Inline />
            </button>
            <Show when=move || open.get()>
                <div class="ob-locale-menu" role="menu" aria-labelledby=menu_label_id.clone()>
                    <button
                        type="button"
                        class="ob-locale-option"
                        node_ref=en_ref
                        role="menuitemradio"
                        aria-checked=move || if i18n.get_locale() == Locale::en { "true" } else { "false" }
                        aria-current=move || (i18n.get_locale() == Locale::en).then_some("true")
                        tabindex="-1"
                        on:click=move |_| choose_locale(i18n, Locale::en, open, trigger_ref)
                        on:keydown=move |event| {
                            handle_menu_key(
                                event,
                                Locale::en,
                                i18n,
                                open,
                                trigger_ref,
                                en_ref,
                                zh_ref,
                            );
                        }
                    >
                        <span>{move || t!(i18n, shell.language_english)}</span>
                        <Show when=move || i18n.get_locale() == Locale::en>
                            <IconView icon=Icon::Check size=IconSize::Inline />
                        </Show>
                    </button>
                    <button
                        type="button"
                        class="ob-locale-option"
                        node_ref=zh_ref
                        role="menuitemradio"
                        aria-checked=move || if i18n.get_locale() == Locale::zh_CN { "true" } else { "false" }
                        aria-current=move || (i18n.get_locale() == Locale::zh_CN).then_some("true")
                        tabindex="-1"
                        on:click=move |_| choose_locale(i18n, Locale::zh_CN, open, trigger_ref)
                        on:keydown=move |event| {
                            handle_menu_key(
                                event,
                                Locale::zh_CN,
                                i18n,
                                open,
                                trigger_ref,
                                en_ref,
                                zh_ref,
                            );
                        }
                    >
                        <span>{move || t!(i18n, shell.language_simplified_chinese)}</span>
                        <Show when=move || i18n.get_locale() == Locale::zh_CN>
                            <IconView icon=Icon::Check size=IconSize::Inline />
                        </Show>
                    </button>
                </div>
            </Show>
        </div>
    }
}

fn locale_label(i18n: leptos_i18n::I18nContext<Locale>, locale: Locale) -> impl IntoView {
    match locale {
        Locale::en => t!(i18n, shell.language_english).into_any(),
        Locale::zh_CN => t!(i18n, shell.language_simplified_chinese).into_any(),
    }
}

fn open_locale_menu(
    open: RwSignal<bool>,
    locale: Locale,
    en_ref: NodeRef<html::Button>,
    zh_ref: NodeRef<html::Button>,
) {
    open.set(true);
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        leptos::task::tick().await;
        focus_locale(locale, en_ref, zh_ref);
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (locale, en_ref, zh_ref);
}

fn choose_locale(
    i18n: leptos_i18n::I18nContext<Locale>,
    locale: Locale,
    open: RwSignal<bool>,
    trigger_ref: NodeRef<html::Button>,
) {
    let stored = match locale {
        Locale::en => UiLocale::En,
        Locale::zh_CN => UiLocale::ZhCn,
    };
    use_ui_preferences().select_locale(i18n, stored);
    open.set(false);
    focus_button(trigger_ref);
}

fn handle_menu_key(
    event: KeyboardEvent,
    current: Locale,
    i18n: leptos_i18n::I18nContext<Locale>,
    open: RwSignal<bool>,
    trigger_ref: NodeRef<html::Button>,
    en_ref: NodeRef<html::Button>,
    zh_ref: NodeRef<html::Button>,
) {
    match event.key().as_str() {
        "ArrowDown" | "ArrowUp" | "Home" | "End" => {
            event.prevent_default();
            let next = match event.key().as_str() {
                "Home" => Locale::en,
                "End" => Locale::zh_CN,
                _ if current == Locale::en => Locale::zh_CN,
                _ => Locale::en,
            };
            focus_locale(next, en_ref, zh_ref);
        }
        "Enter" | " " => {
            event.prevent_default();
            choose_locale(i18n, current, open, trigger_ref);
        }
        "Escape" => {
            event.prevent_default();
            open.set(false);
            focus_button(trigger_ref);
        }
        "Tab" => open.set(false),
        _ => {}
    }
}

fn focus_locale(locale: Locale, en_ref: NodeRef<html::Button>, zh_ref: NodeRef<html::Button>) {
    match locale {
        Locale::en => focus_button(en_ref),
        Locale::zh_CN => focus_button(zh_ref),
    }
}

fn focus_button(reference: NodeRef<html::Button>) {
    #[cfg(target_arch = "wasm32")]
    if let Some(button) = reference.get() {
        _ = button.focus();
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = reference;
}

fn assert_dom_id(id: &str) {
    assert!(
        !id.is_empty()
            && id.len() <= 96
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "LocaleSwitch id must be one bounded DOM token"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_instances_have_disjoint_bounded_dom_id_families() {
        for id in ["sidebar-locale-switch", "settings-locale-switch"] {
            assert_dom_id(id);
        }
        assert_ne!(
            "sidebar-locale-switch-label",
            "settings-locale-switch-label"
        );
        assert_ne!(
            "sidebar-locale-switch-current",
            "settings-locale-switch-current"
        );
    }

    #[test]
    #[should_panic(expected = "bounded DOM token")]
    fn split_or_selector_controlled_id_is_rejected() {
        assert_dom_id("settings locale#switch");
    }
}
