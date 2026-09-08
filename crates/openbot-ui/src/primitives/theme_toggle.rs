//! Three-state token theme switch.

use leptos::prelude::*;
use leptos::{ev::KeyboardEvent, html};
pub use openbot_contracts::ui::UiTheme as Theme;

use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::preferences::use_ui_preferences;

use super::{IconSize, IconView};

/// Switch the current document among system/light/dark without reloading.
#[component]
pub fn ThemeToggle() -> impl IntoView {
    let i18n = use_i18n();
    let preferences = use_ui_preferences();
    let system_ref = NodeRef::<html::Button>::new();
    let light_ref = NodeRef::<html::Button>::new();
    let dark_ref = NodeRef::<html::Button>::new();
    let select = move |next: Theme| {
        preferences.select_theme(next);
    };
    view! {
        <div
            class="ob-segmented"
            role="radiogroup"
            aria-label=move || t_string!(i18n, shell.theme_label).to_owned()
        >
            <button
                type="button"
                class="ob-segmented-button"
                node_ref=system_ref
                role="radio"
                aria-checked=move || if preferences.theme() == Theme::System { "true" } else { "false" }
                tabindex=move || -i32::from(preferences.theme() != Theme::System)
                on:click=move |_| select(Theme::System)
                on:keydown=move |event| {
                    handle_radio_key(
                        event,
                        Theme::System,
                        select,
                        system_ref,
                        light_ref,
                        dark_ref,
                    );
                }
            >
                <IconView icon=Icon::SunMoon size=IconSize::Inline />
                {move || t!(i18n, shell.theme_system)}
            </button>
            <button
                type="button"
                class="ob-segmented-button"
                node_ref=light_ref
                role="radio"
                aria-checked=move || if preferences.theme() == Theme::Light { "true" } else { "false" }
                tabindex=move || -i32::from(preferences.theme() != Theme::Light)
                on:click=move |_| select(Theme::Light)
                on:keydown=move |event| {
                    handle_radio_key(
                        event,
                        Theme::Light,
                        select,
                        system_ref,
                        light_ref,
                        dark_ref,
                    );
                }
            >
                <IconView icon=Icon::Sun size=IconSize::Inline />
                {move || t!(i18n, shell.theme_light)}
            </button>
            <button
                type="button"
                class="ob-segmented-button"
                node_ref=dark_ref
                role="radio"
                aria-checked=move || if preferences.theme() == Theme::Dark { "true" } else { "false" }
                tabindex=move || -i32::from(preferences.theme() != Theme::Dark)
                on:click=move |_| select(Theme::Dark)
                on:keydown=move |event| {
                    handle_radio_key(
                        event,
                        Theme::Dark,
                        select,
                        system_ref,
                        light_ref,
                        dark_ref,
                    );
                }
            >
                <IconView icon=Icon::Moon size=IconSize::Inline />
                {move || t!(i18n, shell.theme_dark)}
            </button>
        </div>
    }
}

fn handle_radio_key(
    event: KeyboardEvent,
    current: Theme,
    select: impl Fn(Theme) + Copy,
    system_ref: NodeRef<html::Button>,
    light_ref: NodeRef<html::Button>,
    dark_ref: NodeRef<html::Button>,
) {
    let next = match event.key().as_str() {
        "ArrowRight" | "ArrowDown" => match current {
            Theme::System => Theme::Light,
            Theme::Light => Theme::Dark,
            Theme::Dark => Theme::System,
        },
        "ArrowLeft" | "ArrowUp" => match current {
            Theme::System => Theme::Dark,
            Theme::Light => Theme::System,
            Theme::Dark => Theme::Light,
        },
        "Home" => Theme::System,
        "End" => Theme::Dark,
        _ => return,
    };
    event.prevent_default();
    select(next);
    focus_theme(next, system_ref, light_ref, dark_ref);
}

fn focus_theme(
    theme: Theme,
    system_ref: NodeRef<html::Button>,
    light_ref: NodeRef<html::Button>,
    dark_ref: NodeRef<html::Button>,
) {
    #[cfg(target_arch = "wasm32")]
    {
        let target = match theme {
            Theme::System => system_ref.get(),
            Theme::Light => light_ref.get(),
            Theme::Dark => dark_ref.get(),
        };
        if let Some(target) = target {
            _ = target.focus();
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (theme, system_ref, light_ref, dark_ref);
}
