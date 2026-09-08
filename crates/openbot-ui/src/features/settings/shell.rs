//! Shared 200px secondary navigation for implemented `/settings` destinations.

use leptos::prelude::*;
use leptos_router::hooks::use_location;

use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{IconSize, IconView};

const MODELS_PATH: &str = "/settings/models";
const GENERAL_PATH: &str = "/settings";
const CONNECTED_ACCOUNTS_PATH: &str = "/settings/connected-accounts";
const COMPONENTS_GALLERY_PATH: &str = "/settings/components-gallery";
const MEMORY_PATH: &str = "/settings/memory";

/// Settings secondary shell. The global App shell remains the only owner of `<main>`.
#[component]
pub fn SettingsShell(children: Children) -> impl IntoView {
    let i18n = use_i18n();
    let location = use_location();
    let general_location = location.clone();
    let connected_accounts_location = location.clone();
    let components_gallery_location = location.clone();
    let models_location = location.clone();
    let memory_location = location;
    view! {
        <div class="ob-settings-shell">
            <aside class="ob-settings-subnav">
                <nav aria-label=move || t_string!(i18n, settings.title).to_owned()>
                    <a class="ob-settings-back" href="/">
                        <IconView icon=Icon::ArrowLeft size=IconSize::Inline />
                        <span>{move || t!(i18n, settings.back_to_app)}</span>
                    </a>
                    <ul class="ob-settings-subnav-list">
                        <li>
                            <a
                                class="ob-settings-subnav-link"
                                href=GENERAL_PATH
                                data-state=move || {
                                    is_current(&general_location.pathname.get(), GENERAL_PATH)
                                        .then_some("current")
                                }
                                aria-current=move || {
                                    is_current(&general_location.pathname.get(), GENERAL_PATH)
                                        .then_some("page")
                                }
                            >
                                <IconView icon=Icon::Settings size=IconSize::Inline />
                                <span>{move || t!(i18n, settings.nav_general)}</span>
                            </a>
                        </li>
                        <li>
                            <a
                                class="ob-settings-subnav-link"
                                href=CONNECTED_ACCOUNTS_PATH
                                data-state=move || {
                                    is_section_current(
                                        &connected_accounts_location.pathname.get(),
                                        CONNECTED_ACCOUNTS_PATH,
                                    )
                                    .then_some("current")
                                }
                                aria-current=move || {
                                    is_section_current(
                                        &connected_accounts_location.pathname.get(),
                                        CONNECTED_ACCOUNTS_PATH,
                                    )
                                    .then_some("page")
                                }
                            >
                                <IconView icon=Icon::Plug size=IconSize::Inline />
                                <span>{move || t!(i18n, settings.nav_connected_accounts)}</span>
                            </a>
                        </li>
                        <li>
                            <a
                                class="ob-settings-subnav-link"
                                href=COMPONENTS_GALLERY_PATH
                                data-state=move || {
                                    is_section_current(
                                        &components_gallery_location.pathname.get(),
                                        COMPONENTS_GALLERY_PATH,
                                    )
                                    .then_some("current")
                                }
                                aria-current=move || {
                                    is_section_current(
                                        &components_gallery_location.pathname.get(),
                                        COMPONENTS_GALLERY_PATH,
                                    )
                                    .then_some("page")
                                }
                            >
                                <IconView icon=Icon::LayoutGrid size=IconSize::Inline />
                                <span>{move || t!(i18n, settings.nav_gallery)}</span>
                            </a>
                        </li>
                        <li>
                            <a
                                class="ob-settings-subnav-link"
                                href=MEMORY_PATH
                                data-state=move || {
                                    is_current(&memory_location.pathname.get(), MEMORY_PATH)
                                        .then_some("current")
                                }
                                aria-current=move || {
                                    is_current(&memory_location.pathname.get(), MEMORY_PATH)
                                        .then_some("page")
                                }
                            >
                                <IconView icon=Icon::Brain size=IconSize::Inline />
                                <span>{move || t!(i18n, shell.nav_memory)}</span>
                            </a>
                        </li>
                        <li>
                            <a class="ob-settings-subnav-link" href=MODELS_PATH
                                data-state=move || is_current(&models_location.pathname.get(), MODELS_PATH).then_some("current")
                                aria-current=move || is_current(&models_location.pathname.get(), MODELS_PATH).then_some("page")>
                                <IconView icon=Icon::Plug size=IconSize::Inline />
                                <span>{move || t!(i18n, models.title)}</span>
                            </a>
                        </li>
                    </ul>
                </nav>
            </aside>
            <div class="ob-settings-shell-content">
                {children()}
            </div>
        </div>
    }
}

fn is_current(pathname: &str, destination: &str) -> bool {
    pathname == destination
}

fn is_section_current(pathname: &str, destination: &str) -> bool {
    pathname == destination
        || pathname
            .strip_prefix(destination)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_real_settings_destinations_exist_and_general_is_exact() {
        assert_eq!(
            [
                GENERAL_PATH,
                MODELS_PATH,
                CONNECTED_ACCOUNTS_PATH,
                COMPONENTS_GALLERY_PATH,
                MEMORY_PATH,
            ]
            .len(),
            5
        );
        assert!(is_current("/settings", GENERAL_PATH));
        assert!(!is_current("/settings/memory", GENERAL_PATH));
        assert!(is_current("/settings/memory", MEMORY_PATH));
        assert!(!is_current("/settings/connected-accounts", MEMORY_PATH));
        assert!(is_section_current(
            "/settings/connected-accounts",
            CONNECTED_ACCOUNTS_PATH
        ));
        assert!(is_section_current(
            "/settings/connected-accounts/google-drive",
            CONNECTED_ACCOUNTS_PATH
        ));
        assert!(!is_section_current(
            "/settings/connected-accounts-legacy",
            CONNECTED_ACCOUNTS_PATH
        ));
        assert!(is_section_current(
            "/settings/components-gallery/showQuote",
            COMPONENTS_GALLERY_PATH
        ));
    }
}
