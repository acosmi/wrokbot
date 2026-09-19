//! Shared reactive UI preferences with serialized partial persistence.

use leptos::prelude::*;
use leptos_i18n::I18nContext;
use openbot_contracts::ui::{UiLocale, UiTheme, UpdateUiPreferences};

#[cfg(target_arch = "wasm32")]
use crate::api::{load_ui_preferences, save_ui_preferences};
use crate::i18n::{Locale, t, use_i18n};

/// Reactive state shared by theme/locale controls and the startup loader.
#[derive(Clone, Copy)]
pub struct UiPreferenceContext {
    theme: RwSignal<UiTheme>,
    pending: RwSignal<UpdateUiPreferences>,
    saving: RwSignal<bool>,
    save_error: RwSignal<bool>,
    interaction_revision: RwSignal<u64>,
    #[cfg(target_arch = "wasm32")]
    worker_owner: StoredValue<Option<Owner>>,
}

/// Install one preference context and start the authenticated cross-device read.
pub fn provide_ui_preferences(i18n: I18nContext<Locale>) -> UiPreferenceContext {
    let context = UiPreferenceContext {
        theme: RwSignal::new(current_theme()),
        pending: RwSignal::new(UpdateUiPreferences::default()),
        saving: RwSignal::new(false),
        save_error: RwSignal::new(false),
        interaction_revision: RwSignal::new(0),
        #[cfg(target_arch = "wasm32")]
        worker_owner: StoredValue::new(Owner::current()),
    };
    provide_context(context);
    load_stored_preferences(context, i18n);
    context
}

/// Get the context installed by the app shell.
pub fn use_ui_preferences() -> UiPreferenceContext {
    use_context().expect("AppShell provides UiPreferenceContext")
}

impl UiPreferenceContext {
    /// Current effective theme.
    #[must_use]
    pub fn theme(self) -> UiTheme {
        self.theme.get()
    }

    /// Whether one or more preference updates are still awaiting a server receipt.
    #[must_use]
    pub fn is_saving(self) -> bool {
        self.saving.get()
    }

    /// Apply and enqueue one explicit theme choice without reloading.
    pub fn select_theme(self, theme: UiTheme) {
        apply_theme(theme);
        self.theme.set(theme);
        self.enqueue(UpdateUiPreferences {
            theme: Some(theme),
            locale: None,
        });
    }

    /// Apply and enqueue one explicit locale choice without reloading.
    pub fn select_locale(self, i18n: I18nContext<Locale>, locale: UiLocale) {
        i18n.set_locale(contract_locale(locale));
        self.enqueue(UpdateUiPreferences {
            theme: None,
            locale: Some(locale),
        });
    }

    fn enqueue(self, update: UpdateUiPreferences) {
        self.interaction_revision
            .update(|revision| *revision = revision.saturating_add(1));
        self.save_error.set(false);
        self.pending.update(|pending| {
            if update.theme.is_some() {
                pending.theme = update.theme;
            }
            if update.locale.is_some() {
                pending.locale = update.locale;
            }
        });
        if self.saving.get_untracked() {
            return;
        }
        self.saving.set(true);
        #[cfg(target_arch = "wasm32")]
        {
            // Enqueue can run inside ThemeToggle/LocaleSwitch event owners. A locale change may
            // reconstruct that child owner while the PUT is in flight; binding the worker there
            // would cancel the receipt path and leave `saving=true` forever. The AppShell owner
            // captured by `provide_ui_preferences` survives those child reconstructions.
            let start_worker = || {
                leptos::task::spawn_local_scoped_with_cancellation(async move {
                    loop {
                        let next = self.pending.get_untracked();
                        self.pending.set(UpdateUiPreferences::default());
                        if next.is_empty() {
                            self.saving.set(false);
                            break;
                        }
                        if save_ui_preferences(next).await.is_err() {
                            self.save_error.set(true);
                        }
                    }
                });
            };
            match self.worker_owner.get_value() {
                Some(owner) => owner.with(start_worker),
                None => start_worker(),
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.pending.set(UpdateUiPreferences::default());
            self.saving.set(false);
            self.save_error.set(true);
        }
    }
}

/// Visible, localized persistence failure; preference writes never fail silently.
#[component]
pub fn PreferenceSaveStatus() -> impl IntoView {
    let i18n = use_i18n();
    let preferences = use_ui_preferences();
    view! {
        <Show when=move || preferences.is_saving()>
            <p class="ob-preference-saving" role="status">
                {move || t!(i18n, shell.preference_saving)}
            </p>
        </Show>
        <Show when=move || preferences.save_error.get()>
            <p class="ob-preference-error" role="alert">
                {move || t!(i18n, shell.preference_save_error)}
            </p>
        </Show>
    }
}

fn load_stored_preferences(context: UiPreferenceContext, i18n: I18nContext<Locale>) {
    let starting_revision = context.interaction_revision.get_untracked();
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        let Ok(stored) = load_ui_preferences().await else {
            return;
        };
        if context.interaction_revision.get_untracked() != starting_revision {
            return;
        }
        if let Some(theme) = stored.theme {
            apply_theme(theme);
            context.theme.set(theme);
        }
        if let Some(locale) = stored.locale {
            i18n.set_locale(contract_locale(locale));
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (context, i18n, starting_revision);
}

const fn contract_locale(locale: UiLocale) -> Locale {
    match locale {
        UiLocale::En => Locale::en,
        UiLocale::ZhCn => Locale::zh_CN,
    }
}

#[cfg(target_arch = "wasm32")]
fn current_theme() -> UiTheme {
    let Some(root) = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.document_element())
    else {
        return UiTheme::System;
    };
    let classes = root.class_list();
    if classes.contains("dark") {
        UiTheme::Dark
    } else if classes.contains("light") {
        UiTheme::Light
    } else {
        UiTheme::System
    }
}

#[cfg(not(target_arch = "wasm32"))]
const fn current_theme() -> UiTheme {
    UiTheme::System
}

#[cfg(target_arch = "wasm32")]
fn apply_theme(theme: UiTheme) {
    let Some(root) = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.document_element())
    else {
        return;
    };
    let classes = root.class_list();
    _ = classes.remove_2("light", "dark");
    match theme {
        UiTheme::System => {}
        UiTheme::Light => _ = classes.add_1("light"),
        UiTheme::Dark => _ = classes.add_1("dark"),
    }
}

#[cfg(not(target_arch = "wasm32"))]
const fn apply_theme(_theme: UiTheme) {}
