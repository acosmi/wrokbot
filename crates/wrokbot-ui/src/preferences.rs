//! Shared reactive UI preferences with serialized partial persistence.

use leptos::prelude::*;
use leptos_i18n::I18nContext;
use openbot_contracts::ui::{UiLocale, UiPreferences, UiTheme, UpdateUiPreferences};

#[cfg(target_arch = "wasm32")]
use crate::api::{load_ui_preferences, save_ui_preferences};
use crate::i18n::{Locale, t, use_i18n};
use crate::primitives::Button;

/// Local drafts do not carry authority; the expected version comes only from a completed GET.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PreferenceDraft {
    theme: Option<UiTheme>,
    locale: Option<UiLocale>,
}

impl PreferenceDraft {
    fn is_empty(self) -> bool {
        self.theme.is_none() && self.locale.is_none()
    }
    fn merge(&mut self, newer: Self) {
        self.theme = newer.theme.or(self.theme);
        self.locale = newer.locale.or(self.locale);
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct PreferenceWrites {
    known: Option<UiPreferences>,
    draft: PreferenceDraft,
    in_flight: Option<UpdateUiPreferences>,
    paused: bool,
}

impl PreferenceWrites {
    fn take_request(&mut self) -> Option<UpdateUiPreferences> {
        if self.paused || self.in_flight.is_some() || self.draft.is_empty() {
            return None;
        }
        let known = self.known?;
        let request = UpdateUiPreferences {
            theme: self.draft.theme,
            locale: self.draft.locale,
            expected_revision: known.revision,
        };
        self.draft = PreferenceDraft::default();
        self.in_flight = Some(request);
        Some(request)
    }

    #[cfg(any(target_arch = "wasm32", test))]
    fn acknowledge(&mut self, stored: UiPreferences) {
        self.known = Some(stored);
        self.in_flight = None;
        // A receipt updates server knowledge, never the draft or the already edited DOM.
    }

    fn pause(&mut self) {
        if let Some(failed) = self.in_flight.take() {
            let mut retained = PreferenceDraft {
                theme: failed.theme,
                locale: failed.locale,
            };
            retained.merge(self.draft);
            self.draft = retained;
        }
        self.paused = true;
    }
}

/// Reactive state shared by theme/locale controls and the startup loader.
#[derive(Clone, Copy)]
pub struct UiPreferenceContext {
    theme: RwSignal<UiTheme>,
    writes: RwSignal<PreferenceWrites>,
    reading: RwSignal<bool>,
    interaction_revision: RwSignal<u64>,
    #[cfg(target_arch = "wasm32")]
    worker_owner: StoredValue<Option<Owner>>,
}

/// Install one preference context and start the authenticated cross-device read.
pub fn provide_ui_preferences(i18n: I18nContext<Locale>) -> UiPreferenceContext {
    let context = UiPreferenceContext {
        theme: RwSignal::new(current_theme()),
        writes: RwSignal::new(PreferenceWrites::default()),
        reading: RwSignal::new(false),
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
        let writes = self.writes.get();
        !writes.paused && (writes.in_flight.is_some() || !writes.draft.is_empty())
    }

    /// Apply and enqueue one explicit theme choice without reloading.
    pub fn select_theme(self, theme: UiTheme) {
        apply_theme(theme);
        self.theme.set(theme);
        self.enqueue(PreferenceDraft {
            theme: Some(theme),
            locale: None,
        });
    }

    /// Apply and enqueue one explicit locale choice without reloading.
    pub fn select_locale(self, i18n: I18nContext<Locale>, locale: UiLocale) {
        i18n.set_locale(contract_locale(locale));
        self.enqueue(PreferenceDraft {
            theme: None,
            locale: Some(locale),
        });
    }

    fn enqueue(self, update: PreferenceDraft) {
        self.writes.update(|writes| writes.draft.merge(update));
        let Some(next) = self.interaction_revision.get_untracked().checked_add(1) else {
            self.writes.update(PreferenceWrites::pause);
            return;
        };
        self.interaction_revision.set(next);
        self.start_worker();
    }

    fn start_worker(self) {
        let Some(mut writes) = self.writes.try_get_untracked() else {
            return;
        };
        let Some(first) = writes.take_request() else {
            return;
        };
        self.writes.set(writes);
        #[cfg(target_arch = "wasm32")]
        {
            // Enqueue can run inside ThemeToggle/LocaleSwitch event owners. A locale change may
            // reconstruct that child owner while the PUT is in flight; binding the worker there
            // would cancel the receipt path and leave `saving=true` forever. The AppShell owner
            // captured by `provide_ui_preferences` survives those child reconstructions.
            let start_worker = || {
                leptos::task::spawn_local_scoped_with_cancellation(async move {
                    let mut next = first;
                    loop {
                        let result = save_ui_preferences(next).await;
                        let Some(mut writes) = self.writes.try_get_untracked() else {
                            return;
                        };
                        match result {
                            Ok(stored) => writes.acknowledge(stored),
                            Err(_) => {
                                writes.pause();
                                self.writes.try_set(writes);
                                return;
                            }
                        }
                        let following = writes.take_request();
                        self.writes.try_set(writes);
                        let Some(following) = following else {
                            return;
                        };
                        next = following;
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
            let _ = first;
            self.writes.update(PreferenceWrites::pause);
        }
    }

    fn retry(self, i18n: I18nContext<Locale>) {
        if self.reading.get_untracked() {
            return;
        }
        self.writes.update(|writes| writes.paused = false);
        if self.writes.get_untracked().known.is_none() {
            load_stored_preferences(self, i18n);
        } else {
            // Keep the last known version after a lost response; CAS reveals a possible commit.
            self.start_worker();
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
        <Show when=move || preferences.writes.get().paused>
            <p class="ob-preference-error" role="alert">
                {move || t!(i18n, shell.preference_save_error)}
            </p>
            <Button on_activate=move |_| preferences.retry(i18n)>{move || t!(i18n, common.retry)}</Button>
        </Show>
    }
}

fn load_stored_preferences(context: UiPreferenceContext, i18n: I18nContext<Locale>) {
    if context.reading.get_untracked() {
        return;
    }
    context.reading.set(true);
    let starting_revision = context.interaction_revision.get_untracked();
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        let result = load_ui_preferences().await;
        let Some(mut writes) = context.writes.try_get_untracked() else {
            return;
        };
        context.reading.try_set(false);
        let Ok(stored) = result else {
            writes.pause();
            context.writes.try_set(writes);
            return;
        };
        writes.known = Some(stored);
        let apply_stored = context.interaction_revision.get_untracked() == starting_revision
            && writes.draft.is_empty()
            && !writes.paused;
        context.writes.try_set(writes);
        if apply_stored {
            if let Some(theme) = stored.theme {
                apply_theme(theme);
                context.theme.set(theme);
            }
            if let Some(locale) = stored.locale {
                i18n.set_locale(contract_locale(locale));
            }
        }
        context.start_worker();
    });
    #[cfg(not(target_arch = "wasm32"))]
    {
        context.reading.set(false);
        let _ = (i18n, starting_revision);
    }
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

#[cfg(test)]
mod persistence_tests {
    use super::*;

    fn stored(revision: i64, theme: UiTheme) -> UiPreferences {
        UiPreferences {
            theme: Some(theme),
            locale: None,
            revision: Some(revision),
            updated_at: Some(time::OffsetDateTime::UNIX_EPOCH),
        }
    }

    #[test]
    fn initial_read_is_required_and_success_preserves_edits_made_during_the_request() {
        let mut writes = PreferenceWrites::default();
        writes.draft.merge(PreferenceDraft {
            theme: Some(UiTheme::Dark),
            locale: None,
        });
        assert!(writes.take_request().is_none());
        assert_eq!(writes.draft.theme, Some(UiTheme::Dark));
        // Only this completed GET establishes that no persistent row exists.
        writes.known = Some(UiPreferences::default());
        let first = writes.take_request().unwrap();
        assert_eq!(first.expected_revision, None);
        assert!(writes.take_request().is_none());
        writes.draft.merge(PreferenceDraft {
            theme: Some(UiTheme::Light),
            locale: Some(UiLocale::ZhCn),
        });
        writes.acknowledge(stored(1, UiTheme::Dark));
        assert_eq!(writes.draft.theme, Some(UiTheme::Light));
        assert_eq!(writes.draft.locale, Some(UiLocale::ZhCn));
        let second = writes.take_request().unwrap();
        assert_eq!(second.expected_revision, Some(1));
        assert_eq!(second.theme, Some(UiTheme::Light));
        assert_eq!(second.locale, Some(UiLocale::ZhCn));
        assert_eq!(first.theme, Some(UiTheme::Dark));
        assert_eq!(first.locale, None);
    }

    #[test]
    fn failed_or_conflicted_request_preserves_latest_draft_and_never_automatically_rebases() {
        let mut writes = PreferenceWrites {
            known: Some(stored(2, UiTheme::Dark)),
            ..PreferenceWrites::default()
        };
        writes.draft = PreferenceDraft {
            theme: Some(UiTheme::Light),
            locale: Some(UiLocale::En),
        };
        let first = writes.take_request().unwrap();
        writes.draft.merge(PreferenceDraft {
            theme: Some(UiTheme::System),
            locale: None,
        });
        writes.pause();
        assert_eq!(writes.draft.theme, Some(UiTheme::System));
        assert_eq!(writes.draft.locale, Some(UiLocale::En));
        assert!(writes.take_request().is_none());
        writes.draft.merge(PreferenceDraft {
            theme: None,
            locale: Some(UiLocale::ZhCn),
        });
        assert!(writes.take_request().is_none());
        assert_eq!(writes.known.unwrap().revision, Some(2));
        // The explicit retry keeps the old known version even if the lost request committed.
        writes.paused = false;
        let retried = writes.take_request().unwrap();
        assert_eq!(retried.expected_revision, first.expected_revision);
        assert_eq!(retried.theme, Some(UiTheme::System));
        assert_eq!(retried.locale, Some(UiLocale::ZhCn));
    }

    #[test]
    fn a_destroyed_authenticated_mount_cannot_update_the_next_preference_context() {
        let old_owner = Owner::new();
        let old = old_owner.with(|| RwSignal::new(PreferenceWrites::default()));
        old_owner.cleanup();
        Owner::new().with(|| {
            let next = RwSignal::new(PreferenceWrites::default());
            assert!(old.try_get_untracked().is_none());
            assert!(next.get_untracked().known.is_none());
            assert!(next.get_untracked().draft.is_empty());
        });
    }
}
