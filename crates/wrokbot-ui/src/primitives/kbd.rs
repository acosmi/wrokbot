//! Platform-aware semantic keyboard chord.

use leptos::prelude::*;

use crate::i18n::{t_string, use_i18n};

/// Optional modifier shown before a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KbdModifier {
    /// Command on Apple platforms, Control elsewhere.
    Primary,
    /// Literal Control.
    Control,
    /// Option on Apple platforms, Alt elsewhere.
    Alt,
    /// Shift.
    Shift,
}

/// Closed special keys plus a validated ASCII character.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KbdKey {
    /// Enter/Return.
    Enter,
    /// Escape.
    Escape,
    /// Slash.
    Slash,
    /// One ASCII alphanumeric character.
    Character(char),
}

/// Render one localized, platform-aware keyboard chord.
#[component]
pub fn Kbd(#[prop(optional)] modifier: Option<KbdModifier>, key: KbdKey) -> impl IntoView {
    let i18n = use_i18n();
    let apple = is_apple_platform();
    let (visible, accessible) = chord_labels(i18n, apple, modifier, key);
    view! {
        <kbd class="ob-kbd" aria-label=accessible>
            {visible}
        </kbd>
    }
}

fn chord_labels(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    apple: bool,
    modifier: Option<KbdModifier>,
    key: KbdKey,
) -> (String, String) {
    let (visible_key, accessible_key) = match key {
        KbdKey::Enter => (
            t_string!(i18n, keyboard.enter_short).to_owned(),
            t_string!(i18n, keyboard.enter).to_owned(),
        ),
        KbdKey::Escape => (
            t_string!(i18n, keyboard.escape_short).to_owned(),
            t_string!(i18n, keyboard.escape).to_owned(),
        ),
        KbdKey::Slash => ("/".to_owned(), t_string!(i18n, keyboard.slash).to_owned()),
        KbdKey::Character(character) => {
            let label = validated_character(character).to_string();
            (label.clone(), label)
        }
    };
    let Some(modifier) = modifier else {
        return (visible_key, accessible_key);
    };
    let (visible_modifier, separator) = modifier_visible(modifier, apple);
    let accessible_modifier = match (modifier, apple) {
        (KbdModifier::Primary, true) => t_string!(i18n, keyboard.command).to_owned(),
        (KbdModifier::Primary | KbdModifier::Control, false) | (KbdModifier::Control, true) => {
            t_string!(i18n, keyboard.control).to_owned()
        }
        (KbdModifier::Alt, true) => t_string!(i18n, keyboard.option).to_owned(),
        (KbdModifier::Alt, false) => t_string!(i18n, keyboard.alt).to_owned(),
        (KbdModifier::Shift, _) => t_string!(i18n, keyboard.shift).to_owned(),
    };
    (
        format!("{visible_modifier}{separator}{visible_key}"),
        format!("{accessible_modifier} {accessible_key}"),
    )
}

const fn modifier_visible(modifier: KbdModifier, apple: bool) -> (&'static str, &'static str) {
    match (modifier, apple) {
        (KbdModifier::Primary, true) => ("⌘", ""),
        (KbdModifier::Primary | KbdModifier::Control, false) | (KbdModifier::Control, true) => {
            ("Ctrl", "+")
        }
        (KbdModifier::Alt, true) => ("⌥", ""),
        (KbdModifier::Alt, false) => ("Alt", "+"),
        (KbdModifier::Shift, true) => ("⇧", ""),
        (KbdModifier::Shift, false) => ("Shift", "+"),
    }
}

fn validated_character(character: char) -> char {
    assert!(
        character.is_ascii_alphanumeric(),
        "Kbd character must be ASCII alphanumeric"
    );
    character.to_ascii_uppercase()
}

fn is_apple_platform() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::window().is_some_and(|window| {
            let platform = window
                .navigator()
                .platform()
                .unwrap_or_default()
                .to_ascii_lowercase();
            ["mac", "iphone", "ipad", "ipod"]
                .iter()
                .any(|needle| platform.contains(needle))
        })
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        cfg!(target_os = "macos")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "ASCII alphanumeric")]
    fn arbitrary_punctuation_cannot_bypass_the_closed_special_keys() {
        let _ = validated_character('?');
    }

    #[test]
    fn ordinary_character_is_normalized_once() {
        assert_eq!(validated_character('k'), 'K');
        assert_eq!(modifier_visible(KbdModifier::Primary, true), ("⌘", ""));
        assert_eq!(modifier_visible(KbdModifier::Primary, false), ("Ctrl", "+"));
        assert_eq!(modifier_visible(KbdModifier::Alt, true), ("⌥", ""));
        assert_eq!(modifier_visible(KbdModifier::Shift, false), ("Shift", "+"));
    }
}
