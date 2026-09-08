//! Deterministic same-origin avatar or initials fallback.

use leptos::prelude::*;
use sha2::{Digest, Sha256};

/// Avatar diameter from the first-source 24/32/40px set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AvatarSize {
    /// 24px compact roster avatar.
    Small,
    /// 32px default avatar.
    #[default]
    Medium,
    /// 40px profile/transcript avatar.
    Large,
}

impl AvatarSize {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Small => "sm",
            Self::Medium => "md",
            Self::Large => "lg",
        }
    }
}

/// Stable principal avatar. Remote image URLs are constructively rejected.
#[component]
pub fn Avatar(
    #[prop(into)] principal_id: String,
    #[prop(into)] name: TextProp,
    #[prop(optional, into)] image_src: Option<String>,
    #[prop(optional)] size: AvatarSize,
) -> impl IntoView {
    assert!(!name.get().is_empty(), "Avatar name must be nonempty");
    assert!(
        !principal_id.is_empty()
            && principal_id.len() <= 256
            && !principal_id.as_bytes().contains(&0),
        "Avatar principal_id must be bounded and nonempty"
    );
    if let Some(source) = &image_src {
        assert_same_origin_image(source);
    }
    let palette = palette_index(&principal_id).to_string();
    let fallback_name = name.clone();
    let image = image_src
        .map(|source| view! { <img class="ob-avatar-image" src=source alt="" /> }.into_any());
    view! {
        <span
            class="ob-avatar"
            role="img"
            aria-label=move || name.get()
            data-size=size.as_str()
            data-palette=palette
        >
            {image.unwrap_or_else(|| view! {
                <span class="ob-avatar-initials" aria-hidden="true">
                    {move || initials(&fallback_name.get())}
                </span>
            }.into_any())}
        </span>
    }
}

fn palette_index(principal_id: &str) -> u8 {
    let digest = Sha256::digest(principal_id.as_bytes());
    let prefix = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    u8::try_from(prefix % 8).expect("modulo eight fits u8")
}

fn initials(name: &str) -> String {
    let trimmed = name.trim();
    let Some(first) = trimmed.chars().next() else {
        return "?".to_owned();
    };
    if is_cjk(first) {
        return first.to_string();
    }
    let words = trimmed.split_whitespace().collect::<Vec<_>>();
    let mut output = String::new();
    if let Some(character) = words.first().and_then(|word| word.chars().next()) {
        output.extend(character.to_uppercase());
    }
    if words.len() > 1
        && let Some(character) = words.last().and_then(|word| word.chars().next())
    {
        output.extend(character.to_uppercase());
    }
    if output.is_empty() {
        "?".to_owned()
    } else {
        output
    }
}

fn is_cjk(character: char) -> bool {
    matches!(
        character as u32,
        0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF | 0x20000..=0x2FA1F
    )
}

fn assert_same_origin_image(source: &str) {
    assert!(
        source.starts_with('/')
            && !source.starts_with("//")
            && source.len() <= 2048
            && !source
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b'\\'),
        "Avatar image must be one bounded same-origin absolute path"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initials_palette_and_image_boundary_are_deterministic() {
        assert_eq!(initials("Ada Lovelace"), "AL");
        assert_eq!(initials("  张 三  "), "张");
        assert_eq!(initials("OpenBot"), "O");
        assert_eq!(palette_index("principal-1"), palette_index("principal-1"));
        assert!(palette_index("principal-1") < 8);
        assert_same_origin_image("/attachments/avatar.png");
    }

    #[test]
    #[should_panic(expected = "same-origin")]
    fn remote_avatar_images_are_rejected() {
        assert_same_origin_image("https://attacker.example/avatar.png");
    }
}
