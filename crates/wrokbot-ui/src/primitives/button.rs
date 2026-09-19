//! Accessible button primitive.

use leptos::ev::KeyboardEvent;
use leptos::prelude::*;

/// Visual button variant. Only `Primary` uses a solid inverse surface.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ButtonVariant {
    /// Neutral chip button.
    #[default]
    Chip,
    /// The page's single primary action treatment.
    Primary,
    /// Low-emphasis navigation/action.
    Ghost,
    /// Destructive intent expressed by text and icon color, never a filled red surface.
    DangerText,
}

impl ButtonVariant {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Chip => "chip",
            Self::Primary => "primary",
            Self::Ghost => "ghost",
            Self::DangerText => "danger-text",
        }
    }
}

/// Button height from the tokenized control scale.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ButtonSize {
    /// 28px control.
    Small,
    /// 32px default control.
    #[default]
    Medium,
    /// 36px control.
    Large,
}

impl ButtonSize {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Small => "sm",
            Self::Medium => "md",
            Self::Large => "lg",
        }
    }
}

/// Closed visual states used by the design gallery for CSS-only interaction snapshots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ButtonPreviewState {
    /// Force the hover treatment without a pointing device.
    Hover,
    /// Force the focus-visible treatment for a deterministic golden.
    FocusVisible,
    /// Force the active/pressed treatment.
    Active,
}

impl ButtonPreviewState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Hover => "hover",
            Self::FocusVisible => "focus-visible",
            Self::Active => "active",
        }
    }
}

/// Render a semantic `<button>` with token-only variants and explicit loading/disabled states.
#[component]
pub fn Button(
    /// Optional stable DOM ID for focus choreography.
    #[prop(optional, into)]
    id: Option<String>,
    /// Optional accessible name when visible content alone is ambiguous (for example repeated rows).
    #[prop(optional, into)]
    aria_label: Option<TextProp>,
    /// Visual treatment.
    #[prop(optional)]
    variant: ButtonVariant,
    /// Tokenized control height.
    #[prop(optional)]
    size: ButtonSize,
    /// Reactive disabled state.
    #[prop(optional, into)]
    disabled: MaybeProp<bool>,
    /// Reactive loading state; loading also disables activation.
    #[prop(optional, into)]
    loading: MaybeProp<bool>,
    /// Invalid state supplied by the owning Field/use case.
    #[prop(optional, into)]
    invalid: MaybeProp<bool>,
    /// Optional toggle selection state; when present it is mirrored to `aria-pressed`.
    #[prop(optional, into)]
    selected: MaybeProp<bool>,
    /// Optional disclosure state; when present it is mirrored to `aria-expanded`.
    #[prop(optional, into)]
    open: MaybeProp<bool>,
    /// One forced interaction state for the compile-time design gallery.
    #[prop(optional)]
    preview_state: Option<ButtonPreviewState>,
    /// Pointer or keyboard activation callback.
    #[prop(into)]
    on_activate: UnsyncCallback<()>,
    /// Visible button content.
    children: Children,
) -> impl IntoView {
    let unavailable =
        Signal::derive(move || disabled.get().unwrap_or(false) || loading.get().unwrap_or(false));
    view! {
        <button
            id=id
            aria-label=move || aria_label.as_ref().map(TextProp::get)
            type="button"
            class="ob-button"
            data-variant=variant.as_str()
            data-size=size.as_str()
            data-state=move || button_state_tokens(
                preview_state,
                unavailable.get(),
                loading.get().unwrap_or(false),
                invalid.get().unwrap_or(false),
                selected.get().unwrap_or(false),
                open.get().unwrap_or(false),
            )
            aria-busy=move || loading.get().map(explicit_bool)
            aria-invalid=move || invalid.get().map(explicit_bool)
            aria-pressed=move || selected.get().map(explicit_bool)
            aria-expanded=move || open.get().map(explicit_bool)
            disabled=move || unavailable.get()
            on:click=move |event| {
                if !unavailable.get() {
                    let _ = event;
                    on_activate.run(());
                }
            }
            on:keydown=move |event: KeyboardEvent| {
                if matches!(event.key().as_str(), "Enter" | " ") && !unavailable.get() {
                    event.prevent_default();
                    on_activate.run(());
                }
            }
        >
            {children()}
        </button>
    }
}

fn button_state_tokens(
    preview_state: Option<ButtonPreviewState>,
    disabled: bool,
    loading: bool,
    invalid: bool,
    selected: bool,
    open: bool,
) -> Option<String> {
    let mut states = Vec::with_capacity(6);
    if let Some(state) = preview_state {
        states.push(state.as_str());
    }
    if disabled {
        states.push("disabled");
    }
    if loading {
        states.push("loading");
    }
    if invalid {
        states.push("invalid");
    }
    if selected {
        states.push("selected");
    }
    if open {
        states.push("open");
    }
    (!states.is_empty()).then(|| states.join(" "))
}

const fn explicit_bool(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn button_state_tokens_are_closed_ordered_and_complete() {
        assert_eq!(
            button_state_tokens(None, false, false, false, false, false),
            None
        );
        assert_eq!(
            button_state_tokens(
                Some(ButtonPreviewState::FocusVisible),
                true,
                true,
                true,
                true,
                true,
            ),
            Some("focus-visible disabled loading invalid selected open".to_owned())
        );
        assert_eq!(explicit_bool(false), "false");
        assert_eq!(explicit_bool(true), "true");
    }
}
