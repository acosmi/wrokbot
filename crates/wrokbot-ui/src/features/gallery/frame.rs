//! Neutral compiled-component frame and closed semantic badge vocabulary.

use leptos::prelude::*;

/// Fixed semantic tone vocabulary for model-filled compiled components.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GalleryTone {
    /// No positive/negative meaning.
    #[default]
    Neutral,
    /// Successful/healthy fact.
    Positive,
    /// Caution requiring attention.
    Caution,
    /// Refusal/failure fact.
    Negative,
}

impl GalleryTone {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Neutral => "neutral",
            Self::Positive => "positive",
            Self::Caution => "caution",
            Self::Negative => "negative",
        }
    }
}

/// Shared neutral chrome around one compiled component.
#[component]
pub fn GalleryFrame(
    /// Optional component title.
    #[prop(optional, into)]
    title: TextProp,
    /// Optional one-line reason/context below the title.
    #[prop(optional, into)]
    caption: TextProp,
    /// Optional action rendered beside the title; model content never chooses its callback.
    #[prop(optional)]
    action: Option<AnyView>,
    children: Children,
) -> impl IntoView {
    let show_header = !title.get().trim().is_empty() || action.is_some();
    let visible_title = title.clone();
    let visible_caption = caption.clone();
    view! {
        <figure class="ob-gallery-frame">
            {show_header.then(|| view! {
                <figcaption class="ob-gallery-frame-caption">
                    <div class="ob-gallery-frame-copy">
                        <p hidden=move || visible_title.get().trim().is_empty()>
                            {move || title.get()}
                        </p>
                        <span hidden=move || visible_caption.get().trim().is_empty()>
                            {move || caption.get()}
                        </span>
                    </div>
                    {action}
                </figcaption>
            })}
            <div class="ob-gallery-frame-body">{children()}</div>
        </figure>
    }
}

/// Compact semantic text+dot mark; semantic color never becomes chrome/background.
#[component]
pub fn GalleryBadge(#[prop(optional)] tone: GalleryTone, children: Children) -> impl IntoView {
    view! {
        <span class="ob-gallery-badge" data-tone=tone.as_str()>
            <span aria-hidden="true"></span>
            {children()}
        </span>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_tone_vocabulary_is_closed_and_ordered() {
        assert_eq!(
            [
                GalleryTone::Neutral.as_str(),
                GalleryTone::Positive.as_str(),
                GalleryTone::Caution.as_str(),
                GalleryTone::Negative.as_str(),
            ],
            ["neutral", "positive", "caution", "negative"]
        );
    }
}
