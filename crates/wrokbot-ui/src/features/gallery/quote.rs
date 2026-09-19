//! `showQuote` compiled component renderer.

use leptos::prelude::*;

use crate::i18n::{t, t_string, use_i18n};

use super::GalleryFrame;

/// Render a quotation from plain text component arguments.
#[component]
pub fn QuoteCard(
    quote: String,
    attribution: String,
    #[prop(optional)] context: Option<String>,
) -> AnyView {
    let i18n = use_i18n();
    if quote.is_empty() {
        return view! {
            <GalleryFrame title=move || t_string!(i18n, gallery.quotation).to_owned()>
                <p class="ob-gallery-empty-copy">{move || t!(i18n, gallery.nothing_to_quote)}</p>
            </GalleryFrame>
        }
        .into_any();
    }
    let show_attribution = !attribution.is_empty();
    let quote = StoredValue::new(quote);
    let attribution = StoredValue::new(format!("— {attribution}"));
    view! {
        <GalleryFrame
            title=move || t_string!(i18n, gallery.quotation).to_owned()
            caption=context.unwrap_or_default()
        >
            <blockquote class="ob-gallery-quote">
                <p>{move || quote.get_value()}</p>
                <Show when=move || show_attribution>
                    <footer>{move || attribution.get_value()}</footer>
                </Show>
            </blockquote>
        </GalleryFrame>
    }
    .into_any()
}
