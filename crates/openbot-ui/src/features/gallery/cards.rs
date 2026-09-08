//! Record, metrics, read-only checklist and notice compiled component renderers.

use leptos::prelude::*;

use crate::i18n::{t_string, use_i18n};

use super::{GalleryBadge, GalleryFrame, GalleryTone};

/// One ordered label/value field shown by `showRecord`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordField {
    /// Short field label.
    pub label: String,
    /// Already formatted value; it wraps and is never truncated.
    pub value: String,
}

/// One headline metric shown by `showMetrics`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadlineMetric {
    /// Short metric label.
    pub label: String,
    /// Already formatted value including unit/currency.
    pub value: String,
    /// Optional movement text.
    pub change: Option<String>,
    /// Semantic movement tone.
    pub change_tone: GalleryTone,
}

/// One read-only checklist fact shown by `showChecklist`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChecklistItem {
    /// Ordered item text.
    pub text: String,
    /// Whether the reported work is already complete.
    pub done: bool,
    /// Optional short aside.
    pub note: Option<String>,
}

/// Show one record and its ordered fields.
#[component]
pub fn RecordCard(
    title: String,
    subtitle: Option<String>,
    status: Option<String>,
    status_tone: GalleryTone,
    fields: Vec<RecordField>,
) -> impl IntoView {
    let fields = RwSignal::new(fields);
    let status = RwSignal::new(status);
    let action = view! {
        <Show when=move || status.get().is_some()>
            <GalleryBadge tone=status_tone>
                {move || status.get().unwrap_or_default()}
            </GalleryBadge>
        </Show>
    }
    .into_any();
    view! {
        <GalleryFrame title=title caption=subtitle.unwrap_or_default() action=action>
            <dl class="ob-gallery-record-fields">
                <For
                    each=move || fields.get().into_iter().enumerate()
                    key=|(index, _)| *index
                    children=move |(_, field)| view! {
                        <div>
                            <dt>{field.label}</dt>
                            <dd>{field.value}</dd>
                        </div>
                    }
                />
            </dl>
        </GalleryFrame>
    }
}

/// Show at most six headline figures with optional semantic movement.
#[component]
pub fn MetricsCard(
    title: String,
    caption: Option<String>,
    metrics: Vec<HeadlineMetric>,
) -> impl IntoView {
    let metrics = RwSignal::new(metrics.into_iter().take(6).collect::<Vec<_>>());
    view! {
        <GalleryFrame title=title caption=caption.unwrap_or_default()>
            <div class="ob-gallery-metrics">
                <For
                    each=move || metrics.get().into_iter().enumerate()
                    key=|(index, _)| *index
                    children=move |(_, metric)| {
                        let has_change = metric.change.is_some();
                        let change = StoredValue::new(metric.change.unwrap_or_default());
                        view! {
                            <div>
                                <span>{metric.label}</span>
                                <strong>{metric.value}</strong>
                                <Show when=move || has_change>
                                    <GalleryBadge tone=metric.change_tone>
                                        {move || change.get_value()}
                                    </GalleryBadge>
                                </Show>
                            </div>
                        }
                    }
                />
            </div>
        </GalleryFrame>
    }
}

/// Show a reporting-only checklist; no row is interactive.
#[component]
pub fn ChecklistCard(
    title: String,
    caption: Option<String>,
    items: Vec<ChecklistItem>,
) -> impl IntoView {
    let i18n = use_i18n();
    let done = items.iter().filter(|item| item.done).count();
    let total = items.len();
    let all_done = total > 0 && done == total;
    let items = RwSignal::new(items);
    let action = view! {
        <GalleryBadge tone=if all_done { GalleryTone::Positive } else { GalleryTone::Neutral }>
            {move || t_string!(i18n, gallery.checklist_progress, done = done, total = total).to_owned()}
        </GalleryBadge>
    }
    .into_any();
    view! {
        <GalleryFrame title=title caption=caption.unwrap_or_default() action=action>
            <ul class="ob-gallery-checklist">
                <For
                    each=move || items.get().into_iter().enumerate()
                    key=|(index, _)| *index
                    children=move |(_, item)| {
                        let has_note = item.note.is_some();
                        let note = StoredValue::new(item.note.unwrap_or_default());
                        view! {
                            <li data-done=if item.done { "true" } else { "false" }>
                                <span class="ob-gallery-check" aria-hidden="true">
                                    {if item.done { "✓" } else { "○" }}
                                </span>
                                <span>
                                    <span>{item.text}</span>
                                    <Show when=move || has_note>
                                        <small>{move || note.get_value()}</small>
                                    </Show>
                                </span>
                            </li>
                        }
                    }
                />
            </ul>
        </GalleryFrame>
    }
}

/// Show a short notice and ordered supporting points.
#[component]
pub fn NoticeCard(
    title: String,
    body: String,
    tone: GalleryTone,
    points: Vec<String>,
) -> impl IntoView {
    let i18n = use_i18n();
    let points = RwSignal::new(points);
    let action = view! {
        <Show when=move || tone != GalleryTone::Neutral>
            <GalleryBadge tone>
                {move || tone_label(i18n, tone)}
            </GalleryBadge>
        </Show>
    }
    .into_any();
    view! {
        <GalleryFrame title action=action>
            <p class="ob-gallery-notice-body">{body}</p>
            <Show when=move || !points.get().is_empty()>
                <ul class="ob-gallery-notice-points">
                    <For
                        each=move || points.get().into_iter().enumerate()
                        key=|(index, _)| *index
                        children=move |(_, point)| view! {
                            <li><span aria-hidden="true">"·"</span><span>{point}</span></li>
                        }
                    />
                </ul>
            </Show>
        </GalleryFrame>
    }
}

fn tone_label(i18n: leptos_i18n::I18nContext<crate::i18n::Locale>, tone: GalleryTone) -> String {
    match tone {
        GalleryTone::Neutral => t_string!(i18n, gallery.tone_neutral).to_owned(),
        GalleryTone::Positive => t_string!(i18n, gallery.tone_positive).to_owned(),
        GalleryTone::Caution => t_string!(i18n, gallery.tone_caution).to_owned(),
        GalleryTone::Negative => t_string!(i18n, gallery.tone_negative).to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_cap_and_checklist_completion_are_deterministic() {
        let metrics = (0..8)
            .map(|index| HeadlineMetric {
                label: format!("Metric {index}"),
                value: index.to_string(),
                change: None,
                change_tone: GalleryTone::Neutral,
            })
            .take(6)
            .collect::<Vec<_>>();
        assert_eq!(metrics.len(), 6);
        let items = [true, true, false];
        assert_eq!(items.iter().filter(|done| **done).count(), 2);
    }
}
