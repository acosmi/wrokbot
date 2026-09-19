//! Inert preview registry for the compiled renderers actually present in this Rust build.

use leptos::prelude::*;
#[cfg(test)]
use openbot_contracts::components::compiled_component_manifest;
use openbot_contracts::components::{
    ASK_APPROVAL_COMPONENT_NAME, ASK_CHOICE_COMPONENT_NAME, ComponentApprovalAnswer,
    ComponentApprovalDecision, ComponentChoiceAnswer, ComponentHumanDecisionAnswer,
    SHOW_ACTIVITY_REPORT_COMPONENT_NAME, SHOW_AREA_CHART_COMPONENT_NAME,
    SHOW_BAR_CHART_COMPONENT_NAME, SHOW_CHECKLIST_COMPONENT_NAME, SHOW_LINE_CHART_COMPONENT_NAME,
    SHOW_METRICS_COMPONENT_NAME, SHOW_NOTICE_COMPONENT_NAME, SHOW_PIE_CHART_COMPONENT_NAME,
    SHOW_PROGRESS_COMPONENT_NAME, SHOW_QUOTE_COMPONENT_NAME, SHOW_RECORD_COMPONENT_NAME,
};

use crate::i18n::{t, use_i18n};

use super::{
    AreaChartCard, BarChartCard, ChartPoint, ChartSeries, ChecklistCard, ChecklistItem,
    GalleryTone, HeadlineMetric, HumanDecisionCard, LineChartCard, MetricsCard, NoticeCard,
    PieChartCard, ProgressChartCard, ProgressPoint, QuoteCard, RecordCard, RecordField,
};

const RENDERER_NAMES: [&str; 13] = [
    ASK_APPROVAL_COMPONENT_NAME,
    ASK_CHOICE_COMPONENT_NAME,
    SHOW_ACTIVITY_REPORT_COMPONENT_NAME,
    SHOW_AREA_CHART_COMPONENT_NAME,
    SHOW_BAR_CHART_COMPONENT_NAME,
    SHOW_CHECKLIST_COMPONENT_NAME,
    SHOW_LINE_CHART_COMPONENT_NAME,
    SHOW_METRICS_COMPONENT_NAME,
    SHOW_NOTICE_COMPONENT_NAME,
    SHOW_PIE_CHART_COMPONENT_NAME,
    SHOW_PROGRESS_COMPONENT_NAME,
    SHOW_QUOTE_COMPONENT_NAME,
    SHOW_RECORD_COMPONENT_NAME,
];

/// Stable names this build can actually draw.
#[must_use]
pub const fn renderer_names() -> &'static [&'static str] {
    &RENDERER_NAMES
}

/// Whether one durable catalogue row has a renderer in this exact build.
#[must_use]
pub fn component_has_renderer(name: &str) -> bool {
    renderer_names().contains(&name)
}

/// Draw one inert component sample or an honest stale-row fallback.
#[component]
pub fn ComponentPreview(name: String) -> AnyView {
    let i18n = use_i18n();
    let content = match name.as_str() {
        ASK_APPROVAL_COMPONENT_NAME => view! {
            <HumanDecisionCard
                name=ASK_APPROVAL_COMPONENT_NAME.to_owned()
                arguments=serde_json::json!({
                    "title":"Refund this order?",
                    "summary":"The customer was charged twice for the same order.",
                    "details":[
                        {"label":"Amount","value":"$128.40"},
                        {"label":"Order","value":"2043"}
                    ],
                    "approveLabel":"Refund"
                })
                answer=Signal::derive(|| Some(ComponentHumanDecisionAnswer::Approval(
                    ComponentApprovalAnswer {
                        decision: ComponentApprovalDecision::Approved,
                        note: None,
                    }
                )))
                submitting=Signal::derive(|| false)
                error=Signal::derive(|| false)
            />
        }.into_any(),
        ASK_CHOICE_COMPONENT_NAME => view! {
            <HumanDecisionCard
                name=ASK_CHOICE_COMPONENT_NAME.to_owned()
                arguments=serde_json::json!({
                    "title":"Where should this go?",
                    "summary":"Choose the destination environment.",
                    "options":[
                        {"id":"staging","label":"Staging"},
                        {"id":"production","label":"Production","description":"Live customers"}
                    ]
                })
                answer=Signal::derive(|| Some(ComponentHumanDecisionAnswer::Choice(
                    ComponentChoiceAnswer {
                        choice: "staging".to_owned(),
                        label: "Staging".to_owned(),
                    }
                )))
                submitting=Signal::derive(|| false)
                error=Signal::derive(|| false)
            />
        }.into_any(),
        SHOW_ACTIVITY_REPORT_COMPONENT_NAME => view! {
            <p class="ob-gallery-preview-unavailable">
                {move || t!(i18n, gallery.preview_unavailable)}
            </p>
        }
        .into_any(),
        SHOW_AREA_CHART_COMPONENT_NAME => view! {
            <AreaChartCard
                title="Storage used".to_owned()
                caption=Some("Growing steadily since the migration.".to_owned())
                labels=vec!["Jan".to_owned(), "Feb".to_owned(), "Mar".to_owned(), "Apr".to_owned(), "May".to_owned()]
                series=vec![ChartSeries { name: "TB".to_owned(), values: vec![12.0, 19.0, 26.0, 31.0, 44.0] }]
            />
        }.into_any(),
        SHOW_BAR_CHART_COMPONENT_NAME => view! {
            <BarChartCard
                title="Revenue by team".to_owned()
                caption=Some("Sales leads, and Engineering is closing the gap.".to_owned())
                points=vec![
                    ChartPoint { label: "Sales".to_owned(), value: 120.0 },
                    ChartPoint { label: "Engineering".to_owned(), value: 80.0 },
                    ChartPoint { label: "Support".to_owned(), value: 45.0 },
                ]
            />
        }.into_any(),
        SHOW_CHECKLIST_COMPONENT_NAME => view! {
            <ChecklistCard
                title="Before the release".to_owned()
                caption=None
                items=vec![
                    ChecklistItem { text: "Migrations applied".to_owned(), done: true, note: None },
                    ChecklistItem { text: "Changelog written".to_owned(), done: true, note: None },
                    ChecklistItem { text: "Load test".to_owned(), done: false, note: Some("Waiting on staging".to_owned()) },
                ]
            />
        }
        .into_any(),
        SHOW_LINE_CHART_COMPONENT_NAME => view! {
            <LineChartCard
                title="Signups".to_owned()
                caption=Some("Six weeks, one release.".to_owned())
                labels=vec!["W1".to_owned(), "W2".to_owned(), "W3".to_owned(), "W4".to_owned(), "W5".to_owned(), "W6".to_owned()]
                series=vec![ChartSeries { name: "Signups".to_owned(), values: vec![120.0, 180.0, 160.0, 240.0, 300.0, 420.0] }]
            />
        }.into_any(),
        SHOW_METRICS_COMPONENT_NAME => view! {
            <MetricsCard
                title="This month".to_owned()
                caption=None
                metrics=vec![
                    HeadlineMetric { label: "Revenue".to_owned(), value: "$412k".to_owned(), change: Some("+12% on last month".to_owned()), change_tone: GalleryTone::Positive },
                    HeadlineMetric { label: "Open deals".to_owned(), value: "38".to_owned(), change: None, change_tone: GalleryTone::Neutral },
                    HeadlineMetric { label: "Churn".to_owned(), value: "1.4%".to_owned(), change: Some("+0.3pt".to_owned()), change_tone: GalleryTone::Caution },
                ]
            />
        }
        .into_any(),
        SHOW_NOTICE_COMPONENT_NAME => view! {
            <NoticeCard
                title="Certificate expires in 30 days".to_owned()
                body="The checkout certificate has an owner now, and this is the first of the new alerts.".to_owned()
                tone=GalleryTone::Caution
                points=vec!["Owner: Platform".to_owned(), "Renews automatically once approved".to_owned()]
            />
        }
        .into_any(),
        SHOW_PIE_CHART_COMPONENT_NAME => view! {
            <PieChartCard
                title="Where the month went".to_owned()
                caption=None
                points=vec![
                    ChartPoint { label: "Build".to_owned(), value: 48.0 },
                    ChartPoint { label: "Support".to_owned(), value: 26.0 },
                    ChartPoint { label: "Meetings".to_owned(), value: 26.0 },
                ]
            />
        }.into_any(),
        SHOW_PROGRESS_COMPONENT_NAME => view! {
            <ProgressChartCard
                title="Migration to the new runtime".to_owned()
                caption=Some("Two services left.".to_owned())
                points=vec![
                    ProgressPoint { label: "Services moved".to_owned(), value: 18.0, target: 20.0 },
                    ProgressPoint { label: "Tests ported".to_owned(), value: 240.0, target: 240.0 },
                ]
            />
        }.into_any(),
        SHOW_QUOTE_COMPONENT_NAME => view! {
            <QuoteCard
                quote="Meals under $75 need no receipt. Anything above needs one, and anything above $500 needs your manager before you spend it.".to_owned()
                attribution="the expense policy".to_owned()
                context="Last changed in March.".to_owned()
            />
        }
        .into_any(),
        SHOW_RECORD_COMPONENT_NAME => view! {
            <RecordCard
                title="Invoice 2043".to_owned()
                subtitle=Some("Northwind Traders".to_owned())
                status=Some("Approved".to_owned())
                status_tone=GalleryTone::Neutral
                fields=vec![
                    RecordField { label: "Amount".to_owned(), value: "$4,280.00".to_owned() },
                    RecordField { label: "Raised".to_owned(), value: "12 March".to_owned() },
                    RecordField { label: "Owner".to_owned(), value: "Priya Raman".to_owned() },
                ]
            />
        }
        .into_any(),
        _ => view! {
            <p class="ob-gallery-preview-unavailable">
                {move || t!(i18n, gallery.renderer_unavailable)}
            </p>
        }
        .into_any(),
    };
    view! {
        <div class="ob-gallery-preview" aria-hidden="true">
            {content}
        </div>
    }
    .into_any()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renderer_registry_is_unique_and_exactly_matches_the_current_manifest() {
        let manifest = compiled_component_manifest();
        assert_eq!(
            renderer_names(),
            [
                ASK_APPROVAL_COMPONENT_NAME,
                ASK_CHOICE_COMPONENT_NAME,
                SHOW_ACTIVITY_REPORT_COMPONENT_NAME,
                SHOW_AREA_CHART_COMPONENT_NAME,
                SHOW_BAR_CHART_COMPONENT_NAME,
                SHOW_CHECKLIST_COMPONENT_NAME,
                SHOW_LINE_CHART_COMPONENT_NAME,
                SHOW_METRICS_COMPONENT_NAME,
                SHOW_NOTICE_COMPONENT_NAME,
                SHOW_PIE_CHART_COMPONENT_NAME,
                SHOW_PROGRESS_COMPONENT_NAME,
                SHOW_QUOTE_COMPONENT_NAME,
                SHOW_RECORD_COMPONENT_NAME,
            ]
        );
        assert_eq!(
            manifest
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            renderer_names()
        );
        assert!(component_has_renderer(SHOW_QUOTE_COMPONENT_NAME));
        assert!(!component_has_renderer("showLegacyWidget"));
    }
}
