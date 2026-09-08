//! Safe durable-conversation projection for compiled components.

use leptos::prelude::*;
use openbot_contracts::components::*;
use openbot_contracts::ids::BotId;
use openbot_contracts::sandboxed::is_sandboxed_component_name;
use serde_json::{Map, Value};

use crate::i18n::{t_string, use_i18n};

use super::*;

/// Render one durable ordinary component call, or the shared refusal surface.
#[component]
pub fn ConversationComponent(
    name: String,
    arguments: Value,
    result: Option<String>,
    error_code: Option<String>,
    agent_id: BotId,
    on_ask: UnsyncCallback<(BotId, String)>,
    ask_disabled: Signal<bool>,
) -> AnyView {
    let i18n = use_i18n();
    if is_sandboxed_component_name(&name) {
        return view! {
            <SandboxedConversationComponent name arguments result error_code />
        }
        .into_any();
    }
    let title = compiled_component_title(&name)
        .unwrap_or("Component")
        .to_owned();
    if is_component_human_decision_name(&name) {
        let recorded = result
            .as_deref()
            .and_then(|result| serde_json::from_str::<ComponentHumanDecisionAnswer>(result).ok());
        if error_code.is_some()
            || validate_component_human_decision_arguments(&name, &arguments).is_err()
            || recorded.as_ref().is_none_or(|answer| {
                validate_component_human_decision_answer(&name, &arguments, answer).is_err()
            })
        {
            return view! {
                <RefusedCard
                    title
                    reason=t_string!(i18n, gallery.runtime_refused).to_owned()
                />
            }
            .into_any();
        }
        let recorded = recorded.expect("recorded decision was checked above");
        return view! {
            <HumanDecisionCard
                name
                arguments
                answer=Signal::derive(move || Some(recorded.clone()))
                submitting=Signal::derive(|| false)
                error=Signal::derive(|| false)
            />
        }
        .into_any();
    }
    if error_code.is_some() || validate_compiled_component_arguments(&name, &arguments).is_err() {
        return view! {
            <RefusedCard
                title
                reason=t_string!(i18n, gallery.runtime_refused).to_owned()
            />
        }
        .into_any();
    }
    let object = arguments
        .as_object()
        .expect("validated component arguments are an object");
    match name.as_str() {
        SHOW_ACTIVITY_REPORT_COMPONENT_NAME => {
            let follow_up_agent = agent_id.clone();
            let follow_up = UnsyncCallback::new(move |message: String| {
                on_ask.run((follow_up_agent.clone(), message));
            });
            view! {
                <ActivityReportCard
                    agent_id
                    report=if string(object, "report") == "activity" {
                        ActivityReportKind::Activity
                    } else {
                        ActivityReportKind::Refusals
                    }
                    title=optional_string(object, "title")
                    days=object.get("days").and_then(Value::as_f64)
                    on_ask=follow_up
                    ask_disabled
                />
            }
            .into_any()
        }
        SHOW_QUOTE_COMPONENT_NAME => view! {
            <QuoteCard
                quote=string(object, "quote")
                attribution=string(object, "attribution")
                context=optional_string(object, "context").unwrap_or_default()
            />
        }
        .into_any(),
        SHOW_RECORD_COMPONENT_NAME => view! {
            <RecordCard
                title=string(object, "title")
                subtitle=optional_string(object, "subtitle")
                status=optional_string(object, "status")
                status_tone=tone(object, "statusTone")
                fields={objects(object, "fields")
                    .map(|field| RecordField {
                        label: string(field, "label"),
                        value: string(field, "value"),
                    })
                    .collect::<Vec<_>>()}
            />
        }
        .into_any(),
        SHOW_METRICS_COMPONENT_NAME => view! {
            <MetricsCard
                title=string(object, "title")
                caption=optional_string(object, "caption")
                metrics={objects(object, "metrics")
                    .map(|metric| HeadlineMetric {
                        label: string(metric, "label"),
                        value: string(metric, "value"),
                        change: optional_string(metric, "change"),
                        change_tone: tone(metric, "changeTone"),
                    })
                    .collect::<Vec<_>>()}
            />
        }
        .into_any(),
        SHOW_CHECKLIST_COMPONENT_NAME => view! {
            <ChecklistCard
                title=string(object, "title")
                caption=optional_string(object, "caption")
                items={objects(object, "items")
                    .map(|item| ChecklistItem {
                        text: string(item, "text"),
                        done: item.get("done").and_then(Value::as_bool).unwrap_or(false),
                        note: optional_string(item, "note"),
                    })
                    .collect::<Vec<_>>()}
            />
        }
        .into_any(),
        SHOW_NOTICE_COMPONENT_NAME => view! {
            <NoticeCard
                title=string(object, "title")
                body=string(object, "body")
                tone=tone(object, "tone")
                points=strings(object, "points")
            />
        }
        .into_any(),
        SHOW_BAR_CHART_COMPONENT_NAME => view! {
            <BarChartCard
                title=string(object, "title")
                caption=optional_string(object, "caption")
                points=chart_points(object, false)
            />
        }
        .into_any(),
        SHOW_PIE_CHART_COMPONENT_NAME => view! {
            <PieChartCard
                title=string(object, "title")
                caption=optional_string(object, "caption")
                points=chart_points(object, false)
            />
        }
        .into_any(),
        SHOW_PROGRESS_COMPONENT_NAME => view! {
            <ProgressChartCard
                title=string(object, "title")
                caption=optional_string(object, "caption")
                points={objects(object, "points")
                    .map(|point| ProgressPoint {
                        label: string(point, "label"),
                        value: number(point, "value"),
                        target: number(point, "target"),
                    })
                    .collect::<Vec<_>>()}
            />
        }
        .into_any(),
        SHOW_LINE_CHART_COMPONENT_NAME => view! {
            <LineChartCard
                title=string(object, "title")
                caption=optional_string(object, "caption")
                labels=strings(object, "labels")
                series=chart_series(object)
            />
        }
        .into_any(),
        SHOW_AREA_CHART_COMPONENT_NAME => view! {
            <AreaChartCard
                title=string(object, "title")
                caption=optional_string(object, "caption")
                labels=strings(object, "labels")
                series=chart_series(object)
            />
        }
        .into_any(),
        _ => view! {
            <RefusedCard title reason=t_string!(i18n, gallery.runtime_refused).to_owned() />
        }
        .into_any(),
    }
}

fn string(object: &Map<String, Value>, field: &str) -> String {
    object
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn optional_string(object: &Map<String, Value>, field: &str) -> Option<String> {
    object.get(field).and_then(Value::as_str).map(str::to_owned)
}

fn number(object: &Map<String, Value>, field: &str) -> f64 {
    object.get(field).and_then(Value::as_f64).unwrap_or(0.0)
}

fn objects<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> impl Iterator<Item = &'a Map<String, Value>> {
    object
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
}

fn strings(object: &Map<String, Value>, field: &str) -> Vec<String> {
    object
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn tone(object: &Map<String, Value>, field: &str) -> GalleryTone {
    match object.get(field).and_then(Value::as_str) {
        Some("positive") => GalleryTone::Positive,
        Some("caution") => GalleryTone::Caution,
        Some("negative") => GalleryTone::Negative,
        _ => GalleryTone::Neutral,
    }
}

fn chart_points(object: &Map<String, Value>, _target: bool) -> Vec<ChartPoint> {
    objects(object, "points")
        .map(|point| ChartPoint {
            label: string(point, "label"),
            value: number(point, "value"),
        })
        .collect()
}

fn chart_series(object: &Map<String, Value>) -> Vec<ChartSeries> {
    objects(object, "series")
        .map(|series| ChartSeries {
            name: string(series, "name"),
            values: series
                .get("values")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_f64)
                .collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn helpers_project_only_validated_closed_values() {
        let value = json!({
            "title":"Revenue",
            "points":[{"label":"Sales","value":12.5}]
        });
        validate_compiled_component_arguments(SHOW_BAR_CHART_COMPONENT_NAME, &value).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(string(object, "title"), "Revenue");
        assert_eq!(chart_points(object, false)[0].value, 12.5);
        assert_eq!(tone(object, "tone"), GalleryTone::Neutral);
    }
}
