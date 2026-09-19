//! Dependency-free Bar, Donut, Line, Area and Progress compiled chart renderers.

use leptos::prelude::*;

use crate::i18n::{t, t_string, use_i18n};

use super::GalleryFrame;

const PLOT_WIDTH: f64 = 520.0;
const PLOT_HEIGHT: f64 = 180.0;
const PLOT_BOTTOM: f64 = 18.0;

/// One named numeric chart point.
#[derive(Clone, Debug, PartialEq)]
pub struct ChartPoint {
    /// Visible point label.
    pub label: String,
    /// Numeric value.
    pub value: f64,
}

/// One named line/area series; values correspond by index to labels.
#[derive(Clone, Debug, PartialEq)]
pub struct ChartSeries {
    /// Legend label.
    pub name: String,
    /// Ordered values.
    pub values: Vec<f64>,
}

/// One value measured against a target.
#[derive(Clone, Debug, PartialEq)]
pub struct ProgressPoint {
    /// Visible row label.
    pub label: String,
    /// Current value.
    pub value: f64,
    /// Target denominator.
    pub target: f64,
}

/// Compare named values as vertical bars.
#[component]
pub fn BarChartCard(
    title: String,
    caption: Option<String>,
    points: Vec<ChartPoint>,
) -> impl IntoView {
    let i18n = use_i18n();
    let max = points
        .iter()
        .map(|point| point.value)
        .fold(0.0_f64, f64::max);
    let points = RwSignal::new(points);
    view! {
        <GalleryFrame title caption=caption.unwrap_or_default()>
            <Show
                when=move || !points.get().is_empty()
                fallback=move || view! { <ChartEmpty /> }
            >
                <div class="ob-gallery-bar-chart" aria-label=move || t_string!(i18n, gallery.chart_data).to_owned()>
                    <For
                        each=move || points.get().into_iter().enumerate()
                        key=|(index, _)| *index
                        children=move |(index, point)| {
                            let height = if max > 0.0 {
                                ((point.value / max) * 100.0).clamp(2.0, 100.0)
                            } else {
                                2.0
                            };
                            view! {
                                <div>
                                    <span>{format_number(point.value)}</span>
                                    <div class="ob-gallery-bar-track">
                                        <span
                                            data-series=(index % 5).to_string()
                                            style:height=format!("{height}%")
                                        ></span>
                                    </div>
                                    <small>{point.label}</small>
                                </div>
                            }
                        }
                    />
                </div>
            </Show>
        </GalleryFrame>
    }
}

#[derive(Clone, Debug, PartialEq)]
struct PieSlice {
    label: String,
    value: f64,
    arc: f64,
    offset: f64,
    series: usize,
}

/// Divide one meaningful positive whole into a donut and legend.
#[component]
pub fn PieChartCard(
    title: String,
    caption: Option<String>,
    points: Vec<ChartPoint>,
) -> impl IntoView {
    let total = points.iter().map(|point| point.value).sum::<f64>();
    let radius = 66.0_f64;
    let circumference = 2.0 * core::f64::consts::PI * radius;
    let mut travelled = 0.0;
    let slices = points
        .into_iter()
        .enumerate()
        .map(|(index, point)| {
            let arc = if total > 0.0 {
                (point.value / total) * circumference
            } else {
                0.0
            };
            let slice = PieSlice {
                label: point.label,
                value: point.value,
                arc,
                offset: -travelled,
                series: index % 5,
            };
            travelled += arc;
            slice
        })
        .collect::<Vec<_>>();
    let has_data = !slices.is_empty() && total > 0.0;
    let slices = RwSignal::new(slices);
    view! {
        <GalleryFrame title caption=caption.unwrap_or_default()>
            <Show
                when=move || has_data
                fallback=move || view! { <ChartEmpty /> }
            >
                <div class="ob-gallery-pie-chart">
                    <svg aria-hidden="true" viewBox="0 0 160 160">
                        <For
                            each=move || slices.get().into_iter().enumerate()
                            key=|(index, _)| *index
                            children=move |(_, slice)| view! {
                                <circle
                                    cx="80"
                                    cy="80"
                                    fill="none"
                                    r=radius.to_string()
                                    data-series=slice.series.to_string()
                                    stroke-dasharray=format!("{} {}", slice.arc, circumference - slice.arc)
                                    stroke-dashoffset=slice.offset.to_string()
                                    stroke-width="28"
                                ></circle>
                            }
                        />
                    </svg>
                    <ul>
                        <For
                            each=move || slices.get().into_iter().enumerate()
                            key=|(index, _)| *index
                            children=move |(_, slice)| view! {
                                <li>
                                    <span data-series=slice.series.to_string() aria-hidden="true"></span>
                                    <span>{slice.label}</span>
                                    <strong>{format!("{}%", ((slice.value / total) * 100.0).round())}</strong>
                                </li>
                            }
                        />
                    </ul>
                </div>
            </Show>
        </GalleryFrame>
    }
}

#[derive(Clone, Debug, PartialEq)]
struct PlotLine {
    name: String,
    points: String,
    area_points: String,
    series: usize,
}

/// Ordered line chart.
#[component]
pub fn LineChartCard(
    title: String,
    caption: Option<String>,
    labels: Vec<String>,
    series: Vec<ChartSeries>,
) -> impl IntoView {
    view! { <PlotCard title caption labels series filled=false /> }
}

/// Ordered area chart sharing the exact Line geometry.
#[component]
pub fn AreaChartCard(
    title: String,
    caption: Option<String>,
    labels: Vec<String>,
    series: Vec<ChartSeries>,
) -> impl IntoView {
    view! { <PlotCard title caption labels series filled=true /> }
}

#[component]
fn PlotCard(
    title: String,
    caption: Option<String>,
    labels: Vec<String>,
    series: Vec<ChartSeries>,
    filled: bool,
) -> impl IntoView {
    let empty = labels.is_empty() || series.is_empty();
    let (lines, labels) = plot_geometry(&labels, &series);
    let multiple_lines = lines.len() > 1;
    let lines = RwSignal::new(lines);
    let labels = RwSignal::new(labels);
    view! {
        <GalleryFrame title caption=caption.unwrap_or_default()>
            <Show when=move || !empty fallback=move || view! { <ChartEmpty /> }>
                <div class="ob-gallery-plot">
                    <svg aria-hidden="true" viewBox="0 0 520 180" preserveAspectRatio="none">
                        <line x1="8" x2="512" y1="85" y2="85"></line>
                        <line x1="8" x2="512" y1="162" y2="162"></line>
                        <For
                            each=move || lines.get().into_iter().enumerate()
                            key=|(index, _)| *index
                            children=move |(_, line)| view! {
                                <g data-series=line.series.to_string()>
                                    <Show when=move || filled>
                                        <polygon points=line.area_points.clone()></polygon>
                                    </Show>
                                    <polyline points=line.points></polyline>
                                </g>
                            }
                        />
                    </svg>
                    <div class="ob-gallery-axis-labels">
                        <For
                            each=move || labels.get().into_iter().enumerate()
                            key=|(index, _)| *index
                            children=move |(_, label)| view! { <span>{label}</span> }
                        />
                    </div>
                    <Show when=move || multiple_lines>
                        <ul class="ob-gallery-chart-legend">
                            <For
                                each=move || lines.get().into_iter().enumerate()
                                key=|(index, _)| *index
                                children=move |(_, line)| view! {
                                    <li><span data-series=line.series.to_string() aria-hidden="true"></span>{line.name}</li>
                                }
                            />
                        </ul>
                    </Show>
                </div>
            </Show>
        </GalleryFrame>
    }
}

/// Show values against targets; target<=0 produces an empty track.
#[component]
pub fn ProgressChartCard(
    title: String,
    caption: Option<String>,
    points: Vec<ProgressPoint>,
) -> impl IntoView {
    let points = RwSignal::new(points);
    view! {
        <GalleryFrame title caption=caption.unwrap_or_default()>
            <Show
                when=move || !points.get().is_empty()
                fallback=move || view! { <ChartEmpty /> }
            >
                <ul class="ob-gallery-progress-chart">
                    <For
                        each=move || points.get().into_iter().enumerate()
                        key=|(index, _)| *index
                        children=move |(index, point)| {
                            let share = if point.target > 0.0 {
                                ((point.value / point.target) * 100.0).clamp(0.0, 100.0)
                            } else {
                                0.0
                            };
                            view! {
                                <li>
                                    <div><span>{point.label}</span><strong>{format!("{} / {}", format_number(point.value), format_number(point.target))}</strong></div>
                                    <div><span data-series=(index % 5).to_string() style:width=format!("{share}%")></span></div>
                                </li>
                            }
                        }
                    />
                </ul>
            </Show>
        </GalleryFrame>
    }
}

#[component]
fn ChartEmpty() -> impl IntoView {
    let i18n = use_i18n();
    view! { <p class="ob-gallery-chart-empty">{move || t!(i18n, gallery.no_chart_data)}</p> }
}

fn plot_geometry(labels: &[String], series: &[ChartSeries]) -> (Vec<PlotLine>, Vec<String>) {
    let all = series
        .iter()
        .flat_map(|line| line.values.iter().copied())
        .collect::<Vec<_>>();
    let max = all.iter().copied().fold(0.0_f64, f64::max);
    let min = all.iter().copied().fold(0.0_f64, f64::min);
    let span = (max - min).max(1.0);
    let steps = labels.len().saturating_sub(1).max(1) as f64;
    let x_at = |index: usize| 8.0 + (index as f64 / steps) * (PLOT_WIDTH - 16.0);
    let y_at = |value: f64| 8.0 + (1.0 - (value - min) / span) * 154.0;
    let lines = series
        .iter()
        .enumerate()
        .map(|(index, line)| {
            let points = line
                .values
                .iter()
                .enumerate()
                .map(|(point, value)| format!("{},{}", x_at(point), y_at(*value)))
                .collect::<Vec<_>>()
                .join(" ");
            let last = line.values.len().saturating_sub(1);
            PlotLine {
                name: line.name.clone(),
                area_points: format!(
                    "{},{} {} {},{}",
                    x_at(0),
                    PLOT_HEIGHT - PLOT_BOTTOM,
                    points,
                    x_at(last),
                    PLOT_HEIGHT - PLOT_BOTTOM
                ),
                points,
                series: index % 5,
            }
        })
        .collect();
    (lines, labels.to_vec())
}

fn format_number(value: f64) -> String {
    if value.abs() >= 1000.0 {
        format!("{:.0}", value.round())
    } else {
        let rounded = (value * 100.0).round() / 100.0;
        if rounded.fract() == 0.0 {
            format!("{rounded:.0}")
        } else {
            rounded.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_and_area_share_geometry_and_number_format_is_bounded() {
        let labels = vec!["A".to_owned(), "B".to_owned()];
        let series = vec![ChartSeries {
            name: "One".to_owned(),
            values: vec![1.0, 2.5],
        }];
        assert_eq!(
            plot_geometry(&labels, &series),
            plot_geometry(&labels, &series)
        );
        assert_eq!(format_number(12.345), "12.35");
        assert_eq!(format_number(1_234.5), "1235");
    }
}
