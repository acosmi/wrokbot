//! One channel roster row with bounded same-origin navigation.

use leptos::prelude::*;
use openbot_contracts::command::ChannelSummary;
use time::OffsetDateTime;

use crate::api::channel_route_href;
use crate::i18n::{t_string, use_i18n};
use crate::primitives::{Avatar, AvatarSize};

/// Rich channel navigation row used inside the shared Sidebar children.
#[component]
pub fn ChannelRow(
    /// Authoritative roster projection.
    channel: ChannelSummary,
    /// Whether its destination is the current route.
    #[prop(into)]
    current: MaybeProp<bool>,
) -> impl IntoView {
    let i18n = use_i18n();
    let href = channel_route_href(channel.id.as_str()).expect("server channel id is route-safe");
    let avatar_principal = if channel.agent_ids.is_empty() {
        channel.id.as_str().to_owned()
    } else {
        channel
            .agent_ids
            .iter()
            .map(|id| id.as_str())
            .collect::<Vec<_>>()
            .join("\u{001f}")
    };
    let avatar_name = channel.name.clone();
    let visible_name = channel.name;
    let last_message = channel.last_message.unwrap_or_default();
    let timestamp = channel.last_message_at.map(|at| {
        (
            at.to_string(),
            localized_relative_time(i18n, current_time(), at),
        )
    });
    let description = format!("{visible_name} — {last_message}");
    view! {
        <li class="ob-sidebar-list-item">
            <a
                class="ob-channel-row"
                href=href
                title=description
                aria-current=move || current.get().unwrap_or(false).then_some("page")
                data-state=move || current.get().unwrap_or(false).then_some("current")
            >
                <span class="ob-channel-avatar" aria-hidden="true">
                    <Avatar
                        principal_id=avatar_principal
                        name=avatar_name
                        size=AvatarSize::Medium
                    />
                </span>
                <span class="ob-channel-copy">
                    <span class="ob-channel-heading">
                        <span class="ob-channel-name">{visible_name}</span>
                        {timestamp.map(|(datetime, label)| view! {
                            <time class="ob-channel-time" datetime=datetime>{label}</time>
                        })}
                    </span>
                    <span class="ob-channel-preview">{last_message}</span>
                </span>
            </a>
        </li>
    }
}

fn current_time() -> OffsetDateTime {
    #[cfg(target_arch = "wasm32")]
    {
        let nanos = (js_sys::Date::now() * 1_000_000.0) as i128;
        OffsetDateTime::from_unix_timestamp_nanos(nanos).unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        OffsetDateTime::now_utc()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelativeAge {
    JustNow,
    Minutes(i64),
    Hours(i64),
    Days(i64),
    Weeks(i64),
}

fn relative_age(now: OffsetDateTime, at: OffsetDateTime) -> RelativeAge {
    let elapsed = (now - at).whole_seconds().max(0);
    match elapsed {
        0..=59 => RelativeAge::JustNow,
        60..=3_599 => RelativeAge::Minutes((elapsed + 30) / 60),
        3_600..=86_399 => RelativeAge::Hours((elapsed + 1_800) / 3_600),
        86_400..=604_799 => RelativeAge::Days((elapsed + 43_200) / 86_400),
        _ => RelativeAge::Weeks((elapsed + 302_400) / 604_800),
    }
}

fn localized_relative_time(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    now: OffsetDateTime,
    at: OffsetDateTime,
) -> String {
    match relative_age(now, at) {
        RelativeAge::JustNow => t_string!(i18n, common.just_now).to_owned(),
        RelativeAge::Minutes(count) => {
            t_string!(i18n, channels.time_minutes_ago, count = count).to_owned()
        }
        RelativeAge::Hours(count) => {
            t_string!(i18n, channels.time_hours_ago, count = count).to_owned()
        }
        RelativeAge::Days(count) => {
            t_string!(i18n, channels.time_days_ago, count = count).to_owned()
        }
        RelativeAge::Weeks(count) => {
            t_string!(i18n, channels.time_weeks_ago, count = count).to_owned()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn relative_age_uses_closed_nonnegative_units() {
        let now = datetime!(2026-08-26 12:00 UTC);
        assert_eq!(relative_age(now, now), RelativeAge::JustNow);
        assert_eq!(
            relative_age(now, datetime!(2026-08-26 11:58 UTC)),
            RelativeAge::Minutes(2)
        );
        assert_eq!(
            relative_age(now, datetime!(2026-08-26 09:00 UTC)),
            RelativeAge::Hours(3)
        );
        assert_eq!(
            relative_age(now, datetime!(2026-08-24 12:00 UTC)),
            RelativeAge::Days(2)
        );
        assert_eq!(
            relative_age(now, datetime!(2026-08-12 12:00 UTC)),
            RelativeAge::Weeks(2)
        );
        assert_eq!(
            relative_age(now, datetime!(2026-08-27 12:00 UTC)),
            RelativeAge::JustNow
        );
    }
}
