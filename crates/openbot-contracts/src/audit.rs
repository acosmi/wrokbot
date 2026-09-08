//! 管理员审计页的跨 transport DTO。

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::ids::{ActorId, AuditEventId};

/// 审计页的一行；payload 已在写入边界按领域 allowlist 收口。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditEventView {
    /// 事件 id。
    pub id: AuditEventId,
    /// 已验证 actor；系统事件为 `None`。
    pub actor_user_id: Option<ActorId>,
    /// 固定事件类型字面量；旧库未知类型仍按原字节展示。
    pub event_type: String,
    /// 目标类别。
    pub target_type: String,
    /// 目标 id。
    pub target_id: Option<String>,
    /// 已脱敏/allowlist 化的结构化事实。
    pub payload: Value,
    /// 上游 `Date.toISOString()` 形态：UTC、三位毫秒。
    #[serde(with = "javascript_date")]
    pub created_at: OffsetDateTime,
}

/// 管理员审计 keyset 页。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditPage {
    /// 本页事件，按 `(created_at DESC, id DESC)`。
    pub events: Vec<AuditEventView>,
    /// 下一页 opaque cursor；末页按固定上游 wire 省略该键。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

mod javascript_date {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::format_description::well_known::Rfc3339;
    use time::macros::format_description;
    use time::{OffsetDateTime, UtcOffset};

    const MILLISECOND_UTC: &[time::format_description::FormatItem<'static>] =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");

    pub(super) fn serialize<S>(value: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(
            &value
                .to_offset(UtcOffset::UTC)
                .format(MILLISECOND_UTC)
                .map_err(serde::ser::Error::custom)?,
        )
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        OffsetDateTime::parse(&raw, &Rfc3339).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn audit_page_wire_matches_the_fixed_upstream_shape() {
        let page = AuditPage {
            events: vec![AuditEventView {
                id: AuditEventId::new("event-1"),
                actor_user_id: Some(ActorId::new("admin")),
                event_type: "connector.sync_succeeded".to_owned(),
                target_type: "connector".to_owned(),
                target_id: Some("drive-1".to_owned()),
                payload: serde_json::json!({"itemCount": 3}),
                created_at: datetime!(2026-08-13 12:00:00.123456 UTC),
            }],
            next_cursor: Some("next-page".to_owned()),
        };
        let value = serde_json::to_value(&page).unwrap();
        assert_eq!(value["events"][0]["actorUserId"], "admin");
        assert_eq!(value["events"][0]["createdAt"], "2026-08-13T12:00:00.123Z");
        assert_eq!(value["nextCursor"], "next-page");

        let end = serde_json::to_value(AuditPage::default()).unwrap();
        assert_eq!(end["events"], serde_json::json!([]));
        assert!(end.get("nextCursor").is_none());
    }
}
