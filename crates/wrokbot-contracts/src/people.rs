//! Auth / admin people DTO（上游 `/api/me` 与 `/api/admin/people*` parity 面）。

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::auth::Role;
use crate::ids::ActorId;

/// `/api/me` 的已验证用户投影；不是可反序列化成权限的 [`crate::auth::AuthContext`]。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CurrentUser {
    /// 用户 id。
    pub id: ActorId,
    /// 规范化 email。
    pub email: String,
    /// 展示名。
    pub name: Option<String>,
    /// 头像 URL/标识。
    pub image: Option<String>,
    /// 当前有效角色；admin 优先。
    pub role: Role,
}

/// Exact `/api/me` response envelope shared by Server and GUI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentUserResponse {
    /// Verified public user projection.
    pub user: CurrentUser,
}

/// 管理员 people 页的一行。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Person {
    /// 用户 id。
    pub id: ActorId,
    /// 规范化 email。
    pub email: String,
    /// 展示名。
    pub name: Option<String>,
    /// 头像。
    pub image: Option<String>,
    /// admin 优先的有效角色。
    pub role: Role,
    /// 该地址曾通过的 provider id，稳定排序。
    pub providers: Vec<String>,
    /// 最近 session 创建时刻；从未登录为 `None`。
    #[serde(with = "javascript_date_option")]
    pub last_signed_in_at: Option<OffsetDateTime>,
    /// 是否在 deny 名单。
    pub revoked: bool,
    /// 是否被 `INITIAL_ADMIN_EMAILS` floor 固定为 admin。
    pub configured_admin: bool,
}

/// people keyset 页。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PeoplePage {
    /// 本页人员。
    pub people: Vec<Person>,
    /// 下一页 opaque cursor。
    pub next_cursor: Option<String>,
}

/// Administrator role mutation body. Identity and actor binding never come from this payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangePersonRole {
    /// Requested effective role.
    pub role: Role,
}

/// Administrator access mutation body. Identity and actor binding never come from this payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangePersonAccess {
    /// `true` removes access; `false` restores it.
    pub revoked: bool,
}

/// Exact response envelope shared by Server and GUI for person mutations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonResponse {
    /// Authoritative row after the committed mutation.
    pub person: Person,
}

/// `/api/admin/status` 的封闭状态。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminState {
    /// 当前 actor 已通过 admin gate。
    Ok,
}

/// 管理员状态应答。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminStatus {
    /// 固定 `ok`。
    pub status: AdminState,
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn people_wire_uses_upstream_camel_case_keys_and_empty_page_is_not_null() {
        let page = PeoplePage::default();
        assert_eq!(
            serde_json::to_string(&page).unwrap(),
            r#"{"people":[],"nextCursor":null}"#,
        );
        let status = serde_json::to_string(&AdminStatus {
            status: AdminState::Ok,
        })
        .unwrap();
        assert_eq!(status, r#"{"status":"ok"}"#);
    }

    #[test]
    fn current_user_response_keeps_the_exact_user_envelope() {
        let response = CurrentUserResponse {
            user: CurrentUser {
                id: ActorId::new("user-1"),
                email: "user@example.test".to_owned(),
                name: Some("User".to_owned()),
                image: None,
                role: Role::User,
            },
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(
            json,
            r#"{"user":{"id":"user-1","email":"user@example.test","name":"User","image":null,"role":"user"}}"#
        );
        assert_eq!(
            serde_json::from_str::<CurrentUserResponse>(&json).unwrap(),
            response
        );
    }

    #[test]
    fn person_wire_does_not_expose_internal_auth_generation() {
        let person = Person {
            id: ActorId::new("user-1"),
            email: "user@example.com".to_owned(),
            name: None,
            image: None,
            role: Role::User,
            providers: vec!["oidc".to_owned()],
            last_signed_in_at: None,
            revoked: false,
            configured_admin: false,
        };
        assert_eq!(
            serde_json::to_string(&person).unwrap(),
            r#"{"id":"user-1","email":"user@example.com","name":null,"image":null,"role":"user","providers":["oidc"],"lastSignedInAt":null,"revoked":false,"configuredAdmin":false}"#,
        );
        assert_eq!(
            serde_json::to_string(&ChangePersonRole { role: Role::Admin }).unwrap(),
            r#"{"role":"admin"}"#,
        );
        assert_eq!(
            serde_json::to_string(&ChangePersonAccess { revoked: true }).unwrap(),
            r#"{"revoked":true}"#,
        );
        let response = PersonResponse {
            person: person.clone(),
        };
        assert_eq!(
            serde_json::from_str::<PersonResponse>(&serde_json::to_string(&response).unwrap())
                .unwrap(),
            response,
        );
    }

    #[test]
    fn person_timestamp_matches_javascript_date_to_iso_string_milliseconds() {
        let person = Person {
            id: ActorId::new("user-1"),
            email: "user@example.com".to_owned(),
            name: None,
            image: None,
            role: Role::User,
            providers: Vec::new(),
            last_signed_in_at: Some(datetime!(2026-08-23 01:02:03.123456 UTC)),
            revoked: false,
            configured_admin: false,
        };
        let json = serde_json::to_string(&person).unwrap();
        assert!(
            json.contains(r#""lastSignedInAt":"2026-08-23T01:02:03.123Z""#),
            "上游 Date.toISOString 固定毫秒并截掉微秒：{json}",
        );
        let back: Person = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.last_signed_in_at,
            Some(datetime!(2026-08-23 01:02:03.123 UTC)),
        );
    }
}

/// PostgreSQL timestamp 经上游 JavaScript `Date.toISOString()` 后固定转 UTC、保留三位毫秒。
/// `time::serde::rfc3339` 会把整秒写成无小数、并保留微秒，二者都不是 fixed-upstream wire。
mod javascript_date_option {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::format_description::well_known::Rfc3339;
    use time::macros::format_description;
    use time::{OffsetDateTime, UtcOffset};

    const MILLISECOND_UTC: &[time::format_description::FormatItem<'static>] =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");

    pub(super) fn serialize<S>(
        value: &Option<OffsetDateTime>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) => {
                let rendered = value
                    .to_offset(UtcOffset::UTC)
                    .format(MILLISECOND_UTC)
                    .map_err(serde::ser::Error::custom)?;
                serializer.serialize_some(&rendered)
            }
            None => serializer.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Option<OffsetDateTime>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|raw| OffsetDateTime::parse(&raw, &Rfc3339).map_err(serde::de::Error::custom))
            .transpose()
    }
}
