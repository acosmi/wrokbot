//! 管理员 audit keyset 页编排。

use openbot_contracts::audit::AuditPage;
use openbot_contracts::auth::AuthContext;
use openbot_contracts::error::AppError;
use openbot_contracts::ids::ActorId;
use openbot_domain::text::trim_ecmascript;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::ports::{AuditPageRequest, AuditReader};
use crate::use_cases::people::require_admin;

/// 固定上游 audit 页默认长度。
pub const DEFAULT_AUDIT_PAGE: u32 = 50;
/// 固定上游 audit 页最大长度。
pub const MAX_AUDIT_PAGE: u32 = 100;

/// 管理员 audit 页；鉴权、输入归一和上限在 application，SQL 在 infra。
#[allow(
    clippy::too_many_arguments,
    reason = "八个字段逐项对应固定上游 AuditEventQuery"
)]
pub async fn list_audit_events<R: AuditReader>(
    reader: &R,
    auth: &AuthContext,
    cursor: Option<String>,
    event_type: Option<String>,
    actor_user_id: Option<ActorId>,
    target_type: Option<String>,
    target_id: Option<String>,
    from: Option<String>,
    to: Option<String>,
    limit: Option<i64>,
) -> Result<AuditPage, AppError> {
    require_admin(auth)?;
    let event_types = event_type
        .as_deref()
        .map(|raw| {
            raw.split(',')
                .map(trim_ecmascript)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let target_type = target_type.filter(|value| !value.is_empty());
    let target_id = target_id.filter(|value| !value.is_empty());
    let from = parse_time(from, "from")?;
    let to = parse_time(to, "to")?;
    let limit = limit
        .unwrap_or(i64::from(DEFAULT_AUDIT_PAGE))
        .clamp(1, i64::from(MAX_AUDIT_PAGE)) as u32;
    reader
        .list_audit_events(AuditPageRequest {
            cursor,
            event_types,
            actor_user_id,
            target_type,
            target_id,
            from,
            to,
            limit,
        })
        .await
        .map_err(|error| error.into_app_error())
}

fn parse_time(
    value: Option<String>,
    field: &'static str,
) -> Result<Option<OffsetDateTime>, AppError> {
    value
        .map(|raw| {
            OffsetDateTime::parse(trim_ecmascript(&raw), &Rfc3339)
                .map_err(|_| AppError::MalformedPayload { field })
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::ids::{DeploymentId, TenantId};
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeAuditReader {
        calls: Mutex<Vec<AuditPageRequest>>,
    }

    #[async_trait]
    impl AuditReader for FakeAuditReader {
        async fn list_audit_events(
            &self,
            request: AuditPageRequest,
        ) -> Result<AuditPage, crate::ports::AuditReadError> {
            self.calls.lock().unwrap().push(request);
            Ok(AuditPage::default())
        }
    }

    fn auth(role: Role) -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("actor"),
            [role],
            AuthGeneration::new(1),
            false,
        )
    }

    #[tokio::test]
    async fn admin_query_is_normalized_and_bounded_before_the_port() {
        let reader = FakeAuditReader::default();
        list_audit_events(
            &reader,
            &auth(Role::Admin),
            Some("opaque".to_owned()),
            Some("\u{FEFF}one , two,, \u{3000}".to_owned()),
            Some(ActorId::new("subject")),
            Some(" connector ".to_owned()),
            Some(" drive-1 ".to_owned()),
            Some("2026-08-13T00:00:00Z".to_owned()),
            Some("2026-08-14T00:00:00Z".to_owned()),
            Some(i64::MAX),
        )
        .await
        .unwrap();
        let calls = reader.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].event_types, ["one", "two"]);
        assert_eq!(calls[0].target_type.as_deref(), Some(" connector "));
        assert_eq!(calls[0].target_id.as_deref(), Some(" drive-1 "));
        assert_eq!(calls[0].limit, MAX_AUDIT_PAGE);
        assert!(calls[0].from < calls[0].to);
    }

    #[tokio::test]
    async fn non_admin_and_malformed_time_stop_before_the_port() {
        let reader = FakeAuditReader::default();
        let denied = list_audit_events(
            &reader,
            &auth(Role::User),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            denied,
            AppError::ForbiddenRole {
                required: Role::Admin
            }
        ));

        let malformed = list_audit_events(
            &reader,
            &auth(Role::Admin),
            None,
            None,
            None,
            None,
            None,
            Some("not-a-time".to_owned()),
            None,
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(malformed, AppError::MalformedPayload { field: "from" });
        assert!(reader.calls.lock().unwrap().is_empty());
    }
}
