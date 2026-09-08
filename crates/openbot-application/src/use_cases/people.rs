//! `/api/me` 与 admin people 用例编排。

use openbot_contracts::auth::{AuthContext, Role};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::ActorId;
use openbot_contracts::people::{AdminState, AdminStatus, CurrentUser, PeoplePage, Person};
use openbot_domain::text::trim_ecmascript;

use crate::ports::{PeopleAdministration, PeoplePageRequest};

/// 上游 people store 默认页长。
pub const DEFAULT_PEOPLE_PAGE: u32 = 50;
/// 上游 people store 最大页长。
pub const MAX_PEOPLE_PAGE: u32 = 200;

/// 当前用户投影。
pub async fn current_user<P: PeopleAdministration>(
    people: &P,
    auth: &AuthContext,
) -> Result<CurrentUser, AppError> {
    people
        .current_user(auth.actor())
        .await
        .map_err(|error| error.into_app_error())
}

/// 管理员 gate 探针。
pub fn admin_status(auth: &AuthContext) -> Result<AdminStatus, AppError> {
    require_admin(auth)?;
    Ok(AdminStatus {
        status: AdminState::Ok,
    })
}

/// 管理员 people keyset 页。
pub async fn list_people<P: PeopleAdministration>(
    people: &P,
    auth: &AuthContext,
    search: Option<String>,
    cursor: Option<String>,
    limit: Option<i64>,
) -> Result<PeoplePage, AppError> {
    require_admin(auth)?;
    let search = search.and_then(|value| {
        let trimmed = trim_ecmascript(&value);
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    });
    let limit = limit
        .unwrap_or(i64::from(DEFAULT_PEOPLE_PAGE))
        .clamp(1, i64::from(MAX_PEOPLE_PAGE)) as u32;
    people
        .list_people(PeoplePageRequest {
            search,
            cursor,
            limit,
        })
        .await
        .map_err(|error| error.into_app_error())
}

/// 管理员角色变更。
pub async fn change_person_role<P: PeopleAdministration>(
    people: &P,
    auth: &AuthContext,
    subject: &ActorId,
    desired: Role,
) -> Result<Person, AppError> {
    require_admin(auth)?;
    people
        .change_role(auth.actor(), subject, desired)
        .await
        .map_err(|error| error.into_app_error())
}

/// 管理员访问移除/恢复。
pub async fn change_person_access<P: PeopleAdministration>(
    people: &P,
    auth: &AuthContext,
    subject: &ActorId,
    revoked: bool,
) -> Result<Person, AppError> {
    require_admin(auth)?;
    people
        .change_access(auth.actor(), subject, revoked)
        .await
        .map_err(|error| error.into_app_error())
}

pub(crate) fn require_admin(auth: &AuthContext) -> Result<(), AppError> {
    if auth.has_role(Role::Admin) {
        Ok(())
    } else {
        Err(AppError::ForbiddenRole {
            required: Role::Admin,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakes::{FakePeopleAdministration, PeopleCall, sample_person};
    use crate::ports::PeoplePortError;
    use openbot_contracts::error::IdentityConflictReason;
    use openbot_contracts::ids::{DeploymentId, TenantId};

    fn auth(actor: &str, roles: impl IntoIterator<Item = Role>) -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep-1"),
            TenantId::new("tenant-1"),
            ActorId::new(actor),
            roles,
            openbot_contracts::auth::AuthGeneration::new(1),
            false,
        )
    }

    #[tokio::test]
    async fn non_admin_is_rejected_before_people_port_is_touched() {
        let people = FakePeopleAdministration::seeded([sample_person("user-1", Role::User)]);
        let error = list_people(&people, &auth("user-1", [Role::User]), None, None, None)
            .await
            .expect_err("plain user 不得列 people");
        assert_eq!(
            error,
            AppError::ForbiddenRole {
                required: Role::Admin
            }
        );
        assert!(people.calls().is_empty(), "403 必须发生在端口调用之前");
    }

    #[tokio::test]
    async fn list_normalises_search_and_clamps_limit_in_application() {
        let people = FakePeopleAdministration::seeded([
            sample_person("admin-1", Role::Admin),
            sample_person("user-1", Role::User),
        ]);
        let page = list_people(
            &people,
            &auth("admin-1", [Role::Admin]),
            Some("  user  ".to_owned()),
            Some("opaque".to_owned()),
            Some(i64::MAX),
        )
        .await
        .unwrap();
        assert_eq!(page.people.len(), 2);
        assert_eq!(
            people.calls(),
            vec![PeopleCall::List(PeoplePageRequest {
                search: Some("user".to_owned()),
                cursor: Some("opaque".to_owned()),
                limit: MAX_PEOPLE_PAGE,
            })]
        );
    }

    #[tokio::test]
    async fn list_search_uses_exact_ecmascript_trim_string() {
        let people = FakePeopleAdministration::seeded([
            sample_person("admin-1", Role::Admin),
            sample_person("user-1", Role::User),
        ]);
        let admin = auth("admin-1", [Role::Admin]);

        list_people(
            &people,
            &admin,
            Some("\u{FEFF}\u{3000}user\u{00A0}".to_owned()),
            None,
            None,
        )
        .await
        .unwrap();
        list_people(
            &people,
            &admin,
            Some("\u{0085}user\u{0085}".to_owned()),
            None,
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            people.calls(),
            vec![
                PeopleCall::List(PeoplePageRequest {
                    search: Some("user".to_owned()),
                    cursor: None,
                    limit: DEFAULT_PEOPLE_PAGE,
                }),
                PeopleCall::List(PeoplePageRequest {
                    search: Some("\u{0085}user\u{0085}".to_owned()),
                    cursor: None,
                    limit: DEFAULT_PEOPLE_PAGE,
                }),
            ],
            "BOM 必须裁掉，而 ECMAScript 不认的 U+0085 必须保留",
        );
    }

    #[tokio::test]
    async fn current_user_and_mutations_forward_only_authoritative_actor() {
        let people = FakePeopleAdministration::seeded([
            sample_person("admin-1", Role::Admin),
            sample_person("user-1", Role::User),
        ]);
        let admin = auth("admin-1", [Role::Admin]);
        let me = current_user(&people, &admin).await.unwrap();
        assert_eq!(me.id.as_str(), "admin-1");
        change_person_role(&people, &admin, &ActorId::new("user-1"), Role::Admin)
            .await
            .unwrap();
        change_person_access(&people, &admin, &ActorId::new("user-1"), true)
            .await
            .unwrap();
        assert_eq!(
            people.calls(),
            vec![
                PeopleCall::Current(ActorId::new("admin-1")),
                PeopleCall::Role {
                    actor: ActorId::new("admin-1"),
                    subject: ActorId::new("user-1"),
                    role: Role::Admin,
                },
                PeopleCall::Access {
                    actor: ActorId::new("admin-1"),
                    subject: ActorId::new("user-1"),
                    revoked: true,
                },
            ]
        );
    }

    #[tokio::test]
    async fn domain_identity_conflict_survives_port_mapping_with_its_stable_code() {
        let people = FakePeopleAdministration::failing(PeoplePortError::IdentityConflict {
            reason: IdentityConflictReason::RoleLastAdmin,
        });
        let error = change_person_role(
            &people,
            &auth("admin-1", [Role::Admin]),
            &ActorId::new("admin-2"),
            Role::User,
        )
        .await
        .expect_err("last admin 必须拒绝");
        assert_eq!(error.http_status(), 409);
        assert_eq!(error.code().as_str(), "identity_role_change_last_admin");
    }
}
