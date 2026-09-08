//! Deployment-wide action policy 读写编排。

use openbot_contracts::auth::AuthContext;
use openbot_contracts::error::AppError;
use openbot_contracts::policy::{ActionPolicyDocument, ActionPolicyMode};
use openbot_domain::policy::{ActionPolicy, PolicyMode};

use crate::ports::PolicyAdministration;
use crate::use_cases::people::require_admin;

/// 管理员读取当前 policy；未配置以 `None` 保留，不伪造 allow-all 文档。
pub async fn get_action_policy<P: PolicyAdministration>(
    policies: &P,
    auth: &AuthContext,
) -> Result<Option<ActionPolicyDocument>, AppError> {
    require_admin(auth)?;
    policies
        .current_policy()
        .await
        .map(|policy| policy.map(to_document))
        .map_err(|error| error.into_app_error())
}

/// 管理员保存 policy；updated_by 只取权威 actor，成功后回读实际生效文档。
pub async fn set_action_policy<P: PolicyAdministration>(
    policies: &P,
    auth: &AuthContext,
    document: ActionPolicyDocument,
) -> Result<ActionPolicyDocument, AppError> {
    require_admin(auth)?;
    policies
        .set_policy(auth.actor(), from_document(document))
        .await
        .map_err(|error| error.into_app_error())?;
    policies
        .current_policy()
        .await
        .map_err(|error| error.into_app_error())?
        .map(to_document)
        .ok_or(AppError::DependencyUnavailable {
            dependency: "policy_store",
        })
}

fn from_document(document: ActionPolicyDocument) -> ActionPolicy {
    ActionPolicy {
        mode: match document.mode {
            ActionPolicyMode::Enforce => PolicyMode::Enforce,
            ActionPolicyMode::DryRun => PolicyMode::DryRun,
        },
        deny: document.deny,
        allow: document.allow,
    }
}

fn to_document(policy: ActionPolicy) -> ActionPolicyDocument {
    ActionPolicyDocument {
        mode: match policy.mode {
            PolicyMode::Enforce => ActionPolicyMode::Enforce,
            PolicyMode::DryRun => ActionPolicyMode::DryRun,
        },
        deny: policy.deny,
        allow: policy.allow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use openbot_contracts::auth::{AuthGeneration, Role};
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakePolicies {
        current: Mutex<Option<ActionPolicy>>,
        actors: Mutex<Vec<ActorId>>,
    }

    #[async_trait]
    impl PolicyAdministration for FakePolicies {
        async fn current_policy(
            &self,
        ) -> Result<Option<ActionPolicy>, crate::ports::PolicyAdministrationError> {
            Ok(self.current.lock().unwrap().clone())
        }

        async fn set_policy(
            &self,
            updated_by: &ActorId,
            policy: ActionPolicy,
        ) -> Result<(), crate::ports::PolicyAdministrationError> {
            self.actors.lock().unwrap().push(updated_by.clone());
            *self.current.lock().unwrap() = Some(policy);
            Ok(())
        }
    }

    fn auth(role: Role) -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("admin-id"),
            [role],
            AuthGeneration::new(1),
            true,
        )
    }

    fn document() -> ActionPolicyDocument {
        ActionPolicyDocument {
            mode: ActionPolicyMode::DryRun,
            deny: vec!["false".to_owned()],
            allow: vec!["true".to_owned()],
        }
    }

    #[tokio::test]
    async fn admin_round_trip_uses_authoritative_actor_and_exact_mode_mapping() {
        let policies = FakePolicies::default();
        assert_eq!(
            get_action_policy(&policies, &auth(Role::Admin))
                .await
                .unwrap(),
            None
        );
        let saved = set_action_policy(&policies, &auth(Role::Admin), document())
            .await
            .unwrap();
        assert_eq!(saved, document());
        assert_eq!(
            policies.actors.lock().unwrap().as_slice(),
            [ActorId::new("admin-id")]
        );
        assert_eq!(
            get_action_policy(&policies, &auth(Role::Admin))
                .await
                .unwrap(),
            Some(document())
        );
    }

    #[tokio::test]
    async fn non_admin_is_rejected_before_read_or_write_port_effects() {
        let policies = FakePolicies::default();
        let read = get_action_policy(&policies, &auth(Role::User))
            .await
            .unwrap_err();
        let write = set_action_policy(&policies, &auth(Role::User), document())
            .await
            .unwrap_err();
        assert!(matches!(
            read,
            AppError::ForbiddenRole {
                required: Role::Admin
            }
        ));
        assert!(matches!(
            write,
            AppError::ForbiddenRole {
                required: Role::Admin
            }
        ));
        assert!(policies.actors.lock().unwrap().is_empty());
        assert!(policies.current.lock().unwrap().is_none());
    }
}
