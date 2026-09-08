//! Actual canonical PostgreSQL authority, including the legitimate first-install generation zero.

use super::*;
use openbot_contracts::auth::{AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_infra::auth::single_user::desktop_local::{
    CurrentOsUserAppDataRoot, DesktopLocalAuthorityStore,
};
use openbot_infra::db::{fresh, pool};

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

struct InstanceFolder(std::path::PathBuf);
impl Drop for InstanceFolder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
#[ignore = "requires an owned PostgreSQL 17 fixture via OPENBOT_TEST_DATABASE_URL"]
async fn canonical_pg_confirmation_preserves_zero_and_rejects_revoked_or_changed_authority() {
    let admin = harness::admin_config("canonical_pg_confirmation");
    harness::with_temp_database(&admin, "confirmation", |config| async move {
        let database = pool::connect(&config).await.unwrap();
        {
            let mut client = database.get().await.unwrap();
            fresh::apply(&mut client).await.unwrap();
        }
        let folder = InstanceFolder(std::env::temp_dir().join(format!(
            "wrok-confirmation-authority-{}",
            uuid::Uuid::now_v7()
        )));
        let store = DesktopLocalAuthorityStore::new(
            CurrentOsUserAppDataRoot::from_current_os_user_app_data(&folder.0).unwrap(),
        );
        let installation = store.load_or_create().unwrap();
        installation.provision_postgres(&database).await.unwrap();
        let original = installation
            .load_runtime_auth_context(&database)
            .await
            .unwrap();
        assert_eq!(original.auth_generation().get(), 0);
        let authority =
            PostgresLocalConfirmationAuthority::new(installation.clone(), database.clone());
        assert_eq!(authority.verify_current(&original).await.unwrap(), original);

        let context = |deployment: DeploymentId,
                       tenant: TenantId,
                       actor: ActorId,
                       generation: u64,
                       single_user: bool,
                       roles: Vec<Role>| {
            AuthContextBuilder::from_verified_session(
                deployment,
                tenant,
                actor,
                AuthGeneration::new(generation),
                single_user,
            )
            .with_roles(roles)
            .build()
        };
        let different = [
            context(
                DeploymentId::new("different"),
                original.tenant().clone(),
                original.actor().clone(),
                0,
                true,
                vec![Role::Admin, Role::User],
            ),
            context(
                original.deployment().clone(),
                TenantId::new("different"),
                original.actor().clone(),
                0,
                true,
                vec![Role::Admin, Role::User],
            ),
            context(
                original.deployment().clone(),
                original.tenant().clone(),
                ActorId::new("different"),
                0,
                true,
                vec![Role::Admin, Role::User],
            ),
            context(
                original.deployment().clone(),
                original.tenant().clone(),
                original.actor().clone(),
                1,
                true,
                vec![Role::Admin, Role::User],
            ),
            context(
                original.deployment().clone(),
                original.tenant().clone(),
                original.actor().clone(),
                0,
                false,
                vec![Role::Admin, Role::User],
            ),
            context(
                original.deployment().clone(),
                original.tenant().clone(),
                original.actor().clone(),
                0,
                true,
                vec![Role::Admin],
            ),
        ];
        for expected in different {
            assert!(matches!(
                authority.verify_current(&expected).await,
                Err(AppError::Unauthenticated)
            ));
        }
        let client = database.get().await.unwrap();
        client
            .execute(
                "UPDATE public.users SET auth_generation=1 WHERE id=$1",
                &[&original.actor().as_str()],
            )
            .await
            .unwrap();
        assert!(matches!(
            authority.verify_current(&original).await,
            Err(AppError::Unauthenticated)
        ));
        let advanced = installation
            .load_runtime_auth_context(&database)
            .await
            .unwrap();
        assert_eq!(advanced.auth_generation().get(), 1);
        assert_eq!(authority.verify_current(&advanced).await.unwrap(), advanced);

        let email: String = client
            .query_one(
                "SELECT email FROM public.users WHERE id=$1",
                &[&original.actor().as_str()],
            )
            .await
            .unwrap()
            .get(0);
        client
            .execute(
                "INSERT INTO public.revoked_access(email,revoked_by) VALUES($1,$2)",
                &[&email, &original.actor().as_str()],
            )
            .await
            .unwrap();
        assert!(matches!(
            authority.verify_current(&advanced).await,
            Err(AppError::Unauthenticated)
        ));
        assert_eq!(
            client
                .query_one(
                    "SELECT count(*) FROM public.revoked_access WHERE email=$1",
                    &[&email]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
            1
        );
        client
            .execute(
                "DELETE FROM public.revoked_access WHERE email=$1",
                &[&email],
            )
            .await
            .unwrap();
        client
            .execute(
                "UPDATE public.user_roles SET role='user' WHERE user_id=$1",
                &[&original.actor().as_str()],
            )
            .await
            .unwrap();
        assert!(matches!(
            authority.verify_current(&advanced).await,
            Err(AppError::Unauthenticated)
        ));
        // Verification never repairs a role or re-provisions an identity behind the user's back.
        assert_eq!(
            client
                .query_one(
                    "SELECT role::text FROM public.user_roles WHERE user_id=$1",
                    &[&original.actor().as_str()]
                )
                .await
                .unwrap()
                .get::<_, String>(0),
            "user"
        );
        client
            .execute(
                "DELETE FROM public.user_roles WHERE user_id=$1",
                &[&original.actor().as_str()],
            )
            .await
            .unwrap();
        client
            .execute(
                "DELETE FROM public.users WHERE id=$1",
                &[&original.actor().as_str()],
            )
            .await
            .unwrap();
        assert!(matches!(
            authority.verify_current(&advanced).await,
            Err(AppError::Unauthenticated)
        ));
        assert_eq!(
            client
                .query_one(
                    "SELECT count(*) FROM public.users WHERE id=$1",
                    &[&original.actor().as_str()]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
        drop(client);
        database.close();
        Ok(())
    })
    .await;
}
