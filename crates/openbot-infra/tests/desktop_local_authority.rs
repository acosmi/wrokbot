//! Desktop Local instance authority → PostgreSQL principal → package membership true vertical.

mod harness;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use harness::{admin_config, with_temp_database};
use openbot_application::tenant::package::{
    LoadedTenantPackage, TenantPackageFiles, synchronize_tenant_package, validate_tenant_package,
};
use openbot_contracts::auth::Role;
use openbot_infra::auth::single_user::desktop_local::{
    CurrentOsUserAppDataRoot, DESKTOP_LOCAL_ACTOR_ID, DESKTOP_LOCAL_EMAIL, DESKTOP_LOCAL_NAME,
    DesktopLocalAuthorityStore,
};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::tenant::PostgresTenantPackageSynchronizer;

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn authority_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "openbot-desktop-local-pg-{}-{}",
        std::process::id(),
        TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ))
}

fn loaded_package(tenant_id: &str) -> LoadedTenantPackage {
    let files = TenantPackageFiles {
        brand: format!("tenant: {{ id: {tenant_id}, product_name: Desktop Local }}"),
        agents: "agents: [{ id: desktop-assistant, name: Assistant, title: Local Assistant, role_description: Help locally., type: built-in, system_prompt: Answer carefully. }]".to_owned(),
        channels: "channels: [{ id: desktop-home, name: Home, description: Local home., permitted_agents: [desktop-assistant], allowed_groups: [all] }]".to_owned(),
        model: "model: { provider: openai, credential_secret_ref: openai-key, default_model: gpt-4.1 }".to_owned(),
        knowledge: "sources: []".to_owned(),
    };
    LoadedTenantPackage::new(
        validate_tenant_package(files).unwrap(),
        "/desktop-local/package".to_owned(),
        "d".repeat(64),
    )
    .unwrap()
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn principal_repair_and_package_membership_use_one_desktop_authority() {
    let admin = admin_config("principal_repair_and_package_membership_use_one_desktop_authority");
    with_temp_database(&admin, "desktop_local_authority", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let root = authority_root();
        let outcome = async {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let authority = DesktopLocalAuthorityStore::new(
                CurrentOsUserAppDataRoot::from_current_os_user_app_data(&root)
                    .map_err(|error| error.to_string())?,
            )
            .load_or_create()
            .map_err(|error| error.to_string())?;
            authority
                .provision_postgres(&pool)
                .await
                .map_err(|error| error.to_string())?;

            let client = pool.get().await.map_err(|error| error.to_string())?;
            let row = client
                .query_one(
                    "SELECT email,name,email_verified,groups,auth_generation FROM public.users WHERE id=$1",
                    &[&DESKTOP_LOCAL_ACTOR_ID],
                )
                .await
                .map_err(|error| error.to_string())?;
            let roles = client
                .query(
                    "SELECT role::text FROM public.user_roles WHERE user_id=$1 ORDER BY role",
                    &[&DESKTOP_LOCAL_ACTOR_ID],
                )
                .await
                .map_err(|error| error.to_string())?
                .into_iter()
                .map(|row| row.get::<_, String>(0))
                .collect::<Vec<_>>();
            if row.get::<_, String>("email") != DESKTOP_LOCAL_EMAIL
                || row.get::<_, Option<String>>("name").as_deref()
                    != Some(DESKTOP_LOCAL_NAME)
                || row.get::<_, bool>("email_verified")
                || row.get::<_, Vec<String>>("groups") != Vec::<String>::new()
                || row.get::<_, Option<i64>>("auth_generation") != Some(0)
                || roles != ["admin"]
            {
                return Err(format!("Desktop canonical principal不符：roles={roles:?}"));
            }
            client
                .execute(
                    "UPDATE public.users SET email='changed@localhost.invalid',name='Changed',auth_generation=7 WHERE id=$1",
                    &[&DESKTOP_LOCAL_ACTOR_ID],
                )
                .await
                .map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.user_roles(user_id,role) VALUES($1,'user')",
                    &[&DESKTOP_LOCAL_ACTOR_ID],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            authority
                .provision_postgres(&pool)
                .await
                .map_err(|error| error.to_string())?;
            let synchronizer = PostgresTenantPackageSynchronizer::new(pool.clone());
            let package = loaded_package(authority.auth_context().tenant().as_str());
            let context = authority
                .tenant_package_audience_context()
                .map_err(|error| error.to_string())?;
            let report = synchronize_tenant_package(&synchronizer, &package, &context)
                .await
                .map_err(|error| error.to_string())?;

            let client = pool.get().await.map_err(|error| error.to_string())?;
            let repaired = client
                .query_one(
                    "SELECT email,name,auth_generation, EXISTS(SELECT 1 FROM public.channel_memberships WHERE channel_id='desktop-home' AND user_id=$1) AS member FROM public.users WHERE id=$1",
                    &[&DESKTOP_LOCAL_ACTOR_ID],
                )
                .await
                .map_err(|error| error.to_string())?;
            let roles = client
                .query(
                    "SELECT role::text FROM public.user_roles WHERE user_id=$1 ORDER BY role",
                    &[&DESKTOP_LOCAL_ACTOR_ID],
                )
                .await
                .map_err(|error| error.to_string())?
                .into_iter()
                .map(|row| row.get::<_, String>(0))
                .collect::<Vec<_>>();
            if repaired.get::<_, String>("email") != DESKTOP_LOCAL_EMAIL
                || repaired.get::<_, Option<String>>("name").as_deref()
                    != Some(DESKTOP_LOCAL_NAME)
                || repaired.get::<_, Option<i64>>("auth_generation") != Some(7)
                || !repaired.get::<_, bool>("member")
                || roles != ["admin"]
                || report.memberships_granted != 1
                || !report.single_user_groups_ignored
            {
                return Err(format!(
                    "repair/package membership不完整：roles={roles:?} report={report:?}"
                ));
            }
            drop(client);
            let runtime=authority.load_runtime_auth_context(&pool).await.map_err(|e|e.to_string())?;
            if runtime.auth_generation().get()!=7 || runtime.actor().as_str()!=DESKTOP_LOCAL_ACTOR_ID
                || runtime.tenant()!=authority.auth_context().tenant()
                || runtime.deployment()!=authority.auth_context().deployment()
                || runtime.roles().iter().copied().collect::<Vec<_>>()!=[Role::Admin,Role::User]
            { return Err("Desktop runtime did not bind repaired generation and canonical role".to_owned()); }
            Ok(())
        }
        .await;
        pool.close();
        let _ = std::fs::remove_dir_all(root);
        outcome
    })
    .await;
}
