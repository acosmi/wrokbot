//! Canonical PostgreSQL principal -> real Server resolver startup snapshot.

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::sync::{Arc, Mutex};

use harness::{admin_config, with_temp_database};
use http::Request;
use openbot_contracts::auth::Role;
use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::auth::single_user::{
    SINGLE_USER_ACTOR_ID, initialize_single_user, load_single_user_principal,
};
use openbot_infra::db::{baseline, native, pool};
use openbot_server::{AuthResolver, SingleUserAuthResolver};

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn repaired_nonzero_generations_bind_runtime_and_live_session_per_deployment() {
    let snapshots = Arc::new(Mutex::new(Vec::new()));
    for (deployment, tenant, generation) in [
        ("server-a", "tenant-a", 7_i64),
        ("server-b", "tenant-b", 11_i64),
    ] {
        let snapshots = Arc::clone(&snapshots);
        with_temp_database(&admin_config("canonical Server runtime"), "serverprincipal", |config| async move {
            let pool=pool::connect(&config).await.map_err(|e|e.to_string())?;
            let outcome=async {
                let mut client=pool.get().await.map_err(|e|e.to_string())?;
                baseline::apply(&client).await.map_err(|e|e.to_string())?;
                native::apply(&mut client).await.map_err(|e|e.to_string())?;
                drop(client);
                if load_single_user_principal(&pool,DeploymentId::new(deployment),TenantId::new(tenant)).await.is_ok() { return Err("unprovisioned runtime was minted".to_owned()); }
                initialize_single_user(&pool,true).await.map_err(|e|e.to_string())?;
                let client=pool.get().await.map_err(|e|e.to_string())?;
                client.execute("UPDATE public.users SET email='changed@example.test',name='Changed',auth_generation=$2 WHERE id=$1", &[&SINGLE_USER_ACTOR_ID,&generation]).await.map_err(|e|e.to_string())?;
                client.execute("INSERT INTO public.user_roles(user_id,role) VALUES($1,'user')", &[&SINGLE_USER_ACTOR_ID]).await.map_err(|e|e.to_string())?;
                drop(client);
                initialize_single_user(&pool,true).await.map_err(|e|e.to_string())?;
                let principal=load_single_user_principal(&pool,DeploymentId::new(deployment),TenantId::new(tenant)).await.map_err(|e|e.to_string())?;
                let resolver=SingleUserAuthResolver::from_verified_principal(principal,default_session_lifetime());
                let (parts,())=Request::builder().header("x-actor","forged").header("x-auth-generation","0").body(()).unwrap().into_parts();
                let resolved=resolver.resolve_with_assurance(&parts).await.map_err(|e|e.to_string())?;
                let auth=resolved.context();
                let expected=u64::try_from(generation).map_err(|e|e.to_string())?;
                if auth.auth_generation().get()!=expected || auth.actor().as_str()!=SINGLE_USER_ACTOR_ID
                    || auth.deployment().as_str()!=deployment || auth.tenant().as_str()!=tenant
                    || !auth.is_single_user() || auth.roles().iter().copied().collect::<Vec<_>>()!=[Role::Admin,Role::User]
                    || resolved.live_session().map(|live|live.state().generation().get())!=Some(expected)
                { return Err("runtime or session did not use the repaired canonical snapshot".to_owned()); }
                snapshots.lock().map_err(|_|"snapshot lock")?.push(auth.clone());
                let next=generation+1;
                pool.get().await.map_err(|e|e.to_string())?.execute("UPDATE public.users SET auth_generation=$2 WHERE id=$1", &[&SINGLE_USER_ACTOR_ID,&next]).await.map_err(|e|e.to_string())?;
                if resolver.resolve(&parts).await.map_err(|e|e.to_string())?.auth_generation().get()!=expected { return Err("old runtime silently upgraded itself after authorization changed".to_owned()); }
                Ok(())
            }.await;
            pool.close();outcome
        }).await;
    }
    let snapshots = snapshots.lock().unwrap();
    assert_eq!(snapshots.len(), 2);
    assert_ne!(snapshots[0].deployment(), snapshots[1].deployment());
    assert_ne!(snapshots[0].tenant(), snapshots[1].tenant());
    assert_eq!(snapshots[0].auth_generation().get(), 7);
    assert_eq!(snapshots[1].auth_generation().get(), 11);
}
