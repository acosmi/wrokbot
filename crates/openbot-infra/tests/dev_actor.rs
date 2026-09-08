//! 固定上游 `dev-actor.integration.test.ts` 的单用户 canonical identity 真库矩阵。

mod harness;

use std::time::Duration;

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use harness::{admin_config, with_temp_database};
use tokio_postgres::NoTls;

use openbot_contracts::auth::Role;
use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_infra::auth::single_user::{
    SINGLE_USER_ACTOR_ID, SINGLE_USER_EMAIL, SINGLE_USER_NAME, initialize_single_user,
    load_single_user_principal,
};
use openbot_infra::db::{baseline, native, pool};

fn unreachable_lazy_pool() -> Pool {
    let mut config = tokio_postgres::Config::new();
    config
        .host("127.0.0.1")
        .port(1)
        .user("must-not-connect")
        .dbname("must-not-connect");
    let manager = Manager::from_config(
        config,
        NoTls,
        ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        },
    );
    Pool::builder(manager)
        .max_size(1)
        .runtime(Runtime::Tokio1)
        .create_timeout(Some(Duration::from_millis(10)))
        .build()
        .expect("惰性池构造不建连")
}

async fn provision(pool: &Pool) -> Result<(), String> {
    let mut client = pool.get().await.map_err(|error| error.to_string())?;
    baseline::apply(&client)
        .await
        .map_err(|error| error.to_string())?;
    native::apply(&mut client)
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

#[tokio::test]
async fn disabled_initialization_never_touches_the_database() {
    let pool = unreachable_lazy_pool();
    assert!(!initialize_single_user(&pool, false).await.unwrap());
    assert_eq!(pool.status().size, 0, "disabled 路径不得创建连接");
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn enabled_initialization_restores_canonical_identity_and_one_admin_role() {
    let admin =
        admin_config("enabled_initialization_restores_canonical_identity_and_one_admin_role");
    with_temp_database(&admin, "dev_actor_restore", |config| async move {
        let pool = pool::connect(&config).await.map_err(|error| error.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            if !initialize_single_user(&pool, true)
                .await
                .map_err(|error| error.to_string())?
            {
                return Err("enabled 初始化错误返回 false".to_owned());
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            let first = client
                .query_one(
                    "SELECT email,name,email_verified,groups,auth_generation \
                     FROM public.users WHERE id=$1",
                    &[&SINGLE_USER_ACTOR_ID],
                )
                .await
                .map_err(|error| error.to_string())?;
            let roles: Vec<String> = client
                .query(
                    "SELECT role::text FROM public.user_roles WHERE user_id=$1 ORDER BY role",
                    &[&SINGLE_USER_ACTOR_ID],
                )
                .await
                .map_err(|error| error.to_string())?
                .into_iter()
                .map(|row| row.get(0))
                .collect();
            if first.get::<_, String>("email") != SINGLE_USER_EMAIL
                || first.get::<_, Option<String>>("name").as_deref() != Some(SINGLE_USER_NAME)
                || first.get::<_, bool>("email_verified")
                || first.get::<_, Vec<String>>("groups") != Vec::<String>::new()
                || first.get::<_, Option<i64>>("auth_generation") != Some(0)
                || roles != ["admin"]
            {
                return Err(format!("首次 canonical user/role 不符：roles={roles:?}"));
            }

            client
                .execute(
                    "UPDATE public.users SET email='changed@example.test',name='Changed',auth_generation=7 \
                     WHERE id=$1",
                    &[&SINGLE_USER_ACTOR_ID],
                )
                .await
                .map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.user_roles(user_id,role) VALUES($1,'user')",
                    &[&SINGLE_USER_ACTOR_ID],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            initialize_single_user(&pool, true)
                .await
                .map_err(|error| error.to_string())?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let restored = client
                .query_one(
                    "SELECT email,name,auth_generation FROM public.users WHERE id=$1",
                    &[&SINGLE_USER_ACTOR_ID],
                )
                .await
                .map_err(|error| error.to_string())?;
            let roles: Vec<String> = client
                .query(
                    "SELECT role::text FROM public.user_roles WHERE user_id=$1 ORDER BY role",
                    &[&SINGLE_USER_ACTOR_ID],
                )
                .await
                .map_err(|error| error.to_string())?
                .into_iter()
                .map(|row| row.get(0))
                .collect();
            if restored.get::<_, String>("email") != SINGLE_USER_EMAIL
                || restored.get::<_, Option<String>>("name").as_deref()
                    != Some(SINGLE_USER_NAME)
                || restored.get::<_, Option<i64>>("auth_generation") != Some(7)
                || roles != ["admin"]
            {
                return Err(format!(
                    "重复初始化未恢复 identity/角色或错误重置 generation：roles={roles:?}"
                ));
            }
            drop(client);
            let verified = load_single_user_principal(
                &pool, DeploymentId::new("server-a"), TenantId::new("tenant-a"),
            ).await.map_err(|error| error.to_string())?;
            let auth=verified.auth_context();
            if auth.actor().as_str()!=SINGLE_USER_ACTOR_ID || auth.auth_generation().get()!=7
                || auth.roles().iter().copied().collect::<Vec<_>>()!=[Role::Admin,Role::User]
                || auth.deployment().as_str()!="server-a" || auth.tenant().as_str()!="tenant-a"
                || !auth.is_single_user()
            { return Err("runtime principal lost repaired generation or canonical roles".to_owned()); }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn canonical_snapshot_rejects_missing_denied_roles_and_corrupt_generation() {
    with_temp_database(&admin_config("canonical snapshot refusal"), "canonicalrefusal", |config| async move {
        let pool=pool::connect(&config).await.map_err(|e|e.to_string())?;
        let outcome=async {
            provision(&pool).await?;
            let load=||load_single_user_principal(&pool,DeploymentId::new("server-a"),TenantId::new("tenant-a"));
            if load().await.is_ok() { return Err("unprovisioned principal was accepted".to_owned()); }
            initialize_single_user(&pool,true).await.map_err(|e|e.to_string())?;
            let initial=load().await.map_err(|e|e.to_string())?;
            if initial.auth_context().auth_generation().get()!=0 { return Err("fresh generation must be zero".to_owned()); }
            let client=pool.get().await.map_err(|e|e.to_string())?;
            for sql in [
                "DELETE FROM public.user_roles WHERE user_id='dev-local-user'",
                "INSERT INTO public.user_roles(user_id,role) VALUES ('dev-local-user','user')",
                "INSERT INTO public.user_roles(user_id,role) VALUES ('dev-local-user','admin')",
            ] {
                client.batch_execute(sql).await.map_err(|e|e.to_string())?;
                if load().await.is_ok() { return Err("noncanonical role collection accepted".to_owned()); }
            }
            client.batch_execute("DELETE FROM public.user_roles WHERE user_id='dev-local-user' AND role='user'; INSERT INTO public.revoked_access(email,revoked_by) VALUES ('dev@openbot.local','synthetic-admin');").await.map_err(|e|e.to_string())?;
            if load().await.is_ok() { return Err("denied canonical actor accepted".to_owned()); }
            initialize_single_user(&pool,true).await.map_err(|e|e.to_string())?;
            if load().await.is_ok() { return Err("repair bypassed canonical deny".to_owned()); }
            client.batch_execute("DELETE FROM public.revoked_access; UPDATE public.users SET auth_generation=NULL WHERE id='dev-local-user';").await.map_err(|e|e.to_string())?;
            if load().await.map_err(|e|e.to_string())?.auth_context().auth_generation().get()!=0 { return Err("legacy NULL generation compatibility changed".to_owned()); }
            client.batch_execute("UPDATE public.users SET email='changed@example.test' WHERE id='dev-local-user';").await.map_err(|e|e.to_string())?;
            if load().await.is_ok() { return Err("changed canonical email accepted before repair".to_owned()); }
            // Explicit corrupt-schema fault injection; the production CHECK normally forbids this.
            client.batch_execute("UPDATE public.users SET email='dev@openbot.local' WHERE id='dev-local-user'; ALTER TABLE public.users DROP CONSTRAINT users_auth_generation_nonnegative; UPDATE public.users SET auth_generation=-1 WHERE id='dev-local-user';").await.map_err(|e|e.to_string())?;
            if load().await.is_ok() { return Err("negative generation silently became zero".to_owned()); }
            drop(client);
            pool.close();
            if load().await.is_ok() { return Err("closed database minted fallback authority".to_owned()); }
            Ok(())
        }.await;
        pool.close();outcome
    }).await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn conflicting_email_fails_loudly_and_rolls_back_the_whole_repair() {
    let admin = admin_config("conflicting_email_fails_loudly_and_rolls_back_the_whole_repair");
    with_temp_database(&admin, "dev_actor_conflict", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .batch_execute(&format!(
                    "INSERT INTO public.users(id,email,name) VALUES \
                       ('{SINGLE_USER_ACTOR_ID}','changed@example.test','Changed'), \
                       ('email-owner','{SINGLE_USER_EMAIL}','Existing owner'); \
                     INSERT INTO public.user_roles(user_id,role) VALUES \
                       ('{SINGLE_USER_ACTOR_ID}','admin'),('{SINGLE_USER_ACTOR_ID}','user');"
                ))
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let error = initialize_single_user(&pool, true)
                .await
                .expect_err("canonical email 被别人占用必须响亮失败");
            if error.sqlstate() != Some("23505")
                || format!("{error}").contains(SINGLE_USER_EMAIL)
                || format!("{error:?}").contains(SINGLE_USER_EMAIL)
            {
                return Err(format!("冲突错误未脱敏或 SQLSTATE 不符：{error:?}"));
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            let email: String = client
                .query_one(
                    "SELECT email FROM public.users WHERE id=$1",
                    &[&SINGLE_USER_ACTOR_ID],
                )
                .await
                .map_err(|error| error.to_string())?
                .get(0);
            let role_count: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.user_roles WHERE user_id=$1",
                    &[&SINGLE_USER_ACTOR_ID],
                )
                .await
                .map_err(|error| error.to_string())?
                .get(0);
            if email != "changed@example.test" || role_count != 2 {
                return Err("identity 冲突后事务没有完整回滚".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}
