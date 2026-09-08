//! 单用户模式唯一 principal 的 PostgreSQL 持久化。
//!
//! 固定 actor id 不能随重写改名：上游用它把 thread/memory 归到同一个人，换 id 会把旧数据
//! 变成孤儿。初始化只在显式启用时访问数据库；启用后以一个事务恢复 canonical user 字段并
//! 通过领域 [`plan_set_role`] 把角色集合收敛为唯一 admin。
//!
//! 这段固定兼容键只属于Server `OPENBOT_SINGLE_USER`。Desktop Local按v4 §6.1绑定当前OS用户的
//! app-data namespace与本地app instance，走嵌套的[`desktop_local`]，不得复用Server部署身份。

#[path = "desktop_local.rs"]
pub mod desktop_local;

use deadpool_postgres::Pool;
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_domain::identity::roles::plan_set_role;

use crate::db::InfraError;
use crate::repo::people_admin::apply_role_plan;

/// 与固定上游 `DEV_ACTOR.id` 相同；既有数据兼容键。
pub const SINGLE_USER_ACTOR_ID: &str = "dev-local-user";

/// 与固定上游 `DEV_ACTOR.email` 相同。
pub const SINGLE_USER_EMAIL: &str = "dev@openbot.local";

/// 上游 actor 没有另设 name，持久化时回落到 email。
pub const SINGLE_USER_NAME: &str = SINGLE_USER_EMAIL;

/// A Server-only canonical principal whose generation and role were read from PostgreSQL.
/// No caller-supplied actor, role, generation or AuthContext can construct this proof.
#[derive(Clone, Debug)]
pub struct VerifiedSingleUserPrincipal {
    auth: AuthContext,
}

impl VerifiedSingleUserPrincipal {
    /// Borrow the startup snapshot; runtime data access must still recheck its generation.
    #[must_use]
    pub const fn auth_context(&self) -> &AuthContext {
        &self.auth
    }

    /// Move the database-verified Server identity into its runtime resolver.
    #[must_use]
    pub fn into_auth_context(self) -> AuthContext {
        self.auth
    }
}

/// Load the fixed Server principal after explicit single-user provisioning.
/// Deployment/tenant are host startup configuration, never renderer-supplied identity.
/// Missing/denied/noncanonical users, bad generations and noncanonical roles fail closed.
pub async fn load_single_user_principal(
    pool: &Pool,
    deployment: DeploymentId,
    tenant: TenantId,
) -> Result<VerifiedSingleUserPrincipal, InfraError> {
    if [deployment.as_str(), tenant.as_str()]
        .iter()
        .any(|value| value.is_empty() || value.as_bytes().contains(&0))
    {
        return Err(InfraError::repository_invariant("canonical_scope_invalid"));
    }
    let generation =
        load_canonical_generation(pool, SINGLE_USER_ACTOR_ID, SINGLE_USER_EMAIL).await?;
    Ok(VerifiedSingleUserPrincipal {
        auth: AuthContextBuilder::from_verified_session(
            deployment,
            tenant,
            ActorId::new(SINGLE_USER_ACTOR_ID),
            generation,
            true,
        )
        // Preserve the existing local-runtime Admin + User projection after verifying soleAdmin in PG.
        .with_roles([Role::Admin, Role::User])
        .build(),
    })
}

pub(super) async fn load_canonical_generation(
    pool: &Pool,
    actor_id: &str,
    email: &str,
) -> Result<AuthGeneration, InfraError> {
    let client = pool
        .get()
        .await
        .map_err(|error| InfraError::connect("读取canonical principal连接", error))?;
    // One statement supplies one consistent authority snapshot. Later actor/role changes do not
    // silently upgrade this startup identity; operation-level generation checks invalidate it.
    let row = client
        .query_opt(
            "SELECT coalesce(u.auth_generation,0) AS generation,u.email=$2 AS canonical_email, \
                    EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) AS denied, \
                    ARRAY(SELECT ur.role::text FROM public.user_roles ur \
                          WHERE ur.user_id=u.id ORDER BY ur.role::text) AS roles \
             FROM public.users u WHERE u.id=$1",
            &[&actor_id, &email],
        )
        .await
        .map_err(|error| InfraError::query("读取canonical principal授权快照", error))?
        .ok_or_else(|| InfraError::repository_invariant("canonical_principal_missing"))?;
    let generation: i64 = row
        .try_get("generation")
        .map_err(|error| InfraError::query("解析canonical generation", error))?;
    let canonical_email: bool = row
        .try_get("canonical_email")
        .map_err(|error| InfraError::query("解析canonical identity", error))?;
    let denied: bool = row
        .try_get("denied")
        .map_err(|error| InfraError::query("解析canonical deny", error))?;
    let roles: Vec<String> = row
        .try_get("roles")
        .map_err(|error| InfraError::query("解析canonical roles", error))?;
    if !canonical_email || denied || roles != ["admin"] {
        return Err(InfraError::repository_invariant(
            "canonical_principal_refused",
        ));
    }
    let generation = u64::try_from(generation)
        .map_err(|_| InfraError::repository_invariant("canonical_generation_invalid"))?;
    Ok(AuthGeneration::new(generation))
}

/// 按显式开关初始化单用户 principal。
///
/// `enabled=false` 在取连接之前返回 `Ok(false)`；`true` 时恢复 canonical id/email/name，保留
/// 已有 `auth_generation`，并把 `user_roles` 原子收敛为 admin 一行。
///
/// # Errors
///
/// 取连接、事务、唯一约束或写入失败均返回脱敏 [`InfraError`]；canonical email 已被另一用户
/// 占用时因此响亮失败，不会接管或删除对方。
pub async fn initialize_single_user(pool: &Pool, enabled: bool) -> Result<bool, InfraError> {
    if !enabled {
        return Ok(false);
    }

    initialize_canonical_principal(
        pool,
        SINGLE_USER_ACTOR_ID,
        SINGLE_USER_EMAIL,
        SINGLE_USER_NAME,
    )
    .await?;
    Ok(true)
}

pub(super) async fn initialize_canonical_principal(
    pool: &Pool,
    actor_id: &str,
    email: &str,
    name: &str,
) -> Result<(), InfraError> {
    let mut client = pool
        .get()
        .await
        .map_err(|error| InfraError::connect("取单用户初始化连接", error))?;
    let transaction = client
        .transaction()
        .await
        .map_err(|error| InfraError::query("开始单用户初始化事务", error))?;
    let affected = transaction
        .execute(
            "INSERT INTO public.users \
             (id,email,name,email_verified,groups,auth_generation) \
             VALUES($1,$2,$3,false,'{}'::text[],0) \
             ON CONFLICT(id) DO UPDATE SET \
               email=EXCLUDED.email,name=EXCLUDED.name,updated_at=clock_timestamp()",
            &[&actor_id, &email, &name],
        )
        .await
        .map_err(|error| InfraError::query("恢复单用户 canonical identity", error))?;
    if affected != 1 {
        return Err(InfraError::repository_invariant(
            "single_user_upsert_count_invalid",
        ));
    }

    let actor = ActorId::new(actor_id);
    // §6.1 直接裁决单用户唯一 principal 是 admin；多用户新身份才由 seed_role 判 floor。
    apply_role_plan(&transaction, &plan_set_role(&actor, Role::Admin)).await?;

    transaction
        .commit()
        .await
        .map_err(|error| InfraError::query("提交单用户初始化事务", error))?;
    Ok(())
}
