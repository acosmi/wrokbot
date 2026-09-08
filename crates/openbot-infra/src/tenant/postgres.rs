//! Tenant Package 的 PostgreSQL 原子同步与 materialized membership 投影。

use std::collections::BTreeSet;

use async_trait::async_trait;
use deadpool_postgres::Pool;
use openbot_application::tenant::package::{
    LoadedTenantPackage, TenantAgentConfiguration, TenantAgentType, TenantPackageAudienceContext,
    TenantPackageCollision, TenantPackageStoreError, TenantPackageSyncReport,
    TenantPackageSynchronizer, TenantThemeStatus,
};
use openbot_domain::identity::groups::AudienceNote;
use postgres_types::FromSqlOwned;
use uuid::Uuid;

use crate::db::InfraError;
use crate::db::types::{AgentType, AgentVisibility};

/// PostgreSQL Tenant Package 同步适配器。
#[derive(Clone, Debug)]
pub struct PostgresTenantPackageSynchronizer {
    pool: Pool,
}

impl PostgresTenantPackageSynchronizer {
    /// 用共享连接池构造。
    #[must_use]
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TenantPackageSynchronizer for PostgresTenantPackageSynchronizer {
    async fn synchronize(
        &self,
        loaded: &LoadedTenantPackage,
        context: &TenantPackageAudienceContext,
        audiences: &[openbot_application::tenant::package::TenantChannelAudienceReport],
    ) -> Result<TenantPackageSyncReport, TenantPackageStoreError> {
        let package = &loaded.package;
        let expected_audiences: BTreeSet<_> = package
            .channels
            .iter()
            .map(|channel| channel.id.as_str())
            .collect();
        let actual_audiences: BTreeSet<_> = audiences
            .iter()
            .map(|report| report.channel_id.as_str())
            .collect();
        if expected_audiences != actual_audiences || audiences.len() != package.channels.len() {
            return Err(TenantPackageStoreError::Corrupt {
                field: "audience_report",
            });
        }

        let mut client = self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "tenant package 获取 PostgreSQL 连接失败");
            TenantPackageStoreError::Unavailable
        })?;
        let transaction = client.transaction().await.map_err(|error| {
            log_query("开始 tenant package 事务", error);
            TenantPackageStoreError::Unavailable
        })?;
        transaction
            .batch_execute(
                "LOCK TABLE public.deployment_packages,public.agents,public.agent_profiles,\
                 public.channels,public.channel_agents,public.channel_memberships \
                 IN SHARE ROW EXCLUSIVE MODE",
            )
            .await
            .map_err(|error| {
                log_query("锁定 tenant package 表", error);
                TenantPackageStoreError::Unavailable
            })?;

        let reserved: bool = transaction
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM public.agents WHERE id=ANY($1))",
                &[&vec!["fleet", "policy"]],
            )
            .await
            .map_err(|error| unavailable("检查 deployment route 保留 Agent", error))?
            .try_get(0)
            .map_err(|_| TenantPackageStoreError::Corrupt { field: "agent.id" })?;
        if reserved {
            return Err(TenantPackageStoreError::Collision {
                kind: TenantPackageCollision::ReservedAgent,
            });
        }

        let package_id: Uuid = transaction
            .query_one(
                "INSERT INTO public.deployment_packages(tenant_id,source_path,checksum,loaded_at) \
                 VALUES($1,$2,$3,clock_timestamp()) ON CONFLICT(tenant_id) DO UPDATE SET \
                 source_path=excluded.source_path,checksum=excluded.checksum,loaded_at=excluded.loaded_at \
                 RETURNING id",
                &[&package.tenant_id, &loaded.source_path, &loaded.checksum],
            )
            .await
            .map_err(|error| unavailable("upsert deployment package", error))?
            .try_get("id")
            .map_err(|_| TenantPackageStoreError::Corrupt {
                field: "deployment_packages.id",
            })?;

        preflight_agent_collisions(&transaction, loaded, package_id).await?;
        preflight_channel_collisions(&transaction, loaded, package_id).await?;

        for agent in &package.agents {
            let agent_type = match agent.agent_type {
                TenantAgentType::BuiltIn => AgentType::BuiltIn,
                TenantAgentType::RemoteAgUi => AgentType::RemoteAgUi,
            };
            let configuration = match &agent.configuration {
                TenantAgentConfiguration::BuiltIn {
                    system_prompt,
                    provider_source,
                } => {
                    serde_json::json!({
                        "systemPrompt": system_prompt,
                        "providerSource": provider_source.as_str(),
                    })
                }
                TenantAgentConfiguration::RemoteAgUi { endpoint } => {
                    serde_json::json!({"endpoint": endpoint})
                }
            };
            transaction
                .execute(
                    "INSERT INTO public.agents(id,name,type,configuration,package_id,updated_at) \
                     VALUES($1,$2,$3,$4,$5,clock_timestamp()) ON CONFLICT(id) DO UPDATE SET \
                     name=excluded.name,type=excluded.type,configuration=excluded.configuration,\
                     package_id=excluded.package_id,updated_at=excluded.updated_at",
                    &[
                        &agent.id,
                        &agent.name,
                        &agent_type,
                        &configuration,
                        &package_id,
                    ],
                )
                .await
                .map_err(|error| unavailable("upsert package agent", error))?;
            let avatar_seed = agent.avatar_seed.as_deref().unwrap_or(&agent.id);
            let visibility = AgentVisibility::Public;
            transaction
                .execute(
                    "INSERT INTO public.agent_profiles(\
                       agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at,updated_at) \
                     VALUES($1,NULL,$2,$3,$4,$5,NULL,clock_timestamp()) ON CONFLICT(agent_id) DO UPDATE SET \
                     owner_user_id=NULL,title=excluded.title,role_description=excluded.role_description,\
                     avatar_seed=excluded.avatar_seed,visibility=excluded.visibility,deleted_at=NULL,\
                     updated_at=excluded.updated_at",
                    &[
                        &agent.id,
                        &agent.title,
                        &agent.role_description,
                        &avatar_seed,
                        &visibility,
                    ],
                )
                .await
                .map_err(|error| unavailable("upsert package agent profile", error))?;
        }

        for channel in &package.channels {
            let groups: Vec<Option<String>> =
                channel.allowed_groups.iter().cloned().map(Some).collect();
            transaction
                .execute(
                    "INSERT INTO public.channels(\
                       id,name,description,suggested_prompts,allowed_groups,package_id,updated_at) \
                     VALUES($1,$2,$3,'{}',$4,$5,clock_timestamp()) ON CONFLICT(id) DO UPDATE SET \
                     name=excluded.name,description=excluded.description,\
                     allowed_groups=excluded.allowed_groups,package_id=excluded.package_id,\
                     updated_at=excluded.updated_at",
                    &[
                        &channel.id,
                        &channel.name,
                        &channel.description,
                        &groups,
                        &package_id,
                    ],
                )
                .await
                .map_err(|error| unavailable("upsert package channel", error))?;
            transaction
                .execute(
                    "DELETE FROM public.channel_agents WHERE channel_id=$1",
                    &[&channel.id],
                )
                .await
                .map_err(|error| unavailable("清理 package channel agents", error))?;
            for agent in &channel.permitted_agents {
                transaction
                    .execute(
                        "INSERT INTO public.channel_agents(channel_id,agent_id) VALUES($1,$2)",
                        &[&channel.id, agent],
                    )
                    .await
                    .map_err(|error| unavailable("写 package channel agent", error))?;
            }
        }

        let membership = reconcile_memberships(&transaction, loaded, context).await?;
        transaction.commit().await.map_err(|error| {
            log_query("提交 tenant package 事务", error);
            TenantPackageStoreError::Unavailable
        })?;

        Ok(TenantPackageSyncReport {
            tenant_id: package.tenant_id.clone(),
            agents: usize_to_u64(package.agents.len(), "agents_count")?,
            channels: usize_to_u64(package.channels.len(), "channels_count")?,
            memberships_granted: membership.granted,
            memberships_revoked: membership.revoked,
            generations_advanced: membership.generations,
            single_user_groups_ignored: audiences
                .iter()
                .all(|report| report.note == AudienceNote::SingleUserGroupsIgnored),
            knowledge_sources_compatibility_only: usize_to_u64(
                package.knowledge_sources.len(),
                "knowledge_count",
            )?,
            runtime_theme_ignored: package.theme_status
                == TenantThemeStatus::CompatibilityInputIgnored,
        })
    }
}

async fn preflight_agent_collisions(
    transaction: &tokio_postgres::Transaction<'_>,
    loaded: &LoadedTenantPackage,
    package_id: Uuid,
) -> Result<(), TenantPackageStoreError> {
    let ids: Vec<String> = loaded
        .package
        .agents
        .iter()
        .map(|agent| agent.id.clone())
        .collect();
    if ids.is_empty() {
        return Ok(());
    }
    let rows = transaction
        .query(
            "SELECT a.id,a.package_id,p.owner_user_id FROM public.agents a \
             LEFT JOIN public.agent_profiles p ON p.agent_id=a.id WHERE a.id=ANY($1) FOR UPDATE OF a",
            &[&ids],
        )
        .await
        .map_err(|error| unavailable("检查 package agent collision", error))?;
    for row in rows {
        let existing_package: Option<Uuid> = column(&row, "package_id")?;
        let owner: Option<String> = column(&row, "owner_user_id")?;
        match existing_package {
            None => {
                return Err(TenantPackageStoreError::Collision {
                    kind: TenantPackageCollision::UserAgent,
                });
            }
            Some(existing) if existing != package_id => {
                return Err(TenantPackageStoreError::Collision {
                    kind: TenantPackageCollision::OtherPackageAgent,
                });
            }
            Some(_) if owner.is_some() => {
                return Err(TenantPackageStoreError::Collision {
                    kind: TenantPackageCollision::UserProfile,
                });
            }
            Some(_) => {}
        }
    }
    Ok(())
}

async fn preflight_channel_collisions(
    transaction: &tokio_postgres::Transaction<'_>,
    loaded: &LoadedTenantPackage,
    package_id: Uuid,
) -> Result<(), TenantPackageStoreError> {
    let ids: Vec<String> = loaded
        .package
        .channels
        .iter()
        .map(|channel| channel.id.clone())
        .collect();
    if ids.is_empty() {
        return Ok(());
    }
    let rows = transaction
        .query(
            "SELECT id,package_id FROM public.channels WHERE id=ANY($1) FOR UPDATE",
            &[&ids],
        )
        .await
        .map_err(|error| unavailable("检查 package channel collision", error))?;
    for row in rows {
        let existing: Option<Uuid> = column(&row, "package_id")?;
        if existing != Some(package_id) {
            return Err(TenantPackageStoreError::Collision {
                kind: TenantPackageCollision::Channel,
            });
        }
    }
    Ok(())
}

#[derive(Default)]
struct MembershipCounts {
    granted: u64,
    revoked: u64,
    generations: u64,
}

async fn reconcile_memberships(
    transaction: &tokio_postgres::Transaction<'_>,
    loaded: &LoadedTenantPackage,
    context: &TenantPackageAudienceContext,
) -> Result<MembershipCounts, TenantPackageStoreError> {
    let channel_ids: Vec<String> = loaded
        .package
        .channels
        .iter()
        .map(|channel| channel.id.clone())
        .collect();
    if channel_ids.is_empty() {
        return Ok(MembershipCounts::default());
    }
    let user_rows = transaction
        .query(
            "SELECT u.id,u.groups,ra.email IS NULL AS active FROM public.users u \
             LEFT JOIN public.revoked_access ra ON ra.email=lower(u.email) ORDER BY u.id FOR UPDATE OF u",
            &[],
        )
        .await
        .map_err(|error| unavailable("读取 package membership 用户", error))?;
    let existing_rows = transaction
        .query(
            "SELECT channel_id,user_id FROM public.channel_memberships \
             WHERE channel_id=ANY($1) FOR UPDATE",
            &[&channel_ids],
        )
        .await
        .map_err(|error| unavailable("读取 package memberships", error))?;
    let existing: BTreeSet<(String, String)> = existing_rows
        .iter()
        .map(|row| Ok((column(row, "channel_id")?, column(row, "user_id")?)))
        .collect::<Result<_, TenantPackageStoreError>>()?;
    let mut desired = BTreeSet::new();
    for row in &user_rows {
        let user_id: String = column(row, "id")?;
        let active: bool = column(row, "active")?;
        let groups: Vec<Option<String>> = column(row, "groups")?;
        let groups: BTreeSet<String> = groups
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or(TenantPackageStoreError::Corrupt {
                field: "users.groups",
            })?
            .into_iter()
            .collect();
        if !active {
            continue;
        }
        for channel in &loaded.package.channels {
            let included = match context {
                TenantPackageAudienceContext::SingleUser { principal } => {
                    principal.as_str() == user_id
                }
                TenantPackageAudienceContext::MultiUser { .. } => {
                    // users.groups 是上次已验证登录写下的规范化投影，但 0015 没有持久化“由哪家
                    // provider/哪档 normalization 产生”。包同步因此只做逐字匹配：可能暂时
                    // 少授予，绝不借另一家 IdP 的规则扩大等价类；下次登录会用权威 mapping
                    // 经 project_membership 补齐。`all` 不依赖该 provenance，照常全量 provision。
                    channel.audience.is_everyone()
                        || channel
                            .audience
                            .named_groups()
                            .iter()
                            .any(|group| groups.contains(group))
                }
            };
            if included {
                desired.insert((channel.id.clone(), user_id.clone()));
            }
        }
    }

    let grants: Vec<_> = desired.difference(&existing).cloned().collect();
    let revokes: Vec<_> = existing.difference(&desired).cloned().collect();
    for (channel, user) in &revokes {
        transaction
            .execute(
                "DELETE FROM public.channel_memberships WHERE channel_id=$1 AND user_id=$2",
                &[channel, user],
            )
            .await
            .map_err(|error| unavailable("撤销 package membership", error))?;
    }
    for (channel, user) in &grants {
        transaction
            .execute(
                "INSERT INTO public.channel_memberships(channel_id,user_id,created_at) \
                 VALUES($1,$2,clock_timestamp()) ON CONFLICT(channel_id,user_id) DO NOTHING",
                &[channel, user],
            )
            .await
            .map_err(|error| unavailable("写 package membership", error))?;
    }
    let revoked_users: BTreeSet<&str> = revokes.iter().map(|(_, user)| user.as_str()).collect();
    for user in &revoked_users {
        let advanced = transaction
            .execute(
                "UPDATE public.users SET auth_generation=coalesce(auth_generation,0)+1,\
                 updated_at=clock_timestamp() WHERE id=$1 AND coalesce(auth_generation,0)<9223372036854775807",
                &[user],
            )
            .await
            .map_err(|error| unavailable("推进 package membership generation", error))?;
        if advanced != 1 {
            return Err(TenantPackageStoreError::Corrupt {
                field: "users.auth_generation",
            });
        }
        transaction
            .execute("DELETE FROM public.sessions WHERE user_id=$1", &[user])
            .await
            .map_err(|error| unavailable("清理 package membership sessions", error))?;
    }
    Ok(MembershipCounts {
        granted: usize_to_u64(grants.len(), "membership_grants")?,
        revoked: usize_to_u64(revokes.len(), "membership_revokes")?,
        generations: usize_to_u64(revoked_users.len(), "generation_count")?,
    })
}

fn column<T: FromSqlOwned>(
    row: &tokio_postgres::Row,
    name: &'static str,
) -> Result<T, TenantPackageStoreError> {
    row.try_get(name)
        .map_err(|_| TenantPackageStoreError::Corrupt { field: name })
}

fn unavailable(context: &'static str, error: tokio_postgres::Error) -> TenantPackageStoreError {
    log_query(context, error);
    TenantPackageStoreError::Unavailable
}

fn log_query(context: &'static str, error: tokio_postgres::Error) {
    let safe = InfraError::query(context, error);
    tracing::error!(error = %safe, "tenant package PostgreSQL 事务失败");
}

fn usize_to_u64(value: usize, field: &'static str) -> Result<u64, TenantPackageStoreError> {
    u64::try_from(value).map_err(|_| TenantPackageStoreError::Corrupt { field })
}
