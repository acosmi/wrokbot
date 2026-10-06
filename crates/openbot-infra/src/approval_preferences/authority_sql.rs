//! 实际当前 actor/Bot/Thread/Host 行的一个 RC statement，以及按原来源取得的共享锁。
//! 所有参数只来自 repository namespace、原 AuthContext 和已验证的完整键。

use std::sync::OnceLock;

pub(super) const LOCK_ACTOR: &str = "SELECT id FROM public.users WHERE id=$1 FOR SHARE";
pub(super) const LOCK_BOT: &str = "SELECT id FROM public.agents WHERE id=$1 FOR SHARE NOWAIT";
pub(super) const LOCK_PROFILE: &str =
    "SELECT agent_id FROM public.agent_profiles WHERE agent_id=$1 FOR SHARE NOWAIT";
pub(super) const LOCK_PACKAGE: &str =
    "SELECT id FROM public.deployment_packages WHERE id=$1 FOR SHARE NOWAIT";
pub(super) const LOCK_THREAD: &str = "SELECT thread_id FROM public.threads \
    WHERE thread_id=$1 AND deployment_id=$2 AND tenant_id=$3 AND status<>'deleted' \
    FOR SHARE NOWAIT";
pub(super) const LOCK_THREAD_MEMBER: &str = "SELECT thread_id FROM public.thread_memberships \
    WHERE thread_id=$1 AND user_id=$2 FOR SHARE NOWAIT";
pub(super) const LOCK_CHANNEL: &str = "SELECT id FROM public.channels WHERE id=$1 FOR SHARE NOWAIT";
pub(super) const LOCK_CHANNEL_MEMBER: &str = "SELECT channel_id FROM public.channel_memberships \
    WHERE channel_id=$1 AND user_id=$2 FOR SHARE NOWAIT";
pub(super) const LOCK_CHANNEL_BOT: &str = "SELECT channel_id FROM public.channel_agents \
    WHERE channel_id=$1 AND agent_id=$2 FOR SHARE NOWAIT";

// advisory 只串行化争用；存储唯一性和 CAS 始终使用完整六键，碰撞不授予任何其他键的权限。
pub(super) const KEY_LOCK_SEED: i64 = 0x4150_5052_4546_3031;
pub(super) const LOCK_KEY: &str = "SELECT pg_advisory_xact_lock(hashtextextended(\
    jsonb_build_array($1::text,$2::text,$3::text,$4::text,$5::text,$6::text)::text,$7))";

pub(super) const ROW_COLUMNS: &str = "preference_id,deployment_id,tenant_id,actor_id,bot_id,\
    target_kind,target_id,tool_name,effect,preference,revision,created_at,updated_at";

pub(super) const ROW_KEY: &str = "deployment_id=$1 AND tenant_id=$2 AND actor_id=$3 \
    AND bot_id=$4 AND target_kind=$5 AND target_id=$6";

pub(super) fn row_for_update() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| {
        format!(
            "SELECT {ROW_COLUMNS} FROM openbot_internal.approval_preferences \
         WHERE {ROW_KEY} FOR UPDATE"
        )
    })
    .as_str()
}

pub(super) fn insert() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| {
        format!(
            "WITH stamp AS MATERIALIZED (SELECT clock_timestamp() AS at) \
         INSERT INTO openbot_internal.approval_preferences \
         (deployment_id,tenant_id,actor_id,bot_id,target_kind,target_id,\
          preference_id,tool_name,effect,preference,revision,created_at,updated_at) \
         SELECT $1,$2,$3,$4,$5,$6,$7,'remember','write',$8,1,at,at FROM stamp \
         RETURNING {ROW_COLUMNS}"
        )
    })
    .as_str()
}

pub(super) fn update() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| {
        format!(
            "UPDATE openbot_internal.approval_preferences \
         SET preference=$8,revision=$9,updated_at=clock_timestamp() \
         WHERE {ROW_KEY} AND revision=$7 RETURNING {ROW_COLUMNS}"
        )
    })
    .as_str()
}

/// 一行联合观察；Session、权限与来源没有分成旧事务或不同 snapshot。
pub(super) fn current(desktop: bool) -> &'static str {
    static SERVER: OnceLock<String> = OnceLock::new();
    static DESKTOP: OnceLock<String> = OnceLock::new();
    let slot = if desktop { &DESKTOP } else { &SERVER };
    slot.get_or_init(|| {
        let (canary_columns, canary_join) = if desktop {
            (
                ",pcs.system_identifier::text AS preference_database_system_identifier,\
                 d.oid AS preference_database_oid,\
                 CASE WHEN octet_length(c.dataset_id)=32 THEN c.dataset_id END AS preference_canary_dataset,\
                 CASE WHEN octet_length(c.deployment_id) BETWEEN 1 AND 512 THEN c.deployment_id END AS preference_canary_deployment,\
                 CASE WHEN octet_length(c.tenant_id) BETWEEN 1 AND 512 THEN c.tenant_id END AS preference_canary_tenant,\
                 CASE WHEN octet_length(c.key_id)=32 THEN c.key_id END AS preference_canary_key,\
                 c.key_version AS preference_canary_key_version,c.canary_schema AS preference_canary_schema,\
                 CASE WHEN octet_length(c.encrypted_canary) BETWEEN 1 AND 4096 THEN c.encrypted_canary END AS preference_canary_encrypted",
                " LEFT JOIN pg_catalog.pg_control_system() pcs ON true \
                  LEFT JOIN pg_catalog.pg_database d ON d.datname=current_database() \
                  LEFT JOIN openbot_internal.desktop_vault_canaries c \
                    ON c.deployment_id=$1 AND c.tenant_id=$2 AND c.key_version=1",
            )
        } else { ("", "") };
        format!(r"/* remember_preference_current_authority */
          SELECT u.id AS current_actor,u.auth_generation AS current_generation,
            CASE WHEN octet_length(u.email) BETWEEN 1 AND 512 THEN u.email END AS current_email,
            EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) AS denied,
            ARRAY(SELECT ur.role::text FROM public.user_roles ur
                  WHERE ur.user_id=u.id ORDER BY ur.role::text) AS current_roles,
            b.package_id AS bot_package,
            t.thread_id AS source_thread,t.anchor_kind AS source_kind,t.anchor_id AS source_anchor,
            ch.package_id AS channel_package,
            s.id AS session_id,s.user_id AS session_user,s.token AS session_token,
            s.created_at AS session_created,s.updated_at AS session_updated,
            s.expires_at AS session_expires,s.auth_generation AS session_generation,
            coalesce(u.id=$3
              AND EXISTS(SELECT 1 FROM public.user_roles ur
                         WHERE ur.user_id=u.id AND ur.role IN ('user','admin'))
              AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email))
              AND p.agent_id=b.id AND p.deleted_at IS NULL
              AND (p.visibility='public' OR p.owner_user_id=$3)
              AND (b.package_id IS NULL OR (bp.id=b.package_id AND bp.tenant_id=$2))
              AND ($5::text IN ('memory_user','memory_bot') OR
                ($5='memory_thread' AND t.status<>'deleted' AND
                  ((t.anchor_kind='direct_bot' AND t.anchor_id=b.id AND EXISTS(
                     SELECT 1 FROM public.thread_memberships tm
                     WHERE tm.thread_id=t.thread_id AND tm.user_id=$3))
                   OR (t.anchor_kind='channel' AND ch.id=t.anchor_id
                       AND (ch.package_id IS NULL OR (cp.id=ch.package_id AND cp.tenant_id=$2))
                       AND EXISTS(SELECT 1 FROM public.channel_memberships cm
                                  WHERE cm.channel_id=ch.id AND cm.user_id=$3)
                       AND EXISTS(SELECT 1 FROM public.channel_agents ca
                                  WHERE ca.channel_id=ch.id AND ca.agent_id=b.id))))),false) AS source_visible
          {canary_columns}
          FROM (SELECT 1) anchor
          LEFT JOIN public.users u ON u.id=$3
          LEFT JOIN public.agents b ON b.id=$4
          LEFT JOIN public.agent_profiles p ON p.agent_id=b.id
          LEFT JOIN public.deployment_packages bp ON bp.id=b.package_id
          LEFT JOIN public.threads t ON $5='memory_thread' AND t.thread_id=$6
            AND t.deployment_id=$1 AND t.tenant_id=$2
          LEFT JOIN public.channels ch ON t.anchor_kind='channel' AND ch.id=t.anchor_id
          LEFT JOIN public.deployment_packages cp ON cp.id=ch.package_id
          LEFT JOIN public.sessions s ON s.id=$7::text AND s.user_id=u.id
          {canary_join}")
    }).as_str()
}
