//! Recall authority has two linearization points: the actor row is held through the read
//! transaction; explicit contexts and candidate memories share one final SQL snapshot.
//! Context rows are not locked, avoiding a user/package lock inversion with package sync.

/// Internal parameters match recall's candidate query: tenant, actor, bot, thread and deployment
/// are $1, $2, $3, $4 and $11. The caller must LEFT JOIN its candidates onto this single bool row
/// to distinguish invisible context (404) from visible context without matching memories (empty).
pub(super) const CONTEXT_CTE: &str = "WITH recall_authority AS (
    SELECT
      ($4::text IS NULL OR EXISTS(
        SELECT 1 FROM public.threads t
        WHERE t.thread_id=$4 AND t.tenant_id=$1 AND t.deployment_id=$11
          AND t.status<>'deleted' AND (
            (t.anchor_kind='direct_bot' AND EXISTS(
              SELECT 1 FROM public.thread_memberships tm
              WHERE tm.thread_id=t.thread_id AND tm.user_id=$2))
            OR (t.anchor_kind='channel' AND EXISTS(
              SELECT 1 FROM public.channel_memberships cm
              JOIN public.channels c ON c.id=cm.channel_id
              LEFT JOIN public.deployment_packages cp ON cp.id=c.package_id
              WHERE c.id=t.anchor_id AND cm.user_id=$2
                AND (c.package_id IS NULL OR cp.tenant_id=$1)))
          )))
      AND ($3::text IS NULL OR EXISTS(
        SELECT 1 FROM public.agents a
        JOIN public.agent_profiles p ON p.agent_id=a.id
        LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id
        WHERE a.id=$3 AND p.deleted_at IS NULL
          AND (p.visibility='public' OR p.owner_user_id=$2)
          AND (a.package_id IS NULL OR dp.tenant_id=$1)
      )) AS authorized
)";
