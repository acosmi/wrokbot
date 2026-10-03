//! Current R398 source visibility and R423 workspace observation through one PG statement.
//!
//! These private-construction facts describe that statement's snapshot. They are not a cached
//! permission, a byte handle, an effect receipt or authority for a later artifact transaction.

use std::sync::{Arc, OnceLock};

use openbot_contracts::artifacts::is_valid_artifact_identity;
use openbot_contracts::auth::AuthContext;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, RunId, ThreadId};
use openbot_domain::artifact::{ArtifactWorkspaceKey, ArtifactWorkspaceKind};
use time::OffsetDateTime;

use crate::artifact_registry::ArtifactDatasetRegistry;
use crate::thread_directory::reconciliation_visibility::VISIBLE_RUN;

const SOURCE_SUFFIX: &str = r"
SELECT statement_timestamp() AS observed_at,
       CASE WHEN s.valid THEN v.thread_id END AS source_thread_id,
       CASE WHEN s.valid THEN v.run_id END AS source_run_id,
       CASE WHEN s.valid THEN v.actor_id END AS owner_actor_id,
       CASE WHEN s.valid THEN v.bot_id END AS source_bot_id,
       CASE WHEN s.valid THEN
         CASE t.anchor_kind WHEN 'channel' THEN 'channel' WHEN 'direct_bot' THEN 'thread' END
       END AS workspace_kind,
       CASE WHEN s.valid THEN
         CASE t.anchor_kind WHEN 'channel' THEN t.anchor_id WHEN 'direct_bot' THEN t.thread_id END
       END AS workspace_id,
       CASE WHEN d.valid THEN b.dataset_id END AS dataset_id,
       NOT s.valid AS bad_source_shape,
       NOT d.valid AS bad_dataset_binding
FROM visible_run v
JOIN public.threads t ON t.thread_id=v.thread_id
LEFT JOIN openbot_internal.artifact_dataset_bindings b
  ON b.deployment_id=$4 AND b.tenant_id=$5
CROSS JOIN LATERAL (
 SELECT coalesce(
   octet_length(v.thread_id) BETWEEN 1 AND 512
   AND v.thread_id !~ U&'[\0001-\001F\007F-\009F]'
   AND octet_length(v.run_id) BETWEEN 1 AND 512
   AND v.run_id !~ U&'[\0001-\001F\007F-\009F]'
   AND octet_length(v.actor_id) BETWEEN 1 AND 512
   AND v.actor_id !~ U&'[\0001-\001F\007F-\009F]'
   AND octet_length(v.bot_id) BETWEEN 1 AND 512
   AND v.bot_id !~ U&'[\0001-\001F\007F-\009F]'
   AND octet_length(t.anchor_id) BETWEEN 1 AND 512
   AND t.anchor_id !~ U&'[\0001-\001F\007F-\009F]'
   AND t.anchor_kind IN ('channel','direct_bot'),false) AS valid
) s
CROSS JOIN LATERAL (
 SELECT coalesce(
   b.dataset_id=$7 AND b.binding_schema=1 AND b.initial_origin=$8 AND b.created_at=$9
   AND octet_length(b.dataset_id) BETWEEN 1 AND 512
   AND b.dataset_id !~ U&'[\0001-\001F\007F-\009F]',false) AS valid
) d
";

/// Stable source-observation failures, independent of an eventual transport DTO.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactSourceError {
    /// The selector does not satisfy the existing UUID-thread/opaque-run bounds.
    #[error("artifact_source_invalid_input")]
    InvalidInput { field: &'static str },
    /// Missing, wrong namespace or currently invisible sources share this closed result.
    #[error("artifact_source_not_visible")]
    NotVisible,
    /// The owned PostgreSQL pool or statement is unavailable.
    #[error("artifact_source_unavailable")]
    Unavailable,
    /// A visible source has a malformed shape or the immutable dataset tuple has changed.
    #[error("artifact_source_corrupt")]
    Corrupt { field: &'static str },
}

/// A current, bounded source/workspace fact. No public constructor or serialization authority.
pub struct VerifiedArtifactSource {
    thread_id: ThreadId,
    run_id: RunId,
    owner_actor_id: ActorId,
    source_bot_id: BotId,
    workspace: ArtifactWorkspaceKey,
    dataset_id: String,
    observed_at: OffsetDateTime,
    _dataset_owner: Arc<()>,
}

impl VerifiedArtifactSource {
    #[must_use]
    pub const fn thread_id(&self) -> &ThreadId {
        &self.thread_id
    }
    #[must_use]
    pub const fn run_id(&self) -> &RunId {
        &self.run_id
    }
    #[must_use]
    pub const fn owner_actor_id(&self) -> &ActorId {
        &self.owner_actor_id
    }
    #[must_use]
    pub const fn source_bot_id(&self) -> &BotId {
        &self.source_bot_id
    }
    #[must_use]
    pub const fn workspace(&self) -> &ArtifactWorkspaceKey {
        &self.workspace
    }
    #[must_use]
    pub fn dataset_id(&self) -> &str {
        &self.dataset_id
    }
    #[must_use]
    pub const fn observed_at(&self) -> OffsetDateTime {
        self.observed_at
    }
}

impl core::fmt::Debug for VerifiedArtifactSource {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VerifiedArtifactSource(<observed>)")
    }
}

impl ArtifactDatasetRegistry {
    /// Recheck the current actor and the owned dataset tuple in the same statement snapshot.
    ///
    /// Run status is deliberately not restricted to Unknown. Sharing a channel workspace does
    /// not widen R398's original run-owner predicate, including for administrators.
    pub async fn observe_source(
        &self,
        auth: &AuthContext,
        thread: &ThreadId,
        run: &RunId,
    ) -> Result<VerifiedArtifactSource, ArtifactSourceError> {
        if !ThreadIdentity::is_plausible(thread) {
            return Err(ArtifactSourceError::InvalidInput { field: "thread_id" });
        }
        if !is_valid_artifact_identity(run.as_str()) {
            return Err(ArtifactSourceError::InvalidInput { field: "run_id" });
        }
        if auth.deployment().as_str() != self.binding().deployment_id()
            || auth.tenant().as_str() != self.binding().tenant_id()
        {
            return Err(ArtifactSourceError::NotVisible);
        }
        let generation = i64::try_from(auth.auth_generation().get())
            .map_err(|_| ArtifactSourceError::NotVisible)?;
        let created_at = self.binding().created_at();
        let client = self
            .pool()
            .get()
            .await
            .map_err(|_| ArtifactSourceError::Unavailable)?;
        let row = client
            .query_opt(
                source_sql(),
                &[
                    &thread.as_str(),
                    &run.as_str(),
                    &auth.actor().as_str(),
                    &auth.deployment().as_str(),
                    &auth.tenant().as_str(),
                    &generation,
                    &self.binding().dataset_id(),
                    &self.binding().initial_origin(),
                    &created_at,
                ],
            )
            .await
            .map_err(|_| ArtifactSourceError::Unavailable)?
            .ok_or(ArtifactSourceError::NotVisible)?;
        let bad_source: bool = row
            .try_get("bad_source_shape")
            .map_err(|_| corrupt("source_shape"))?;
        let bad_dataset: bool = row
            .try_get("bad_dataset_binding")
            .map_err(|_| corrupt("dataset_binding"))?;
        if bad_source {
            return Err(corrupt("source_shape"));
        }
        if bad_dataset {
            return Err(corrupt("dataset_binding"));
        }
        let thread_id: String = row
            .try_get("source_thread_id")
            .map_err(|_| corrupt("thread_id"))?;
        let run_id: String = row
            .try_get("source_run_id")
            .map_err(|_| corrupt("run_id"))?;
        let owner_actor_id: String = row
            .try_get("owner_actor_id")
            .map_err(|_| corrupt("actor_id"))?;
        let source_bot_id: String = row
            .try_get("source_bot_id")
            .map_err(|_| corrupt("bot_id"))?;
        let workspace_kind: String = row
            .try_get("workspace_kind")
            .map_err(|_| corrupt("workspace_kind"))?;
        let workspace_id: String = row
            .try_get("workspace_id")
            .map_err(|_| corrupt("workspace_id"))?;
        let dataset_id: String = row
            .try_get("dataset_id")
            .map_err(|_| corrupt("dataset_id"))?;
        let observed_at = row
            .try_get("observed_at")
            .map_err(|_| corrupt("observed_at"))?;
        for value in [
            &thread_id,
            &run_id,
            &owner_actor_id,
            &source_bot_id,
            &dataset_id,
        ] {
            if !is_valid_artifact_identity(value) {
                return Err(corrupt("source_shape"));
            }
        }
        if thread_id != thread.as_str()
            || run_id != run.as_str()
            || owner_actor_id != auth.actor().as_str()
            || dataset_id != self.binding().dataset_id()
        {
            return Err(corrupt("source_binding"));
        }
        let kind = match workspace_kind.as_str() {
            "channel" => ArtifactWorkspaceKind::Channel,
            "thread" => ArtifactWorkspaceKind::Thread,
            _ => return Err(corrupt("workspace_kind")),
        };
        let workspace =
            ArtifactWorkspaceKey::new(kind, &workspace_id).map_err(|_| corrupt("workspace_id"))?;
        Ok(VerifiedArtifactSource {
            thread_id: ThreadId::new(thread_id),
            run_id: RunId::new(run_id),
            owner_actor_id: ActorId::new(owner_actor_id),
            source_bot_id: BotId::new(source_bot_id),
            workspace,
            dataset_id,
            observed_at,
            _dataset_owner: self.owner(),
        })
    }
}

fn source_sql() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| format!("{VISIBLE_RUN}{SOURCE_SUFFIX}"))
        .as_str()
}

const fn corrupt(field: &'static str) -> ArtifactSourceError {
    ArtifactSourceError::Corrupt { field }
}
