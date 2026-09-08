//! Built-in Agent lifecycle → append-only PostgreSQL audit hash chain。

use async_trait::async_trait;
use openbot_application::{AgentAudit, AgentAuditError, AgentAuditKind, RunExecutionLease};
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload};
use openbot_domain::vault::SecretBytes;

use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};

/// Production lifecycle audit writer；checkpoint key Debug/Drop 由 SecretBytes 管理。
pub struct PostgresAgentAudit {
    pool: deadpool_postgres::Pool,
    checkpoint_key: SecretBytes,
}

impl PostgresAgentAudit {
    /// Construct with the same domain-separated audit key as every other writer。
    pub fn new(
        pool: deadpool_postgres::Pool,
        checkpoint_key: Vec<u8>,
    ) -> Result<Self, AgentAuditError> {
        if checkpoint_key.is_empty() {
            return Err(AgentAuditError::Unavailable);
        }
        Ok(Self {
            pool,
            checkpoint_key: SecretBytes::new(checkpoint_key),
        })
    }
}

impl core::fmt::Debug for PostgresAgentAudit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PostgresAgentAudit")
            .field("checkpoint_key", &"[redacted]")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl AgentAudit for PostgresAgentAudit {
    async fn record(
        &self,
        lease: &RunExecutionLease,
        kind: AgentAuditKind,
    ) -> Result<(), AgentAuditError> {
        let mut client = self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "Agent audit 获取 PostgreSQL 连接失败");
            AgentAuditError::Unavailable
        })?;
        let transaction = client.transaction().await.map_err(|error| {
            tracing::error!(error = %error, "Agent audit 开始事务失败");
            AgentAuditError::Unavailable
        })?;
        let (id, created_at) = next_event_coordinates(&transaction)
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "Agent audit 分配坐标失败");
                AgentAuditError::Unavailable
            })?;
        let (event_type, payload) = audit_shape(kind)?;
        let target_id = AuditIdentifier::new(lease.run_id().as_str())
            .map_err(|_| AgentAuditError::Unavailable)?;
        let event = AuditEvent {
            id,
            actor: Some(lease.actor_id().clone()),
            event_type,
            target_kind: AuditLabel::new("run"),
            target_id: Some(target_id),
            payload,
            created_at,
        };
        append_event_in_transaction(&transaction, &event, self.checkpoint_key.expose())
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "Agent audit append 失败");
                AgentAuditError::Unavailable
            })?;
        transaction.commit().await.map_err(|error| {
            tracing::error!(error = %error, "Agent audit commit 结果未知");
            AgentAuditError::Unavailable
        })?;
        Ok(())
    }
}

fn audit_shape(kind: AgentAuditKind) -> Result<(AuditEventType, AuditPayload), AgentAuditError> {
    match kind {
        AgentAuditKind::Invoked => Ok((AuditEventType::AGENT_INVOKED, AuditPayload::empty())),
        AgentAuditKind::StreamStalled => Ok((
            AuditEventType::AGENT_STREAM_STALLED,
            AuditPayload::from_facts([AuditFact::ErrorCode(AuditLabel::new(
                "agent_stream_stalled",
            ))])
            .map_err(|_| AgentAuditError::Unavailable)?,
        )),
        AgentAuditKind::RunDeadlineExceeded => Ok((
            AuditEventType::AGENT_RUN_DEADLINE_EXCEEDED,
            AuditPayload::from_facts([AuditFact::ErrorCode(AuditLabel::new(
                "run_deadline_exceeded",
            ))])
            .map_err(|_| AgentAuditError::Unavailable)?,
        )),
        AgentAuditKind::RunCostBudgetUnpriced => cost_budget_refusal("run_cost_budget_unpriced"),
        AgentAuditKind::RunCostBudgetCurrencyMismatch => {
            cost_budget_refusal("run_cost_budget_currency_mismatch")
        }
        AgentAuditKind::RunCostBudgetExceeded => cost_budget_refusal("run_cost_budget_exceeded"),
    }
}

fn cost_budget_refusal(
    code: &'static str,
) -> Result<(AuditEventType, AuditPayload), AgentAuditError> {
    Ok((
        AuditEventType::AGENT_RUN_COST_BUDGET_REFUSED,
        AuditPayload::from_facts([AuditFact::ErrorCode(AuditLabel::new(code))])
            .map_err(|_| AgentAuditError::Unavailable)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_payloads_are_allowlisted_and_never_accept_content() {
        for kind in [
            AgentAuditKind::Invoked,
            AgentAuditKind::StreamStalled,
            AgentAuditKind::RunDeadlineExceeded,
            AgentAuditKind::RunCostBudgetUnpriced,
            AgentAuditKind::RunCostBudgetCurrencyMismatch,
            AgentAuditKind::RunCostBudgetExceeded,
        ] {
            let (_, payload) = audit_shape(kind).unwrap();
            assert!(payload.len() <= 1);
            assert!(payload.get("content").is_none());
            assert!(payload.get("prompt").is_none());
        }
    }
}
