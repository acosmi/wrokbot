//! Actor-scoped remote AG-UI interrupt list/resolve use cases.

use std::collections::BTreeSet;

use openbot_contracts::auth::AuthContext;
use openbot_contracts::error::AppError;
use openbot_contracts::remote_interrupt::{
    PendingRemoteInterrupt, PendingRemoteInterrupts, RemoteInterruptAnswer,
    RemoteInterruptAnswerStatus, RemoteInterruptResolved, is_remote_interrupt_request_id,
};
use serde_json::Value;
use time::OffsetDateTime;

use crate::{
    ProviderRemoteResumeEntry, ProviderRemoteResumeStatus, RemoteInterruptCoordinator,
    RemoteInterruptError,
};

const MAX_PENDING_REMOTE_INTERRUPTS: usize = 100;

/// List pending rows after the adapter has freshly validated actor authority.
pub async fn list_pending_remote_interrupts(
    port: &dyn RemoteInterruptCoordinator,
    auth: &AuthContext,
) -> Result<PendingRemoteInterrupts, AppError> {
    let rows = port
        .list_pending(auth)
        .await
        .map_err(remote_interrupt_error)?;
    if rows.len() > MAX_PENDING_REMOTE_INTERRUPTS {
        return Err(dependency_corrupt());
    }
    let mut request_ids = BTreeSet::new();
    let mut interrupts = Vec::with_capacity(rows.len());
    for row in rows {
        if !request_ids.insert(row.request_id().to_owned()) {
            return Err(dependency_corrupt());
        }
        let payload = row.untrusted_payload();
        let Some(object) = payload.as_object() else {
            return Err(dependency_corrupt());
        };
        let allowed = [
            "id",
            "reason",
            "message",
            "toolCallId",
            "responseSchema",
            "expiresAt",
            "metadata",
        ];
        if object.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err(dependency_corrupt());
        }
        let reason = object
            .get("reason")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(dependency_corrupt)?
            .to_owned();
        let message = match object.get("message") {
            Some(Value::String(value)) => Some(value.clone()),
            Some(_) => return Err(dependency_corrupt()),
            None => None,
        };
        let response_schema = match object.get("responseSchema") {
            Some(value) if value.is_object() => Some(value.clone()),
            Some(_) => return Err(dependency_corrupt()),
            None => None,
        };
        interrupts.push(PendingRemoteInterrupt {
            request_id: row.request_id().to_owned(),
            run_id: row.run_id().to_owned(),
            agent_id: row.bot_id().to_owned(),
            untrusted_reason: reason,
            untrusted_message: message,
            untrusted_response_schema: response_schema,
            requested_at_ms: unix_millis(row.requested_at())?,
            expires_at_ms: unix_millis(row.expires_at())?,
        });
    }
    Ok(PendingRemoteInterrupts { interrupts })
}

/// Validate a closed answer and call the one durable authority port.
pub async fn resolve_remote_interrupt(
    port: &dyn RemoteInterruptCoordinator,
    auth: &AuthContext,
    request_id: String,
    answer: RemoteInterruptAnswer,
) -> Result<RemoteInterruptResolved, AppError> {
    if !is_remote_interrupt_request_id(&request_id)
        || (answer.status == RemoteInterruptAnswerStatus::Cancelled && answer.payload.is_some())
    {
        return Err(AppError::MalformedPayload {
            field: "remote_interrupt",
        });
    }
    let status = match answer.status {
        RemoteInterruptAnswerStatus::Resolved => ProviderRemoteResumeStatus::Resolved,
        RemoteInterruptAnswerStatus::Cancelled => ProviderRemoteResumeStatus::Cancelled,
    };
    ProviderRemoteResumeEntry::new("validation".to_owned(), status, answer.payload.clone())
        .map_err(|_| AppError::MalformedPayload {
            field: "remote_interrupt_payload",
        })?;
    let receipt = port
        .resolve(auth, &request_id, status, answer.payload)
        .await
        .map_err(remote_interrupt_error)?;
    if receipt.request_id() != request_id || receipt.status() != status {
        return Err(dependency_corrupt());
    }
    Ok(RemoteInterruptResolved {
        request_id,
        status: answer.status,
        replayed: receipt.replayed(),
    })
}

fn unix_millis(value: OffsetDateTime) -> Result<i64, AppError> {
    i64::try_from(value.unix_timestamp_nanos() / 1_000_000).map_err(|_| dependency_corrupt())
}

fn remote_interrupt_error(error: RemoteInterruptError) -> AppError {
    match error {
        RemoteInterruptError::Stale => AppError::NotVisible,
        RemoteInterruptError::Conflict => AppError::RequestConflict {
            resource: "remote_interrupt",
        },
        RemoteInterruptError::CommitUnknown => AppError::ReconciliationRequired { accepted: false },
        RemoteInterruptError::Unavailable | RemoteInterruptError::Corrupt { .. } => {
            dependency_corrupt()
        }
    }
}

const fn dependency_corrupt() -> AppError {
    AppError::DependencyUnavailable {
        dependency: "remote_interrupts",
    }
}
