//! Authenticated actor-scoped per-run provider cost-budget use cases.

use async_trait::async_trait;
use openbot_contracts::auth::AuthContext;
use openbot_contracts::budget::{RunCostBudgetPreference, RunCostCapInput};
use openbot_contracts::error::AppError;

/// Validated positive cap in one explicit currency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunCostCap {
    currency: String,
    max_cost_micro_units: u64,
}

impl RunCostCap {
    /// Validate a closed wire/storage value.
    pub fn new(
        currency: String,
        max_cost_micro_units: u64,
    ) -> Result<Self, RunCostBudgetAdministrationError> {
        if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(RunCostBudgetAdministrationError::InvalidInput { field: "currency" });
        }
        if max_cost_micro_units == 0 || max_cost_micro_units > i64::MAX as u64 {
            return Err(RunCostBudgetAdministrationError::InvalidInput {
                field: "maxCostMicroUnits",
            });
        }
        Ok(Self {
            currency,
            max_cost_micro_units,
        })
    }

    /// Parse a canonical decimal-string API input without JavaScript numeric coercion.
    pub fn from_input(input: RunCostCapInput) -> Result<Self, RunCostBudgetAdministrationError> {
        let amount = input.max_cost_micro_units.as_bytes();
        if amount.is_empty()
            || amount.len() > 19
            || !matches!(amount[0], b'1'..=b'9')
            || !amount[1..].iter().all(u8::is_ascii_digit)
        {
            return Err(RunCostBudgetAdministrationError::InvalidInput {
                field: "maxCostMicroUnits",
            });
        }
        let parsed = input.max_cost_micro_units.parse::<u64>().map_err(|_| {
            RunCostBudgetAdministrationError::InvalidInput {
                field: "maxCostMicroUnits",
            }
        })?;
        Self::new(input.currency, parsed)
    }

    /// Exact three-letter currency code.
    #[must_use]
    pub fn currency(&self) -> &str {
        &self.currency
    }

    /// Positive cap in whole micro currency units.
    #[must_use]
    pub const fn max_cost_micro_units(&self) -> u64 {
        self.max_cost_micro_units
    }

    fn into_input(self) -> RunCostCapInput {
        RunCostCapInput {
            currency: self.currency,
            max_cost_micro_units: self.max_cost_micro_units.to_string(),
        }
    }
}

/// Stable persistence/use-case failure without actor ids or database text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RunCostBudgetAdministrationError {
    /// Closed input failed validation.
    #[error("run_cost_budget_invalid_input field={field}")]
    InvalidInput {
        /// Static field only.
        field: &'static str,
    },
    /// PostgreSQL dependency is unavailable.
    #[error("run_cost_budget_unavailable")]
    Unavailable,
    /// Stored data violates the closed shape.
    #[error("run_cost_budget_corrupt field={field}")]
    Corrupt {
        /// Static field only.
        field: &'static str,
    },
    /// Commit result is unknown; caller must re-read.
    #[error("run_cost_budget_commit_unknown")]
    CommitUnknown,
}

impl RunCostBudgetAdministrationError {
    /// Stable public application mapping.
    #[must_use]
    pub const fn into_app_error(self) -> AppError {
        match self {
            Self::InvalidInput { field } => AppError::MalformedPayload { field },
            Self::Unavailable | Self::Corrupt { .. } => AppError::DependencyUnavailable {
                dependency: "run_cost_budget",
            },
            Self::CommitUnknown => AppError::ReconciliationRequired { accepted: true },
        }
    }
}

/// Shared Server/Desktop actor-scoped budget persistence port.
#[async_trait]
pub trait RunCostBudgetAdministration: Send + Sync {
    /// Read the exact deployment/tenant/actor preference; absence means no user cap.
    async fn get(
        &self,
        auth: &AuthContext,
    ) -> Result<Option<RunCostCap>, RunCostBudgetAdministrationError>;

    /// Fully replace the exact actor preference; `None` deletes/disables it.
    async fn replace(
        &self,
        auth: &AuthContext,
        cap: Option<RunCostCap>,
    ) -> Result<Option<RunCostCap>, RunCostBudgetAdministrationError>;
}

/// Fail-closed default until a host injects PostgreSQL storage.
#[derive(Debug, Default)]
pub struct NoRunCostBudgetAdministration;

#[async_trait]
impl RunCostBudgetAdministration for NoRunCostBudgetAdministration {
    async fn get(
        &self,
        _auth: &AuthContext,
    ) -> Result<Option<RunCostCap>, RunCostBudgetAdministrationError> {
        Err(RunCostBudgetAdministrationError::Unavailable)
    }

    async fn replace(
        &self,
        _auth: &AuthContext,
        _cap: Option<RunCostCap>,
    ) -> Result<Option<RunCostCap>, RunCostBudgetAdministrationError> {
        Err(RunCostBudgetAdministrationError::Unavailable)
    }
}

/// Read the authenticated actor's budget as its closed wire form.
pub async fn get_run_cost_budget(
    port: &dyn RunCostBudgetAdministration,
    auth: &AuthContext,
) -> Result<RunCostBudgetPreference, AppError> {
    let cap = port
        .get(auth)
        .await
        .map_err(RunCostBudgetAdministrationError::into_app_error)?;
    Ok(RunCostBudgetPreference {
        cap: cap.map(RunCostCap::into_input),
    })
}

/// Validate and fully replace the authenticated actor's budget.
pub async fn replace_run_cost_budget(
    port: &dyn RunCostBudgetAdministration,
    auth: &AuthContext,
    preference: RunCostBudgetPreference,
) -> Result<RunCostBudgetPreference, AppError> {
    let cap = preference
        .cap
        .map(RunCostCap::from_input)
        .transpose()
        .map_err(RunCostBudgetAdministrationError::into_app_error)?;
    let stored = port
        .replace(auth, cap)
        .await
        .map_err(RunCostBudgetAdministrationError::into_app_error)?;
    Ok(RunCostBudgetPreference {
        cap: stored.map(RunCostCap::into_input),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakePort(Mutex<Vec<Option<RunCostCap>>>);

    #[async_trait]
    impl RunCostBudgetAdministration for FakePort {
        async fn get(
            &self,
            _auth: &AuthContext,
        ) -> Result<Option<RunCostCap>, RunCostBudgetAdministrationError> {
            Ok(None)
        }

        async fn replace(
            &self,
            _auth: &AuthContext,
            cap: Option<RunCostCap>,
        ) -> Result<Option<RunCostCap>, RunCostBudgetAdministrationError> {
            self.0.lock().unwrap().push(cap.clone());
            Ok(cap)
        }
    }

    fn auth() -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("actor"),
            [Role::User],
            AuthGeneration::new(1),
            false,
        )
    }

    #[tokio::test]
    async fn invalid_or_noncanonical_caps_never_reach_storage() {
        let port = FakePort::default();
        for (currency, amount, field) in [
            ("usd", "1", "currency"),
            ("USD", "0", "maxCostMicroUnits"),
            ("USD", "01", "maxCostMicroUnits"),
            ("USD", "9223372036854775808", "maxCostMicroUnits"),
        ] {
            assert_eq!(
                replace_run_cost_budget(
                    &port,
                    &auth(),
                    RunCostBudgetPreference {
                        cap: Some(RunCostCapInput {
                            currency: currency.to_owned(),
                            max_cost_micro_units: amount.to_owned(),
                        }),
                    },
                )
                .await,
                Err(AppError::MalformedPayload { field })
            );
        }
        assert!(port.0.lock().unwrap().is_empty());

        let stored = replace_run_cost_budget(
            &port,
            &auth(),
            RunCostBudgetPreference {
                cap: Some(RunCostCapInput {
                    currency: "USD".to_owned(),
                    max_cost_micro_units: "250000".to_owned(),
                }),
            },
        )
        .await
        .unwrap();
        assert_eq!(stored.cap.unwrap().max_cost_micro_units, "250000");
        assert_eq!(port.0.lock().unwrap().len(), 1);
    }
}
