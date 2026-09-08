//! PostgreSQL actor-scoped per-run provider cost-budget persistence.

use async_trait::async_trait;
use openbot_application::{
    RunCostBudgetAdministration, RunCostBudgetAdministrationError, RunCostCap,
};
use openbot_contracts::auth::AuthContext;
use tokio_postgres::Row;

/// Production cross-device cost-budget store used by both Server and Desktop.
#[derive(Clone)]
pub struct PostgresRunCostBudgetAdministration {
    pool: deadpool_postgres::Pool,
}

impl PostgresRunCostBudgetAdministration {
    /// Construct from the shared PostgreSQL pool.
    #[must_use]
    pub fn new(pool: deadpool_postgres::Pool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RunCostBudgetAdministration for PostgresRunCostBudgetAdministration {
    async fn get(
        &self,
        auth: &AuthContext,
    ) -> Result<Option<RunCostCap>, RunCostBudgetAdministrationError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| RunCostBudgetAdministrationError::Unavailable)?;
        let row = client
            .query_opt(
                "SELECT currency,max_cost_micro_units FROM public.user_run_cost_budgets \
                 WHERE deployment_id=$1 AND tenant_id=$2 AND actor_user_id=$3",
                &[
                    &auth.deployment().as_str(),
                    &auth.tenant().as_str(),
                    &auth.actor().as_str(),
                ],
            )
            .await
            .map_err(|error| unavailable("读取 run cost budget 失败", error))?;
        row.as_ref().map(decode).transpose()
    }

    async fn replace(
        &self,
        auth: &AuthContext,
        cap: Option<RunCostCap>,
    ) -> Result<Option<RunCostCap>, RunCostBudgetAdministrationError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| RunCostBudgetAdministrationError::Unavailable)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| RunCostBudgetAdministrationError::Unavailable)?;
        let stored = match cap {
            Some(cap) => {
                let amount = i64::try_from(cap.max_cost_micro_units()).map_err(|_| {
                    RunCostBudgetAdministrationError::InvalidInput {
                        field: "maxCostMicroUnits",
                    }
                })?;
                let row = transaction
                    .query_one(
                        "INSERT INTO public.user_run_cost_budgets( \
                           deployment_id,tenant_id,actor_user_id,currency,max_cost_micro_units,updated_at \
                         ) VALUES($1,$2,$3,$4,$5,clock_timestamp()) \
                         ON CONFLICT(deployment_id,tenant_id,actor_user_id) DO UPDATE SET \
                           currency=EXCLUDED.currency,max_cost_micro_units=EXCLUDED.max_cost_micro_units, \
                           updated_at=clock_timestamp() \
                         RETURNING currency,max_cost_micro_units",
                        &[
                            &auth.deployment().as_str(),
                            &auth.tenant().as_str(),
                            &auth.actor().as_str(),
                            &cap.currency(),
                            &amount,
                        ],
                    )
                    .await
                    .map_err(|error| unavailable("保存 run cost budget 失败", error))?;
                Some(decode(&row)?)
            }
            None => {
                transaction
                    .execute(
                        "DELETE FROM public.user_run_cost_budgets \
                         WHERE deployment_id=$1 AND tenant_id=$2 AND actor_user_id=$3",
                        &[
                            &auth.deployment().as_str(),
                            &auth.tenant().as_str(),
                            &auth.actor().as_str(),
                        ],
                    )
                    .await
                    .map_err(|error| unavailable("删除 run cost budget 失败", error))?;
                None
            }
        };
        transaction
            .commit()
            .await
            .map_err(|_| RunCostBudgetAdministrationError::CommitUnknown)?;
        Ok(stored)
    }
}

fn decode(row: &Row) -> Result<RunCostCap, RunCostBudgetAdministrationError> {
    let currency = row
        .try_get::<_, String>("currency")
        .map_err(|_| RunCostBudgetAdministrationError::Corrupt { field: "currency" })?;
    let amount = row.try_get::<_, i64>("max_cost_micro_units").map_err(|_| {
        RunCostBudgetAdministrationError::Corrupt {
            field: "max_cost_micro_units",
        }
    })?;
    let amount = u64::try_from(amount).map_err(|_| RunCostBudgetAdministrationError::Corrupt {
        field: "max_cost_micro_units",
    })?;
    RunCostCap::new(currency, amount).map_err(|_| RunCostBudgetAdministrationError::Corrupt {
        field: "run_cost_budget",
    })
}

fn unavailable(
    context: &'static str,
    error: tokio_postgres::Error,
) -> RunCostBudgetAdministrationError {
    tracing::warn!(error = %error, "{context}");
    RunCostBudgetAdministrationError::Unavailable
}
