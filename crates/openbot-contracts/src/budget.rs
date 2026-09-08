//! Closed actor-scoped run-cost budget contracts shared with the native and WASM hosts.

use serde::{Deserialize, Serialize};

/// One explicit per-run cost cap input.
///
/// The amount is a canonical decimal string of micro currency units. A string avoids silently
/// rounding PostgreSQL `bigint` values in JavaScript, while validation remains application-owned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunCostCapInput {
    /// Three-letter uppercase currency code. OpenBot never converts currencies.
    pub currency: String,
    /// Positive whole micro currency units, encoded as canonical base-10 digits.
    pub max_cost_micro_units: String,
}

/// Full replacement value for the authenticated actor's per-run cost budget.
///
/// `None` explicitly disables the user cap. Actor, deployment and tenant never cross this wire.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunCostBudgetPreference {
    /// Enabled cap, or `null` when the actor has no user-configured cap.
    pub cap: Option<RunCostCapInput>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_cost_budget_wire_is_closed_and_preserves_large_integers() {
        let preference = RunCostBudgetPreference {
            cap: Some(RunCostCapInput {
                currency: "USD".to_owned(),
                max_cost_micro_units: "9007199254740992".to_owned(),
            }),
        };
        assert_eq!(
            serde_json::to_string(&preference).unwrap(),
            r#"{"cap":{"currency":"USD","maxCostMicroUnits":"9007199254740992"}}"#
        );
        assert_eq!(
            serde_json::from_str::<RunCostBudgetPreference>(r#"{"cap":null}"#).unwrap(),
            RunCostBudgetPreference::default()
        );
        assert!(
            serde_json::from_str::<RunCostBudgetPreference>(
                r#"{"cap":{"currency":"USD","maxCostMicroUnits":"1","actor":"admin"}}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<RunCostBudgetPreference>(
                r#"{"cap":null,"deploymentId":"attacker"}"#
            )
            .is_err()
        );
    }
}
