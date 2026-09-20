//! Closed enforcement plan and granularity compiler for network scope egress.
//!
//! Enforces that policies requiring TLS inner inspection (path rules, multi-authority,
//! encrypted redirect checking) fail closed prior to network or listener socket binding,
//! as mandated by v5 §10.5a / PA-06.

use super::{GatewayError, GatewayPolicy};

/// Required egress inspection granularity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EgressRequirement {
    /// Ordinary destination checking (host, subdomain, port, IP/CIDR).
    DestinationOnly,
    /// Inner HTTPS request authority and URL path inspection.
    TlsInnerAuthorityPath,
    /// Inspection of multiple distinct authorities over a single reused connection.
    TlsMultiAuthority,
    /// Evaluation of encrypted redirects inside TLS.
    TlsEncryptedRedirect,
}

/// Verifiable egress policy enforcement fidelity level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressFidelity {
    /// Only network destination constraints (host, port, IP) are verified.
    NetworkDestinationEnforced,
    /// Inner HTTPS request constraints are inspected by a trusted external verifier.
    HttpsRequestPolicyEnforced,
}

impl EgressFidelity {
    /// Stable wire representation defined by v5 §10.5a.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NetworkDestinationEnforced => "network_destination_enforced",
            Self::HttpsRequestPolicyEnforced => "https_request_policy_enforced",
        }
    }
}

impl core::fmt::Display for EgressFidelity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Sealed enforcement plan compiled from host-owned policy rules.
///
/// Untrusted callers cannot construct this type to falsely report installed inspectors.
#[derive(Clone, Debug)]
pub struct EnforcementPlan {
    fidelity: EgressFidelity,
    policy: GatewayPolicy,
}

impl EnforcementPlan {
    /// Compile a policy into an execution plan.
    ///
    /// If the policy requires any strong TLS inner inspection, compilation fails closed
    /// with `GatewayError::EgressPolicyUnsupported` because no trusted HTTPS inspector is installed.
    pub fn compile(policy: &GatewayPolicy) -> Result<Self, GatewayError> {
        if policy.requires_strong_tls_enforcement() {
            return Err(GatewayError::EgressPolicyUnsupported);
        }
        Ok(Self {
            fidelity: EgressFidelity::NetworkDestinationEnforced,
            policy: policy.clone(),
        })
    }

    pub(super) fn matches_policy(&self, policy: &GatewayPolicy) -> bool {
        &self.policy == policy
    }

    /// The active fidelity level of this compiled plan.
    #[must_use]
    pub const fn fidelity(&self) -> EgressFidelity {
        self.fidelity
    }
}
