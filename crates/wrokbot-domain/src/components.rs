//! Pure compiled-component publication, withholding and data-function decisions.
//!
//! Persistence supplies facts; this module owns their meaning. A component is open by default only
//! after it is both published and has a published description. One exclusion row with the current
//! Agent closes that grant. Data-function permission is independent: one grant row authorizes one
//! component/function pair, and absence always refuses.

/// Persistence-independent facts for one component and one Agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentGrantFacts {
    /// Whether the compiled-component governance row exists.
    pub exists: bool,
    /// Authoritative publication bit.
    pub published: bool,
    /// Whether a non-null published model-facing description exists.
    pub has_published_description: bool,
    /// Whether an exclusion row exists for this exact Agent.
    pub withheld_from_agent: bool,
}

/// Closed refusal classes; user-facing prose remains in the GUI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentGrantRefusal {
    /// The governance row does not exist.
    UnknownComponent,
    /// Publication is false or its published description is absent.
    Unpublished,
    /// An explicit exclusion exists for the current Agent.
    WithheldFromAgent,
    /// The component/function grant row is absent.
    FunctionNotGranted,
}

/// Pure component authorization result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentGrantDecision {
    /// The checked grant permits continuing.
    Allowed,
    /// The checked grant refuses continuing.
    Refused(ComponentGrantRefusal),
}

/// Decide publication plus per-Agent withholding in the only valid order.
#[must_use]
pub const fn decide_component_grant(facts: ComponentGrantFacts) -> ComponentGrantDecision {
    if !facts.exists {
        return ComponentGrantDecision::Refused(ComponentGrantRefusal::UnknownComponent);
    }
    if !facts.published || !facts.has_published_description {
        return ComponentGrantDecision::Refused(ComponentGrantRefusal::Unpublished);
    }
    if facts.withheld_from_agent {
        return ComponentGrantDecision::Refused(ComponentGrantRefusal::WithheldFromAgent);
    }
    ComponentGrantDecision::Allowed
}

/// Decide one independent component/data-function grant.
#[must_use]
pub const fn decide_component_function_grant(granted: bool) -> ComponentGrantDecision {
    if granted {
        ComponentGrantDecision::Allowed
    } else {
        ComponentGrantDecision::Refused(ComponentGrantRefusal::FunctionNotGranted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALLOWED: ComponentGrantFacts = ComponentGrantFacts {
        exists: true,
        published: true,
        has_published_description: true,
        withheld_from_agent: false,
    };

    #[test]
    fn publication_description_and_exact_agent_exclusion_all_fail_closed() {
        assert_eq!(
            decide_component_grant(ALLOWED),
            ComponentGrantDecision::Allowed
        );
        assert_eq!(
            decide_component_grant(ComponentGrantFacts {
                exists: false,
                ..ALLOWED
            }),
            ComponentGrantDecision::Refused(ComponentGrantRefusal::UnknownComponent)
        );
        for facts in [
            ComponentGrantFacts {
                published: false,
                ..ALLOWED
            },
            ComponentGrantFacts {
                has_published_description: false,
                ..ALLOWED
            },
        ] {
            assert_eq!(
                decide_component_grant(facts),
                ComponentGrantDecision::Refused(ComponentGrantRefusal::Unpublished)
            );
        }
        assert_eq!(
            decide_component_grant(ComponentGrantFacts {
                withheld_from_agent: true,
                ..ALLOWED
            }),
            ComponentGrantDecision::Refused(ComponentGrantRefusal::WithheldFromAgent)
        );
    }

    #[test]
    fn data_function_requires_its_own_positive_grant() {
        assert_eq!(
            decide_component_function_grant(true),
            ComponentGrantDecision::Allowed
        );
        assert_eq!(
            decide_component_function_grant(false),
            ComponentGrantDecision::Refused(ComponentGrantRefusal::FunctionNotGranted)
        );
    }
}
