//! Pure create-time coworker routing and prompt projection (v3 §3.2 / R18).

pub use openbot_contracts::command::MAX_CHANNEL_ROUTING_REASON_CODE_POINTS as MAX_ROUTING_REASON_CODE_POINTS;
use openbot_contracts::ids::BotId;
use serde_json::Value;

/// Below this threshold an inferred match defers to the deterministic default.
pub const MIN_ROUTING_CONFIDENCE: f64 = 0.6;

/// One currently visible routing candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutingCandidate {
    /// Authoritative Agent identity.
    pub id: BotId,
    /// Display name.
    pub name: String,
    /// Operator-authored purpose.
    pub role_description: String,
    /// Stable system names reachable through current Agent grants; a hint, never permission.
    pub reaches: Vec<String>,
}

/// Stable audit reason; raw user text and model prose never need to enter the audit payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutingReasonCode {
    /// The person explicitly selected a visible coworker.
    ExplicitChoice,
    /// There was at most one candidate, so no model call was needed.
    OnlyCandidate,
    /// The deployment model or credential was unavailable.
    RouterUnavailable,
    /// The model output was not a usable JSON object.
    InvalidResponse,
    /// The model named an identity outside the authoritative roster.
    CandidateNotVisible,
    /// The returned match was below the fixed confidence threshold.
    LowConfidence,
    /// A visible candidate cleared the threshold.
    ModelMatch,
}

impl RoutingReasonCode {
    /// Stable audit label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitChoice => "explicit_choice",
            Self::OnlyCandidate => "only_candidate",
            Self::RouterUnavailable => "router_unavailable",
            Self::InvalidResponse => "invalid_response",
            Self::CandidateNotVisible => "candidate_not_visible",
            Self::LowConfidence => "low_confidence",
            Self::ModelMatch => "model_match",
        }
    }
}

/// Pure routing result. `reason_code` is durable; `reason` is bounded presentation text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutingDecision {
    /// Chosen authoritative Agent.
    pub agent_id: BotId,
    /// Chosen display name.
    pub name: String,
    /// Short user-facing explanation.
    pub reason: String,
    /// Whether the choice is the deterministic default rather than an inferred match.
    pub fallback: bool,
    /// Stable audit classification.
    pub reason_code: RoutingReasonCode,
}

/// Model completion fact passed into the pure classifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutingCompletion<'a> {
    /// Provider/credential/transport was unavailable.
    Unavailable,
    /// Raw model text; it is parsed and bounded here.
    Answer(&'a str),
}

/// More than one candidate requires a model completion; zero/one never does.
#[must_use]
pub const fn needs_completion(candidates: &[RoutingCandidate]) -> bool {
    candidates.len() > 1
}

/// Render the exact fixed-upstream routing prompt, adding reach hints only where facts exist.
#[must_use]
pub fn routing_prompt(text: &str, candidates: &[RoutingCandidate]) -> String {
    let roster = candidates
        .iter()
        .map(|candidate| {
            let mut lines = vec![
                format!("- id: {}", candidate.id),
                format!("  name: {}", candidate.name),
                format!("  for: {}", candidate.role_description),
            ];
            if !candidate.reaches.is_empty() {
                lines.push(format!("  can reach: {}", candidate.reaches.join(", ")));
            }
            lines.join("\n")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let mut lines = vec![
        "You route a person's message to the one coworker best suited to it.".to_owned(),
        "Here are the coworkers and what each is for:".to_owned(),
        roster,
        String::new(),
        "Reply with only JSON: {\"agentId\": \"<one id from the list>\", \"reason\": \"<short, names the fit>\", \"confidence\": <0..1>}.".to_owned(),
        "Pick the specialist whose purpose matches the message. If none clearly fits, use the most general coworker and give it a low confidence.".to_owned(),
    ];
    if candidates
        .iter()
        .any(|candidate| !candidate.reaches.is_empty())
    {
        lines.push("When the message names a system a coworker can reach, prefer that coworker: one that cannot reach it has no way to answer and will fall back to a browser that is signed in as nobody. Purpose still comes first — a specialist with no systems listed is right for a question about its specialism.".to_owned());
    }
    lines.push(String::new());
    lines.push(format!("Message: {text}"));
    lines.join("\n")
}

/// Classify one completion. Every uncertain outcome returns the deterministic default.
#[must_use]
pub fn decide(
    candidates: &[RoutingCandidate],
    default_id: &BotId,
    completion: RoutingCompletion<'_>,
) -> RoutingDecision {
    let fallback = |reason: &'static str, reason_code| {
        let chosen = candidates
            .iter()
            .find(|candidate| &candidate.id == default_id)
            .or_else(|| candidates.first());
        chosen.map_or_else(
            || RoutingDecision {
                agent_id: default_id.clone(),
                name: default_id.as_str().to_owned(),
                reason: reason.to_owned(),
                fallback: true,
                reason_code,
            },
            |chosen| RoutingDecision {
                agent_id: chosen.id.clone(),
                name: chosen.name.clone(),
                reason: reason.to_owned(),
                fallback: true,
                reason_code,
            },
        )
    };

    if candidates.len() <= 1 {
        return fallback(
            "the only coworker available",
            RoutingReasonCode::OnlyCandidate,
        );
    }
    let RoutingCompletion::Answer(raw) = completion else {
        return fallback(
            "sent to your default while the router was unreachable",
            RoutingReasonCode::RouterUnavailable,
        );
    };
    let Some(object) = json_object_slice(raw) else {
        return fallback(
            "sent to your default; the router's answer did not parse",
            RoutingReasonCode::InvalidResponse,
        );
    };
    let Ok(parsed) = serde_json::from_str::<Value>(object) else {
        return fallback(
            "sent to your default; the router's answer did not parse",
            RoutingReasonCode::InvalidResponse,
        );
    };
    let Some(parsed) = parsed.as_object() else {
        return fallback(
            "sent to your default; the router's answer did not parse",
            RoutingReasonCode::InvalidResponse,
        );
    };
    let id = parsed
        .get("agentId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some(chosen) = candidates
        .iter()
        .find(|candidate| candidate.id.as_str() == id)
    else {
        return fallback(
            "sent to your default; the router named no coworker on your roster",
            RoutingReasonCode::CandidateNotVisible,
        );
    };
    let confidence = parsed
        .get("confidence")
        .and_then(Value::as_f64)
        .unwrap_or_default();
    if confidence < MIN_ROUTING_CONFIDENCE {
        return fallback(
            "sent to your default; no specialist was a confident match",
            RoutingReasonCode::LowConfidence,
        );
    }
    let reason = parsed
        .get("reason")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .map(bounded_reason)
        .unwrap_or_else(|| format!("matches {}", chosen.name));
    RoutingDecision {
        agent_id: chosen.id.clone(),
        name: chosen.name.clone(),
        reason,
        fallback: false,
        reason_code: RoutingReasonCode::ModelMatch,
    }
}

fn json_object_slice(raw: &str) -> Option<&str> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    (start <= end).then(|| &raw[start..=end])
}

fn bounded_reason(reason: &str) -> String {
    let mut code_points = reason.chars();
    let bounded = code_points
        .by_ref()
        .take(MAX_ROUTING_REASON_CODE_POINTS)
        .collect::<String>();
    if code_points.next().is_some() {
        let mut shortened = bounded
            .chars()
            .take(MAX_ROUTING_REASON_CODE_POINTS - 1)
            .collect::<String>();
        shortened.push('…');
        shortened
    } else {
        bounded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roster() -> Vec<RoutingCandidate> {
        [
            ("general-assistant", "General Assistant", "everyday work"),
            ("knowledge", "Knowledge", "company knowledge questions"),
            (
                "risk-analyst",
                "Risk Analyst",
                "transaction monitoring and fraud risk",
            ),
        ]
        .into_iter()
        .map(|(id, name, role)| RoutingCandidate {
            id: BotId::new(id),
            name: name.to_owned(),
            role_description: role.to_owned(),
            reaches: Vec::new(),
        })
        .collect()
    }

    fn default_id() -> BotId {
        BotId::new("general-assistant")
    }

    #[test]
    fn routes_to_the_specialist_the_model_picks_named_not_a_fal() {
        let decision = decide(
            &roster(),
            &default_id(),
            RoutingCompletion::Answer(
                r#"{"agentId":"risk-analyst","reason":"fraud review","confidence":0.9}"#,
            ),
        );
        assert_eq!(decision.agent_id.as_str(), "risk-analyst");
        assert_eq!(decision.name, "Risk Analyst");
        assert!(!decision.fallback);
        assert!(decision.reason.contains("fraud"));
    }

    #[test]
    fn falls_back_to_the_default_named_when_the_model_is_unreac() {
        let decision = decide(&roster(), &default_id(), RoutingCompletion::Unavailable);
        assert_eq!(decision.agent_id, default_id());
        assert!(decision.fallback);
        assert!(decision.reason.contains("unreachable"));
    }

    #[test]
    fn falls_back_when_the_answer_does_not_parse() {
        let decision = decide(
            &roster(),
            &default_id(),
            RoutingCompletion::Answer("I think the risk analyst?"),
        );
        assert_eq!(decision.agent_id, default_id());
        assert!(decision.fallback);
    }

    #[test]
    fn never_acts_on_an_id_that_is_not_on_the_roster() {
        let decision = decide(
            &roster(),
            &default_id(),
            RoutingCompletion::Answer(
                r#"{"agentId":"payroll-bot","reason":"payroll","confidence":0.99}"#,
            ),
        );
        assert_eq!(decision.agent_id, default_id());
        assert!(decision.fallback);
        assert!(decision.reason.contains("no coworker on your roster"));
    }

    #[test]
    fn defers_to_the_default_when_confidence_is_low() {
        let decision = decide(
            &roster(),
            &default_id(),
            RoutingCompletion::Answer(
                r#"{"agentId":"risk-analyst","reason":"maybe","confidence":0.3}"#,
            ),
        );
        assert_eq!(decision.agent_id, default_id());
        assert!(decision.fallback);
    }

    #[test]
    fn a_fenced_padded_json_answer_is_still_parsed() {
        let decision = decide(
            &roster(),
            &default_id(),
            RoutingCompletion::Answer(
                "```json\n{\"agentId\":\"knowledge\",\"reason\":\"policy lookup\",\"confidence\":0.8}\n```",
            ),
        );
        assert_eq!(decision.agent_id.as_str(), "knowledge");
        assert!(!decision.fallback);
    }

    #[test]
    fn a_single_coworker_roster_is_a_fallback_not_a_model_call() {
        let candidates = vec![roster().remove(0)];
        assert!(!needs_completion(&candidates));
        let decision = decide(
            &candidates,
            &default_id(),
            RoutingCompletion::Answer(r#"{"agentId":"other","confidence":1}"#),
        );
        assert_eq!(decision.agent_id, default_id());
        assert!(decision.fallback);
        assert_eq!(decision.reason_code, RoutingReasonCode::OnlyCandidate);
    }

    fn reach_roster() -> Vec<RoutingCandidate> {
        vec![
            RoutingCandidate {
                id: BotId::new("knowledge"),
                name: "Knowledge".to_owned(),
                role_description: "company knowledge questions".to_owned(),
                reaches: Vec::new(),
            },
            RoutingCandidate {
                id: BotId::new("risk-analyst"),
                name: "Risk Analyst".to_owned(),
                role_description: "risk and compliance".to_owned(),
                reaches: vec!["google-drive".to_owned()],
            },
        ]
    }

    #[test]
    fn names_the_systems_in_the_roster_the_model_is_given() {
        assert!(
            routing_prompt("what is in my Drive doc?", &reach_roster())
                .contains("can reach: google-drive")
        );
    }

    #[test]
    fn says_nothing_about_reach_for_a_coworker_that_holds_nothi() {
        let prompt = routing_prompt("anything", &reach_roster());
        let knowledge = &prompt
            [prompt.find("id: knowledge").unwrap()..prompt.find("id: risk-analyst").unwrap()];
        assert!(!knowledge.contains("can reach"));
    }

    #[test]
    fn tells_the_model_to_prefer_reach_without_letting_it_overr() {
        let prompt = routing_prompt("anything", &reach_roster());
        assert!(prompt.contains("prefer that coworker"));
        assert!(prompt.contains("Purpose still comes first"));
    }

    #[test]
    fn a_roster_with_no_reach_at_all_reads_exactly_as_it_did_be() {
        let prompt = routing_prompt(
            "anything",
            &[RoutingCandidate {
                id: BotId::new("a"),
                name: "A".to_owned(),
                role_description: "alpha".to_owned(),
                reaches: Vec::new(),
            }],
        );
        assert!(!prompt.contains("can reach"));
    }

    #[test]
    fn model_reason_is_bounded_by_unicode_code_points() {
        let long = "界".repeat(MAX_ROUTING_REASON_CODE_POINTS + 20);
        let raw = format!(r#"{{"agentId":"knowledge","reason":"{long}","confidence":0.9}}"#);
        let decision = decide(&roster(), &default_id(), RoutingCompletion::Answer(&raw));
        assert_eq!(
            decision.reason.chars().count(),
            MAX_ROUTING_REASON_CODE_POINTS
        );
        assert!(decision.reason.ends_with('…'));
    }
}
