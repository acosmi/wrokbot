//! Candidate acceptance-record checker (v5 §24.2–§24.4 and v6 §24.5a / PA-08).
//!
//! Required IDs come from the v5 body or frozen v6 tool policy, never from the record.
//! Matching files and digests do not certify signatures, notarization, real
//! accounts, OS operations, or product release. Synthetic fixtures are test-only.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Result, anyhow, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const MAX_JSON_BYTES: u64 = 1024 * 1024;
const MAX_EVIDENCE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_EVIDENCE_FILES: usize = 256;
const MAX_REQUIREMENTS: usize = 256;
const MAX_FINDINGS: usize = 256;
const MAX_EVIDENCE_PER_REQUIREMENT: usize = 32;
const MAX_ARTIFACT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MACOS_GATES: [&str; 8] = ["A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7"];
const MACOS_V5_IDS: [&str; 14] = [
    "V5-KEY-01",
    "V5-START-01",
    "V5-CONFIRM-01",
    "V5-CRASH-01",
    "V5-NATIVE-01",
    "V5-PIXEL-01",
    "V5-BACKUP-01",
    "V5-UPGRADE-01",
    "V5-EGRESS-01",
    "V5-MODEL-01",
    "V5-SDK-01",
    "V5-CAP-01",
    "V5-RELEASE-01",
    "V5-SPEC-01",
];
const MODEL_SOURCES: [&str; 3] = ["model.custom", "model.sdk_gateway", "model.account_bridge"];
const PRODUCT_STORIES: [&str; 3] = ["story.workbench", "story.agent_tools", "story.computer"];
const SUBSEQUENT_IDS: [&str; 1] = ["V5-DEVICE-01"];
const STATUSES: [&str; 4] = ["planned", "blocked", "failed", "passed"];
const SEVERITIES: [&str; 4] = ["P0", "P1", "P2", "note"];
const FINDING_STATUSES: [&str; 2] = ["open", "closed"];
const FULL_V5_REMAINING: [&str; 8] = [
    "G0–G8 remaining gates in §24.1/§24.4, including historical G0 input originals",
    "§25 Definition of Done (ten clauses; cannot close from macos_first_release or todo=0)",
    "original parity/fixture T-ID identity, overlay schema, and unfinished ledger items",
    "R212 mobile four-client / multi-device production wiring (V5-DEVICE-01)",
    "Windows / Linux / runsc runtime evidence independent of macOS first release",
    "G2 external SAML/XSW review and Server KMS/HSM",
    "G8 production-scale backup/legacy drills, signing/notarization, and operator attestation",
    "formal golden / AX / reduced-motion matrix (GUI first source, not this checker)",
];
const V6_MIN_SPEC_REVISION: u32 = 268;
const V6_MACOS_ALWAYS: [&str; 2] = ["AR6-04", "AR6-10"];
const V6_EVENT_GATES: [&str; 6] = ["E0", "E1", "E2", "E3", "E4", "E5"];
const V6_WORKFLOWS: [&str; 10] = [
    "V6-AUTO-01",
    "V6-EVENT-01",
    "V6-CONNECTOR-01",
    "V6-NODE-01",
    "V6-SUBAGENT-01",
    "V6-BUDGET-01",
    "V6-ARTIFACT-01",
    "V6-PREFERENCE-01",
    "V6-TERMINAL-01",
    "V6-SPEC-01",
];
const V6_M1_WORKFLOWS: [&str; 9] = [
    "V6-AUTO-01",
    "V6-EVENT-01",
    "V6-CONNECTOR-01",
    "V6-SUBAGENT-01",
    "V6-BUDGET-01",
    "V6-ARTIFACT-01",
    "V6-PREFERENCE-01",
    "V6-TERMINAL-01",
    "V6-SPEC-01",
];
const V6_M1_AR6: [&str; 7] = [
    "AR6-02", "AR6-04", "AR6-05", "AR6-06", "AR6-07", "AR6-08", "AR6-10",
];

#[derive(Debug, Serialize, Clone)]
pub(crate) struct AcceptanceReport {
    pub ok: bool,
    pub structure_valid: bool,
    pub admission_conditions_present: bool,
    pub controller_verified: bool,
    pub product_certified: bool,
    pub release_certified: bool,
    pub scope: String,
    pub scope_recognized: bool,
    pub collection_supported: bool,
    pub full_admission_supported: bool,
    pub v6_policy_verified: bool,
    pub full_v5_supported: bool,
    pub full_v5_remaining_sources: Vec<String>,
    pub required_ids: Vec<String>,
    pub required_set_source: String,
    pub diagnostics: Vec<Diagnostic>,
    pub oracles: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Clone)]
pub(crate) struct Diagnostic {
    pub severity: &'static str,
    pub code: String,
    pub path: String,
    pub locator: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    schema_version: u32,
    scope: String,
    #[serde(default)]
    spec_digest: Option<String>,
    source_commit: String,
    working_tree_digest: String,
    lock_digest: String,
    ui_digest: String,
    artifact_digest: Option<String>,
    platform: String,
    arch: String,
    os_version: String,
    enabled_capabilities: Vec<String>,
    requirements: Vec<Requirement>,
    findings: Vec<Finding>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Requirement {
    clause: String,
    id: String,
    applicable: bool,
    owner: String,
    status: String,
    command: String,
    scenario: String,
    evidence: Vec<EvidenceRef>,
    result: String,
    limits: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct EvidenceRef {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Finding {
    id: String,
    severity: String,
    status: String,
    summary: String,
    #[serde(default)]
    waiver: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CandidateManifest {
    schema_version: u32,
    source_commit: String,
    working_tree_digest: String,
    lock_digest: String,
    ui_digest: String,
    artifact_digest: Option<String>,
    platform: String,
    arch: String,
    #[serde(default)]
    v6_policy: Option<V6Policy>,
    #[serde(default)]
    evidence: BTreeMap<String, PackedEvidence>,
    #[serde(default)]
    artifact_file: Option<ArtifactFile>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V6Policy {
    schema_version: u32,
    scope: String,
    spec_version: String,
    spec_revision: u32,
    spec_digest: String,
    conditional_paths: ConditionalPaths,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConditionalPaths {
    oauth_rotation: bool,
    shared_profile: bool,
    remote_server_tls: bool,
}

#[derive(Debug, Deserialize)]
struct CurrentSpecMetadata {
    version: String,
    last_revision: u32,
}

struct SpecDocument {
    path: PathBuf,
    text: String,
    digest: String,
}

#[derive(Clone, Copy)]
struct ReportSupport {
    scope_recognized: bool,
    collection_supported: bool,
    full_admission_supported: bool,
    v6_policy_verified: bool,
}

impl ReportSupport {
    fn for_scope(scope: &str, v6_policy_verified: bool) -> Self {
        Self {
            scope_recognized: is_known_scope(scope),
            collection_supported: matches!(
                scope,
                "macos_first_release" | "event_workflows_v6" | "full_v6"
            ),
            full_admission_supported: matches!(scope, "macos_first_release" | "event_workflows_v6"),
            v6_policy_verified,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ArtifactFile {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Deserialize, Clone)]
struct PackedEvidence {
    bytes: u64,
    sha256: String,
}

pub(crate) fn run(args: &[String]) -> Result<()> {
    let opts = parse_args(args)?;
    let report = evaluate(&opts);
    if opts.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_human(&report);
    }
    if report.ok {
        Ok(())
    } else {
        let errors = report
            .diagnostics
            .iter()
            .filter(|d| d.severity == "error")
            .count();
        bail!(
            "acceptance-check: {errors} error diagnostics (structure/admission-conditions only; not product/release certification)"
        )
    }
}

pub(crate) struct Opts {
    record: PathBuf,
    candidate: PathBuf,
    evidence_root: PathBuf,
    spec: Option<PathBuf>,
    json: bool,
}

fn parse_args(args: &[String]) -> Result<Opts> {
    let mut record = None;
    let mut candidate = None;
    let mut evidence_root = None;
    let mut spec = None;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--record" => {
                i += 1;
                record = Some(PathBuf::from(args.get(i).ok_or_else(|| {
                    anyhow!("acceptance-check: --record requires a path")
                })?));
            }
            "--candidate" => {
                i += 1;
                candidate = Some(PathBuf::from(args.get(i).ok_or_else(|| {
                    anyhow!("acceptance-check: --candidate requires a path")
                })?));
            }
            "--evidence-root" => {
                i += 1;
                evidence_root = Some(PathBuf::from(args.get(i).ok_or_else(|| {
                    anyhow!("acceptance-check: --evidence-root requires a path")
                })?));
            }
            "--spec" => {
                i += 1;
                spec = Some(PathBuf::from(args.get(i).ok_or_else(|| {
                    anyhow!("acceptance-check: --spec requires a path")
                })?));
            }
            other => bail!("acceptance-check: unknown argument `{other}`"),
        }
        i += 1;
    }
    Ok(Opts {
        record: record.ok_or_else(|| anyhow!("usage: cargo xtask acceptance-check --record <json> --candidate <trusted-candidate-manifest> --evidence-root <dir> [--spec <v5-or-v6-first-source.md>] [--json]"))?,
        candidate: candidate.ok_or_else(|| anyhow!("usage: cargo xtask acceptance-check --record <json> --candidate <trusted-candidate-manifest> --evidence-root <dir> [--spec <v5-or-v6-first-source.md>] [--json]"))?,
        evidence_root: evidence_root.ok_or_else(|| anyhow!("usage: cargo xtask acceptance-check --record <json> --candidate <trusted-candidate-manifest> --evidence-root <dir> [--spec <v5-or-v6-first-source.md>] [--json]"))?,
        spec,
        json,
    })
}

pub(crate) fn evaluate(opts: &Opts) -> AcceptanceReport {
    let mut diagnostics = Vec::new();
    let mut oracles = BTreeMap::new();
    oracles.insert("record".into(), opts.record.display().to_string());
    oracles.insert(
        "candidate_manifest".into(),
        opts.candidate.display().to_string(),
    );
    oracles.insert(
        "evidence_root".into(),
        opts.evidence_root.display().to_string(),
    );
    if same_path(&opts.record, &opts.candidate) {
        push_error(
            &mut diagnostics,
            "trust_anchor",
            &opts.candidate.display().to_string(),
            "candidate",
            "candidate manifest must be an independently specified trust anchor, not the record path",
        );
    }

    let fallback_required = required_macos_ids(None, &mut diagnostics, &mut oracles);
    let (record, record_value) = match load_json_with_value::<Record>(&opts.record, "record") {
        Ok(value) => value,
        Err(diag) => {
            diagnostics.push(diag);
            return finish(
                "unknown",
                &fallback_required,
                diagnostics,
                oracles,
                false,
                false,
                ReportSupport::for_scope("unknown", false),
            );
        }
    };
    let (candidate, candidate_value) = match load_json_with_value::<CandidateManifest>(
        &opts.candidate,
        "candidate",
    ) {
        Ok(value) => value,
        Err(diag) => {
            diagnostics.push(diag);
            if record.scope == "full_v6" {
                push_error(
                    &mut diagnostics,
                    "full_v6_aggregate_closure_unimplemented",
                    "record",
                    "scope",
                    "full_v6 required-item collection is supported, but parity/fixtures/overlay/platform aggregate closure is not implemented",
                );
            }
            let required = if matches!(record.scope.as_str(), "event_workflows_v6" | "full_v6") {
                required_v6_ids(&record.scope, None)
            } else {
                fallback_required
            };
            return finish(
                &record.scope,
                &required,
                diagnostics,
                oracles,
                false,
                false,
                ReportSupport::for_scope(&record.scope, false),
            );
        }
    };
    let spec_document = opts
        .spec
        .as_deref()
        .and_then(|path| load_spec_document(path, &mut diagnostics, &mut oracles));
    let v6_mode = matches!(record.scope.as_str(), "event_workflows_v6" | "full_v6")
        || record_value.get("specDigest").is_some()
        || candidate.v6_policy.is_some()
        || candidate_value.get("v6Policy").is_some()
        || spec_document.as_ref().is_some_and(spec_declares_v6);
    let required = if v6_mode {
        required_v6_ids(&record.scope, candidate.v6_policy.as_ref())
    } else {
        required_macos_ids(
            spec_document
                .as_ref()
                .map(|document| (document.path.as_path(), document.text.as_str())),
            &mut diagnostics,
            &mut oracles,
        )
    };
    oracles.insert(
        "required_set_policy".into(),
        if v6_mode {
            "v6 §24.5a tool policy + trusted candidate v6Policy conditional paths; never the record"
                .into()
        } else {
            "v5 §24.2 A0–A7 + §24.4 macOS V5 IDs excluding V5-DEVICE-01 + three model sources + three product stories".into()
        },
    );
    oracles.insert(
        "spec_default".into(),
        if v6_mode {
            "v6 requires an explicit --spec bound by exact SHA-256 and current metadata".into()
        } else {
            "controlled built-in v5 requirement policy; optional --spec is explicit".into()
        },
    );
    let v6_policy_verified = if v6_mode {
        check_v6_contract(
            &record,
            &candidate,
            &record_value,
            &candidate_value,
            spec_document.as_ref(),
            &mut diagnostics,
            &mut oracles,
        )
    } else {
        false
    };

    oracles.insert(
        "enabled_capabilities".into(),
        if record.enabled_capabilities.is_empty() {
            "(empty; does not shrink the required set)".into()
        } else {
            record.enabled_capabilities.join(",")
        },
    );
    if record.schema_version != 1 {
        push_error(
            &mut diagnostics,
            "schema_version",
            "record",
            "schemaVersion",
            &format!("schemaVersion must be 1, found {}", record.schema_version),
        );
    }
    if candidate.schema_version != 1 {
        push_error(
            &mut diagnostics,
            "schema_version",
            "candidate",
            "schemaVersion",
            &format!(
                "candidate schemaVersion must be 1, found {}",
                candidate.schema_version
            ),
        );
    }

    let full_v5 = record.scope == "full_v5";
    let full_v6 = record.scope == "full_v6";
    let support = ReportSupport::for_scope(&record.scope, v6_policy_verified);
    if !support.scope_recognized {
        push_error(
            &mut diagnostics,
            "unknown_scope",
            "record",
            "scope",
            &format!(
                "scope must be macos_first_release, full_v5, event_workflows_v6, or full_v6; found {}",
                record.scope
            ),
        );
    }
    if full_v5 {
        push_error(
            &mut diagnostics,
            "full_v5_unsupported",
            "record",
            "scope",
            "full_v5 required set is not implemented; macos_first_release collection must not be reused, and todo=0 is not complete v5",
        );
    }
    if full_v6 {
        push_error(
            &mut diagnostics,
            "full_v6_aggregate_closure_unimplemented",
            "record",
            "scope",
            "full_v6 required-item collection is supported, but parity/fixtures/overlay/platform aggregate closure is not implemented",
        );
    }

    check_identity_fields(&record, &mut diagnostics);
    check_digest_join(&record, &candidate, &mut diagnostics);
    check_requirements(&record, &required, &mut diagnostics);
    check_findings(&record, &mut diagnostics);
    let evidence_ok = check_evidence(&record, &candidate, &opts.evidence_root, &mut diagnostics);

    let artifact_ok = check_artifact(&candidate, &opts.evidence_root, &mut diagnostics);
    let structure_valid = diagnostics.iter().all(|d| d.severity != "error");
    let all_required_passed = required.iter().all(|id| {
        record
            .requirements
            .iter()
            .any(|r| r.id == *id && r.applicable && r.status == "passed" && !r.evidence.is_empty())
    });
    let no_blocking_findings = record.findings.iter().all(|f| {
        !matches!(f.severity.as_str(), "P0" | "P1")
            || (f.status == "closed" && f.waiver.as_deref().is_none_or(|w| w.trim().is_empty()))
    });
    let has_artifact = record
        .artifact_digest
        .as_ref()
        .is_some_and(|d| is_sha256(d));
    let platform_matches_scope =
        record.scope != "macos_first_release" || record.platform == "macos";
    let admission_conditions_present = structure_valid
        && support.full_admission_supported
        && (!v6_mode || v6_policy_verified)
        && all_required_passed
        && record
            .requirements
            .iter()
            .all(|r| !r.applicable || r.status == "passed")
        && artifact_ok
        && no_blocking_findings
        && has_artifact
        && evidence_ok
        && platform_matches_scope;

    finish(
        &record.scope,
        &required,
        diagnostics,
        oracles,
        structure_valid,
        admission_conditions_present,
        support,
    )
}

fn required_macos_ids(
    spec: Option<(&Path, &str)>,
    diagnostics: &mut Vec<Diagnostic>,
    oracles: &mut BTreeMap<String, String>,
) -> Vec<String> {
    let mut ids = base_macos_ids(false);
    if let Some((path, text)) = spec {
        oracles.insert("spec".into(), path.display().to_string());
        if ["### 24.2 ", "### 24.4 ", "## 25."]
            .iter()
            .any(|heading| text.matches(heading).count() != 1)
        {
            push_error(
                diagnostics,
                "truncated_input",
                &path.display().to_string(),
                "spec",
                "supplied specification must contain the unambiguous acceptance sections",
            );
        }
        let section = text.split("### 24.2 ").nth(1).unwrap_or("");
        let gate_re = Regex::new(r"(?m)^\s*\|\s*(A[0-7])\s").expect("A-gate regex");
        for cap in gate_re.captures_iter(section) {
            ids.insert(cap[1].to_string());
        }
        if let Some(work) = text
            .split("### 24.4 ")
            .nth(1)
            .and_then(|s| s.split("## 25.").next())
        {
            let id_re = Regex::new(r"V5-[A-Z]+-\d+").expect("V5 id regex");
            for m in id_re.find_iter(work) {
                if SUBSEQUENT_IDS.iter().all(|skip| m.as_str() != *skip) {
                    ids.insert(m.as_str().to_string());
                }
            }
        }
    }
    ids.into_iter().collect()
}

fn is_known_scope(scope: &str) -> bool {
    matches!(
        scope,
        "macos_first_release" | "full_v5" | "event_workflows_v6" | "full_v6"
    )
}

fn base_macos_ids(include_device: bool) -> BTreeSet<String> {
    let mut ids: BTreeSet<String> = MACOS_GATES
        .iter()
        .chain(MACOS_V5_IDS.iter())
        .chain(MODEL_SOURCES.iter())
        .chain(PRODUCT_STORIES.iter())
        .map(|s| (*s).to_string())
        .collect();
    if include_device {
        ids.insert("V5-DEVICE-01".into());
    }
    ids
}

fn required_v6_ids(scope: &str, policy: Option<&V6Policy>) -> Vec<String> {
    let mut ids = match scope {
        "macos_first_release" => base_macos_ids(false),
        "event_workflows_v6" => V6_EVENT_GATES
            .iter()
            .chain(V6_M1_WORKFLOWS.iter())
            .chain(V6_M1_AR6.iter())
            .map(|id| (*id).to_string())
            .collect(),
        "full_v6" => {
            let mut full = base_macos_ids(true);
            full.extend((0..=8).map(|n| format!("G{n}")));
            full.extend(V6_EVENT_GATES.iter().map(|id| (*id).to_string()));
            full.extend(V6_WORKFLOWS.iter().map(|id| (*id).to_string()));
            full.extend((1..=10).map(|n| format!("AR6-{n:02}")));
            full.extend((1..=10).map(|n| format!("DOD-{n:02}")));
            full.extend(
                [
                    "parity.identity",
                    "parity.closure",
                    "fixtures.closure",
                    "overlay.closure",
                    "R212.ios",
                    "R212.android",
                    "R212.harmonyos",
                    "R212.wechat",
                    "platform.windows",
                    "platform.linux_server",
                ]
                .map(str::to_string),
            );
            full
        }
        _ => BTreeSet::new(),
    };
    if scope == "macos_first_release" {
        ids.extend(V6_MACOS_ALWAYS.iter().map(|id| (*id).to_string()));
    }
    if matches!(scope, "macos_first_release" | "event_workflows_v6")
        && let Some(policy) = policy
    {
        if policy.conditional_paths.oauth_rotation {
            ids.insert("AR6-01".into());
        }
        if policy.conditional_paths.shared_profile {
            ids.insert("AR6-03".into());
        }
        if policy.conditional_paths.remote_server_tls {
            ids.insert("AR6-09".into());
        }
    }
    ids.into_iter().collect()
}

fn load_spec_document(
    path: &Path,
    diagnostics: &mut Vec<Diagnostic>,
    oracles: &mut BTreeMap<String, String>,
) -> Option<SpecDocument> {
    oracles.insert("spec".into(), path.display().to_string());
    let bytes = match super::checked_input::read_argument(path, 8 * 1024 * 1024) {
        Ok(bytes) => bytes,
        Err(_) => {
            push_error(
                diagnostics,
                "missing_file",
                &path.display().to_string(),
                "spec",
                "optional --spec was given but could not be read; tool policy still applies",
            );
            return None;
        }
    };
    let digest = sha256_hex(&bytes);
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            push_error(
                diagnostics,
                "invalid_utf8",
                &path.display().to_string(),
                "spec",
                "supplied specification is not valid UTF-8",
            );
            return None;
        }
    };
    Some(SpecDocument {
        path: path.to_path_buf(),
        text,
        digest,
    })
}

fn spec_declares_v6(document: &SpecDocument) -> bool {
    if document.text.contains("### 24.5a ") {
        return true;
    }
    let marker_count = Regex::new(r"<!--\s*first-source-current\b")
        .expect("metadata starts")
        .find_iter(&document.text)
        .count();
    if marker_count == 0 {
        return false;
    }
    let re =
        Regex::new(r"(?s)<!--\s*first-source-current\s+(\{.*?\})\s*-->").expect("metadata regex");
    let captures: Vec<_> = re.captures_iter(&document.text).collect();
    if marker_count != 1 || captures.len() != 1 {
        return true;
    }
    match super::checked_input::json::<CurrentSpecMetadata>(captures[0][1].as_bytes()) {
        Ok(metadata) => metadata.version != "v5" || metadata.last_revision == 0,
        Err(_) => true,
    }
}

fn check_v6_contract(
    record: &Record,
    candidate: &CandidateManifest,
    record_value: &serde_json::Value,
    candidate_value: &serde_json::Value,
    spec: Option<&SpecDocument>,
    diagnostics: &mut Vec<Diagnostic>,
    oracles: &mut BTreeMap<String, String>,
) -> bool {
    let before = diagnostics.len();
    check_closed_v6_json(record_value, candidate_value, diagnostics);
    let spec_metadata = if let Some(spec) = spec {
        for heading in ["### 3.6 ", "### 24.3 ", "### 24.4 ", "### 24.5 ", "## 25."] {
            if spec.text.matches(heading).count() != 1 {
                push_error(
                    diagnostics,
                    "spec_section_identity",
                    &spec.path.display().to_string(),
                    heading.trim(),
                    "v6 specification requires each controlled acceptance section exactly once",
                );
            }
        }
        parse_current_spec_metadata(spec, diagnostics)
    } else {
        None
    };
    let Some(policy) = candidate.v6_policy.as_ref() else {
        push_error(
            diagnostics,
            "missing_v6_policy",
            "candidate",
            "v6Policy",
            "v6 scopes require the independently supplied closed v6Policy object",
        );
        if record.spec_digest.is_none() {
            push_error(
                diagnostics,
                "missing_field",
                "record",
                "specDigest",
                "v6 record requires specDigest",
            );
        }
        if spec.is_none() {
            push_error(
                diagnostics,
                "missing_spec",
                "--spec",
                "spec",
                "v6 validation requires the actual first-source file through --spec",
            );
        }
        return false;
    };
    oracles.insert(
        "v6_policy_scope".into(),
        if policy.scope.len() <= 64 {
            policy.scope.clone()
        } else {
            "(overlong)".into()
        },
    );
    oracles.insert(
        "v6_policy_spec_revision".into(),
        policy.spec_revision.to_string(),
    );
    oracles.insert(
        "v6_policy_spec_digest".into(),
        if policy.spec_digest.len() == 64 {
            policy.spec_digest.clone()
        } else {
            "(invalid shape)".into()
        },
    );

    if policy.scope.len() > 64 || policy.spec_version.len() > 16 {
        push_error(
            diagnostics,
            "budget",
            "candidate",
            "v6Policy",
            "v6Policy scope/version strings exceed their bounded contract",
        );
    }
    if policy.schema_version != 1 {
        push_error(
            diagnostics,
            "schema_version",
            "candidate",
            "v6Policy.schemaVersion",
            "v6Policy.schemaVersion must be 1",
        );
    }
    if !matches!(
        policy.scope.as_str(),
        "macos_first_release" | "event_workflows_v6" | "full_v6"
    ) {
        push_error(
            diagnostics,
            "unknown_scope",
            "candidate",
            "v6Policy.scope",
            "v6Policy.scope is outside the v6 closed scope set",
        );
    }
    if policy.scope != record.scope {
        push_error(
            diagnostics,
            "scope_mismatch",
            "record",
            "scope",
            "record.scope must exactly match trusted candidate v6Policy.scope",
        );
    }
    if policy.spec_version != "v6" {
        push_error(
            diagnostics,
            "spec_version_mismatch",
            "candidate",
            "v6Policy.specVersion",
            "v6Policy.specVersion must be exactly v6",
        );
    }
    if policy.spec_revision < V6_MIN_SPEC_REVISION {
        push_error(
            diagnostics,
            "spec_revision_mismatch",
            "candidate",
            "v6Policy.specRevision",
            &format!("v6Policy.specRevision must be at least {V6_MIN_SPEC_REVISION}"),
        );
    }
    if !is_sha256(&policy.spec_digest) {
        push_error(
            diagnostics,
            "digest_shape",
            "candidate",
            "v6Policy.specDigest",
            "v6Policy.specDigest must be 64 lowercase hex characters",
        );
    }
    let Some(record_digest) = record.spec_digest.as_deref() else {
        push_error(
            diagnostics,
            "missing_field",
            "record",
            "specDigest",
            "v6 record requires specDigest",
        );
        return false;
    };
    if !is_sha256(record_digest) {
        push_error(
            diagnostics,
            "digest_shape",
            "record",
            "specDigest",
            "record.specDigest must be 64 lowercase hex characters",
        );
    }
    if record_digest != policy.spec_digest {
        push_error(
            diagnostics,
            "spec_digest_mismatch",
            "record",
            "specDigest",
            "record.specDigest must exactly match trusted candidate v6Policy.specDigest",
        );
    }
    let Some(spec) = spec else {
        push_error(
            diagnostics,
            "missing_spec",
            "--spec",
            "spec",
            "v6 validation requires the actual first-source file through --spec",
        );
        return false;
    };
    oracles.insert("actual_spec_digest".into(), spec.digest.clone());
    if spec.digest != policy.spec_digest || spec.digest != record_digest {
        push_error(
            diagnostics,
            "spec_digest_mismatch",
            &spec.path.display().to_string(),
            "sha256",
            "actual --spec bytes must match both record.specDigest and v6Policy.specDigest",
        );
    }
    if let Some(metadata) = spec_metadata {
        if metadata.version != policy.spec_version {
            push_error(
                diagnostics,
                "spec_version_mismatch",
                &spec.path.display().to_string(),
                "first-source-current.version",
                "actual specification version must match v6Policy.specVersion",
            );
        }
        if metadata.last_revision != policy.spec_revision {
            push_error(
                diagnostics,
                "spec_revision_mismatch",
                &spec.path.display().to_string(),
                "first-source-current.last_revision",
                "actual specification revision must match v6Policy.specRevision",
            );
        }
    }
    diagnostics.len() == before
}

fn parse_current_spec_metadata(
    spec: &SpecDocument,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<CurrentSpecMetadata> {
    let re =
        Regex::new(r"(?s)<!--\s*first-source-current\s+(\{.*?\})\s*-->").expect("metadata regex");
    let captures: Vec<_> = re.captures_iter(&spec.text).collect();
    let starts = Regex::new(r"<!--\s*first-source-current\b")
        .expect("metadata starts")
        .find_iter(&spec.text)
        .count();
    if captures.len() != 1 || starts != 1 {
        push_error(
            diagnostics,
            if captures.is_empty() {
                "truncated_input"
            } else {
                "duplicate_metadata"
            },
            &spec.path.display().to_string(),
            "first-source-current",
            "v6 specification must contain exactly one parseable first-source-current block",
        );
        return None;
    }
    match super::checked_input::json::<CurrentSpecMetadata>(captures[0][1].as_bytes()) {
        Ok(metadata) => Some(metadata),
        Err(_) => {
            push_error(
                diagnostics,
                "invalid_json",
                &spec.path.display().to_string(),
                "first-source-current",
                "first-source-current metadata must be valid JSON with unique fields",
            );
            None
        }
    }
}

fn check_closed_v6_json(
    record: &serde_json::Value,
    candidate: &serde_json::Value,
    diagnostics: &mut Vec<Diagnostic>,
) {
    check_object_keys(
        record,
        &[
            "schemaVersion",
            "scope",
            "specDigest",
            "sourceCommit",
            "workingTreeDigest",
            "lockDigest",
            "uiDigest",
            "artifactDigest",
            "platform",
            "arch",
            "osVersion",
            "enabledCapabilities",
            "requirements",
            "findings",
        ],
        "record",
        diagnostics,
    );
    if let Some(requirements) = record.get("requirements").and_then(|v| v.as_array()) {
        for (index, requirement) in requirements.iter().enumerate() {
            let path = format!("record.requirements[{index}]");
            check_object_keys(
                requirement,
                &[
                    "clause",
                    "id",
                    "applicable",
                    "owner",
                    "status",
                    "command",
                    "scenario",
                    "evidence",
                    "result",
                    "limits",
                ],
                &path,
                diagnostics,
            );
            if let Some(evidence) = requirement.get("evidence").and_then(|v| v.as_array()) {
                for (evidence_index, item) in evidence.iter().enumerate() {
                    check_object_keys(
                        item,
                        &["path", "sha256"],
                        &format!("{path}.evidence[{evidence_index}]"),
                        diagnostics,
                    );
                }
            }
        }
    }
    if let Some(findings) = record.get("findings").and_then(|v| v.as_array()) {
        for (index, finding) in findings.iter().enumerate() {
            check_object_keys(
                finding,
                &["id", "severity", "status", "summary", "waiver"],
                &format!("record.findings[{index}]"),
                diagnostics,
            );
        }
    }
    check_object_keys(
        candidate,
        &[
            "schemaVersion",
            "purpose",
            "sourceCommit",
            "workingTreeDigest",
            "lockDigest",
            "uiDigest",
            "artifactDigest",
            "platform",
            "arch",
            "evidence",
            "artifactFile",
            "v6Policy",
        ],
        "candidate",
        diagnostics,
    );
    if let Some(entries) = candidate.get("evidence").and_then(|v| v.as_object()) {
        for (path, entry) in entries {
            check_object_keys(
                entry,
                &["bytes", "sha256"],
                &format!("candidate.evidence.{path}"),
                diagnostics,
            );
        }
    }
    if let Some(artifact) = candidate.get("artifactFile") {
        check_object_keys(
            artifact,
            &["path", "bytes", "sha256"],
            "candidate.artifactFile",
            diagnostics,
        );
    }
    if let Some(policy) = candidate.get("v6Policy") {
        check_object_keys(
            policy,
            &[
                "schemaVersion",
                "scope",
                "specVersion",
                "specRevision",
                "specDigest",
                "conditionalPaths",
            ],
            "candidate.v6Policy",
            diagnostics,
        );
        if let Some(paths) = policy.get("conditionalPaths") {
            check_object_keys(
                paths,
                &["oauthRotation", "sharedProfile", "remoteServerTls"],
                "candidate.v6Policy.conditionalPaths",
                diagnostics,
            );
        }
    }
}

fn check_object_keys(
    value: &serde_json::Value,
    allowed: &[&str],
    path: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(object) = value.as_object() else {
        return;
    };
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            push_error(
                diagnostics,
                "unknown_field",
                path,
                key,
                "v6 input object contains a field outside its closed contract",
            );
        }
    }
}

fn check_identity_fields(record: &Record, diagnostics: &mut Vec<Diagnostic>) {
    if !is_commit(&record.source_commit) {
        push_error(
            diagnostics,
            "digest_shape",
            "record",
            "sourceCommit",
            "sourceCommit must be 40 lowercase hex characters",
        );
    }
    for (name, value) in [
        ("workingTreeDigest", record.working_tree_digest.as_str()),
        ("lockDigest", record.lock_digest.as_str()),
        ("uiDigest", record.ui_digest.as_str()),
    ] {
        if !is_sha256(value) {
            push_error(
                diagnostics,
                "digest_shape",
                "record",
                name,
                &format!("{name} must be 64 lowercase hex characters"),
            );
        }
    }
    if let Some(artifact) = &record.artifact_digest
        && !is_sha256(artifact)
    {
        push_error(
            diagnostics,
            "digest_shape",
            "record",
            "artifactDigest",
            "artifactDigest must be null or 64 lowercase hex characters",
        );
    }
    if record.platform.trim().is_empty()
        || record.arch.trim().is_empty()
        || record.os_version.trim().is_empty()
        || record.platform.len() > 32
        || record.arch.len() > 32
        || record.os_version.len() > 128
    {
        push_error(
            diagnostics,
            "missing_field",
            "record",
            "platform/arch/osVersion",
            "platform, arch and osVersion must be non-empty",
        );
    }
    if record.enabled_capabilities.len() > 64
        || record
            .enabled_capabilities
            .iter()
            .any(|c| c.is_empty() || c.len() > 128)
        || record
            .enabled_capabilities
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != record.enabled_capabilities.len()
    {
        push_error(
            diagnostics,
            "budget",
            "record",
            "enabledCapabilities",
            "capabilities must be bounded, nonempty and unique",
        );
    }
    if record.platform == "macos"
        && !matches!(record.arch.as_str(), "arm64" | "x64" | "x86_64" | "aarch64")
    {
        push_error(
            diagnostics,
            "unknown_platform",
            "record",
            "arch",
            "unsupported macOS architecture identity",
        );
    }
    if record.requirements.len() > MAX_REQUIREMENTS {
        push_error(
            diagnostics,
            "budget",
            "record",
            "requirements",
            &format!("requirements exceed {MAX_REQUIREMENTS}"),
        );
    }
    if record.findings.len() > MAX_FINDINGS {
        push_error(
            diagnostics,
            "budget",
            "record",
            "findings",
            &format!("findings exceed {MAX_FINDINGS}"),
        );
    }
}

fn check_digest_join(
    record: &Record,
    candidate: &CandidateManifest,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let pairs = [
        (
            "sourceCommit",
            record.source_commit.as_str(),
            candidate.source_commit.as_str(),
        ),
        (
            "workingTreeDigest",
            record.working_tree_digest.as_str(),
            candidate.working_tree_digest.as_str(),
        ),
        (
            "lockDigest",
            record.lock_digest.as_str(),
            candidate.lock_digest.as_str(),
        ),
        (
            "uiDigest",
            record.ui_digest.as_str(),
            candidate.ui_digest.as_str(),
        ),
    ];
    for (name, left, right) in pairs {
        if left != right {
            push_error(
                diagnostics,
                "digest_mismatch",
                "record",
                name,
                &format!("{name} does not match the independently specified candidate manifest"),
            );
        }
    }
    if record.artifact_digest != candidate.artifact_digest {
        push_error(
            diagnostics,
            "digest_mismatch",
            "record",
            "artifactDigest",
            "artifactDigest does not match the independently specified candidate manifest",
        );
    }
    if record.platform != candidate.platform || record.arch != candidate.arch {
        push_error(
            diagnostics,
            "digest_mismatch",
            "record",
            "platform/arch",
            "platform/arch do not match the independently specified candidate manifest",
        );
    }
}

fn check_requirements(record: &Record, required: &[String], diagnostics: &mut Vec<Diagnostic>) {
    let mut seen = BTreeSet::new();
    for req in &record.requirements {
        if !seen.insert(req.id.clone()) {
            push_error(
                diagnostics,
                "duplicate_requirement",
                "record",
                &req.id,
                "requirement id is duplicated",
            );
        }
        if req.clause.trim().is_empty() || req.owner.trim().is_empty() || req.id.trim().is_empty() {
            push_error(
                diagnostics,
                "missing_field",
                "record",
                &req.id,
                "requirement clause and owner must be non-empty",
            );
        }
        if !STATUSES.contains(&req.status.as_str()) {
            push_error(
                diagnostics,
                "unknown_status",
                "record",
                &req.id,
                &format!("unknown requirement status {}", req.status),
            );
        }
        if req.id.len() > 128
            || req.clause.len() > 1024
            || req.owner.len() > 256
            || req.command.len() > 8192
            || req.scenario.len() > 8192
            || req.result.len() > 8192
            || req.limits.len() > 8192
        {
            push_error(
                diagnostics,
                "budget",
                "record",
                &req.id,
                "requirement limits exceed 8192 bytes",
            );
        }
        if req.evidence.len() > MAX_EVIDENCE_PER_REQUIREMENT {
            push_error(
                diagnostics,
                "budget",
                "record",
                &req.id,
                &format!("evidence entries exceed {MAX_EVIDENCE_PER_REQUIREMENT}"),
            );
        }
        let mut seen_evidence = BTreeSet::new();
        for evidence in &req.evidence {
            if !is_sha256(&evidence.sha256) || evidence.path.len() > 4096 {
                push_error(
                    diagnostics,
                    "digest_shape",
                    "record",
                    &req.id,
                    "evidence identity must be bounded with an exact digest",
                );
            }
            if let Err(error) = confined_rel(&evidence.path) {
                diagnostics.push(error);
            }
            if !seen_evidence.insert(&evidence.path) {
                push_error(
                    diagnostics,
                    "duplicate_evidence",
                    "record",
                    &req.id,
                    "duplicate evidence identity",
                );
            }
        }
        if req.status == "passed" && (req.evidence.is_empty() || req.result.trim().is_empty()) {
            push_error(
                diagnostics,
                "passed_without_evidence",
                "record",
                &req.id,
                "passed requires original evidence paths/digests and a result; a command string is not enough",
            );
        }
        if required.iter().any(|id| id == &req.id) && !req.applicable {
            push_error(
                diagnostics,
                "required_marked_inapplicable",
                "record",
                &req.id,
                "tool-policy required item cannot be waived as inapplicable",
            );
        }
    }
    for id in required {
        if !record.requirements.iter().any(|r| r.id == *id) {
            push_error(
                diagnostics,
                "missing_required",
                "record",
                id,
                "tool-policy required item is missing; the required set is not taken from the record or enabledCapabilities",
            );
        }
    }
}

fn check_findings(record: &Record, diagnostics: &mut Vec<Diagnostic>) {
    let mut seen = BTreeSet::new();
    for finding in &record.findings {
        if !seen.insert(finding.id.clone()) {
            push_error(
                diagnostics,
                "duplicate_finding",
                "record",
                &finding.id,
                "finding id is duplicated",
            );
        }
        if !SEVERITIES.contains(&finding.severity.as_str()) {
            push_error(
                diagnostics,
                "unknown_status",
                "record",
                &finding.id,
                &format!("unknown finding severity {}", finding.severity),
            );
        }
        if !FINDING_STATUSES.contains(&finding.status.as_str()) {
            push_error(
                diagnostics,
                "unknown_status",
                "record",
                &finding.id,
                &format!("unknown finding status {}", finding.status),
            );
        }
        if finding.summary.trim().is_empty()
            || finding.summary.len() > 8192
            || finding.id.trim().is_empty()
            || finding.id.len() > 128
        {
            push_error(
                diagnostics,
                "missing_field",
                "record",
                &finding.id,
                "finding summary must be non-empty",
            );
        }
        if matches!(finding.severity.as_str(), "P0" | "P1")
            && finding
                .waiver
                .as_deref()
                .is_some_and(|w| !w.trim().is_empty())
        {
            push_error(
                diagnostics,
                "risk_accepted_p0_p1",
                "record",
                &finding.id,
                "P0/P1 cannot be eliminated by risk acceptance",
            );
        }
        if matches!(finding.severity.as_str(), "P0" | "P1") && finding.status == "open" {
            push_error(
                diagnostics,
                "open_p0_p1",
                "record",
                &finding.id,
                "open P0/P1 blocks admission",
            );
        }
    }
}

fn check_evidence(
    record: &Record,
    candidate: &CandidateManifest,
    evidence_root: &Path,
    diagnostics: &mut Vec<Diagnostic>,
) -> bool {
    if candidate.evidence.len() > MAX_EVIDENCE_FILES {
        push_error(
            diagnostics,
            "budget",
            "candidate",
            "evidence",
            &format!("candidate evidence entries exceed {MAX_EVIDENCE_FILES}"),
        );
        return false;
    }
    let mut ok = true;
    for (path, claimed) in &candidate.evidence {
        if let Err(error) = confined_rel(path) {
            diagnostics.push(error);
            ok = false;
        }
        if !is_sha256(&claimed.sha256) || claimed.bytes > MAX_EVIDENCE_BYTES {
            push_error(
                diagnostics,
                "digest_shape",
                "candidate",
                "evidence",
                "invalid bounded evidence inventory entry",
            );
            ok = false;
        }
    }
    let mut files_seen = 0usize;
    for req in &record.requirements {
        if req.status != "passed" {
            continue;
        }
        if req.command.trim().is_empty() && req.scenario.trim().is_empty() {
            push_error(
                diagnostics,
                "passed_without_evidence",
                "record",
                &req.id,
                "passed requires an actual command or scenario, not only a digest",
            );
            ok = false;
        }
        for item in &req.evidence {
            files_seen += 1;
            if files_seen > MAX_EVIDENCE_FILES {
                push_error(
                    diagnostics,
                    "budget",
                    "record",
                    &req.id,
                    &format!("evidence files exceed {MAX_EVIDENCE_FILES}"),
                );
                return false;
            }
            if !is_sha256(&item.sha256) {
                push_error(
                    diagnostics,
                    "digest_shape",
                    "record",
                    &req.id,
                    "evidence sha256 must be 64 lowercase hex characters",
                );
                ok = false;
                continue;
            }
            let rel = match confined_rel(&item.path) {
                Ok(path) => path,
                Err(diag) => {
                    diagnostics.push(diag);
                    ok = false;
                    continue;
                }
            };
            let Some(claimed) = candidate.evidence.get(&rel) else {
                push_error(
                    diagnostics,
                    "cross_candidate",
                    "record",
                    &req.id,
                    &format!("evidence `{rel}` is not attributed in this candidate manifest"),
                );
                ok = false;
                continue;
            };
            if claimed.bytes == 0 {
                push_error(
                    diagnostics,
                    "passed_without_evidence",
                    "record",
                    &req.id,
                    "an empty file is not original execution evidence",
                );
                ok = false;
                continue;
            }
            if claimed.sha256 != item.sha256 {
                push_error(
                    diagnostics,
                    "digest_mismatch",
                    "record",
                    &req.id,
                    &format!(
                        "record hash for `{rel}` does not match the candidate evidence inventory"
                    ),
                );
                ok = false;
                continue;
            }
            let joined = evidence_root.join(&rel);
            match read_evidence_file(evidence_root, &joined, &rel) {
                Ok(bytes) => {
                    if bytes.len() as u64 != claimed.bytes || sha256_hex(&bytes) != item.sha256 {
                        push_error(
                            diagnostics,
                            "evidence_mismatch",
                            &rel,
                            &req.id,
                            "on-disk evidence bytes do not match the recorded digest; a stale hash cannot hide a modified file",
                        );
                        ok = false;
                    }
                }
                Err(diag) => {
                    diagnostics.push(diag);
                    ok = false;
                }
            }
        }
    }
    ok
}

fn input_diagnostic(error: super::checked_input::InputError, path: &Path) -> Diagnostic {
    use super::checked_input::InputError;
    let code = match error {
        InputError::Path => "path_escape",
        InputError::Symlink => "symlink_escape",
        InputError::Limit => "budget",
        InputError::Changed => "input_changed",
        #[cfg(not(unix))]
        InputError::Unsupported => "platform_unsupported",
        InputError::Missing => "missing_evidence",
    };
    diag(
        code,
        &path.display().to_string(),
        "file",
        "input cannot be read under its bounded directory authority",
    )
}

fn read_evidence_file(root: &Path, _path: &Path, rel: &str) -> Result<Vec<u8>, Diagnostic> {
    super::checked_input::read_under(root, Path::new(rel), MAX_EVIDENCE_BYTES)
        .map_err(|e| input_diagnostic(e, Path::new(rel)))
}

fn check_artifact(
    candidate: &CandidateManifest,
    root: &Path,
    diagnostics: &mut Vec<Diagnostic>,
) -> bool {
    let Some(digest) = candidate.artifact_digest.as_deref() else {
        if candidate.artifact_file.is_some() {
            push_error(
                diagnostics,
                "artifact_shape",
                "candidate",
                "artifactFile",
                "artifact file cannot be declared without an artifact digest",
            );
        }
        return false;
    };
    let Some(artifact) = &candidate.artifact_file else {
        push_error(
            diagnostics,
            "artifact_evidence_missing",
            "candidate",
            "artifactFile",
            "an artifact digest requires independently inventoried artifact bytes",
        );
        return false;
    };
    if artifact.bytes == 0
        || artifact.bytes > MAX_ARTIFACT_BYTES
        || artifact.sha256 != digest
        || !is_sha256(digest)
    {
        push_error(
            diagnostics,
            "artifact_shape",
            "candidate",
            "artifactFile",
            "invalid or conflicting bounded artifact identity",
        );
        return false;
    }
    let path = match confined_rel(&artifact.path) {
        Ok(path) => path,
        Err(error) => {
            diagnostics.push(error);
            return false;
        }
    };
    match super::checked_input::hash_under(root, Path::new(&path), MAX_ARTIFACT_BYTES) {
        Ok((actual, size)) if actual == digest && size == artifact.bytes => true,
        Ok(_) => {
            push_error(
                diagnostics,
                "artifact_mismatch",
                &path,
                "artifactFile",
                "actual artifact bytes do not match the candidate",
            );
            false
        }
        Err(error) => {
            diagnostics.push(input_diagnostic(error, Path::new(&path)));
            false
        }
    }
}

fn confined_rel(relative: &str) -> Result<String, Diagnostic> {
    if relative.is_empty()
        || relative.len() > 4096
        || relative.contains('\\')
        || relative
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(diag("path_escape", relative, "path", "empty evidence path"));
    }
    let path = Path::new(relative);
    if path.is_absolute() {
        return Err(diag(
            "path_escape",
            relative,
            "path",
            "absolute evidence paths are rejected",
        ));
    }
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            _ => {
                return Err(diag(
                    "path_escape",
                    relative,
                    "path",
                    "evidence path contains '..' or another disallowed component",
                ));
            }
        }
    }
    Ok(relative.to_owned())
}

fn finish(
    scope: &str,
    required: &[String],
    diagnostics: Vec<Diagnostic>,
    oracles: BTreeMap<String, String>,
    structure_valid: bool,
    admission_conditions_present: bool,
    support: ReportSupport,
) -> AcceptanceReport {
    let errors = diagnostics.iter().any(|d| d.severity == "error");
    let required_set_source = oracles
        .get("required_set_policy")
        .cloned()
        .unwrap_or_else(|| "tool policy; not the record".into());
    AcceptanceReport {
        ok: !errors,
        structure_valid: structure_valid && !errors,
        admission_conditions_present: admission_conditions_present
            && !errors
            && support.full_admission_supported,
        controller_verified: false,
        product_certified: false,
        release_certified: false,
        scope: scope.to_string(),
        scope_recognized: support.scope_recognized,
        collection_supported: support.collection_supported,
        full_admission_supported: support.full_admission_supported,
        v6_policy_verified: support.v6_policy_verified,
        full_v5_supported: false,
        full_v5_remaining_sources: FULL_V5_REMAINING.iter().map(|s| (*s).to_string()).collect(),
        required_ids: required.to_vec(),
        required_set_source,
        diagnostics,
        oracles,
    }
}

fn print_human(report: &AcceptanceReport) {
    println!("acceptance-check: scope={}", report.scope);
    println!(
        "structure_valid={} admission_conditions_present={} scope_recognized={} collection_supported={} full_admission_supported={} v6_policy_verified={} controller_verified=false product_certified=false release_certified=false full_v5_supported=false",
        report.structure_valid,
        report.admission_conditions_present,
        report.scope_recognized,
        report.collection_supported,
        report.full_admission_supported,
        report.v6_policy_verified,
    );
    println!("required_set_source={}", report.required_set_source);
    println!("required_ids={}", report.required_ids.join(","));
    if report.scope == "full_v5" || !report.full_v5_supported {
        println!("full_v5 remaining sources:");
        for item in &report.full_v5_remaining_sources {
            println!("  - {item}");
        }
    }
    for (key, value) in &report.oracles {
        println!("oracle {key}: {value}");
    }
    for diag in &report.diagnostics {
        println!(
            "{} {}: {} ({}; {})",
            diag.severity, diag.code, diag.message, diag.path, diag.locator
        );
    }
    println!(
        "acceptance-check: not product or release certification; synthetic fixtures are test-only"
    );
}

fn load_json_with_value<T: for<'de> Deserialize<'de>>(
    path: &Path,
    label: &str,
) -> Result<(T, serde_json::Value), Diagnostic> {
    let bytes = super::checked_input::read_argument(path, MAX_JSON_BYTES)
        .map_err(|e| input_diagnostic(e, path))?;
    if bytes.is_empty() {
        return Err(diag(
            "truncated_input",
            &path.display().to_string(),
            label,
            "JSON input is empty",
        ));
    }
    let value: serde_json::Value = super::checked_input::json(&bytes).map_err(|_| {
        diag(
            "invalid_json",
            &path.display().to_string(),
            label,
            "invalid JSON or duplicate object member",
        )
    })?;
    let typed = serde_json::from_value(value.clone()).map_err(|_| {
        diag(
            "invalid_json",
            &path.display().to_string(),
            label,
            "JSON fields do not match the bounded acceptance schema",
        )
    })?;
    Ok((typed, value))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn same_path(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(a), Ok(b)) => a == b,
        _ => left == right,
    }
}

fn push_error(
    diagnostics: &mut Vec<Diagnostic>,
    code: &str,
    path: &str,
    locator: &str,
    message: &str,
) {
    diagnostics.push(diag(code, path, locator, message));
}

fn diag(code: &str, path: &str, locator: &str, message: &str) -> Diagnostic {
    Diagnostic {
        severity: "error",
        code: code.to_string(),
        path: path.to_string(),
        locator: locator.to_string(),
        message: message.to_string(),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    const COMMIT: &str = "52ea4d0a651b5919561aed8fd56b14fcfb4401b2";
    const TREE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const LOCK: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const UI: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TempTree {
        root: PathBuf,
    }

    impl TempTree {
        fn new(tag: &str) -> Self {
            loop {
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos();
                let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
                let root = std::env::temp_dir().join(format!(
                    "openbot-acceptance-{tag}-{}-{nanos}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&root) {
                    Ok(()) => return Self { root },
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("temp: {error}"),
                }
            }
        }

        fn write(&self, rel: &str, bytes: impl AsRef<[u8]>) {
            let path = self.root.join(rel);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("parent");
            }
            fs::write(path, bytes).expect("write");
        }

        fn path(&self, rel: &str) -> PathBuf {
            self.root.join(rel)
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[derive(Clone, Copy)]
    struct Scene {
        drop_id: Option<&'static str>,
        empty_capabilities: bool,
        artifact: bool,
        status: &'static str,
        splice_lock: bool,
        mutate_evidence: bool,
        stale_hash: bool,
        traversal: bool,
        duplicate: bool,
        risk_p1: bool,
        open_p1: bool,
        inapplicable: Option<&'static str>,
        full_v5: bool,
        passed_no_evidence: bool,
    }

    impl Default for Scene {
        fn default() -> Self {
            Self {
                drop_id: None,
                empty_capabilities: false,
                artifact: false,
                status: "planned",
                splice_lock: false,
                mutate_evidence: false,
                stale_hash: false,
                traversal: false,
                duplicate: false,
                risk_p1: false,
                open_p1: false,
                inapplicable: None,
                full_v5: false,
                passed_no_evidence: false,
            }
        }
    }

    struct Harness {
        tree: TempTree,
        opts: Opts,
    }

    impl Harness {
        fn new(scene: Scene) -> Self {
            let tree = TempTree::new("case");
            let evidence_body = b"synthetic-evidence-v1\n";
            let evidence_hash = sha256_hex(evidence_body);
            tree.write("evidence/a0.log", evidence_body);
            let artifact_body = b"synthetic artifact; not an installable release\n";
            let artifact_hash = sha256_hex(artifact_body);
            if scene.artifact {
                tree.write("evidence/artifact.bin", artifact_body);
            }
            let ids = required_macos_ids(None, &mut Vec::new(), &mut BTreeMap::new());
            let mut requirements = Vec::new();
            for id in &ids {
                if scene.drop_id == Some(id.as_str()) {
                    continue;
                }
                let passed = scene.status == "passed" && !scene.passed_no_evidence;
                let evidence = if scene.traversal {
                    vec![serde_json::json!({"path":"../../etc/passwd","sha256":evidence_hash})]
                } else if passed {
                    vec![serde_json::json!({"path":"a0.log","sha256":evidence_hash})]
                } else {
                    Vec::new()
                };
                requirements.push(serde_json::json!({
                    "clause": "§24.2",
                    "id": id,
                    "applicable": scene.inapplicable != Some(id.as_str()),
                    "owner": "backend",
                    "status": scene.status,
                    "command": if passed { "cargo test --locked" } else { "" },
                    "scenario": if passed { "synthetic" } else { "not-run" },
                    "evidence": evidence,
                    "result": if passed { "synthetic pass" } else { "" },
                    "limits": "test-only"
                }));
            }
            if scene.duplicate
                && let Some(first) = requirements.first().cloned()
            {
                requirements.push(first);
            }
            let findings = if scene.risk_p1 {
                vec![serde_json::json!({
                    "id":"F-P1","severity":"P1","status":"open","summary":"still open","waiver":"risk_accepted"
                })]
            } else if scene.open_p1 {
                vec![serde_json::json!({
                    "id":"F-P1","severity":"P1","status":"open","summary":"still open"
                })]
            } else {
                Vec::new()
            };
            let record_lock = if scene.splice_lock { UI } else { LOCK };
            let record = serde_json::json!({
                "schemaVersion": 1,
                "scope": if scene.full_v5 { "full_v5" } else { "macos_first_release" },
                "sourceCommit": COMMIT,
                "workingTreeDigest": TREE,
                "lockDigest": record_lock,
                "uiDigest": UI,
                "artifactDigest": if scene.artifact { serde_json::Value::String(artifact_hash.clone()) } else { serde_json::Value::Null },
                "platform": "macos",
                "arch": "arm64",
                "osVersion": "15.0",
                "enabledCapabilities": if scene.empty_capabilities {
                    Vec::<String>::new()
                } else {
                    vec![
                        "model.custom".to_string(),
                        "model.sdk_gateway".to_string(),
                        "model.account_bridge".to_string(),
                    ]
                },
                "requirements": requirements,
                "findings": findings
            });
            let claimed_hash = if scene.stale_hash {
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string()
            } else {
                evidence_hash.clone()
            };
            let mut candidate = serde_json::json!({
                "schemaVersion": 1,
                "purpose": "trusted-candidate-manifest; not product acceptance",
                "sourceCommit": COMMIT,
                "workingTreeDigest": TREE,
                "lockDigest": LOCK,
                "uiDigest": UI,
                "artifactDigest": if scene.artifact { serde_json::Value::String(artifact_hash.clone()) } else { serde_json::Value::Null },
                "platform": "macos",
                "arch": "arm64",
                "evidence": {
                    "a0.log": {"bytes": evidence_body.len(), "sha256": claimed_hash}
                }
            });
            if scene.artifact {
                candidate["artifactFile"] = serde_json::json!({"path":"artifact.bin","bytes":artifact_body.len(),"sha256":artifact_hash});
            }
            tree.write("record.json", serde_json::to_vec_pretty(&record).unwrap());
            tree.write(
                "candidate.json",
                serde_json::to_vec_pretty(&candidate).unwrap(),
            );
            if scene.mutate_evidence {
                tree.write("evidence/a0.log", b"mutated-evidence\n");
            }
            let opts = Opts {
                record: tree.path("record.json"),
                candidate: tree.path("candidate.json"),
                evidence_root: tree.path("evidence"),
                spec: None,
                json: true,
            };
            Self { tree, opts }
        }

        fn evaluate(&self) -> AcceptanceReport {
            evaluate(&self.opts)
        }
    }

    #[derive(Clone, Copy, Default)]
    struct V6Conditions {
        oauth_rotation: bool,
        shared_profile: bool,
        remote_server_tls: bool,
    }

    struct V6Harness {
        _tree: TempTree,
        opts: Opts,
    }

    impl V6Harness {
        fn new(scope: &str, conditions: V6Conditions) -> Self {
            let tree = TempTree::new("v6-case");
            let spec = b"# synthetic v6 specification\n\
### 3.6 Grok workflows\n\
### 24.3 Acceptance records\n\
### 24.4 v5 obligations\n\
### 24.5 v6 admission\n\
### 24.5a v6 collection\n\
## 25. Definition of Done\n\
<!-- first-source-current {\"version\":\"v6\",\"last_revision\":268} -->\n";
            let spec_digest = sha256_hex(spec);
            tree.write("spec.md", spec);
            let evidence_body = b"synthetic-v6-evidence\n";
            let evidence_hash = sha256_hex(evidence_body);
            tree.write("evidence/run.log", evidence_body);
            let artifact_body = b"synthetic-v6-artifact\n";
            let artifact_hash = sha256_hex(artifact_body);
            tree.write("evidence/artifact.bin", artifact_body);
            let policy = V6Policy {
                schema_version: 1,
                scope: scope.to_string(),
                spec_version: "v6".into(),
                spec_revision: 268,
                spec_digest: spec_digest.clone(),
                conditional_paths: ConditionalPaths {
                    oauth_rotation: conditions.oauth_rotation,
                    shared_profile: conditions.shared_profile,
                    remote_server_tls: conditions.remote_server_tls,
                },
            };
            let requirements = required_v6_ids(scope, Some(&policy))
                .into_iter()
                .map(|id| {
                    serde_json::json!({
                        "clause": "§24.5a",
                        "id": id,
                        "applicable": true,
                        "owner": "backend",
                        "status": "passed",
                        "command": "synthetic-check",
                        "scenario": "synthetic contract fixture",
                        "evidence": [{"path":"run.log","sha256":evidence_hash}],
                        "result": "synthetic pass",
                        "limits": "checker behavior only"
                    })
                })
                .collect::<Vec<_>>();
            let record = serde_json::json!({
                "schemaVersion": 1,
                "scope": scope,
                "specDigest": spec_digest,
                "sourceCommit": COMMIT,
                "workingTreeDigest": TREE,
                "lockDigest": LOCK,
                "uiDigest": UI,
                "artifactDigest": artifact_hash,
                "platform": "macos",
                "arch": "arm64",
                "osVersion": "15.0",
                "enabledCapabilities": [],
                "requirements": requirements,
                "findings": []
            });
            let candidate = serde_json::json!({
                "schemaVersion": 1,
                "purpose": "trusted-candidate-manifest; synthetic checker fixture",
                "sourceCommit": COMMIT,
                "workingTreeDigest": TREE,
                "lockDigest": LOCK,
                "uiDigest": UI,
                "artifactDigest": artifact_hash,
                "platform": "macos",
                "arch": "arm64",
                "v6Policy": {
                    "schemaVersion": 1,
                    "scope": scope,
                    "specVersion": "v6",
                    "specRevision": 268,
                    "specDigest": spec_digest,
                    "conditionalPaths": {
                        "oauthRotation": conditions.oauth_rotation,
                        "sharedProfile": conditions.shared_profile,
                        "remoteServerTls": conditions.remote_server_tls
                    }
                },
                "evidence": {
                    "run.log": {"bytes": evidence_body.len(), "sha256": evidence_hash}
                },
                "artifactFile": {
                    "path": "artifact.bin",
                    "bytes": artifact_body.len(),
                    "sha256": artifact_hash
                }
            });
            tree.write("record.json", serde_json::to_vec_pretty(&record).unwrap());
            tree.write(
                "candidate.json",
                serde_json::to_vec_pretty(&candidate).unwrap(),
            );
            let opts = Opts {
                record: tree.path("record.json"),
                candidate: tree.path("candidate.json"),
                evidence_root: tree.path("evidence"),
                spec: Some(tree.path("spec.md")),
                json: true,
            };
            Self { _tree: tree, opts }
        }

        fn evaluate(&self) -> AcceptanceReport {
            evaluate(&self.opts)
        }

        fn edit_record(&self, edit: impl FnOnce(&mut serde_json::Value)) {
            edit_json(&self.opts.record, edit);
        }

        fn edit_candidate(&self, edit: impl FnOnce(&mut serde_json::Value)) {
            edit_json(&self.opts.candidate, edit);
        }

        fn bind_current_spec_digest(&self) {
            let digest = sha256_hex(&fs::read(self.opts.spec.as_ref().unwrap()).unwrap());
            self.edit_record(|record| record["specDigest"] = digest.clone().into());
            self.edit_candidate(|candidate| candidate["v6Policy"]["specDigest"] = digest.into());
        }
    }

    fn edit_json(path: &Path, edit: impl FnOnce(&mut serde_json::Value)) {
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        edit(&mut value);
        fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }

    #[test]
    fn temp_tree_names_are_unique_under_parallel_creation() {
        let handles = (0..64)
            .map(|_| std::thread::spawn(|| TempTree::new("parallel").root.clone()))
            .collect::<Vec<_>>();
        let paths = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(paths.len(), 64);
    }

    #[test]
    fn controller_review_digest_without_artifact_bytes_cannot_admit() {
        let h = Harness::new(Scene {
            artifact: true,
            status: "passed",
            ..Scene::default()
        });
        let mut candidate: serde_json::Value =
            serde_json::from_slice(&fs::read(&h.opts.candidate).unwrap()).unwrap();
        candidate.as_object_mut().unwrap().remove("artifactFile");
        fs::write(&h.opts.candidate, serde_json::to_vec(&candidate).unwrap()).unwrap();
        assert!(!h.evaluate().admission_conditions_present);
    }

    #[test]
    fn controller_review_applicable_additional_blocker_cannot_admit() {
        let h = Harness::new(Scene {
            artifact: true,
            status: "passed",
            ..Scene::default()
        });
        let mut record: serde_json::Value =
            serde_json::from_slice(&fs::read(&h.opts.record).unwrap()).unwrap();
        record["requirements"].as_array_mut().unwrap().push(serde_json::json!({
            "id":"additional-blocker","clause":"local-regression","applicable":true,"owner":"reviewer",
            "status":"blocked","command":"","scenario":"pending","evidence":[],"result":"","limits":"test-only"
        }));
        fs::write(&h.opts.record, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(!h.evaluate().admission_conditions_present);
    }

    #[test]
    fn controller_review_p1_waiver_cannot_hide_behind_another_label() {
        let h = Harness::new(Scene::default());
        let mut record: serde_json::Value =
            serde_json::from_slice(&fs::read(&h.opts.record).unwrap()).unwrap();
        record["findings"] = serde_json::json!([{"id":"P1-test","severity":"P1","status":"closed","summary":"not fixed","waiver":"accepted_by_admin"}]);
        fs::write(&h.opts.record, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(!h.evaluate().ok);
    }

    #[test]
    fn controller_review_invalid_planned_evidence_is_not_structurally_valid() {
        let h = Harness::new(Scene::default());
        let mut record: serde_json::Value =
            serde_json::from_slice(&fs::read(&h.opts.record).unwrap()).unwrap();
        record["requirements"][0]["evidence"] =
            serde_json::json!([{"path":"../escape", "sha256":"bad"}]);
        fs::write(&h.opts.record, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(!h.evaluate().structure_valid);
    }

    #[test]
    fn controller_review_empty_supplied_spec_is_not_silently_ignored() {
        let mut h = Harness::new(Scene::default());
        h.tree
            .write("empty-spec.md", b"unrelated or truncated input");
        h.opts.spec = Some(h.tree.path("empty-spec.md"));
        assert!(!h.evaluate().ok);
    }

    #[test]
    fn controller_review_actual_artifact_tamper_is_rejected() {
        let h = Harness::new(Scene {
            artifact: true,
            status: "passed",
            ..Scene::default()
        });
        assert!(h.evaluate().admission_conditions_present);
        h.tree.write("evidence/artifact.bin", b"replaced");
        let report = h.evaluate();
        assert!(!report.admission_conditions_present);
        assert!(codes(&report).iter().any(|c| c == "artifact_mismatch"));
    }

    #[test]
    fn controller_review_candidate_duplicate_map_and_linked_parent_are_rejected() {
        let h = Harness::new(Scene::default());
        let original = fs::read_to_string(&h.opts.candidate).unwrap();
        fs::write(
            &h.opts.candidate,
            original.replacen("\"evidence\":", "\"evidence\":{},\"evidence\":", 1),
        )
        .unwrap();
        assert!(codes(&h.evaluate()).iter().any(|c| c == "invalid_json"));
        fs::write(&h.opts.candidate, original).unwrap();
        fs::create_dir(h.tree.path("evidence/subdir")).unwrap();
        symlink("subdir", h.tree.path("evidence/alias")).unwrap();
        h.tree.write("evidence/subdir/data", b"test");
        assert!(
            read_evidence_file(
                &h.opts.evidence_root,
                &h.tree.path("evidence/alias/data"),
                "alias/data"
            )
            .is_err()
        );
        assert!(confined_rel(r"..\outside").is_err());
    }

    #[test]
    fn controller_review_unreferenced_bad_inventory_and_empty_execution_evidence_fail() {
        let h = Harness::new(Scene::default());
        let mut candidate: serde_json::Value =
            serde_json::from_slice(&fs::read(&h.opts.candidate).unwrap()).unwrap();
        candidate["evidence"]["unused"] = serde_json::json!({"bytes":1,"sha256":"bad"});
        fs::write(&h.opts.candidate, serde_json::to_vec(&candidate).unwrap()).unwrap();
        assert!(!h.evaluate().structure_valid);
        let h = Harness::new(Scene {
            artifact: true,
            status: "passed",
            ..Scene::default()
        });
        let hash = sha256_hex(b"");
        h.tree.write("evidence/a0.log", b"");
        let mut candidate: serde_json::Value =
            serde_json::from_slice(&fs::read(&h.opts.candidate).unwrap()).unwrap();
        candidate["evidence"]["a0.log"] = serde_json::json!({"bytes":0,"sha256":hash});
        fs::write(&h.opts.candidate, serde_json::to_vec(&candidate).unwrap()).unwrap();
        let mut record: serde_json::Value =
            serde_json::from_slice(&fs::read(&h.opts.record).unwrap()).unwrap();
        for requirement in record["requirements"].as_array_mut().unwrap() {
            requirement["evidence"][0]["sha256"] = hash.clone().into();
        }
        fs::write(&h.opts.record, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(!h.evaluate().admission_conditions_present);
    }

    fn codes(report: &AcceptanceReport) -> Vec<String> {
        report.diagnostics.iter().map(|d| d.code.clone()).collect()
    }

    fn assert_has(report: &AcceptanceReport, code: &str) {
        assert!(
            !report.ok,
            "expected failure {code}, diags={:?}",
            report.diagnostics
        );
        assert!(
            codes(report).iter().any(|c| c == code),
            "expected {code} in {:?}",
            codes(report)
        );
        assert!(!report.product_certified);
        assert!(!report.release_certified);
        assert!(!report.controller_verified);
        assert!(!report.full_v5_supported);
    }

    #[test]
    fn acceptance_positive_development_record_is_not_release() {
        let harness = Harness::new(Scene::default());
        let report = harness.evaluate();
        assert!(report.ok, "{:?}", report.diagnostics);
        assert!(report.structure_valid);
        assert!(!report.admission_conditions_present);
        assert!(!report.product_certified);
        assert!(!report.release_certified);
        assert!(!report.full_v5_supported);
        assert!(report.scope_recognized);
        assert!(report.collection_supported);
        assert!(report.full_admission_supported);
        assert!(!report.v6_policy_verified);
        assert!(report.required_ids.iter().any(|id| id == "A4"));
        assert!(report.required_ids.iter().any(|id| id == "model.custom"));
        assert!(report.full_v5_remaining_sources.len() >= 8);
        let _ = &harness.tree;
    }

    #[test]
    fn acceptance_positive_passed_with_artifact_still_not_certified() {
        let harness = Harness::new(Scene {
            artifact: true,
            status: "passed",
            ..Scene::default()
        });
        let report = harness.evaluate();
        assert!(report.ok, "{:?}", report.diagnostics);
        assert!(report.structure_valid);
        assert!(report.admission_conditions_present);
        assert!(!report.controller_verified);
        assert!(!report.product_certified);
        assert!(!report.release_certified);
        let _ = &harness.tree;
    }

    #[test]
    fn acceptance_missing_a4_fails() {
        let harness = Harness::new(Scene {
            drop_id: Some("A4"),
            ..Scene::default()
        });
        assert_has(&harness.evaluate(), "missing_required");
        let _ = &harness.tree;
    }

    #[test]
    fn acceptance_missing_model_source_fails() {
        let harness = Harness::new(Scene {
            drop_id: Some("model.account_bridge"),
            ..Scene::default()
        });
        assert_has(&harness.evaluate(), "missing_required");
        let _ = &harness.tree;
    }

    #[test]
    fn acceptance_empty_capabilities_cannot_drop_stories() {
        let harness = Harness::new(Scene {
            empty_capabilities: true,
            drop_id: Some("story.workbench"),
            ..Scene::default()
        });
        assert_has(&harness.evaluate(), "missing_required");
        let _ = &harness.tree;
    }

    #[test]
    fn acceptance_inapplicable_cannot_hide_required() {
        let harness = Harness::new(Scene {
            inapplicable: Some("story.computer"),
            ..Scene::default()
        });
        assert_has(&harness.evaluate(), "required_marked_inapplicable");
        let _ = &harness.tree;
    }

    #[test]
    fn acceptance_missing_artifact_cannot_admit() {
        let harness = Harness::new(Scene {
            status: "passed",
            artifact: false,
            ..Scene::default()
        });
        let report = harness.evaluate();
        assert!(report.ok, "{:?}", report.diagnostics);
        assert!(!report.admission_conditions_present);
        assert!(!report.release_certified);
        let _ = &harness.tree;
    }

    #[test]
    fn acceptance_forged_artifact_digest_fails() {
        let harness = Harness::new(Scene {
            artifact: true,
            status: "passed",
            ..Scene::default()
        });
        let mut record: serde_json::Value =
            serde_json::from_slice(&fs::read(harness.opts.record.clone()).unwrap()).unwrap();
        record["artifactDigest"] = serde_json::json!(TREE);
        fs::write(
            &harness.opts.record,
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
        assert_has(&harness.evaluate(), "digest_mismatch");
        let _ = &harness.tree;
    }

    #[test]
    fn acceptance_spliced_lock_digest_fails() {
        let harness = Harness::new(Scene {
            splice_lock: true,
            ..Scene::default()
        });
        assert_has(&harness.evaluate(), "digest_mismatch");
        let _ = &harness.tree;
    }

    #[test]
    fn acceptance_modified_evidence_with_stale_hash_fails() {
        let harness = Harness::new(Scene {
            artifact: true,
            status: "passed",
            mutate_evidence: true,
            ..Scene::default()
        });
        assert_has(&harness.evaluate(), "evidence_mismatch");
        let _ = &harness.tree;
    }

    #[test]
    fn acceptance_path_traversal_fails() {
        let harness = Harness::new(Scene {
            status: "passed",
            artifact: true,
            traversal: true,
            ..Scene::default()
        });
        assert_has(&harness.evaluate(), "path_escape");
        let _ = &harness.tree;
    }

    #[test]
    fn acceptance_symlink_escape_fails() {
        let harness = Harness::new(Scene {
            status: "passed",
            artifact: true,
            ..Scene::default()
        });
        let outside = harness.tree.path("outside.log");
        fs::write(&outside, b"escaped\n").unwrap();
        let link = harness.tree.path("evidence/a0.log");
        fs::remove_file(&link).unwrap();
        symlink(&outside, &link).unwrap();
        assert_has(&harness.evaluate(), "symlink_escape");
        let _ = &harness.tree;
    }

    #[test]
    fn acceptance_duplicate_requirement_fails() {
        let harness = Harness::new(Scene {
            duplicate: true,
            ..Scene::default()
        });
        assert_has(&harness.evaluate(), "duplicate_requirement");
        let _ = &harness.tree;
    }

    #[test]
    fn acceptance_blocked_renamed_passed_without_evidence_fails() {
        let harness = Harness::new(Scene {
            status: "passed",
            passed_no_evidence: true,
            artifact: true,
            ..Scene::default()
        });
        assert_has(&harness.evaluate(), "passed_without_evidence");
        let _ = &harness.tree;
    }

    #[test]
    fn acceptance_risk_accepted_p1_fails() {
        let harness = Harness::new(Scene {
            risk_p1: true,
            ..Scene::default()
        });
        assert_has(&harness.evaluate(), "risk_accepted_p0_p1");
        let _ = &harness.tree;
    }

    #[test]
    fn acceptance_open_p1_blocks_admission() {
        let harness = Harness::new(Scene {
            open_p1: true,
            artifact: true,
            status: "passed",
            ..Scene::default()
        });
        assert_has(&harness.evaluate(), "open_p0_p1");
        let _ = &harness.tree;
    }

    #[test]
    fn acceptance_full_v5_is_explicitly_unsupported() {
        let harness = Harness::new(Scene {
            full_v5: true,
            ..Scene::default()
        });
        let report = harness.evaluate();
        assert_has(&report, "full_v5_unsupported");
        assert!(!report.full_v5_supported);
        assert!(!report.admission_conditions_present);
        assert!(
            report
                .full_v5_remaining_sources
                .iter()
                .any(|s| s.contains("§25"))
        );
        let _ = &harness.tree;
    }

    #[test]
    fn acceptance_v6_m1_complete_collection_is_admissible_but_not_certified() {
        let harness = V6Harness::new("event_workflows_v6", V6Conditions::default());
        let report = harness.evaluate();
        assert!(report.ok, "{:?}", report.diagnostics);
        assert!(report.structure_valid);
        assert!(report.admission_conditions_present);
        assert!(report.scope_recognized);
        assert!(report.collection_supported);
        assert!(report.full_admission_supported);
        assert!(report.v6_policy_verified);
        assert!(report.required_ids.iter().any(|id| id == "E5"));
        assert!(report.required_ids.iter().any(|id| id == "V6-AUTO-01"));
        assert!(report.required_ids.iter().any(|id| id == "AR6-08"));
        assert!(!report.required_ids.iter().any(|id| id == "V6-NODE-01"));
        assert_eq!(report.required_ids.len(), 22);
        assert!(!report.controller_verified);
        assert!(!report.product_certified);
        assert!(!report.release_certified);
    }

    #[test]
    fn acceptance_v6_macos_uses_all_explicit_conditional_paths() {
        let harness = V6Harness::new(
            "macos_first_release",
            V6Conditions {
                oauth_rotation: true,
                shared_profile: true,
                remote_server_tls: true,
            },
        );
        let report = harness.evaluate();
        assert!(report.ok, "{:?}", report.diagnostics);
        assert!(report.admission_conditions_present);
        for id in ["AR6-01", "AR6-03", "AR6-04", "AR6-09", "AR6-10"] {
            assert!(report.required_ids.iter().any(|required| required == id));
        }
        assert!(report.required_ids.iter().any(|id| id == "A0"));
        assert!(report.required_ids.iter().any(|id| id == "V5-SPEC-01"));
        assert_eq!(report.required_ids.len(), 33);
    }

    #[test]
    fn acceptance_full_v6_collects_complete_ids_but_never_admits() {
        let harness = V6Harness::new("full_v6", V6Conditions::default());
        let report = harness.evaluate();
        assert_has(&report, "full_v6_aggregate_closure_unimplemented");
        assert!(report.scope_recognized);
        assert!(report.collection_supported);
        assert!(!report.full_admission_supported);
        assert!(!report.admission_conditions_present);
        for id in [
            "A7",
            "G8",
            "E5",
            "V5-DEVICE-01",
            "V6-NODE-01",
            "AR6-10",
            "DOD-10",
            "parity.identity",
            "fixtures.closure",
            "R212.harmonyos",
            "platform.linux_server",
        ] {
            assert!(report.required_ids.iter().any(|required| required == id));
        }
        assert_eq!(report.required_ids.len(), 84);
    }

    #[test]
    fn acceptance_v6_missing_workflow_cannot_be_hidden_by_capabilities() {
        let harness = V6Harness::new("event_workflows_v6", V6Conditions::default());
        harness.edit_record(|record| {
            record["enabledCapabilities"] = serde_json::json!([]);
            record["requirements"]
                .as_array_mut()
                .unwrap()
                .retain(|requirement| requirement["id"] != "V6-EVENT-01");
        });
        assert_has(&harness.evaluate(), "missing_required");
    }

    #[test]
    fn acceptance_v6_scope_cannot_relabel_an_m1_record_as_m0() {
        let harness = V6Harness::new("event_workflows_v6", V6Conditions::default());
        harness.edit_record(|record| record["scope"] = "macos_first_release".into());
        let report = harness.evaluate();
        assert_has(&report, "scope_mismatch");
        assert_has(&report, "missing_required");
    }

    #[test]
    fn acceptance_v6_unknown_scope_is_rejected() {
        let harness = V6Harness::new("future_v6_scope", V6Conditions::default());
        let report = harness.evaluate();
        assert_has(&report, "unknown_scope");
        assert!(!report.scope_recognized);
        assert!(!report.collection_supported);
        assert!(!report.full_admission_supported);
    }

    #[test]
    fn acceptance_v6_conditional_paths_have_no_implicit_false_default() {
        let harness = V6Harness::new("event_workflows_v6", V6Conditions::default());
        harness.edit_candidate(|candidate| {
            candidate["v6Policy"]["conditionalPaths"]
                .as_object_mut()
                .unwrap()
                .remove("oauthRotation");
        });
        assert_has(&harness.evaluate(), "invalid_json");
    }

    #[test]
    fn acceptance_v6_scope_requires_policy_and_spec() {
        let harness = V6Harness::new("event_workflows_v6", V6Conditions::default());
        harness.edit_candidate(|candidate| {
            candidate.as_object_mut().unwrap().remove("v6Policy");
        });
        assert_has(&harness.evaluate(), "missing_v6_policy");

        let mut harness = V6Harness::new("event_workflows_v6", V6Conditions::default());
        let _ = harness.opts.spec.take();
        assert_has(&harness.evaluate(), "missing_spec");
    }

    #[test]
    fn acceptance_v6_new_field_signals_cannot_downgrade_macos_to_legacy() {
        let mut harness = V6Harness::new("macos_first_release", V6Conditions::default());
        harness.edit_candidate(|candidate| {
            candidate.as_object_mut().unwrap().remove("v6Policy");
        });
        let _ = harness.opts.spec.take();
        let report = harness.evaluate();
        assert_has(&report, "missing_v6_policy");
        assert_has(&report, "missing_spec");

        let mut harness = V6Harness::new("macos_first_release", V6Conditions::default());
        harness.edit_record(|record| {
            record.as_object_mut().unwrap().remove("specDigest");
        });
        harness.edit_candidate(|candidate| candidate["v6Policy"] = serde_json::Value::Null);
        let _ = harness.opts.spec.take();
        let report = harness.evaluate();
        assert_has(&report, "missing_v6_policy");
        assert_has(&report, "missing_field");
    }

    #[test]
    fn acceptance_malformed_current_marker_cannot_fall_back_to_v5() {
        let mut harness = Harness::new(Scene::default());
        harness.tree.write(
            "malformed-current.md",
            b"### 24.2 macOS\n### 24.4 v5\n## 25. DoD\n<!-- first-source-current {\"version\":\"v6\",\"version\":\"v5\",\"last_revision\":268} -->\n",
        );
        harness.opts.spec = Some(harness.tree.path("malformed-current.md"));
        let report = harness.evaluate();
        assert_has(&report, "invalid_json");
        assert_has(&report, "missing_v6_policy");
    }

    #[test]
    fn acceptance_valid_v5_current_metadata_stays_legacy() {
        let mut harness = Harness::new(Scene::default());
        harness.tree.write(
            "v5-spec.md",
            b"### 24.2 macOS\n| A0 | gate |\n### 24.4 v5\n## 25. DoD\n<!-- first-source-current {\"version\":\"v5\",\"last_revision\":267} -->\n",
        );
        harness.opts.spec = Some(harness.tree.path("v5-spec.md"));
        let report = harness.evaluate();
        assert!(report.ok, "{:?}", report.diagnostics);
        assert!(!report.v6_policy_verified);
        assert!(!report.admission_conditions_present);
    }

    #[test]
    fn acceptance_v6_applicable_ar6_cannot_be_removed_or_waived() {
        let harness = V6Harness::new("macos_first_release", V6Conditions::default());
        harness.edit_record(|record| {
            record["requirements"]
                .as_array_mut()
                .unwrap()
                .retain(|requirement| requirement["id"] != "AR6-04");
        });
        assert_has(&harness.evaluate(), "missing_required");

        let harness = V6Harness::new(
            "event_workflows_v6",
            V6Conditions {
                oauth_rotation: true,
                ..V6Conditions::default()
            },
        );
        harness.edit_record(|record| {
            record["requirements"]
                .as_array_mut()
                .unwrap()
                .retain(|requirement| requirement["id"] != "AR6-01");
        });
        assert_has(&harness.evaluate(), "missing_required");

        let harness = V6Harness::new("event_workflows_v6", V6Conditions::default());
        harness.edit_record(|record| {
            let ar6 = record["requirements"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|requirement| requirement["id"] == "AR6-02")
                .unwrap();
            ar6["applicable"] = false.into();
        });
        assert_has(&harness.evaluate(), "required_marked_inapplicable");
    }

    #[test]
    fn acceptance_v6_binds_record_policy_and_actual_spec_digest() {
        let harness = V6Harness::new("event_workflows_v6", V6Conditions::default());
        harness.edit_record(|record| record["specDigest"] = TREE.into());
        assert_has(&harness.evaluate(), "spec_digest_mismatch");
    }

    #[test]
    fn acceptance_v6_rejects_duplicate_current_metadata_even_when_rehashed() {
        let harness = V6Harness::new("event_workflows_v6", V6Conditions::default());
        let spec_path = harness.opts.spec.as_ref().unwrap();
        let mut spec = fs::read(spec_path).unwrap();
        spec.extend_from_slice(
            b"<!-- first-source-current {\"version\":\"v6\",\"last_revision\":268} -->\n",
        );
        fs::write(spec_path, spec).unwrap();
        harness.bind_current_spec_digest();
        assert_has(&harness.evaluate(), "duplicate_metadata");
    }

    #[test]
    fn acceptance_v6_accepts_later_frozen_revision_when_exactly_bound() {
        let harness = V6Harness::new("event_workflows_v6", V6Conditions::default());
        let spec_path = harness.opts.spec.as_ref().unwrap();
        let spec = fs::read_to_string(spec_path)
            .unwrap()
            .replace("\"last_revision\":268", "\"last_revision\":270");
        fs::write(spec_path, spec).unwrap();
        harness.edit_candidate(|candidate| candidate["v6Policy"]["specRevision"] = 270.into());
        harness.bind_current_spec_digest();
        let report = harness.evaluate();
        assert!(report.ok, "{:?}", report.diagnostics);
        assert!(report.v6_policy_verified);
    }

    #[test]
    fn acceptance_v6_record_and_policy_objects_are_closed() {
        let harness = V6Harness::new("event_workflows_v6", V6Conditions::default());
        harness.edit_record(|record| record["candidateRequiredIds"] = serde_json::json!([]));
        assert_has(&harness.evaluate(), "unknown_field");

        let harness = V6Harness::new("event_workflows_v6", V6Conditions::default());
        harness.edit_candidate(|candidate| {
            candidate["v6Policy"]["conditionalPaths"]["defaultFalse"] = false.into()
        });
        assert_has(&harness.evaluate(), "invalid_json");
    }

    #[test]
    fn acceptance_on_disk_positive_fixture() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fixture = manifest_dir.join("../../fixtures/v5/acceptance/positive");
        if !fixture.join("record.json").is_file() {
            return;
        }
        let opts = Opts {
            record: fixture.join("record.json"),
            candidate: fixture.join("candidate.json"),
            evidence_root: fixture.join("evidence"),
            spec: None,
            json: true,
        };
        let report = evaluate(&opts);
        assert!(report.ok, "{:?}", report.diagnostics);
        assert!(!report.release_certified);
    }
}
