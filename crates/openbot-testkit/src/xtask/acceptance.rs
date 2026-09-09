//! macOS candidate acceptance-record checker (v5 §24.2–§24.4 / PA-08).
//!
//! Required IDs come from the v5 body plus tool policy, never from the record.
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

#[derive(Debug, Serialize, Clone)]
pub(crate) struct AcceptanceReport {
    pub ok: bool,
    pub structure_valid: bool,
    pub admission_conditions_present: bool,
    pub controller_verified: bool,
    pub product_certified: bool,
    pub release_certified: bool,
    pub scope: String,
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
    evidence: BTreeMap<String, PackedEvidence>,
    #[serde(default)]
    artifact_file: Option<ArtifactFile>,
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
        record: record.ok_or_else(|| anyhow!("usage: cargo xtask acceptance-check --record <json> --candidate <trusted-candidate-manifest> --evidence-root <dir> [--spec <v5.md>] [--json]"))?,
        candidate: candidate.ok_or_else(|| anyhow!("usage: cargo xtask acceptance-check --record <json> --candidate <trusted-candidate-manifest> --evidence-root <dir> [--spec <v5.md>] [--json]"))?,
        evidence_root: evidence_root.ok_or_else(|| anyhow!("usage: cargo xtask acceptance-check --record <json> --candidate <trusted-candidate-manifest> --evidence-root <dir> [--spec <v5.md>] [--json]"))?,
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
    oracles.insert(
        "required_set_policy".into(),
        "v5 §24.2 A0–A7 + §24.4 macOS V5 IDs excluding V5-DEVICE-01 + three model sources + three product stories".into(),
    );
    oracles.insert(
        "spec_default".into(),
        "controlled built-in requirement policy; optional --spec is explicit".into(),
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

    let required = required_macos_ids(opts.spec.as_deref(), &mut diagnostics, &mut oracles);
    let record = match load_json::<Record>(&opts.record, "record") {
        Ok(value) => value,
        Err(diag) => {
            diagnostics.push(diag);
            return finish("unknown", &required, diagnostics, oracles, false, false);
        }
    };
    let candidate = match load_json::<CandidateManifest>(&opts.candidate, "candidate") {
        Ok(value) => value,
        Err(diag) => {
            diagnostics.push(diag);
            return finish(&record.scope, &required, diagnostics, oracles, false, false);
        }
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
    if record.scope != "macos_first_release" && !full_v5 {
        push_error(
            &mut diagnostics,
            "unknown_scope",
            "record",
            "scope",
            &format!(
                "scope must be macos_first_release or full_v5, found {}",
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
    let admission_conditions_present = structure_valid
        && !full_v5
        && all_required_passed
        && record
            .requirements
            .iter()
            .all(|r| !r.applicable || r.status == "passed")
        && artifact_ok
        && no_blocking_findings
        && has_artifact
        && evidence_ok
        && record.platform == "macos";

    finish(
        &record.scope,
        &required,
        diagnostics,
        oracles,
        structure_valid,
        admission_conditions_present,
    )
}

fn required_macos_ids(
    spec: Option<&Path>,
    diagnostics: &mut Vec<Diagnostic>,
    oracles: &mut BTreeMap<String, String>,
) -> Vec<String> {
    let mut ids: BTreeSet<String> = MACOS_GATES
        .iter()
        .chain(MACOS_V5_IDS.iter())
        .chain(MODEL_SOURCES.iter())
        .chain(PRODUCT_STORIES.iter())
        .map(|s| (*s).to_string())
        .collect();
    if let Some(path) = spec {
        oracles.insert("spec".into(), path.display().to_string());
        match super::checked_input::read_argument(path, 8 * 1024 * 1024) {
            Ok(bytes) => {
                if let Ok(text) = String::from_utf8(bytes) {
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
                } else {
                    push_error(
                        diagnostics,
                        "invalid_utf8",
                        &path.display().to_string(),
                        "spec",
                        "v5 spec is not valid UTF-8; falling back to tool policy required set",
                    );
                }
            }
            Err(_) => push_error(
                diagnostics,
                "missing_file",
                &path.display().to_string(),
                "spec",
                "optional --spec was given but could not be read; tool policy still applies",
            ),
        }
    }
    ids.into_iter().collect()
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
                "required macOS first-release item cannot be waived as inapplicable",
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
                "required macOS first-release item is missing; the required set is not taken from the record",
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
) -> AcceptanceReport {
    let errors = diagnostics.iter().any(|d| d.severity == "error");
    let full_v5 = scope == "full_v5";
    AcceptanceReport {
        ok: !errors,
        structure_valid: structure_valid && !errors,
        admission_conditions_present: admission_conditions_present && !errors && !full_v5,
        controller_verified: false,
        product_certified: false,
        release_certified: false,
        scope: scope.to_string(),
        full_v5_supported: false,
        full_v5_remaining_sources: FULL_V5_REMAINING.iter().map(|s| (*s).to_string()).collect(),
        required_ids: required.to_vec(),
        required_set_source: "v5 body + tool policy; not the record".into(),
        diagnostics,
        oracles,
    }
}

fn print_human(report: &AcceptanceReport) {
    println!("acceptance-check: scope={}", report.scope);
    println!(
        "structure_valid={} admission_conditions_present={} controller_verified=false product_certified=false release_certified=false full_v5_supported=false",
        report.structure_valid, report.admission_conditions_present
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

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path, label: &str) -> Result<T, Diagnostic> {
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
    super::checked_input::json(&bytes).map_err(|_| {
        diag(
            "invalid_json",
            &path.display().to_string(),
            label,
            "invalid JSON or duplicate object member",
        )
    })
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
    use std::time::{SystemTime, UNIX_EPOCH};

    const COMMIT: &str = "52ea4d0a651b5919561aed8fd56b14fcfb4401b2";
    const TREE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const LOCK: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const UI: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    struct TempTree {
        root: PathBuf,
    }

    impl TempTree {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "openbot-acceptance-{tag}-{}-{nanos}",
                std::process::id()
            ));
            fs::create_dir_all(&root).expect("temp");
            Self { root }
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
                } else if scene.passed_no_evidence && scene.status == "passed" {
                    Vec::new()
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
            if scene.duplicate {
                if let Some(first) = requirements.first().cloned() {
                    requirements.push(first);
                }
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
