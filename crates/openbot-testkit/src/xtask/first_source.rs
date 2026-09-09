//! Read-only first-source consistency checker (v5 §0.7 / §28.6 / PA-10 / V5-SPEC-01).
//!
//! Independent oracles are the trusted baseline package (history rows + file digests),
//! Rust engine constants, the protocol JSON descriptor, `engine_bundle.rs` manifest
//! schema, and the GUI pointer file. The document under `--root` is the candidate, not
//! a source of its own baseline. This checker never certifies product or release.

use std::collections::{BTreeMap, BTreeSet};
#[cfg(all(test, unix))]
use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Result, anyhow, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const DEFAULT_SPEC_RELPATH: &str = "spec/current.md";
const ENGINE_CONSTANTS_RELPATH: &str = "crates/openbot-contracts/src/engine.rs";
const ENGINE_DESCRIPTOR_RELPATH: &str = "crates/openbot-contracts/engine-protocol-v4.json";
const ENGINE_BUNDLE_RELPATH: &str = "crates/openbot-testkit/src/xtask/engine_bundle.rs";
#[cfg(test)]
const ENTRY_RELPATHS: [&str; 3] = ["guide.md", "README.md", "handoff.md"];
const MAX_REVISIONS: u32 = 16384;
const MAX_DOCUMENT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_JSON_BYTES: u64 = 2 * 1024 * 1024;
const MAX_PACKAGE_FILES: usize = 64;
const FROZEN_PA_MAPPING: [(u32, u32); 10] = [
    (1, 231),
    (2, 232),
    (3, 233),
    (4, 234),
    (5, 235),
    (6, 236),
    (7, 237),
    (8, 238),
    (9, 239),
    (10, 240),
];
const REQUIRED_V5_IDS: [&str; 15] = [
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
    "V5-DEVICE-01",
    "V5-SPEC-01",
];
const REQUIRED_HEADINGS: [&str; 16] = [
    "0.2b", "0.7", "6.4a", "7.3d", "7.3e", "10.5a", "10.7", "13.5", "14.1a", "14.4", "15.5",
    "19.4", "24.2", "24.3", "24.4", "28.6",
];

#[derive(Debug, Serialize, Clone)]
pub(crate) struct FirstSourceReport {
    pub ok: bool,
    pub scope: &'static str,
    pub product_certified: bool,
    pub release_certified: bool,
    pub version: Option<String>,
    pub last_revision: Option<u32>,
    pub spec_sha256: Option<String>,
    pub spec_matches_frozen_bytes: Option<bool>,
    pub diagnostics: Vec<Diagnostic>,
    pub oracles: BTreeMap<String, String>,
    pub unresolved_reference_classes: Vec<String>,
    pub historical_unresolved: Vec<String>,
    pub uncovered_reference_classes: Vec<String>,
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
struct BaselineManifest {
    spec_path: String,
    spec_version: String,
    last_revision: u32,
    spec_sha256: String,
    history_file: String,
    #[serde(default)]
    entry_paths: Option<Vec<String>>,
    files: BTreeMap<String, PackedFile>,
}

#[derive(Debug, Deserialize)]
struct PackedFile {
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HistoryOracle {
    baseline_last_revision: u32,
    revision_row_sha256: BTreeMap<String, String>,
    #[serde(rename = "section24_1BodySha256")]
    section24_1_body_sha256: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct CurrentMetadata {
    version: String,
    last_revision: u32,
    engine_protocol: u64,
    engine_release_epoch: u64,
    engine_manifest_schema: u64,
    gui_source: String,
}

pub(crate) fn run(args: &[String]) -> Result<()> {
    let opts = parse_args(args)?;
    let report = evaluate(&opts.root, &opts.baseline);
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
            "first-source-check: {errors} error diagnostics (scope=document_structure; not product/release certification)"
        )
    }
}

struct Opts {
    root: PathBuf,
    baseline: PathBuf,
    json: bool,
}

fn parse_args(args: &[String]) -> Result<Opts> {
    let mut root = None;
    let mut baseline = None;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--root" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| anyhow!("first-source-check: --root requires a path"))?;
                root = Some(PathBuf::from(value));
            }
            "--baseline" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| anyhow!("first-source-check: --baseline requires a path"))?;
                baseline = Some(PathBuf::from(value));
            }
            other => bail!("first-source-check: unknown argument `{other}`"),
        }
        i += 1;
    }
    Ok(Opts {
        root: root.ok_or_else(|| anyhow!("usage: cargo xtask first-source-check --root <repo> --baseline <trusted-input-manifest> [--json]"))?,
        baseline: baseline.ok_or_else(|| anyhow!("usage: cargo xtask first-source-check --root <repo> --baseline <trusted-input-manifest> [--json]"))?,
        json,
    })
}

pub(crate) fn evaluate(root: &Path, baseline_manifest: &Path) -> FirstSourceReport {
    let mut diagnostics = Vec::new();
    let mut oracles = BTreeMap::new();
    let mut historical_unresolved = Vec::new();
    let mut uncovered = BTreeSet::new();
    oracles.insert(
        "baseline_manifest".into(),
        baseline_manifest.display().to_string(),
    );

    let package_dir = match baseline_manifest.parent() {
        Some(dir) if dir.as_os_str().is_empty() => PathBuf::from("."),
        Some(dir) => dir.to_path_buf(),
        None => {
            push_error(
                &mut diagnostics,
                "truncated_input",
                &baseline_manifest.display().to_string(),
                "parent",
                "baseline manifest has no parent directory",
            );
            return finish(Draft {
                diagnostics,
                oracles,
                version: None,
                last_revision: None,
                spec_sha256: None,
                spec_matches_frozen_bytes: None,
                historical_unresolved,
                uncovered,
            });
        }
    };

    let manifest = match load_json::<BaselineManifest>(baseline_manifest, MAX_JSON_BYTES) {
        Ok(value) => value,
        Err(diag) => {
            diagnostics.push(diag);
            return finish(Draft {
                diagnostics,
                oracles,
                version: None,
                last_revision: None,
                spec_sha256: None,
                spec_matches_frozen_bytes: None,
                historical_unresolved,
                uncovered,
            });
        }
    };
    oracles.insert("spec_path".into(), manifest.spec_path.clone());
    oracles.insert(
        "baseline_last_revision".into(),
        manifest.last_revision.to_string(),
    );
    oracles.insert(
        "baseline_spec_version".into(),
        manifest.spec_version.clone(),
    );

    verify_package_inventory(&package_dir, &manifest, &mut diagnostics);
    let entries = manifest.entry_paths.clone().unwrap_or_else(|| {
        manifest
            .files
            .keys()
            .filter_map(|p| p.strip_prefix("overlay/"))
            .filter(|p| !p.contains('/') && p.ends_with(".md"))
            .map(str::to_owned)
            .collect()
    });
    if entries.len() != 3 || entries.iter().collect::<BTreeSet<_>>().len() != 3 {
        push_error(
            &mut diagnostics,
            "baseline_integrity",
            "baseline",
            "entryPaths",
            "three distinct entry paths must come from the trusted baseline",
        );
    }
    if manifest.spec_path.is_empty()
        || manifest.last_revision == 0
        || manifest.last_revision > MAX_REVISIONS
        || manifest.spec_sha256.len() != 64
        || !manifest
            .spec_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        push_error(
            &mut diagnostics,
            "baseline_integrity",
            "baseline",
            "bounds",
            "invalid bounded baseline identity",
        );
    }
    let history_path = match confined_join(&package_dir, &manifest.history_file) {
        Ok(path) => path,
        Err(error) => {
            diagnostics.push(error);
            return finish(Draft {
                diagnostics,
                oracles,
                version: None,
                last_revision: None,
                spec_sha256: None,
                spec_matches_frozen_bytes: None,
                historical_unresolved,
                uncovered,
            });
        }
    };
    oracles.insert("history".into(), history_path.display().to_string());
    let history =
        match load_json_under::<HistoryOracle>(&history_path, MAX_JSON_BYTES, &package_dir) {
            Ok(value) => Some(value),
            Err(diag) => {
                diagnostics.push(diag);
                None
            }
        };

    let spec_rel = if manifest.spec_path.is_empty() {
        DEFAULT_SPEC_RELPATH.to_string()
    } else {
        manifest.spec_path.clone()
    };
    let spec_path = match confined_join(root, &spec_rel) {
        Ok(path) => path,
        Err(diag) => {
            diagnostics.push(diag);
            return finish(Draft {
                diagnostics,
                oracles,
                version: None,
                last_revision: None,
                spec_sha256: None,
                spec_matches_frozen_bytes: None,
                historical_unresolved,
                uncovered,
            });
        }
    };
    let spec_bytes = match read_bounded(&spec_path, MAX_DOCUMENT_BYTES, root) {
        Ok(bytes) => bytes,
        Err(diag) => {
            diagnostics.push(diag);
            return finish(Draft {
                diagnostics,
                oracles,
                version: None,
                last_revision: None,
                spec_sha256: None,
                spec_matches_frozen_bytes: None,
                historical_unresolved,
                uncovered,
            });
        }
    };
    let spec_sha = sha256_hex(&spec_bytes);
    let spec_text = match String::from_utf8(spec_bytes) {
        Ok(text) => text,
        Err(_) => {
            push_error(
                &mut diagnostics,
                "invalid_utf8",
                &rel_display(root, &spec_path),
                "file",
                "first source is not valid UTF-8",
            );
            return finish(Draft {
                diagnostics,
                oracles,
                version: None,
                last_revision: None,
                spec_sha256: Some(spec_sha),
                spec_matches_frozen_bytes: None,
                historical_unresolved,
                uncovered,
            });
        }
    };

    let current = match parse_current_metadata(&spec_text, &rel_display(root, &spec_path)) {
        Ok(value) => value,
        Err(mut diags) => {
            diagnostics.append(&mut diags);
            return finish(Draft {
                diagnostics,
                oracles,
                version: None,
                last_revision: None,
                spec_sha256: Some(spec_sha),
                spec_matches_frozen_bytes: None,
                historical_unresolved,
                uncovered,
            });
        }
    };
    oracles.insert(
        "first_source_metadata".into(),
        rel_display(root, &spec_path),
    );

    let spec_matches_frozen = spec_sha == manifest.spec_sha256;
    let rows = parse_revision_rows(&spec_text);
    check_revision_sequence(
        &current,
        &rows,
        &rel_display(root, &spec_path),
        &mut diagnostics,
    );
    if let Some(history) = history.as_ref() {
        if history.baseline_last_revision != manifest.last_revision
            || history.baseline_last_revision == 0
            || history.baseline_last_revision > MAX_REVISIONS
            || history.revision_row_sha256.len() != manifest.last_revision as usize
        {
            push_error(
                &mut diagnostics,
                "baseline_integrity",
                "history",
                "baselineLastRevision",
                "history and manifest must freeze the same bounded revision set",
            );
        } else {
            check_frozen_history(
                history,
                &rows,
                &spec_text,
                &rel_display(root, &spec_path),
                &mut diagnostics,
            );
        }
        if current.last_revision == manifest.last_revision
            && !spec_matches_frozen
            && history.baseline_last_revision <= MAX_REVISIONS
            && frozen_history_intact(history, &rows, &spec_text)
        {
            push_error(
                &mut diagnostics,
                "spec_bytes_drift",
                &rel_display(root, &spec_path),
                "sha256",
                "last_revision still equals the frozen baseline and R/§24.1 bytes match, but other document bytes changed; append a named R instead of rewriting in place",
            );
        }
    }

    check_header_index_entries(
        root,
        &spec_text,
        &current,
        &spec_rel,
        &entries,
        &mut diagnostics,
    );
    check_engine_join(root, &spec_text, &current, &mut diagnostics, &mut oracles);
    check_gui(root, &spec_text, &current, &mut diagnostics, &mut oracles);
    check_pa_and_acceptance_ids(&spec_text, &rel_display(root, &spec_path), &mut diagnostics);
    check_headings(&spec_text, &rel_display(root, &spec_path), &mut diagnostics);
    check_references(
        root,
        &spec_path,
        &spec_text,
        &mut diagnostics,
        &mut historical_unresolved,
        &mut uncovered,
    );

    finish(Draft {
        diagnostics,
        oracles,
        version: Some(current.version),
        last_revision: Some(current.last_revision),
        spec_sha256: Some(spec_sha),
        spec_matches_frozen_bytes: Some(spec_matches_frozen),
        historical_unresolved,
        uncovered,
    })
}

struct Draft {
    diagnostics: Vec<Diagnostic>,
    oracles: BTreeMap<String, String>,
    version: Option<String>,
    last_revision: Option<u32>,
    spec_sha256: Option<String>,
    spec_matches_frozen_bytes: Option<bool>,
    historical_unresolved: Vec<String>,
    uncovered: BTreeSet<String>,
}

fn finish(draft: Draft) -> FirstSourceReport {
    let Draft {
        diagnostics,
        oracles,
        version,
        last_revision,
        spec_sha256,
        spec_matches_frozen_bytes,
        mut historical_unresolved,
        uncovered,
    } = draft;
    historical_unresolved.sort();
    historical_unresolved.dedup();
    let uncovered_reference_classes: Vec<String> = uncovered.into_iter().collect();
    let mut unresolved_reference_classes = Vec::new();
    if !historical_unresolved.is_empty() {
        unresolved_reference_classes.push("historical_unresolved".into());
    }
    unresolved_reference_classes.extend(uncovered_reference_classes.iter().cloned());
    unresolved_reference_classes.sort();
    unresolved_reference_classes.dedup();
    let ok = diagnostics.iter().all(|d| d.severity != "error");
    FirstSourceReport {
        ok,
        scope: "document_structure",
        product_certified: false,
        release_certified: false,
        version,
        last_revision,
        spec_sha256,
        spec_matches_frozen_bytes,
        diagnostics,
        oracles,
        unresolved_reference_classes,
        historical_unresolved,
        uncovered_reference_classes,
    }
}

fn print_human(report: &FirstSourceReport) {
    println!("first-source-check: scope={}", report.scope);
    println!(
        "version={} last_revision={} ok={} product_certified=false release_certified=false",
        report.version.as_deref().unwrap_or("unknown"),
        report
            .last_revision
            .map(|n| n.to_string())
            .unwrap_or_else(|| "unknown".into()),
        report.ok
    );
    if let Some(sha) = &report.spec_sha256 {
        println!(
            "spec_sha256={sha} frozen_bytes_match={}",
            report
                .spec_matches_frozen_bytes
                .map(|v| v.to_string())
                .unwrap_or_else(|| "n/a".into())
        );
    }
    println!("oracles:");
    for (key, value) in &report.oracles {
        println!("  {key}: {value}");
    }
    if !report.uncovered_reference_classes.is_empty() {
        println!(
            "uncovered_reference_classes: {}",
            report.uncovered_reference_classes.join(", ")
        );
    }
    if !report.historical_unresolved.is_empty() {
        println!(
            "historical_unresolved: {} (listed, not rewritten, not a silent skip of all checks)",
            report.historical_unresolved.len()
        );
        for item in report.historical_unresolved.iter().take(20) {
            println!("  {item}");
        }
    }
    for diag in &report.diagnostics {
        println!(
            "{} {}: {} ({}; {})",
            diag.severity, diag.code, diag.message, diag.path, diag.locator
        );
    }
    println!("first-source-check: document_structure only; not product or release certification");
}

fn verify_package_inventory(
    package_dir: &Path,
    manifest: &BaselineManifest,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if manifest.files.len() > MAX_PACKAGE_FILES {
        push_error(
            diagnostics,
            "truncated_input",
            "baseline",
            "files",
            &format!(
                "baseline package lists {} files; max {MAX_PACKAGE_FILES}",
                manifest.files.len()
            ),
        );
        return;
    }
    if !manifest.files.contains_key(&manifest.history_file) {
        push_error(
            diagnostics,
            "baseline_integrity",
            &manifest.history_file,
            "files",
            "historyFile is not in the trusted package inventory",
        );
    }
    for (relative, expected) in &manifest.files {
        let path = match confined_join(package_dir, relative) {
            Ok(path) => path,
            Err(diag) => {
                diagnostics.push(diag);
                continue;
            }
        };
        match read_bounded(&path, MAX_DOCUMENT_BYTES, package_dir) {
            Ok(bytes) => {
                if bytes.len() as u64 != expected.bytes || sha256_hex(&bytes) != expected.sha256 {
                    push_error(
                        diagnostics,
                        "baseline_integrity",
                        relative,
                        "sha256",
                        "trusted input file digest or size does not match the baseline manifest",
                    );
                }
            }
            Err(diag) => diagnostics.push(diag),
        }
    }
}

fn parse_current_metadata(text: &str, path: &str) -> Result<CurrentMetadata, Vec<Diagnostic>> {
    let mut diagnostics = Vec::new();
    let re =
        Regex::new(r"(?s)<!--\s*first-source-current\s+(\{.*?\})\s*-->").expect("metadata regex");
    let matches: Vec<_> = re.captures_iter(text).collect();
    if matches.is_empty() {
        push_error(
            &mut diagnostics,
            "truncated_input",
            path,
            "first-source-current",
            "missing first-source-current metadata comment",
        );
        return Err(diagnostics);
    }
    if matches.len() > 1
        || Regex::new(r"<!--\s*first-source-current\b")
            .expect("metadata starts")
            .find_iter(text)
            .count()
            > 1
    {
        push_error(
            &mut diagnostics,
            "duplicate_metadata",
            path,
            "first-source-current",
            &format!(
                "expected one first-source-current comment, found {}",
                matches.len()
            ),
        );
        return Err(diagnostics);
    }
    let json = &matches[0][1];
    match super::checked_input::json::<CurrentMetadata>(json.as_bytes()) {
        Ok(value) => {
            if value.last_revision == 0
                || value.last_revision > MAX_REVISIONS
                || value.version.len() > 32
                || value.gui_source.len() > 4096
            {
                push_error(
                    &mut diagnostics,
                    "truncated_input",
                    path,
                    "last_revision",
                    "metadata fields exceed the bounded current index",
                );
                return Err(diagnostics);
            }
            Ok(value)
        }
        Err(err) => {
            push_error(
                &mut diagnostics,
                "invalid_json",
                path,
                "first-source-current",
                &format!("metadata JSON is invalid: {err}"),
            );
            Err(diagnostics)
        }
    }
}

struct RevisionRow {
    number: u32,
    line_no: usize,
    sha256: String,
}

fn parse_revision_rows(text: &str) -> Vec<RevisionRow> {
    let mut rows = Vec::new();
    for (idx, line) in text.split_inclusive('\n').enumerate() {
        let trimmed = line.trim_end_matches(['\n', '\r']);
        if let Some(number) = revision_row_number(trimmed) {
            rows.push(RevisionRow {
                number,
                line_no: idx + 1,
                sha256: sha256_hex(line.as_bytes()),
            });
        }
    }
    rows
}

fn revision_row_number(line: &str) -> Option<u32> {
    let rest = line.strip_prefix("| R")?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    let after = &rest[digits.len()..];
    if !after.starts_with(" |") {
        return None;
    }
    digits.parse().ok()
}

fn check_revision_sequence(
    current: &CurrentMetadata,
    rows: &[RevisionRow],
    path: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut seen: BTreeMap<u32, usize> = BTreeMap::new();
    let mut duplicates = Vec::new();
    for row in rows {
        if let Some(first) = seen.insert(row.number, row.line_no) {
            duplicates.push((row.number, first, row.line_no));
        }
    }
    for (number, first, second) in duplicates {
        push_error(
            diagnostics,
            "duplicate_revision",
            path,
            &format!("R{number}"),
            &format!("revision R{number} appears at lines {first} and {second}"),
        );
    }
    let numbers: BTreeSet<u32> = rows.iter().map(|r| r.number).collect();
    let expected: BTreeSet<u32> = (1..=current.last_revision.min(MAX_REVISIONS)).collect();
    if numbers != expected
        || !rows
            .iter()
            .map(|r| r.number)
            .eq(1..=current.last_revision.min(MAX_REVISIONS))
    {
        let missing: Vec<_> = expected.difference(&numbers).copied().collect();
        let extra: Vec<_> = numbers.difference(&expected).copied().collect();
        push_error(
            diagnostics,
            "revision_sequence",
            path,
            "R rows",
            &format!(
                "revision rows must be unique and consecutive 1..={}; missing={missing:?} extra={extra:?}",
                current.last_revision
            ),
        );
    }
}

fn frozen_history_intact(history: &HistoryOracle, rows: &[RevisionRow], spec_text: &str) -> bool {
    let by_number: BTreeMap<u32, &RevisionRow> = rows.iter().map(|r| (r.number, r)).collect();
    for n in 1..=history.baseline_last_revision {
        let Some(expected) = history.revision_row_sha256.get(&n.to_string()) else {
            return false;
        };
        let Some(actual) = by_number.get(&n) else {
            return false;
        };
        if &actual.sha256 != expected {
            return false;
        }
    }
    match section_after(spec_text, "### 24.1 ", "### 24.2 ") {
        Some(body) => sha256_hex(body.as_bytes()) == history.section24_1_body_sha256,
        None => false,
    }
}

fn check_frozen_history(
    history: &HistoryOracle,
    rows: &[RevisionRow],
    spec_text: &str,
    path: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let by_number: BTreeMap<u32, &RevisionRow> = rows.iter().map(|r| (r.number, r)).collect();
    for n in 1..=history.baseline_last_revision {
        let expected = history.revision_row_sha256.get(&n.to_string());
        let actual = by_number.get(&n);
        match (expected, actual) {
            (Some(expected), Some(actual)) if &actual.sha256 == expected => {}
            (None, _) => push_error(
                diagnostics,
                "baseline_integrity",
                "history.json",
                &format!("R{n}"),
                "trusted history is missing a frozen row digest; the checker does not regenerate the baseline from the candidate",
            ),
            (Some(_), None) => push_error(
                diagnostics,
                "historical_revision_bytes",
                path,
                &format!("R{n}"),
                "frozen historical revision row is missing from the candidate",
            ),
            (Some(_), Some(actual)) => push_error(
                diagnostics,
                "historical_revision_bytes",
                path,
                &format!("line {}", actual.line_no),
                &format!("frozen R{n} row bytes were rewritten without a named later revision"),
            ),
        }
    }
    match section_after(spec_text, "### 24.1 ", "### 24.2 ") {
        Some(body) => {
            if sha256_hex(body.as_bytes()) != history.section24_1_body_sha256 {
                push_error(
                    diagnostics,
                    "historical_acceptance_bytes",
                    path,
                    "§24.1",
                    "§24.1 historical acceptance body does not match the frozen history oracle",
                );
            }
        }
        None => push_error(
            diagnostics,
            "historical_acceptance_bytes",
            path,
            "§24.1",
            "§24.1 body is missing or truncated",
        ),
    }
}

fn check_header_index_entries(
    root: &Path,
    spec_text: &str,
    current: &CurrentMetadata,
    spec_rel: &str,
    entries: &[String],
    diagnostics: &mut Vec<Diagnostic>,
) {
    let header = spec_text.split("## 0.").next().unwrap_or("");
    let version_token = &current.version;
    let revision_token = format!("R{}", current.last_revision);
    let declared =
        Regex::new(r"现行实施基线\s+(v\d+)，修订到\s+(R\d+)\b").expect("header declaration");
    let header_match = declared.captures(header);
    if !header_match.is_some_and(|c| &c[1] == version_token && c[2] == revision_token) {
        push_error(
            diagnostics,
            "header_version",
            spec_rel,
            "header",
            &format!("page header must name current {version_token} and {revision_token}"),
        );
    }
    let index = section_after(spec_text, "### 0.7 ", "## 1.").unwrap_or("");
    let index_pair = format!("{version_token} / {revision_token}");
    let pair_pattern = Regex::new(&format!(
        r"\b{}\s*/\s*{}\b",
        regex::escape(version_token),
        regex::escape(&revision_token)
    ))
    .expect("entry version");
    if !pair_pattern.is_match(index) {
        push_error(
            diagnostics,
            "index_version",
            spec_rel,
            "§0.7",
            &format!("§0.7 must contain the current index pair `{index_pair}`"),
        );
    }
    for rel in entries {
        let path = match confined_join(root, rel) {
            Ok(path) => path,
            Err(diag) => {
                diagnostics.push(diag);
                continue;
            }
        };
        match read_utf8(&path, MAX_DOCUMENT_BYTES, root) {
            Ok(text) => {
                let pointer = text.lines().find(|line| line.contains(spec_rel));
                if !pointer.is_some_and(|line| pair_pattern.is_match(line)) {
                    push_error(
                        diagnostics,
                        "entry_pointer",
                        rel,
                        "version/R",
                        &format!("entry file must point at {spec_rel} and `{index_pair}`"),
                    );
                }
            }
            Err(diag) => diagnostics.push(diag),
        }
    }
}

fn check_engine_join(
    root: &Path,
    spec_text: &str,
    current: &CurrentMetadata,
    diagnostics: &mut Vec<Diagnostic>,
    oracles: &mut BTreeMap<String, String>,
) {
    oracles.insert("engine_constants".into(), ENGINE_CONSTANTS_RELPATH.into());
    oracles.insert("engine_descriptor".into(), ENGINE_DESCRIPTOR_RELPATH.into());
    oracles.insert(
        "engine_manifest_schema".into(),
        ENGINE_BUNDLE_RELPATH.into(),
    );
    let constants_path = match confined_join(root, ENGINE_CONSTANTS_RELPATH) {
        Ok(path) => path,
        Err(diag) => {
            diagnostics.push(diag);
            return;
        }
    };
    let constants = match read_utf8(&constants_path, MAX_DOCUMENT_BYTES, root) {
        Ok(text) => text,
        Err(diag) => {
            diagnostics.push(diag);
            return;
        }
    };
    let protocol = match unique_capture(
        &constants,
        r"(?m)^pub const ENGINE_PROTOCOL_VERSION:\s*u16\s*=\s*(\d+)\s*;",
        ENGINE_CONSTANTS_RELPATH,
        "ENGINE_PROTOCOL_VERSION",
        diagnostics,
    ) {
        Some(value) => value,
        None => return,
    };
    let epoch = match unique_capture(
        &constants,
        r"(?m)^pub const ENGINE_RELEASE_EPOCH:\s*u64\s*=\s*(\d+)\s*;",
        ENGINE_CONSTANTS_RELPATH,
        "ENGINE_RELEASE_EPOCH",
        diagnostics,
    ) {
        Some(value) => value,
        None => return,
    };
    let descriptor_path = match confined_join(root, ENGINE_DESCRIPTOR_RELPATH) {
        Ok(path) => path,
        Err(diag) => {
            diagnostics.push(diag);
            return;
        }
    };
    let descriptor =
        match load_json_under::<serde_json::Value>(&descriptor_path, MAX_JSON_BYTES, root) {
            Ok(value) => value,
            Err(diag) => {
                diagnostics.push(diag);
                return;
            }
        };
    let desc_protocol = descriptor
        .get("version")
        .and_then(serde_json::Value::as_u64);
    let desc_epoch = descriptor
        .get("release_epoch")
        .and_then(serde_json::Value::as_u64);
    if !(current.engine_protocol == protocol && desc_protocol == Some(protocol)) {
        push_error(
            diagnostics,
            "engine_protocol_join",
            ENGINE_DESCRIPTOR_RELPATH,
            "version",
            &format!(
                "metadata engine_protocol={} rust={} descriptor={:?}; document self-report is not the sole oracle",
                current.engine_protocol, protocol, desc_protocol
            ),
        );
    }
    if !(current.engine_release_epoch == epoch && desc_epoch == Some(epoch)) {
        push_error(
            diagnostics,
            "engine_epoch_join",
            ENGINE_DESCRIPTOR_RELPATH,
            "release_epoch",
            &format!(
                "metadata engine_release_epoch={} rust={} descriptor={:?}",
                current.engine_release_epoch, epoch, desc_epoch
            ),
        );
    }
    let index = section_after(spec_text, "### 0.7 ", "## 1.").unwrap_or("");
    if !index.contains(&format!("ENGINE_PROTOCOL_VERSION={protocol}"))
        || !index.contains(&format!("ENGINE_RELEASE_EPOCH={epoch}"))
    {
        push_error(
            diagnostics,
            "engine_index_join",
            DEFAULT_SPEC_RELPATH,
            "§0.7",
            "§0.7 must join the Rust protocol/epoch constants, not only metadata self-report",
        );
    }
    let bundle_path = match confined_join(root, ENGINE_BUNDLE_RELPATH) {
        Ok(path) => path,
        Err(diag) => {
            diagnostics.push(diag);
            return;
        }
    };
    let bundle = match read_utf8(&bundle_path, MAX_DOCUMENT_BYTES, root) {
        Ok(text) => text,
        Err(diag) => {
            diagnostics.push(diag);
            return;
        }
    };
    if let Some(manifest) = unique_capture(
        &bundle,
        r"(?m)^const MANIFEST_VERSION:\s*u64\s*=\s*(\d+)\s*;",
        ENGINE_BUNDLE_RELPATH,
        "MANIFEST_VERSION",
        diagnostics,
    ) && current.engine_manifest_schema != manifest
    {
        push_error(
            diagnostics,
            "engine_manifest_join",
            ENGINE_BUNDLE_RELPATH,
            "MANIFEST_VERSION",
            &format!(
                "metadata engine_manifest_schema={} rust MANIFEST_VERSION={}",
                current.engine_manifest_schema, manifest
            ),
        );
    }
}

fn check_gui(
    root: &Path,
    spec_text: &str,
    current: &CurrentMetadata,
    diagnostics: &mut Vec<Diagnostic>,
    oracles: &mut BTreeMap<String, String>,
) {
    oracles.insert("gui_source".into(), current.gui_source.clone());
    let gui_path = match confined_join(root, &current.gui_source) {
        Ok(path) => path,
        Err(diag) => {
            diagnostics.push(diag);
            return;
        }
    };
    let gui = match read_utf8(&gui_path, MAX_DOCUMENT_BYTES, root) {
        Ok(text) => text,
        Err(diag) => {
            if diag.code == "missing_file" {
                push_error(
                    diagnostics,
                    "gui_missing",
                    &current.gui_source,
                    "file",
                    "GUI first-source pointer does not resolve to a file",
                );
            } else {
                diagnostics.push(diag);
            }
            return;
        }
    };
    let version_re = Regex::new(r"版本：(v[\d.]+)").expect("gui version regex");
    let gui_version = match version_re.captures(&gui) {
        Some(cap) => cap[1].to_string(),
        None => {
            push_error(
                diagnostics,
                "gui_index_join",
                &current.gui_source,
                "版本",
                "GUI first source has no `版本：v…` marker",
            );
            return;
        }
    };
    let index = section_after(spec_text, "### 0.7 ", "## 1.").unwrap_or("");
    if !index.contains(&current.gui_source) || !index.contains(&gui_version) {
        push_error(
            diagnostics,
            "gui_index_join",
            DEFAULT_SPEC_RELPATH,
            "§0.7",
            &format!(
                "§0.7 must name GUI pointer `{}` and its current version {gui_version}",
                current.gui_source
            ),
        );
    }
}

fn check_pa_and_acceptance_ids(spec_text: &str, path: &str, diagnostics: &mut Vec<Diagnostic>) {
    let work = section_after(spec_text, "### 24.4 ", "## 25.").unwrap_or("");
    let mapping_re = Regex::new(r"(?m)^\s*\| PA-(\d+) / R(\d+) \|").expect("PA mapping regex");
    let mut found: BTreeMap<u32, u32> = BTreeMap::new();
    for cap in mapping_re.captures_iter(work) {
        let pa: u32 = cap[1].parse().unwrap_or(0);
        let rev: u32 = cap[2].parse().unwrap_or(0);
        if found.insert(pa, rev).is_some() {
            push_error(
                diagnostics,
                "audit_mapping",
                path,
                &format!("PA-{pa:02}"),
                "PA row is duplicated in §24.4",
            );
        }
    }
    for (pa, rev) in FROZEN_PA_MAPPING {
        match found.get(&pa) {
            Some(actual) if *actual == rev => {}
            Some(actual) => push_error(
                diagnostics,
                "audit_mapping",
                path,
                &format!("PA-{pa:02}"),
                &format!("§24.4 maps PA-{pa:02} to R{actual}, frozen v5 pairing is R{rev}"),
            ),
            None => push_error(
                diagnostics,
                "audit_mapping",
                path,
                &format!("PA-{pa:02}"),
                "PA row is missing from §24.4; deletions require a named revision and checker policy update",
            ),
        }
    }
    let id_re = Regex::new(r"V5-[A-Z]+-\d+").expect("V5 id regex");
    let expected_rows = [
        (1, "§6.4a", vec!["V5-KEY-01"]),
        (2, "§13.5", vec!["V5-START-01", "V5-CONFIRM-01"]),
        (3, "§14.1a", vec!["V5-CRASH-01"]),
        (4, "§10.7", vec!["V5-NATIVE-01", "V5-PIXEL-01"]),
        (5, "§14.4", vec!["V5-BACKUP-01", "V5-UPGRADE-01"]),
        (6, "§10.5a", vec!["V5-EGRESS-01"]),
        (7, "§7.3d/e", vec!["V5-MODEL-01", "V5-SDK-01"]),
        (8, "§15.5", vec!["V5-CAP-01", "V5-RELEASE-01"]),
        (9, "§0.2b", vec!["V5-DEVICE-01"]),
        (10, "§0.7", vec!["V5-SPEC-01"]),
    ];
    for (pa, clause, ids) in expected_rows {
        if let Some(row) = work
            .lines()
            .find(|line| line.trim_start().starts_with(&format!("| PA-{pa:02} /")))
        {
            let cells = row.split('|').map(str::trim).collect::<Vec<_>>();
            let actual: BTreeSet<_> = cells
                .get(3)
                .into_iter()
                .flat_map(|cell| id_re.find_iter(cell).map(|m| m.as_str()))
                .collect();
            // Missing IDs retain their specific diagnostic below; wrong pairings are a separate join failure.
            let all_present_elsewhere = ids.iter().all(|id| work.contains(id));
            if !cells.get(2).is_some_and(|cell| cell.contains(clause))
                || (all_present_elsewhere && actual != ids.into_iter().collect())
            {
                push_error(
                    diagnostics,
                    "audit_mapping",
                    path,
                    &format!("PA-{pa:02}"),
                    "PA clause and acceptance IDs must match the controlled mapping",
                );
            }
        }
    }
    let in_work: BTreeSet<String> = id_re
        .find_iter(work)
        .map(|m| m.as_str().to_string())
        .collect();
    let in_doc: BTreeSet<String> = id_re
        .find_iter(spec_text)
        .map(|m| m.as_str().to_string())
        .collect();
    for id in REQUIRED_V5_IDS {
        if !in_work.contains(id) {
            push_error(
                diagnostics,
                "acceptance_case_join",
                path,
                id,
                "stable acceptance ID is missing from §24.4",
            );
        }
    }
    if in_work != in_doc {
        let only_doc: Vec<_> = in_doc.difference(&in_work).cloned().collect();
        push_error(
            diagnostics,
            "acceptance_case_join",
            path,
            "V5 IDs",
            &format!(
                "V5 acceptance IDs must be registered in §24.4; extra outside §24.4={only_doc:?}"
            ),
        );
    }
}

fn check_headings(spec_text: &str, path: &str, diagnostics: &mut Vec<Diagnostic>) {
    let heading_re =
        Regex::new(r"(?m)^#{2,3} (\d+(?:\.\d+[a-z]?)?)\.?(?:\s|：)").expect("heading regex");
    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    for cap in heading_re.captures_iter(spec_text) {
        *counts.entry(cap[1].to_string()).or_insert(0) += 1;
    }
    for key in REQUIRED_HEADINGS {
        if counts.get(key).copied().unwrap_or(0) != 1 {
            push_error(
                diagnostics,
                "section_identity",
                path,
                key,
                &format!(
                    "required heading {key} must appear exactly once, found {}",
                    counts.get(key).copied().unwrap_or(0)
                ),
            );
        }
    }
    if let (Some(env), Some(cap)) = (spec_text.find("### 15.4 "), spec_text.find("### 15.5 ")) {
        if env > cap {
            push_error(
                diagnostics,
                "section_order",
                path,
                "§15.4/§15.5",
                "§15.4 must precede §15.5",
            );
        }
    } else if spec_text.contains("### 15.5 ") && !spec_text.contains("### 15.4 ") {
        push_error(
            diagnostics,
            "section_order",
            path,
            "§15.4",
            "§15.4 heading is missing while §15.5 is present",
        );
    }
}

fn check_references(
    root: &Path,
    spec_path: &Path,
    spec_text: &str,
    diagnostics: &mut Vec<Diagnostic>,
    historical_unresolved: &mut Vec<String>,
    uncovered: &mut BTreeSet<String>,
) {
    let active = active_ranges(spec_text);
    let historical = historical_ranges(spec_text);
    let spec_dir = spec_path.parent().unwrap_or(root);
    let md_re = Regex::new(r"\]\(([^)]+)\)").expect("markdown link regex");
    let tick_re =
        Regex::new(r"`((?:docs|crates|tools|parity|fixtures|inventory|examples|apps)/[^`]+)`")
            .expect("tick path regex");
    let mut seen = BTreeSet::new();
    let mut ctx = RefCtx {
        root,
        spec_dir,
        diagnostics,
        historical_unresolved,
        uncovered,
        seen: &mut seen,
    };
    let heading_re =
        Regex::new(r"(?m)^#{1,4}\s+(\d+(?:\.\d+[a-z]?)*)[.：\s]").expect("heading references");
    let headings: BTreeSet<_> = heading_re
        .captures_iter(spec_text)
        .map(|c| c[1].to_owned())
        .collect();
    let section_re = Regex::new(r"§(\d+(?:\.\d+[a-z]?)*)").expect("section references");
    let external_link_re = Regex::new(r"\[[^\]]*\]\((?:https?://|mailto:)[^)]*\)")
        .expect("external section references");
    for (idx, line) in spec_text.split_inclusive('\n').enumerate() {
        let line_no = idx + 1;
        let in_active = in_ranges(line_no, &active);
        let in_historical = in_ranges(line_no, &historical);
        if in_active {
            let local_references = external_link_re.replace_all(line, "");
            for section in section_re.captures_iter(&local_references) {
                if !headings.contains(&section[1]) {
                    push_error(
                        ctx.diagnostics,
                        "section_reference_unresolved",
                        DEFAULT_SPEC_RELPATH,
                        &format!("line {line_no}"),
                        "active section reference does not resolve to a heading",
                    );
                }
            }
        }
        for cap in md_re.captures_iter(line) {
            classify_ref(&mut ctx, cap[1].trim(), line_no, in_active, in_historical);
        }
        for cap in tick_re.captures_iter(line) {
            classify_ref(&mut ctx, cap[1].trim(), line_no, in_active, in_historical);
        }
        if ABS_PATH.is_match(line) {
            let path = ABS_PATH
                .find(line)
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            if in_historical {
                ctx.historical_unresolved
                    .push(format!("line {line_no}: absolute {path}"));
            } else if in_active {
                push_error(
                    ctx.diagnostics,
                    "active_path_unresolved",
                    DEFAULT_SPEC_RELPATH,
                    &format!("line {line_no}"),
                    &format!("active spec cites absolute path {path}"),
                );
            } else {
                ctx.uncovered
                    .insert("absolute_path_outside_classified_regions".into());
                ctx.historical_unresolved
                    .push(format!("line {line_no}: unclassified absolute {path}"));
            }
        }
    }
    ctx.uncovered.insert("external_url".into());
    ctx.uncovered.insert("heading_fragment".into());
    ctx.uncovered.insert("non_path_backtick".into());
}

struct RefCtx<'a> {
    root: &'a Path,
    spec_dir: &'a Path,
    diagnostics: &'a mut Vec<Diagnostic>,
    historical_unresolved: &'a mut Vec<String>,
    uncovered: &'a mut BTreeSet<String>,
    seen: &'a mut BTreeSet<(usize, String)>,
}

fn classify_ref(
    ctx: &mut RefCtx<'_>,
    raw: &str,
    line_no: usize,
    in_active: bool,
    in_historical: bool,
) {
    if !ctx.seen.insert((line_no, raw.to_string())) {
        return;
    }
    let target = raw.split('#').next().unwrap_or(raw).trim();
    if target.is_empty() {
        ctx.uncovered.insert("heading_fragment".into());
        return;
    }
    if let Some(scheme) = target.split(':').next()
        && matches!(scheme, "http" | "https" | "mailto")
    {
        ctx.uncovered.insert("external_url".into());
        return;
    }
    if target.starts_with('/') || looks_like_windows_abs(target) {
        if in_historical {
            ctx.historical_unresolved
                .push(format!("line {line_no}: {target}"));
        } else if in_active {
            push_error(
                ctx.diagnostics,
                "active_path_unresolved",
                DEFAULT_SPEC_RELPATH,
                &format!("line {line_no}"),
                &format!("active spec cites non-repo path {target}"),
            );
        } else {
            ctx.uncovered
                .insert("absolute_path_outside_classified_regions".into());
        }
        return;
    }
    if target.contains("://") {
        ctx.uncovered.insert("external_url".into());
        return;
    }
    let from_root = ctx.root.join(target);
    let from_spec = ctx.spec_dir.join(target);
    let exists = file_exists_under(ctx.root, &from_root) || file_exists_under(ctx.root, &from_spec);
    if exists {
        return;
    }
    if in_historical {
        ctx.historical_unresolved
            .push(format!("line {line_no}: {target}"));
    } else if in_active {
        push_error(
            ctx.diagnostics,
            "active_path_unresolved",
            DEFAULT_SPEC_RELPATH,
            &format!("line {line_no}"),
            &format!("active spec local path does not resolve: {target}"),
        );
    } else {
        ctx.uncovered
            .insert("local_path_outside_classified_regions".into());
        ctx.historical_unresolved
            .push(format!("line {line_no}: unclassified {target}"));
    }
}

fn file_exists_under(root: &Path, candidate: &Path) -> bool {
    let Ok(root_canon) = root.canonicalize() else {
        return false;
    };
    let Ok(canon) = candidate.canonicalize() else {
        return false;
    };
    canon.starts_with(&root_canon) && canon.is_file()
}

fn looks_like_windows_abs(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
}

fn active_ranges(text: &str) -> Vec<(usize, usize)> {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let mut ranges = Vec::new();
    if let Some(end) = heading_line(&lines, "## 0.") {
        ranges.push((1, end.saturating_sub(1).max(1)));
    }
    if let Some(range) = heading_range(&lines, "### 0.7 ", "## 1.") {
        ranges.push(range);
    }
    if let Some(range) = heading_range(&lines, "### 24.2 ", "### 24.3 ") {
        ranges.push(range);
    }
    if let Some(range) = heading_range(&lines, "### 24.3 ", "### 24.4 ") {
        ranges.push(range);
    }
    if let Some(range) = heading_range(&lines, "### 24.4 ", "## 25.") {
        ranges.push(range);
    }
    if let Some(start) = heading_line(&lines, "### 28.6 ") {
        ranges.push((start, lines.len()));
    }
    ranges
}

fn historical_ranges(text: &str) -> Vec<(usize, usize)> {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let mut ranges = Vec::new();
    if let Some(range) = heading_range(&lines, "### 24.1 ", "### 24.2 ") {
        ranges.push(range);
    }
    if let Some(range) = heading_range(&lines, "### 28.1 ", "### 28.2 ") {
        ranges.push(range);
    } else if let Some(range) = heading_range(&lines, "### 28.1 ", "### 28.6 ") {
        ranges.push(range);
    }
    ranges
}

fn heading_line(lines: &[&str], prefix: &str) -> Option<usize> {
    lines
        .iter()
        .position(|line| line.starts_with(prefix))
        .map(|i| i + 1)
}

fn heading_range(lines: &[&str], start: &str, end: &str) -> Option<(usize, usize)> {
    let start_line = heading_line(lines, start)?;
    let end_line = heading_line(lines, end).unwrap_or(lines.len() + 1);
    Some((start_line, end_line.saturating_sub(1).max(start_line)))
}

fn in_ranges(line: usize, ranges: &[(usize, usize)]) -> bool {
    ranges
        .iter()
        .any(|(start, end)| line >= *start && line <= *end)
}

fn unique_capture(
    text: &str,
    pattern: &str,
    path: &str,
    locator: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<u64> {
    let re = Regex::new(pattern).ok()?;
    let found: Vec<_> = re
        .captures_iter(text)
        .filter_map(|cap| cap.get(1).and_then(|m| m.as_str().parse::<u64>().ok()))
        .collect();
    match found.as_slice() {
        [value] => Some(*value),
        [] => {
            push_error(
                diagnostics,
                "truncated_input",
                path,
                locator,
                &format!("did not find {locator} in independent oracle file"),
            );
            None
        }
        _ => {
            push_error(
                diagnostics,
                "duplicate_metadata",
                path,
                locator,
                &format!("oracle file has {} {locator} bindings", found.len()),
            );
            None
        }
    }
}

fn section_after<'a>(text: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let rest = text.split_once(start)?.1;
    Some(rest.split_once(end)?.0)
}

fn input_diagnostic(error: super::checked_input::InputError, path: &Path) -> Diagnostic {
    use super::checked_input::InputError;
    let code = match error {
        InputError::Path | InputError::Symlink => "path_escape",
        InputError::Limit => "truncated_input",
        InputError::Changed => "input_changed",
        #[cfg(not(unix))]
        InputError::Unsupported => "platform_unsupported",
        InputError::Missing => "missing_file",
    };
    diag(
        code,
        &path.display().to_string(),
        "file",
        "input could not be read under its bounded directory authority",
    )
}

fn decode_json<T: for<'de> Deserialize<'de>>(bytes: &[u8], path: &Path) -> Result<T, Diagnostic> {
    if bytes.is_empty() {
        return Err(diag(
            "truncated_input",
            &path.display().to_string(),
            "file",
            "JSON input is empty",
        ));
    }
    super::checked_input::json(bytes).map_err(|_| {
        diag(
            "invalid_json",
            &path.display().to_string(),
            "json",
            "invalid JSON or duplicate object member",
        )
    })
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path, max: u64) -> Result<T, Diagnostic> {
    decode_json(&read_bounded_unscoped(path, max)?, path)
}

fn load_json_under<T: for<'de> Deserialize<'de>>(
    path: &Path,
    max: u64,
    root: &Path,
) -> Result<T, Diagnostic> {
    decode_json(&read_bounded(path, max, root)?, path)
}

fn read_utf8(path: &Path, max: u64, root: &Path) -> Result<String, Diagnostic> {
    String::from_utf8(read_bounded(path, max, root)?).map_err(|_| {
        diag(
            "invalid_utf8",
            &rel_display(root, path),
            "file",
            "input is not UTF-8",
        )
    })
}

fn read_bounded(path: &Path, max: u64, root: &Path) -> Result<Vec<u8>, Diagnostic> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| input_diagnostic(super::checked_input::InputError::Path, path))?;
    super::checked_input::read_under(root, relative, max).map_err(|e| input_diagnostic(e, path))
}

fn read_bounded_unscoped(path: &Path, max: u64) -> Result<Vec<u8>, Diagnostic> {
    super::checked_input::read_argument(path, max).map_err(|e| input_diagnostic(e, path))
}

fn confined_join(root: &Path, relative: &str) -> Result<PathBuf, Diagnostic> {
    if relative.is_empty() {
        return Err(diag("path_escape", relative, "path", "empty relative path"));
    }
    let rel = Path::new(relative);
    if rel.is_absolute() {
        return Err(diag(
            "path_escape",
            relative,
            "path",
            "absolute paths are not read unless independently specified as --root/--baseline",
        ));
    }
    for component in rel.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            _ => {
                return Err(diag(
                    "path_escape",
                    relative,
                    "path",
                    "path contains '..' or another disallowed component",
                ));
            }
        }
    }
    Ok(root.join(rel))
}

fn rel_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| path.display().to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
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

static ABS_PATH: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"(?:/Users/|/home/|[A-Za-z]:\\)[^\s|`]+").expect("absolute path regex")
});

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

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
                "openbot-first-source-{tag}-{}-{nanos}",
                std::process::id()
            ));
            fs::create_dir_all(&root).expect("temp root");
            Self { root }
        }

        fn write(&self, rel: &str, bytes: impl AsRef<[u8]>) {
            let path = self.root.join(rel);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("parent");
            }
            fs::write(path, bytes).expect("write");
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    struct Harness {
        repo: TempTree,
        package: TempTree,
        last_revision: u32,
    }

    impl Harness {
        fn positive() -> Self {
            Self::with_last(240)
        }

        fn with_last(last_revision: u32) -> Self {
            let repo = TempTree::new("repo");
            let package = TempTree::new("pkg");
            let spec = synthetic_spec(last_revision, SpecMut::default());
            write_repo_tree(&repo, last_revision, &spec);
            write_package(&package, last_revision, &spec);
            Self {
                repo,
                package,
                last_revision,
            }
        }

        fn evaluate(&self) -> FirstSourceReport {
            evaluate(&self.repo.root, &self.package.root.join("MANIFEST.json"))
        }

        fn rewrite_spec(&self, spec: &str) {
            self.repo.write(DEFAULT_SPEC_RELPATH, spec);
            for rel in ENTRY_RELPATHS {
                self.repo.write(rel, entry_text(self.last_revision));
            }
        }
    }

    #[derive(Default)]
    struct SpecMut {
        drop_revision: Option<u32>,
        duplicate_revision: Option<u32>,
        rewrite_revision: Option<u32>,
        header_version: Option<&'static str>,
        metadata_protocol: Option<u64>,
        metadata_epoch: Option<u64>,
        metadata_manifest: Option<u64>,
        metadata_gui: Option<&'static str>,
        pa5_revision: Option<u32>,
        drop_v5_id: Option<&'static str>,
        drop_gui_from_index: bool,
        truncate_metadata: bool,
        duplicate_metadata: bool,
        swap_15: bool,
        last_override: Option<u32>,
        extra_revision: bool,
        broken_active_link: bool,
        corrupt_header: bool,
    }

    fn synthetic_spec(last_revision: u32, m: SpecMut) -> String {
        let declared = m.last_override.unwrap_or(last_revision);
        let version = m.header_version.unwrap_or("v5");
        let protocol = m.metadata_protocol.unwrap_or(4);
        let epoch = m.metadata_epoch.unwrap_or(5);
        let manifest = m.metadata_manifest.unwrap_or(2);
        let gui = m.metadata_gui.unwrap_or("docs/gui.md");
        let mut rows = String::new();
        let end = if m.extra_revision {
            declared
        } else {
            last_revision.max(declared)
        };
        for n in 1..=end {
            if m.drop_revision == Some(n) {
                continue;
            }
            let mut line = stub_row(n);
            if m.rewrite_revision == Some(n) {
                line = format!(
                    "| R{n} | §test | rewritten-old | rewritten-problem | rewritten-new | rewritten-evidence |\n"
                );
            }
            rows.push_str(&line);
            if m.duplicate_revision == Some(n) {
                rows.push_str(&stub_row(n));
            }
        }
        if m.extra_revision {
            rows.push_str(&stub_row(declared));
        }
        let pa5 = m.pa5_revision.unwrap_or(235);
        let mut ids = REQUIRED_V5_IDS
            .iter()
            .copied()
            .filter(|id| m.drop_v5_id != Some(*id))
            .collect::<Vec<_>>();
        if ids.len() == 14 {
            ids.push("V5-PLACEHOLDER-01");
        }
        let id_cell = |want: &[&str]| {
            want.iter()
                .copied()
                .filter(|id| ids.iter().any(|have| have == id))
                .collect::<Vec<_>>()
                .join("、")
        };
        let heading_15_4 = if m.swap_15 { "### 15.5 " } else { "### 15.4 " };
        let heading_15_5 = if m.swap_15 { "### 15.4 " } else { "### 15.5 " };
        let gui_index = if m.drop_gui_from_index {
            "GUI 第一真源 | missing-pointer".to_string()
        } else {
            format!("GUI 第一真源 | `{gui}`，当前 v3.2")
        };
        let active_link = if m.broken_active_link {
            "see [missing](docs/no-such-active.md)".to_string()
        } else {
            format!("see [`{gui}`](../{gui})")
        };
        let metadata = if m.truncate_metadata {
            format!(
                "<!-- first-source-current {{\"version\":\"{version}\",\"last_revision\":{declared}"
            )
        } else {
            let json = format!(
                "{{\"version\":\"{version}\",\"last_revision\":{declared},\"engine_protocol\":{protocol},\"engine_release_epoch\":{epoch},\"engine_manifest_schema\":{manifest},\"gui_source\":\"{gui}\"}}"
            );
            let one = format!("<!-- first-source-current {json} -->");
            if m.duplicate_metadata {
                format!("{one}\n{one}")
            } else {
                one
            }
        };
        let mut text = format!(
            "# Synthetic first source\n\
             \n\
             > 文档状态：**现行实施基线 {version}，修订到 {revision_token}**。历史 v4 字样不得被误判为当前版本。\n\
             \n\
             {active_link}\n\
             \n\
             ## 0. 最终裁决\n\
             \n\
             ### 0.2b 账户控制面\n\
             \n\
             subsequent device topology.\n\
             \n\
             ### 0.7 v5 现行索引与状态口径 ({revision_token})\n\
             \n\
             | 事项 | {version} 当前确定值 / 入口 |\n\
             |---|---|\n\
             | 后端第一真源 | 本文件，{version} / {revision_token}；§28.6 为现行优先级 |\n\
             | {gui_index} |\n\
             | 固定引擎事实 | `ENGINE_PROTOCOL_VERSION=4`、`ENGINE_RELEASE_EPOCH=5`、manifest schema=2 |\n\
             \n\
             ## 1. 第一真源\n\
             \n\
             ### 6.4a 密钥\n\
             ### 7.3d 模型\n\
             ### 7.3e SDK\n\
             ### 10.5a 出口\n\
             ### 10.7 原生\n\
             ### 13.5 启动\n\
             ### 14.1a 崩溃\n\
             ### 14.4 备份\n\
             {heading_15_4}环境\n\
             {heading_15_5}能力投影\n\
             ### 19.4 顺序\n\
             \n\
             ### 24.1 历史实施与验收记录（v4 / R1–R230）\n\
             \n\
             以下按原批次保留。旧绝对目录 `/home/example/archive/gone.md` 与 v4 字样是历史证据。\n\
             上游 `server/src/config.ts` 不在本仓。\n\
             \n\
             ### 24.2 macOS 首版 A0–A7\n\
             \n\
             A0–A7 remain required.\n\
             \n\
             ### 24.3 候选验收记录\n\
             \n\
             schemaVersion=1.\n\
             \n\
             ### 24.4 v5 审计修订与未完成范围台账（R231–R240）\n\
             \n\
             | 审计 / 修订 | 规范入口 | 稳定验收ID | 实现/验证状态 | 首版/全范围及责任 |\n\
             |---|---|---|---|---|\n\
             | PA-01 / R231 | §6.4a | {key} | pending | macos |\n\
             | PA-02 / R232 | §13.5 | {start} | pending | macos |\n\
             | PA-03 / R233 | §14.1a | {crash} | pending | macos |\n\
             | PA-04 / R234 | §10.7 | {native} | pending | macos |\n\
             | PA-05 / R{pa5} | §14.4 | {backup} | pending | macos |\n\
             | PA-06 / R236 | §10.5a | {egress} | pending | macos |\n\
             | PA-07 / R237 | §7.3d/e | {model} | pending | macos |\n\
             | PA-08 / R238 | §15.5、§24.2/3 | {cap} | pending | macos |\n\
             | PA-09 / R239 | §0.2b | {device} | pending | later |\n\
             | PA-10 / R240 | §0.7、§28.6 | {spec} | pending | docs |\n\
             \n\
             ## 25. Definition of Done\n\
             \n\
             not certified here.\n\
             \n\
             ### 28.1 修订清单\n\
             \n\
             | 编号 | 位置 | v2 表述 | 问题 | v3 修订 | 证据 |\n\
             | --- | --- | --- | --- | --- | --- |\n\
             {rows}\n\
             ### 28.2 keep\n\
             \n\
             ### 28.6 v5 修订方法、唯一规范与持续一致性 ({revision_token})\n\
             \n\
             see https://example.invalid/spec-ref for uncovered external class.\n\
             \n\
             {metadata}\n",
            revision_token = format!("R{declared}"),
            key = id_cell(&["V5-KEY-01"]),
            start = id_cell(&["V5-START-01", "V5-CONFIRM-01"]),
            crash = id_cell(&["V5-CRASH-01"]),
            native = id_cell(&["V5-NATIVE-01", "V5-PIXEL-01"]),
            backup = id_cell(&["V5-BACKUP-01", "V5-UPGRADE-01"]),
            egress = id_cell(&["V5-EGRESS-01"]),
            model = id_cell(&["V5-MODEL-01", "V5-SDK-01"]),
            cap = id_cell(&["V5-CAP-01", "V5-RELEASE-01"]),
            device = id_cell(&["V5-DEVICE-01"]),
            spec = id_cell(&["V5-SPEC-01"]),
        );
        if m.corrupt_header {
            text = text.replacen("现行实施基线 v5", "现行实施基线 v4", 1);
        }
        text
    }

    fn stub_row(n: u32) -> String {
        format!("| R{n} | §test | v4-old-{n} | problem-{n} | revision-{n} | evidence-{n} |\n")
    }

    fn write_repo_tree(repo: &TempTree, last_revision: u32, spec: &str) {
        repo.write(DEFAULT_SPEC_RELPATH, spec);
        repo.write("docs/gui.md", "版本：v3.2 · 生效日期：2026-09-05\n");
        repo.write(
            ENGINE_CONSTANTS_RELPATH,
            "pub const ENGINE_PROTOCOL_VERSION: u16 = 4;\npub const ENGINE_RELEASE_EPOCH: u64 = 5;\n",
        );
        repo.write(
            ENGINE_DESCRIPTOR_RELPATH,
            "{\"schema\":\"openbot-engine-protocol\",\"version\":4,\"release_epoch\":5}\n",
        );
        repo.write(ENGINE_BUNDLE_RELPATH, "const MANIFEST_VERSION: u64 = 2;\n");
        for rel in ENTRY_RELPATHS {
            repo.write(rel, entry_text(last_revision));
        }
    }

    fn entry_text(last_revision: u32) -> String {
        format!("backend first source {DEFAULT_SPEC_RELPATH} (v5 / R{last_revision})\n")
    }

    fn write_package(package: &TempTree, last_revision: u32, spec: &str) {
        let mut revision_row_sha256 = BTreeMap::new();
        for row in parse_revision_rows(spec) {
            if row.number <= last_revision {
                revision_row_sha256.insert(row.number.to_string(), row.sha256);
            }
        }
        let body = section_after(spec, "### 24.1 ", "### 24.2 ").expect("24.1");
        let history = serde_json::json!({
            "sourcePath": DEFAULT_SPEC_RELPATH,
            "specSha256": sha256_hex(spec.as_bytes()),
            "baselineLastRevision": last_revision,
            "rowEncoding": "UTF-8; original full Markdown row including trailing LF",
            "revisionRowSha256": revision_row_sha256,
            "section24_1BodySha256": sha256_hex(body.as_bytes()),
            "note": "Compare against candidate input; do not regenerate this oracle from that candidate."
        });
        let history_bytes = serde_json::to_vec_pretty(&history).expect("history json");
        package.write("reference/history.json", &history_bytes);
        let mut files = BTreeMap::new();
        files.insert(
            "reference/history.json".to_string(),
            serde_json::json!({
                "bytes": history_bytes.len(),
                "sha256": sha256_hex(&history_bytes)
            }),
        );
        let manifest = serde_json::json!({
            "schemaVersion": 1,
            "purpose": "external-task-inputs; not product acceptance",
            "sourceCommit": "52ea4d0a651b5919561aed8fd56b14fcfb4401b2",
            "specPath": DEFAULT_SPEC_RELPATH,
            "specVersion": "v5",
            "lastRevision": last_revision,
            "specSha256": sha256_hex(spec.as_bytes()),
            "historyFile": "reference/history.json",
            "entryPaths": ENTRY_RELPATHS,
            "files": files
        });
        package.write(
            "MANIFEST.json",
            serde_json::to_vec_pretty(&manifest).expect("manifest"),
        );
    }

    #[test]
    fn controller_review_metadata_revision_budget_is_enforced_before_range_allocation() {
        let text = "<!-- first-source-current {\"version\":\"v5\",\"last_revision\":4294967295,\"engine_protocol\":4,\"engine_release_epoch\":5,\"engine_manifest_schema\":2,\"gui_source\":\"docs/gui.md\"} -->";
        assert!(parse_current_metadata(text, "synthetic").is_err());
    }

    #[test]
    fn controller_review_header_version_is_not_a_substring() {
        let h = Harness::positive();
        let spec = synthetic_spec(240, SpecMut::default()).replacen(
            "现行实施基线 v5",
            "现行实施基线 v50",
            1,
        );
        h.rewrite_spec(&spec);
        assert!(codes(&h.evaluate()).iter().any(|c| c == "header_version"));
    }

    #[test]
    fn controller_review_pa_ids_cannot_be_swapped_by_appending_a_revision() {
        let h = Harness::positive();
        let spec = synthetic_spec(241, SpecMut::default())
            .replace("V5-KEY-01", "SWAP-TEMP")
            .replace("V5-CRASH-01", "V5-KEY-01")
            .replace("SWAP-TEMP", "V5-CRASH-01");
        write_repo_tree(&h.repo, 241, &spec);
        assert!(codes(&h.evaluate()).iter().any(|c| c == "audit_mapping"));
    }

    #[test]
    fn controller_review_history_cannot_shrink_its_baseline_revision() {
        let h = Harness::positive();
        let history_path = h.package.root.join("reference/history.json");
        let mut history: serde_json::Value =
            serde_json::from_slice(&fs::read(&history_path).unwrap()).unwrap();
        history["baselineLastRevision"] = 1.into();
        let data = serde_json::to_vec(&history).unwrap();
        fs::write(&history_path, &data).unwrap();
        let path = h.package.root.join("MANIFEST.json");
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        manifest["files"]["reference/history.json"] =
            serde_json::json!({"bytes":data.len(),"sha256":sha256_hex(&data)});
        fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(
            codes(&h.evaluate())
                .iter()
                .any(|c| c == "baseline_integrity")
        );
    }

    #[test]
    fn controller_review_duplicate_inventory_keys_are_rejected() {
        let text = br#"{"specPath":"spec/current.md","specVersion":"v5","lastRevision":240,"specSha256":"a","historyFile":"history.json","files":{"history.json":{"bytes":1,"sha256":"a"},"history.json":{"bytes":2,"sha256":"b"}}}"#;
        let tree = TempTree::new("duplicate-map");
        tree.write("input.json", text);
        assert!(
            load_json::<BaselineManifest>(&tree.root.join("input.json"), MAX_JSON_BYTES).is_err()
        );
    }

    #[test]
    fn controller_review_active_section_and_nonliteral_oracle_are_rejected() {
        let h = Harness::positive();
        let spec = synthetic_spec(240, SpecMut::default()).replacen(
            "## 1. 第一真源",
            "See §99.9\n## 1. 第一真源",
            1,
        );
        h.rewrite_spec(&spec);
        assert!(
            codes(&h.evaluate())
                .iter()
                .any(|c| c == "section_reference_unresolved")
        );
        h.rewrite_spec(&synthetic_spec(240, SpecMut::default()));
        h.repo.write(ENGINE_CONSTANTS_RELPATH, "pub const ENGINE_PROTOCOL_VERSION: u16 = 4 + 1;\npub const ENGINE_RELEASE_EPOCH: u64 = 5;\n");
        assert!(!h.evaluate().ok);
    }

    #[test]
    fn controller_review_revision_rows_must_remain_in_order() {
        let h = Harness::positive();
        let first = stub_row(1);
        let second = stub_row(2);
        let spec = synthetic_spec(241, SpecMut::default()).replacen(
            &(first.clone() + &second),
            &(second + &first),
            1,
        );
        write_repo_tree(&h.repo, 241, &spec);
        assert!(
            codes(&h.evaluate())
                .iter()
                .any(|c| c == "revision_sequence")
        );
    }

    #[test]
    fn controller_review_external_section_is_not_a_local_reference() {
        let h = Harness::positive();
        let spec = synthetic_spec(241, SpecMut::default()).replacen(
            "## 1. 第一真源",
            "[External standard §99.9](https://example.invalid/standard)\n## 1. 第一真源",
            1,
        );
        write_repo_tree(&h.repo, 241, &spec);
        assert!(h.evaluate().ok);
    }

    fn codes(report: &FirstSourceReport) -> Vec<String> {
        report.diagnostics.iter().map(|d| d.code.clone()).collect()
    }

    fn assert_only(report: &FirstSourceReport, code: &str) {
        assert!(
            !report.ok,
            "expected failure for {code}, got ok={:?} diags={:?}",
            report.ok, report.diagnostics
        );
        assert!(
            report.diagnostics.iter().any(|d| d.code == code),
            "expected {code} in {:?}",
            codes(report)
        );
        let extras: Vec<_> = report
            .diagnostics
            .iter()
            .filter(|d| d.code != code && d.code != "spec_bytes_drift")
            .map(|d| d.code.as_str())
            .collect();
        assert!(
            extras.is_empty(),
            "negative case must change one condition; extra diagnostics={extras:?} all={:?}",
            report.diagnostics
        );
    }

    #[test]
    fn first_source_positive_synthetic_passes() {
        let harness = Harness::positive();
        let report = harness.evaluate();
        assert!(
            report.ok,
            "positive synthetic must pass: {:?}",
            report.diagnostics
        );
        assert_eq!(report.scope, "document_structure");
        assert!(!report.product_certified);
        assert!(!report.release_certified);
        assert_eq!(report.last_revision, Some(240));
        assert_eq!(report.spec_matches_frozen_bytes, Some(true));
        assert!(report.oracles.contains_key("history"));
        assert!(report.oracles.contains_key("engine_constants"));
        assert!(report.oracles.contains_key("engine_descriptor"));
        assert!(report.oracles.contains_key("engine_manifest_schema"));
        assert!(report.oracles.contains_key("gui_source"));
        assert!(
            report
                .historical_unresolved
                .iter()
                .any(|item| item.contains("/home/example/archive/gone.md"))
        );
        assert!(
            report
                .uncovered_reference_classes
                .iter()
                .any(|c| c == "external_url")
        );
    }

    #[test]
    fn first_source_appended_revision_is_allowed() {
        let harness = Harness::positive();
        let spec = synthetic_spec(
            241,
            SpecMut {
                extra_revision: false,
                last_override: Some(241),
                ..SpecMut::default()
            },
        );
        harness.repo.write(DEFAULT_SPEC_RELPATH, &spec);
        harness.repo.write("guide.md", entry_text(241));
        harness.repo.write("README.md", entry_text(241));
        harness.repo.write("handoff.md", entry_text(241));
        let report = harness.evaluate();
        assert!(
            report.ok,
            "appending R241 must not be rejected by a hardcoded R240 ceiling: {:?}",
            report.diagnostics
        );
        assert_eq!(report.last_revision, Some(241));
        assert_eq!(report.spec_matches_frozen_bytes, Some(false));
    }

    #[test]
    fn first_source_historical_v4_text_is_not_current_version_error() {
        let harness = Harness::positive();
        let report = harness.evaluate();
        assert!(report.ok, "{:?}", report.diagnostics);
        assert!(
            !codes(&report)
                .iter()
                .any(|c| c == "header_version" || c == "index_version")
        );
        let spec = fs::read_to_string(harness.repo.root.join(DEFAULT_SPEC_RELPATH)).unwrap();
        assert!(spec.contains("v4"));
    }

    #[test]
    fn first_source_missing_revision_row_fails() {
        let harness = Harness::positive();
        let spec = synthetic_spec(
            240,
            SpecMut {
                drop_revision: Some(100),
                ..SpecMut::default()
            },
        );
        harness.rewrite_spec(&spec);
        let report = harness.evaluate();
        assert!(!report.ok);
        assert!(
            codes(&report)
                .iter()
                .any(|c| c == "revision_sequence" || c == "historical_revision_bytes"),
            "{:?}",
            report.diagnostics
        );
    }

    #[test]
    fn first_source_duplicate_revision_row_fails() {
        let harness = Harness::positive();
        let spec = synthetic_spec(
            240,
            SpecMut {
                duplicate_revision: Some(50),
                ..SpecMut::default()
            },
        );
        harness.rewrite_spec(&spec);
        let report = harness.evaluate();
        assert!(!report.ok);
        assert!(codes(&report).contains(&"duplicate_revision".into()));
    }

    #[test]
    fn first_source_changed_historical_row_fails() {
        let harness = Harness::positive();
        let spec = synthetic_spec(
            240,
            SpecMut {
                rewrite_revision: Some(1),
                ..SpecMut::default()
            },
        );
        harness.rewrite_spec(&spec);
        assert_only(&harness.evaluate(), "historical_revision_bytes");
    }

    #[test]
    fn first_source_wrong_header_version_fails() {
        let harness = Harness::positive();
        let spec = synthetic_spec(
            240,
            SpecMut {
                corrupt_header: true,
                ..SpecMut::default()
            },
        );
        harness.rewrite_spec(&spec);
        let report = harness.evaluate();
        assert!(!report.ok);
        assert!(
            codes(&report).contains(&"header_version".into()),
            "{:?}",
            report.diagnostics
        );
    }

    #[test]
    fn first_source_wrong_entry_pointer_fails() {
        let harness = Harness::positive();
        harness
            .repo
            .write("guide.md", "unrelated pointer v4 / R1\n");
        assert_only(&harness.evaluate(), "entry_pointer");
    }

    #[test]
    fn first_source_metadata_protocol_conflict_fails() {
        let harness = Harness::positive();
        let spec = synthetic_spec(
            240,
            SpecMut {
                metadata_protocol: Some(99),
                ..SpecMut::default()
            },
        );
        harness.rewrite_spec(&spec);
        assert_only(&harness.evaluate(), "engine_protocol_join");
    }

    #[test]
    fn first_source_metadata_epoch_conflict_fails() {
        let harness = Harness::positive();
        let spec = synthetic_spec(
            240,
            SpecMut {
                metadata_epoch: Some(99),
                ..SpecMut::default()
            },
        );
        harness.rewrite_spec(&spec);
        assert_only(&harness.evaluate(), "engine_epoch_join");
    }

    #[test]
    fn first_source_metadata_manifest_conflict_fails() {
        let harness = Harness::positive();
        let spec = synthetic_spec(
            240,
            SpecMut {
                metadata_manifest: Some(9),
                ..SpecMut::default()
            },
        );
        harness.rewrite_spec(&spec);
        assert_only(&harness.evaluate(), "engine_manifest_join");
    }

    #[test]
    fn first_source_pa_mapping_wrong_fails() {
        let harness = Harness::positive();
        let spec = synthetic_spec(
            240,
            SpecMut {
                pa5_revision: Some(999),
                ..SpecMut::default()
            },
        );
        harness.rewrite_spec(&spec);
        assert_only(&harness.evaluate(), "audit_mapping");
    }

    #[test]
    fn first_source_missing_v5_id_fails() {
        let harness = Harness::positive();
        let spec = synthetic_spec(
            240,
            SpecMut {
                drop_v5_id: Some("V5-KEY-01"),
                ..SpecMut::default()
            },
        );
        harness.rewrite_spec(&spec);
        let report = harness.evaluate();
        assert!(!report.ok);
        assert!(codes(&report).contains(&"acceptance_case_join".into()));
    }

    #[test]
    fn first_source_gui_pointer_missing_fails() {
        let harness = Harness::positive();
        let spec = synthetic_spec(
            240,
            SpecMut {
                metadata_gui: Some("docs/missing-gui.md"),
                drop_gui_from_index: true,
                ..SpecMut::default()
            },
        );
        harness.rewrite_spec(&spec);
        let report = harness.evaluate();
        assert!(!report.ok);
        assert!(codes(&report).contains(&"gui_missing".into()));
    }

    #[test]
    fn first_source_gui_version_mismatch_fails() {
        let harness = Harness::positive();
        let spec = synthetic_spec(
            240,
            SpecMut {
                drop_gui_from_index: true,
                ..SpecMut::default()
            },
        );
        harness.rewrite_spec(&spec);
        assert_only(&harness.evaluate(), "gui_index_join");
    }

    #[test]
    fn first_source_truncated_metadata_fails() {
        let harness = Harness::positive();
        let spec = synthetic_spec(
            240,
            SpecMut {
                truncate_metadata: true,
                ..SpecMut::default()
            },
        );
        harness.rewrite_spec(&spec);
        let report = harness.evaluate();
        assert!(!report.ok);
        assert!(codes(&report).contains(&"truncated_input".into()));
    }

    #[test]
    fn first_source_duplicate_metadata_fails() {
        let harness = Harness::positive();
        let spec = synthetic_spec(
            240,
            SpecMut {
                duplicate_metadata: true,
                ..SpecMut::default()
            },
        );
        harness.rewrite_spec(&spec);
        assert_only(&harness.evaluate(), "duplicate_metadata");
    }

    #[test]
    fn first_source_invalid_utf8_fails() {
        let harness = Harness::positive();
        harness.repo.write(DEFAULT_SPEC_RELPATH, [0xff, 0xfe, 0x00]);
        let report = harness.evaluate();
        assert!(!report.ok);
        assert!(codes(&report).contains(&"invalid_utf8".into()));
    }

    #[test]
    fn first_source_invalid_baseline_json_fails() {
        let harness = Harness::positive();
        harness.package.write("MANIFEST.json", "{not-json");
        let report = harness.evaluate();
        assert!(!report.ok);
        assert!(codes(&report).contains(&"invalid_json".into()));
    }

    #[test]
    fn first_source_does_not_self_generate_history() {
        let harness = Harness::positive();
        let spec = synthetic_spec(
            240,
            SpecMut {
                rewrite_revision: Some(2),
                ..SpecMut::default()
            },
        );
        harness.rewrite_spec(&spec);
        let poisoned = serde_json::json!({
            "sourcePath": DEFAULT_SPEC_RELPATH,
            "specSha256": sha256_hex(spec.as_bytes()),
            "baselineLastRevision": 240,
            "revisionRowSha256": parse_revision_rows(&spec).into_iter().map(|r| (r.number.to_string(), r.sha256)).collect::<BTreeMap<_,_>>(),
            "section24_1BodySha256": sha256_hex(section_after(&spec, "### 24.1 ", "### 24.2 ").unwrap().as_bytes())
        });
        harness.repo.write(
            "docs/history-from-candidate.json",
            serde_json::to_vec(&poisoned).unwrap(),
        );
        let report = harness.evaluate();
        assert!(
            !report.ok,
            "rewritten R2 must still fail against the trusted baseline"
        );
        assert!(codes(&report).contains(&"historical_revision_bytes".into()));
    }

    #[test]
    fn first_source_active_missing_path_fails() {
        let harness = Harness::positive();
        let spec = synthetic_spec(
            240,
            SpecMut {
                broken_active_link: true,
                ..SpecMut::default()
            },
        );
        harness.rewrite_spec(&spec);
        let report = harness.evaluate();
        assert!(!report.ok);
        assert!(codes(&report).contains(&"active_path_unresolved".into()));
    }

    #[test]
    fn first_source_on_disk_positive_fixture() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fixture = manifest_dir.join("../../fixtures/v5/first-source/positive");
        if !fixture.join("repo").is_dir() {
            return;
        }
        let report = evaluate(
            &fixture.join("repo"),
            &fixture.join("package/MANIFEST.json"),
        );
        assert!(
            report.ok,
            "on-disk positive fixture must pass: {:?}",
            report.diagnostics
        );
    }
}
