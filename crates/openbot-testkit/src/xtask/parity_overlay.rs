//! Exception-only v4 overlay validation (R124).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use serde::Serialize;

const OVERLAY_RELPATH: &str = "parity/overlay/v4.yaml";
const TOP_LEVEL_KEYS: [&str; 5] = [
    "schema",
    "schema_version",
    "baseline",
    "generated_by",
    "entries",
];
const ENTRY_KEYS: [&str; 7] = [
    "id",
    "disposition",
    "scope",
    "defect",
    "replacement",
    "notes",
    "revalidation_evidence",
];
const DISPOSITIONS: [&str; 4] = ["carry", "revalidate", "split", "superseded"];

#[derive(Debug, Serialize)]
pub(crate) struct OverlayReport {
    pub(crate) file: String,
    pub(crate) baseline: String,
    pub(crate) explicit_entries: usize,
    pub(crate) diff_required_revalidations: usize,
    pub(crate) disposition_counts: BTreeMap<String, usize>,
}

impl OverlayReport {
    pub(crate) fn empty(total_entries: usize) -> Self {
        let mut disposition_counts = empty_counts();
        disposition_counts.insert("carry".to_owned(), total_entries);
        Self {
            file: OVERLAY_RELPATH.to_owned(),
            baseline: "v4".to_owned(),
            explicit_entries: 0,
            diff_required_revalidations: 0,
            disposition_counts,
        }
    }
}

pub(crate) fn validate(
    root: &Path,
    parity_test_ids: &BTreeSet<String>,
    done_targets: &BTreeMap<String, String>,
    total_entries: usize,
    violations: &mut Vec<String>,
) -> OverlayReport {
    let path = root.join(OVERLAY_RELPATH);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            violations.push(format!(
                "{OVERLAY_RELPATH}：R124 exception-only overlay 缺失或不可读：{error}"
            ));
            return OverlayReport::empty(total_entries);
        }
    };
    let document: serde_yaml::Value = match serde_yaml::from_str(&text) {
        Ok(document) => document,
        Err(error) => {
            violations.push(format!("{OVERLAY_RELPATH}：YAML 解析失败：{error}"));
            return OverlayReport::empty(total_entries);
        }
    };
    let mut report = validate_document(&document, parity_test_ids, total_entries, violations);
    report.diff_required_revalidations =
        validate_diff_revalidation(root, done_targets, &document, violations);
    report
}

fn validate_document(
    document: &serde_yaml::Value,
    parity_test_ids: &BTreeSet<String>,
    total_entries: usize,
    violations: &mut Vec<String>,
) -> OverlayReport {
    let Some(map) = document.as_mapping() else {
        violations.push(format!("{OVERLAY_RELPATH}：顶层必须是 mapping"));
        return OverlayReport::empty(total_entries);
    };

    let present = map
        .keys()
        .filter_map(serde_yaml::Value::as_str)
        .collect::<BTreeSet<_>>();
    for key in TOP_LEVEL_KEYS {
        if !present.contains(key) {
            violations.push(format!("{OVERLAY_RELPATH}：缺顶层键 `{key}`"));
        }
    }
    for key in &present {
        if !TOP_LEVEL_KEYS.contains(key) {
            violations.push(format!("{OVERLAY_RELPATH}：出现未定义的顶层键 `{key}`"));
        }
    }

    if string(map, "schema") != Some("parity-overlay") {
        violations.push(format!(
            "{OVERLAY_RELPATH}：schema 必须逐字等于 `parity-overlay`"
        ));
    }
    if map
        .get(serde_yaml::Value::from("schema_version"))
        .and_then(serde_yaml::Value::as_u64)
        != Some(1)
    {
        violations.push(format!("{OVERLAY_RELPATH}：schema_version 必须是整数 1"));
    }
    let baseline = string(map, "baseline").unwrap_or_default().to_owned();
    if baseline != "v4" {
        violations.push(format!("{OVERLAY_RELPATH}：baseline 必须逐字等于 `v4`"));
    }
    if string(map, "generated_by").is_none() {
        violations.push(format!("{OVERLAY_RELPATH}：generated_by 必须是非空字符串"));
    }

    let Some(entries) = map
        .get(serde_yaml::Value::from("entries"))
        .and_then(serde_yaml::Value::as_sequence)
    else {
        violations.push(format!("{OVERLAY_RELPATH}：entries 必须是序列"));
        return OverlayReport::empty(total_entries);
    };

    let mut seen = BTreeSet::new();
    let mut explicit_counts = empty_counts();
    let mut shapes = BTreeMap::new();
    for (index, entry) in entries.iter().enumerate() {
        let Some(entry) = entry.as_mapping() else {
            violations.push(format!("{OVERLAY_RELPATH} entry#{index}：必须是 mapping"));
            continue;
        };
        for key in entry.keys() {
            let Some(key) = key.as_str() else {
                violations.push(format!("{OVERLAY_RELPATH} entry#{index}：键必须是字符串"));
                continue;
            };
            if !ENTRY_KEYS.contains(&key) {
                violations.push(format!(
                    "{OVERLAY_RELPATH} entry#{index}：出现未定义的键 `{key}`"
                ));
            }
        }

        let Some(id) = string(entry, "id") else {
            violations.push(format!(
                "{OVERLAY_RELPATH} entry#{index}：id 必须是非空字符串"
            ));
            continue;
        };
        if !seen.insert(id.to_owned()) {
            violations.push(format!("{OVERLAY_RELPATH}：重复 id `{id}`"));
            continue;
        }
        if !parity_test_ids.contains(id) {
            violations.push(format!(
                "{OVERLAY_RELPATH}：id `{id}` 不存在于 parity ledger 的 test_id 集合"
            ));
        }

        let Some(disposition) = string(entry, "disposition") else {
            violations.push(format!(
                "{OVERLAY_RELPATH} `{id}`：disposition 必须是非空字符串"
            ));
            continue;
        };
        if !DISPOSITIONS.contains(&disposition) {
            violations.push(format!(
                "{OVERLAY_RELPATH} `{id}`：disposition=`{disposition}` 不在 {DISPOSITIONS:?} 内"
            ));
            continue;
        }
        *explicit_counts.entry(disposition.to_owned()).or_insert(0) += 1;
        if disposition == "carry" {
            violations.push(format!(
                "{OVERLAY_RELPATH} `{id}`：carry 必须隐含，exception-only overlay 禁止显式 carry 行"
            ));
        }

        let scope = string(entry, "scope");
        let replacement = string(entry, "replacement");
        if entry.contains_key(serde_yaml::Value::from("revalidation_evidence")) {
            if disposition != "split" {
                violations.push(format!(
                    "{OVERLAY_RELPATH} `{id}`：revalidation_evidence 只允许用于 split 当前 scope 的重验"
                ));
            } else if revalidation_evidence(entry).is_none() {
                violations.push(format!(
                    "{OVERLAY_RELPATH} `{id}`：revalidation_evidence 必须是非空证据引用字符串"
                ));
            }
        }
        let defect = entry
            .get(serde_yaml::Value::from("defect"))
            .and_then(serde_yaml::Value::as_bool);
        if entry.contains_key(serde_yaml::Value::from("defect")) && defect != Some(true) {
            violations.push(format!(
                "{OVERLAY_RELPATH} `{id}`：defect 只允许布尔值 true；无缺陷时应省略该键"
            ));
        }
        match disposition {
            "revalidate" => {
                if entry.contains_key(serde_yaml::Value::from("scope"))
                    || entry.contains_key(serde_yaml::Value::from("replacement"))
                {
                    violations.push(format!(
                        "{OVERLAY_RELPATH} `{id}`：revalidate 不允许 scope/replacement"
                    ));
                }
            }
            "split" => {
                if !matches!(scope, Some("web" | "desktop")) {
                    violations.push(format!(
                        "{OVERLAY_RELPATH} `{id}`：split 必须带 scope=web|desktop"
                    ));
                }
                if entry.contains_key(serde_yaml::Value::from("defect"))
                    || entry.contains_key(serde_yaml::Value::from("replacement"))
                {
                    violations.push(format!(
                        "{OVERLAY_RELPATH} `{id}`：split 不允许 defect/replacement"
                    ));
                }
            }
            "superseded" => {
                if replacement.is_none() {
                    violations.push(format!(
                        "{OVERLAY_RELPATH} `{id}`：superseded 必须带非空 replacement"
                    ));
                }
                if entry.contains_key(serde_yaml::Value::from("scope"))
                    || entry.contains_key(serde_yaml::Value::from("defect"))
                {
                    violations.push(format!(
                        "{OVERLAY_RELPATH} `{id}`：superseded 不允许 scope/defect"
                    ));
                }
            }
            "carry" => {}
            _ => unreachable!("disposition domain checked above"),
        }
        shapes.insert(
            id.to_owned(),
            (disposition.to_owned(), scope.map(str::to_owned), defect),
        );
    }

    require_initial(
        &shapes,
        "T-BROP-0046",
        "revalidate",
        None,
        Some(true),
        violations,
    );
    require_initial(
        &shapes,
        "T-CMP-0015",
        "split",
        Some("web"),
        None,
        violations,
    );
    require_initial(
        &shapes,
        "T-CMP-0018",
        "split",
        Some("web"),
        None,
        violations,
    );

    if seen.len() > total_entries {
        violations.push(format!(
            "{OVERLAY_RELPATH}：显式条目 {} 多于 parity 总条目 {total_entries}",
            seen.len()
        ));
    }
    let mut disposition_counts = explicit_counts;
    let explicit_non_carry = DISPOSITIONS[1..]
        .iter()
        .map(|key| disposition_counts.get(*key).copied().unwrap_or_default())
        .sum::<usize>();
    disposition_counts.insert(
        "carry".to_owned(),
        total_entries.saturating_sub(explicit_non_carry),
    );

    OverlayReport {
        file: OVERLAY_RELPATH.to_owned(),
        baseline,
        explicit_entries: seen.len(),
        diff_required_revalidations: 0,
        disposition_counts,
    }
}

fn validate_diff_revalidation(
    root: &Path,
    done_targets: &BTreeMap<String, String>,
    document: &serde_yaml::Value,
    violations: &mut Vec<String>,
) -> usize {
    let prefixes = match changed_target_prefixes(root) {
        Ok(prefixes) => prefixes,
        Err(error) => {
            violations.push(format!(
                "{OVERLAY_RELPATH}：无法计算 git diff target 前缀：{error}"
            ));
            return 0;
        }
    };
    validate_target_revalidation(&prefixes, done_targets, document, violations)
}

/// A split remains scoped after revalidation: the evidence reference covers only its scope,
/// and does not promote the other host to done. References are declarations reviewed alongside
/// the actual evidence; the gate neither executes nor opens the referenced text.
fn validate_target_revalidation(
    prefixes: &BTreeSet<String>,
    done_targets: &BTreeMap<String, String>,
    document: &serde_yaml::Value,
    violations: &mut Vec<String>,
) -> usize {
    let revalidated = document
        .as_mapping()
        .and_then(|map| map.get(serde_yaml::Value::from("entries")))
        .and_then(serde_yaml::Value::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let entry = entry.as_mapping()?;
            has_diff_revalidation(entry)
                .then(|| string(entry, "id"))
                .flatten()
        })
        .collect::<BTreeSet<_>>();

    let required = done_targets
        .iter()
        .filter(|(_, target)| prefixes.iter().any(|prefix| target.contains(prefix)))
        .collect::<Vec<_>>();
    for (test_id, target) in &required {
        if !revalidated.contains(test_id.as_str()) {
            violations.push(format!(
                "{OVERLAY_RELPATH}：git diff 命中 done target `{target}`，必须为 `{test_id}` 添加 disposition=revalidate，或保留合法 split/scope 并提供非空 revalidation_evidence；均须重跑相应范围的证据"
            ));
        }
    }
    required.len()
}

fn has_diff_revalidation(entry: &serde_yaml::Mapping) -> bool {
    match string(entry, "disposition") {
        Some("revalidate") => ["scope", "replacement", "revalidation_evidence"]
            .iter()
            .all(|key| !entry.contains_key(serde_yaml::Value::from(*key))),
        Some("split") => {
            matches!(string(entry, "scope"), Some("web" | "desktop"))
                && revalidation_evidence(entry).is_some()
                && !entry.contains_key(serde_yaml::Value::from("defect"))
                && !entry.contains_key(serde_yaml::Value::from("replacement"))
        }
        _ => false,
    }
}

fn revalidation_evidence(entry: &serde_yaml::Mapping) -> Option<&str> {
    string(entry, "revalidation_evidence").filter(|value| !value.trim().is_empty())
}

fn changed_target_prefixes(root: &Path) -> anyhow::Result<BTreeSet<String>> {
    let reference = ["origin/main", "main"]
        .into_iter()
        .find(|candidate| {
            Command::new("git")
                .args(["rev-parse", "--verify", &format!("{candidate}^{{commit}}")])
                .current_dir(root)
                .output()
                .is_ok_and(|output| output.status.success())
        })
        .ok_or_else(|| anyhow::anyhow!("origin/main 与 main 都不可解析"))?;
    let merge_base = Command::new("git")
        .args(["merge-base", "HEAD", reference])
        .current_dir(root)
        .output()?;
    if !merge_base.status.success() {
        return Err(anyhow::anyhow!(
            "git merge-base HEAD {reference} failed: {}",
            String::from_utf8_lossy(&merge_base.stderr).trim()
        ));
    }
    let base = String::from_utf8(merge_base.stdout)?.trim().to_owned();
    let output = Command::new("git")
        .args([
            "diff",
            "--name-only",
            "--diff-filter=ACMRT",
            &base,
            "--",
            "crates",
        ])
        .current_dir(root)
        .output()?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "git diff failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .filter_map(path_target_prefix)
        .collect())
}

fn path_target_prefix(path: &str) -> Option<String> {
    let path = path.strip_prefix("crates/openbot-")?;
    let (crate_name, source) = path.split_once("/src/")?;
    let mut prefix = format!("openbot_{}", crate_name.replace('-', "_"));
    let source = source.strip_suffix(".rs")?;
    if source != "lib" {
        let source = source.strip_suffix("/mod").unwrap_or(source);
        if !source.is_empty() {
            prefix.push_str("::");
            prefix.push_str(&source.replace('/', "::"));
        }
    }
    Some(prefix)
}

fn require_initial(
    shapes: &BTreeMap<String, (String, Option<String>, Option<bool>)>,
    id: &str,
    disposition: &str,
    scope: Option<&str>,
    defect: Option<bool>,
    violations: &mut Vec<String>,
) {
    let expected = (disposition.to_owned(), scope.map(str::to_owned), defect);
    if shapes.get(id) != Some(&expected) {
        violations.push(format!(
            "{OVERLAY_RELPATH}：R124 初值 `{id}` 必须是 disposition={disposition}, scope={scope:?}, defect={defect:?}"
        ));
    }
}

fn string<'a>(map: &'a serde_yaml::Mapping, key: &str) -> Option<&'a str> {
    map.get(serde_yaml::Value::from(key))
        .and_then(serde_yaml::Value::as_str)
        .filter(|value| !value.is_empty())
}

fn empty_counts() -> BTreeMap<String, usize> {
    DISPOSITIONS
        .into_iter()
        .map(|key| (key.to_owned(), 0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{DISPOSITIONS, validate_document, validate_target_revalidation};
    use std::collections::{BTreeMap, BTreeSet};

    const VALID: &str = r#"
schema: parity-overlay
schema_version: 1
baseline: v4
generated_by: manual
entries:
  - id: T-BROP-0046
    disposition: revalidate
    defect: true
  - id: T-CMP-0015
    disposition: split
    scope: web
  - id: T-CMP-0018
    disposition: split
    scope: web
"#;

    fn test_ids() -> BTreeSet<String> {
        ["T-BROP-0046", "T-CMP-0015", "T-CMP-0018"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    fn targets() -> BTreeMap<String, String> {
        [
            ("T-BROP-0046", "openbot_computer::control::ControlService"),
            (
                "T-CMP-0015",
                "openbot_ui::features::gallery::sandboxed::renderer",
            ),
        ]
        .into_iter()
        .map(|(id, target)| (id.to_owned(), target.to_owned()))
        .collect()
    }

    fn renderer_prefix() -> BTreeSet<String> {
        BTreeSet::from(["openbot_ui::features::gallery::sandboxed::renderer".to_owned()])
    }

    fn with_web_evidence() -> serde_yaml::Value {
        let mut document: serde_yaml::Value = serde_yaml::from_str(VALID).unwrap();
        document["entries"][1]["revalidation_evidence"] =
            serde_yaml::Value::from("repository contract");
        document
    }

    #[test]
    fn initial_overlay_is_exception_only_and_counts_implicit_carry() {
        let document = serde_yaml::from_str(VALID).expect("valid yaml");
        let mut violations = Vec::new();
        let report = validate_document(&document, &test_ids(), 10, &mut violations);
        assert!(violations.is_empty(), "{violations:?}");
        assert_eq!(report.explicit_entries, 3);
        assert_eq!(report.disposition_counts["carry"], 7);
        assert_eq!(report.disposition_counts["revalidate"], 1);
        assert_eq!(report.disposition_counts["split"], 2);
        assert_eq!(report.disposition_counts["superseded"], 0);
        assert_eq!(report.disposition_counts.len(), DISPOSITIONS.len());
    }

    #[test]
    fn explicit_carry_and_missing_initial_defect_are_rejected() {
        let changed = VALID.replace("    defect: true\n", "").replacen(
            "    disposition: split\n",
            "    disposition: carry\n",
            1,
        );
        let document = serde_yaml::from_str(&changed).expect("valid yaml");
        let mut violations = Vec::new();
        validate_document(&document, &test_ids(), 10, &mut violations);
        assert!(
            violations
                .iter()
                .any(|item| item.contains("carry 必须隐含"))
        );
        assert!(violations.iter().any(|item| item.contains("T-BROP-0046")));
    }

    #[test]
    fn web_split_revalidation_preserves_scope_initial_values_and_all_counts() {
        let original = serde_yaml::from_str(VALID).unwrap();
        let document = with_web_evidence();
        let mut violations = Vec::new();
        let before = validate_document(&original, &test_ids(), 10, &mut violations);
        let after = validate_document(&document, &test_ids(), 10, &mut violations);
        assert_eq!(
            validate_target_revalidation(
                &renderer_prefix(),
                &targets(),
                &document,
                &mut violations
            ),
            1
        );
        assert!(violations.is_empty(), "{violations:?}");
        assert_eq!(document["schema_version"], 1);
        assert_eq!(document["entries"][1]["disposition"], "split");
        assert_eq!(document["entries"][1]["scope"], "web");
        // The pending Desktop counterpart and the other R124 split are not promoted.
        assert_eq!(document["entries"][2], original["entries"][2]);
        assert_eq!(before.disposition_counts, after.disposition_counts);
        assert_eq!(before.explicit_entries, after.explicit_entries);
        assert_eq!(after.disposition_counts["split"], 2);
        assert_eq!(after.disposition_counts["revalidate"], 1);
        assert_eq!(after.disposition_counts.len(), DISPOSITIONS.len());
    }

    #[test]
    fn untouched_split_requires_no_evidence_and_existing_revalidate_still_works() {
        let document = serde_yaml::from_str(VALID).unwrap();
        let mut violations = Vec::new();
        validate_document(&document, &test_ids(), 10, &mut violations);
        let prefixes = BTreeSet::from(["openbot_computer::control".to_owned()]);
        assert_eq!(
            validate_target_revalidation(&prefixes, &targets(), &document, &mut violations),
            1
        );
        assert!(violations.is_empty(), "{violations:?}");
        assert_eq!(
            validate_target_revalidation(&BTreeSet::new(), &targets(), &document, &mut violations),
            0
        );
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn touched_split_without_explicit_evidence_is_not_exempted() {
        let mut document: serde_yaml::Value = serde_yaml::from_str(VALID).unwrap();
        document["entries"][1]["notes"] = serde_yaml::Value::from("revalidated Web iframe");
        let mut violations = Vec::new();
        validate_document(&document, &test_ids(), 10, &mut violations);
        assert!(violations.is_empty(), "{violations:?}");
        assert_eq!(
            validate_target_revalidation(
                &renderer_prefix(),
                &targets(),
                &document,
                &mut violations
            ),
            1
        );
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("T-CMP-0015"));
        assert!(violations[0].contains("revalidation_evidence"));
    }

    #[test]
    fn evidence_must_be_nonempty_string_and_cannot_hide_in_notes_or_another_entry() {
        for raw in [
            "null",
            "true",
            "42",
            "[]",
            "{}",
            "''",
            "'   '",
            "\"\\n\\t\"",
        ] {
            let mut document = with_web_evidence();
            document["entries"][1]["revalidation_evidence"] = serde_yaml::from_str(raw).unwrap();
            let mut violations = Vec::new();
            validate_document(&document, &test_ids(), 10, &mut violations);
            assert!(
                violations
                    .iter()
                    .any(|value| value.contains("非空证据引用字符串")),
                "{raw}: {violations:?}"
            );
            violations.clear();
            validate_target_revalidation(
                &renderer_prefix(),
                &targets(),
                &document,
                &mut violations,
            );
            assert_eq!(violations.len(), 1, "{raw}");
        }
        let mut document: serde_yaml::Value = serde_yaml::from_str(VALID).unwrap();
        document["entries"][2]["revalidation_evidence"] =
            serde_yaml::Value::from("repository contract");
        let mut violations = Vec::new();
        validate_target_revalidation(&renderer_prefix(), &targets(), &document, &mut violations);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("T-CMP-0015"));
    }

    #[test]
    fn evidence_is_split_only_and_forbidden_keys_are_rejected_even_when_null() {
        for disposition in ["carry", "revalidate", "superseded"] {
            for raw in ["null", "''", "'repository contract'"] {
                let mut document: serde_yaml::Value = serde_yaml::from_str(VALID).unwrap();
                document["entries"].as_sequence_mut().unwrap().push(serde_yaml::from_str(
                    &format!("id: T-EXTRA\ndisposition: {disposition}\nreplacement: T-CMP-0015\nrevalidation_evidence: {raw}")
                ).unwrap());
                let mut ids = test_ids();
                ids.insert("T-EXTRA".to_owned());
                let mut violations = Vec::new();
                validate_document(&document, &ids, 10, &mut violations);
                assert!(
                    violations
                        .iter()
                        .any(|value| value.contains("revalidation_evidence 只允许用于 split")),
                    "{disposition}/{raw}: {violations:?}"
                );
            }
        }
        for key in ["scope", "replacement", "revalidation_evidence"] {
            for raw in ["null", "''", "42"] {
                let mut document: serde_yaml::Value = serde_yaml::from_str(VALID).unwrap();
                document["entries"][0][key] = serde_yaml::from_str(raw).unwrap();
                let mut violations = Vec::new();
                validate_document(&document, &test_ids(), 10, &mut violations);
                assert!(!violations.is_empty(), "{key}/{raw}");
                violations.clear();
                let prefixes = BTreeSet::from(["openbot_computer::control".to_owned()]);
                validate_target_revalidation(&prefixes, &targets(), &document, &mut violations);
                assert_eq!(violations.len(), 1, "{key}/{raw}");
            }
        }
    }

    #[test]
    fn invalid_scope_and_r124_scope_changes_are_not_revalidated_by_a_reference() {
        for raw in ["null", "''", "42", "web-and-desktop", "unknown"] {
            let mut document = with_web_evidence();
            document["entries"][1]["scope"] = serde_yaml::from_str(raw).unwrap();
            let mut violations = Vec::new();
            validate_document(&document, &test_ids(), 10, &mut violations);
            assert!(
                violations
                    .iter()
                    .any(|value| value.contains("split 必须带 scope=web|desktop"))
            );
            violations.clear();
            validate_target_revalidation(
                &renderer_prefix(),
                &targets(),
                &document,
                &mut violations,
            );
            assert_eq!(violations.len(), 1, "{raw}");
        }
        let mut document = with_web_evidence();
        document["entries"][1]["scope"] = serde_yaml::Value::from("desktop");
        let mut violations = Vec::new();
        validate_document(&document, &test_ids(), 10, &mut violations);
        assert!(
            violations
                .iter()
                .any(|value| value.contains("R124 初值 `T-CMP-0015`"))
        );
    }

    #[test]
    fn other_legal_desktop_splits_can_revalidate_only_with_their_own_evidence() {
        let mut document: serde_yaml::Value = serde_yaml::from_str(VALID).unwrap();
        document["entries"].as_sequence_mut().unwrap().push(serde_yaml::from_str(
            "id: T-EXTRA\ndisposition: split\nscope: desktop\nrevalidation_evidence: repository contract"
        ).unwrap());
        let mut ids = test_ids();
        ids.insert("T-EXTRA".to_owned());
        let mut done_targets = targets();
        done_targets.insert("T-EXTRA".to_owned(), "openbot_desktop::example".to_owned());
        let prefixes = BTreeSet::from(["openbot_desktop::example".to_owned()]);
        let mut violations = Vec::new();
        let report = validate_document(&document, &ids, 10, &mut violations);
        assert_eq!(
            validate_target_revalidation(&prefixes, &done_targets, &document, &mut violations),
            1
        );
        assert!(violations.is_empty(), "{violations:?}");
        assert_eq!(report.disposition_counts["split"], 3);
        assert_eq!(report.disposition_counts["carry"], 6);
    }

    #[test]
    fn rust_source_path_becomes_ledger_target_prefix() {
        assert_eq!(
            super::path_target_prefix("crates/openbot-computer/src/control.rs").as_deref(),
            Some("openbot_computer::control")
        );
        assert_eq!(
            super::path_target_prefix("crates/openbot-testkit/src/xtask/engine.rs").as_deref(),
            Some("openbot_testkit::xtask::engine")
        );
    }
}
