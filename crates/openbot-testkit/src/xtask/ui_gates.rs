//! Deterministic local gates for the Icon fixture.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use flate2::{Compression, GzBuilder};
use regex::Regex;
use walkdir::WalkDir;

const UI_DIR: &str = "crates/openbot-ui";
const WASM_GZIP_LIMIT: usize = 3_670_016;
/// Icon fixture §10.5 / v3 R123 (2026-08-28): 96 KiB was exhausted at Batch 50 (97,848 B, 456 B
/// left) with 24 route journeys still open, so the limit is 128 KiB with a 120 KiB warning line. The
/// warning exists so the next delta audit is scheduled before the gate turns red, not after.
const CSS_LIMIT: usize = 128 * 1024;
const CSS_WARN: usize = 120 * 1024;
const FONT_LIMIT: usize = 800 * 1024;

pub(crate) fn i18n_check(root: &Path) -> Result<()> {
    let locales = root.join(UI_DIR).join("locales");
    let en = read_locale(&locales.join("en.json"))?;
    let zh = read_locale(&locales.join("zh-CN.json"))?;

    let en_keys = en.keys().cloned().collect::<BTreeSet<_>>();
    let zh_keys = zh.keys().cloned().collect::<BTreeSet<_>>();
    if en_keys != zh_keys {
        bail!(
            "i18n key drift: en_only={:?}, zh-CN_only={:?}",
            en_keys.difference(&zh_keys).collect::<Vec<_>>(),
            zh_keys.difference(&en_keys).collect::<Vec<_>>()
        );
    }

    for key in &en_keys {
        let en_placeholders = placeholder_names(en.get(key).expect("key set was checked"))
            .with_context(|| format!("en.json key `{key}` has malformed interpolation"))?;
        let zh_placeholders = placeholder_names(zh.get(key).expect("key set was checked"))
            .with_context(|| format!("zh-CN.json key `{key}` has malformed interpolation"))?;
        if en_placeholders != zh_placeholders {
            bail!(
                "i18n placeholder drift at `{key}`: en={en_placeholders:?}, zh-CN={zh_placeholders:?}"
            );
        }
    }

    println!(
        "i18n-check: ok ({} leaf keys; en/zh-CN key and placeholder sets exact)",
        en_keys.len()
    );
    Ok(())
}

pub(crate) fn design_lint(root: &Path) -> Result<()> {
    let ui = root.join(UI_DIR);
    let sources = rust_sources(&ui.join("src"))?;
    let literal_or_arbitrary = Regex::new(r"(bg|text|border)-\[#|\[[0-9]+px\]")?;
    let semantic_surface = Regex::new(r"(bg|border)-(danger|caution|success|info)\b")?;
    let shadow = Regex::new(r"shadow-([A-Za-z0-9_-]+)")?;

    let mut violations = Vec::new();
    for (path, source) in &sources {
        let is_guarded_design_gallery_module = path.ends_with("design_gallery.rs")
            && source
                .lines()
                .next()
                .is_some_and(|line| line == "#![cfg(feature = \"design-gallery\")]");
        let source_lines = source.lines().collect::<Vec<_>>();
        for (index, line) in source_lines.iter().enumerate() {
            let line_no = index + 1;
            if line.contains("dark:") {
                violations.push(format!("{}:{line_no}: forbidden `dark:`", path.display()));
            }
            if literal_or_arbitrary.is_match(line) {
                violations.push(format!(
                    "{}:{line_no}: literal color/arbitrary px class",
                    path.display()
                ));
            }
            if semantic_surface.is_match(line) {
                violations.push(format!(
                    "{}:{line_no}: semantic status color used as surface/border",
                    path.display()
                ));
            }
            for capture in shadow.captures_iter(line) {
                let value = capture.get(1).expect("capture exists").as_str();
                if !matches!(value, "popover" | "dialog" | "none") {
                    violations.push(format!(
                        "{}:{line_no}: unapproved shadow `{value}`",
                        path.display()
                    ));
                }
            }
            let is_guarded_app_route = path.ends_with("app.rs")
                && source_lines[..index]
                    .iter()
                    .rev()
                    .take(4)
                    .any(|previous| *previous == "    #[cfg(feature = \"design-gallery\")]");
            if line.contains("/_design")
                && !is_guarded_design_gallery_module
                && !is_guarded_app_route
            {
                violations.push(format!(
                    "{}:{line_no}: production source contains design-gallery route",
                    path.display()
                ));
            }
        }
    }
    if !violations.is_empty() {
        bail!("design-lint violations:\n{}", violations.join("\n"));
    }

    let index = fs::read_to_string(ui.join("index.html"))?;
    if Regex::new(r"(?i)<script\b")?.is_match(&index) {
        bail!("source index.html must contain zero script tags; Trunk emits the external loader");
    }

    let icon_count = check_icons(root, &ui, &sources)?;
    println!(
        "design-lint: ok ({} Rust files; {icon_count} manifest/SVG icons; reverse rules clean)",
        sources.len()
    );
    Ok(())
}

pub(crate) fn css_check(root: &Path, args: &[String]) -> Result<()> {
    let ui = root.join(UI_DIR);
    let css_path = parse_path_option(root, args, "--css")?
        .map_or_else(|| unique_file_with_extension(&ui.join("dist"), "css"), Ok)?;
    let css = fs::read_to_string(&css_path)
        .with_context(|| format!("read compiled CSS {}", css_path.display()))?;
    let sources = rust_sources(&ui.join("src"))?;
    let source_classes = source_class_literals(&sources)?;
    let compiled_classes = compiled_css_classes(&css)?;
    let missing = source_classes
        .difference(&compiled_classes)
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        bail!(
            "compiled CSS misses {} Rust class literals: {:?} (css={})",
            missing.len(),
            missing,
            css_path.display()
        );
    }
    println!(
        "css-check: ok ({} source class literals found in {})",
        source_classes.len(),
        css_path.display()
    );
    Ok(())
}

pub(crate) fn bundle_budget(root: &Path, args: &[String]) -> Result<()> {
    let ui = root.join(UI_DIR);
    let dist = parse_path_option(root, args, "--dist")?.unwrap_or_else(|| ui.join("dist"));
    let wasm = unique_file_with_extension(&dist, "wasm")?;
    let css = unique_file_with_extension(&dist, "css")?;
    let external_scripts = check_dist_script_policy(&dist)?;
    let wasm_bytes = fs::read(&wasm).with_context(|| format!("read {}", wasm.display()))?;
    if wasm_bytes
        .windows(b"_design".len())
        .any(|window| window == b"_design")
    {
        bail!("production WASM contains the design-gallery route literal");
    }
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::best());
    encoder.write_all(&wasm_bytes)?;
    let wasm_gzip = encoder.finish()?.len();
    let css_bytes = file_len(&css)?;
    let fonts = [
        ui.join("assets/fonts/InterVariable.woff2"),
        ui.join("assets/fonts/InterVariable-Italic.woff2"),
    ];
    let font_bytes = fonts
        .iter()
        .map(|path| file_len(path))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .sum::<usize>();

    let mut failures = Vec::new();
    if wasm_gzip > WASM_GZIP_LIMIT {
        failures.push(format!(
            "wasm gzip {wasm_gzip} > {WASM_GZIP_LIMIT} bytes ({})",
            wasm.display()
        ));
    }
    if css_bytes > CSS_LIMIT {
        failures.push(format!(
            "css {css_bytes} > {CSS_LIMIT} bytes ({})",
            css.display()
        ));
    }
    if font_bytes > FONT_LIMIT {
        failures.push(format!("fonts {font_bytes} > {FONT_LIMIT} bytes"));
    }
    if !failures.is_empty() {
        bail!("bundle budget exceeded:\n{}", failures.join("\n"));
    }
    if css_bytes > CSS_WARN {
        println!(
            "bundle-budget: warning css {css_bytes} > {CSS_WARN} bytes (limit {CSS_LIMIT}); schedule the CSS delta audit before the limit turns red"
        );
    }
    println!(
        "bundle-budget: ok (wasm gzip={wasm_gzip}/{WASM_GZIP_LIMIT}; css={css_bytes}/{CSS_LIMIT}; fonts={font_bytes}/{FONT_LIMIT}; external scripts={external_scripts}, inline=0)"
    );
    Ok(())
}

fn check_dist_script_policy(dist: &Path) -> Result<usize> {
    let index_path = dist.join("index.html");
    let index = fs::read_to_string(&index_path)
        .with_context(|| format!("read {}", index_path.display()))?;
    let script = Regex::new(r"(?is)<script\b([^>]*)>")?;
    let src = Regex::new(r#"(?i)\bsrc\s*=\s*["'][^"']+["']"#)?;
    let mut count = 0;
    for capture in script.captures_iter(&index) {
        count += 1;
        let attributes = capture.get(1).expect("capture exists").as_str();
        if !src.is_match(attributes) {
            bail!("compiled index.html contains an inline script");
        }
    }
    if count != 1 || !index.contains("src=\"/openbot-bootstrap.mjs\"") {
        bail!("compiled index.html must contain exactly one external OpenBot bootstrap script");
    }
    let bootstrap_path = dist.join("openbot-bootstrap.mjs");
    let bootstrap = fs::read_to_string(&bootstrap_path)
        .with_context(|| format!("read {}", bootstrap_path.display()))?;
    for forbidden in [
        "http:",
        "https:",
        "eval(",
        "Function(",
        "document.cookie",
        "localStorage",
    ] {
        if bootstrap.contains(forbidden) {
            bail!("external bootstrap contains forbidden token `{forbidden}`");
        }
    }
    if !bootstrap.contains("import init from \"./")
        || !bootstrap.contains("module_or_path: \"/")
        || bootstrap.contains("module_or_path: \"./")
    {
        bail!("external bootstrap must use module-relative JS and root-absolute WASM");
    }
    Ok(count)
}

fn read_locale(path: &Path) -> Result<BTreeMap<String, String>> {
    let source = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&source).with_context(|| format!("parse {}", path.display()))?;
    let mut leaves = BTreeMap::new();
    collect_locale_leaves("", &value, &mut leaves)?;
    Ok(leaves)
}

fn collect_locale_leaves(
    prefix: &str,
    value: &serde_json::Value,
    leaves: &mut BTreeMap<String, String>,
) -> Result<()> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if key.is_empty() {
                    bail!("locale key segment is empty at `{prefix}`");
                }
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                collect_locale_leaves(&path, value, leaves)?;
            }
        }
        serde_json::Value::String(text) if !prefix.is_empty() => {
            if leaves.insert(prefix.to_owned(), text.clone()).is_some() {
                bail!("duplicate locale leaf `{prefix}`");
            }
        }
        _ => bail!("locale leaf `{prefix}` must be a string"),
    }
    Ok(())
}

fn placeholder_names(value: &str) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    let mut rest = value;
    loop {
        let Some(open) = rest.find('{') else {
            if rest.contains('}') {
                bail!("unmatched closing brace");
            }
            break;
        };
        if rest[..open].contains('}') || !rest[open..].starts_with("{{") {
            bail!("single/unmatched brace; leptos_i18n requires `{{{{ name }}}}`");
        }
        let after_open = &rest[open + 2..];
        let close = after_open
            .find("}}")
            .ok_or_else(|| anyhow!("unclosed interpolation"))?;
        let inner = after_open[..close].trim();
        let name = inner.split(',').next().unwrap_or("").trim();
        if name.is_empty()
            || !name.chars().enumerate().all(|(index, character)| {
                character == '_'
                    || character.is_ascii_alphanumeric()
                        && (index > 0 || !character.is_ascii_digit())
            })
        {
            bail!("invalid interpolation name `{name}`");
        }
        names.insert(name.to_owned());
        rest = &after_open[close + 2..];
    }
    Ok(names)
}

fn rust_sources(dir: &Path) -> Result<Vec<(PathBuf, String)>> {
    let mut sources = Vec::new();
    for entry in WalkDir::new(dir).sort_by_file_name() {
        let entry = entry.with_context(|| format!("walk {}", dir.display()))?;
        let path = entry.path();
        if entry.file_type().is_file()
            && path.extension().and_then(|value| value.to_str()) == Some("rs")
        {
            sources.push((
                path.to_path_buf(),
                fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?,
            ));
        }
    }
    Ok(sources)
}

fn check_icons(root: &Path, ui: &Path, sources: &[(PathBuf, String)]) -> Result<usize> {
    let manifest_path = ui.join("design/icons.toml");
    let manifest: toml::Value = toml::from_str(
        &fs::read_to_string(&manifest_path)
            .with_context(|| format!("read {}", manifest_path.display()))?,
    )?;
    let entries = manifest
        .get("icon")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| anyhow!("icons.toml missing [[icon]]"))?;
    let names = entries
        .iter()
        .map(|entry| {
            entry
                .get("name")
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("icon entry missing name"))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if names.len() != entries.len() {
        bail!("icons.toml contains duplicate icon names");
    }
    let expected = manifest
        .get("meta")
        .and_then(|value| value.get("expected_icon_count"))
        .and_then(toml::Value::as_integer)
        .ok_or_else(|| anyhow!("icons.toml missing meta.expected_icon_count"))?;
    if i64::try_from(names.len())? != expected {
        bail!("icon count drift: expected {expected}, got {}", names.len());
    }

    let icon_dir = ui.join("design/icons");
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(&icon_dir).with_context(|| format!("read {}", icon_dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("svg") {
            let name = path
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or_else(|| anyhow!("non-UTF8 SVG name: {}", path.display()))?;
            actual.insert(name.to_owned());
            let svg = fs::read_to_string(&path)?;
            let lower = svg.to_ascii_lowercase();
            if !svg.contains("currentColor")
                || !svg.contains("stroke-width=\"1.75\"")
                || [
                    "<script",
                    "javascript:",
                    "<foreignobject",
                    "<image",
                    "<use",
                    "href=",
                    "url(",
                ]
                .iter()
                .any(|needle| lower.contains(needle))
            {
                bail!("unsafe or drifted SVG: {}", path.display());
            }
        }
    }
    if names != actual {
        bail!(
            "icons.toml/SVG drift: manifest_only={:?}, svg_only={:?}",
            names.difference(&actual).collect::<Vec<_>>(),
            actual.difference(&names).collect::<Vec<_>>()
        );
    }

    let variants = names
        .iter()
        .map(|name| icon_variant(name))
        .collect::<BTreeSet<_>>();
    let usage = Regex::new(r"\bIcon::([A-Z][A-Za-z0-9_]*)")?;
    for (path, source) in sources {
        for capture in usage.captures_iter(source) {
            let variant = capture.get(1).expect("capture exists").as_str();
            if variant != "ALL" && !variants.contains(variant) {
                bail!(
                    "{} uses icon outside allowlist: Icon::{variant}",
                    path.display()
                );
            }
        }
    }
    check_icon_mapping_join(root, &manifest, entries)?;
    Ok(names.len())
}

fn check_icon_mapping_join(
    root: &Path,
    manifest: &toml::Value,
    icon_entries: &[toml::Value],
) -> Result<()> {
    let mapping_path = root.join("fixtures/ui/icon-mappings.json");
    let mapping_source = fs::read_to_string(&mapping_path)
        .with_context(|| format!("read {}", mapping_path.display()))?;
    let fixture: serde_json::Value = serde_json::from_str(&mapping_source)?;
    let documented = parse_icon_mappings(&mapping_source)?;
    if documented.len() != 47 {
        bail!(
            "Icon fixture icon mapping count drift: expected 47, got {}",
            documented.len()
        );
    }

    let source_zip_sha = manifest
        .get("meta")
        .and_then(|value| value.get("source_zip_sha256"))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| anyhow!("icons.toml missing meta.source_zip_sha256"))?;
    if fixture
        .get("source_zip_sha256")
        .and_then(serde_json::Value::as_str)
        != Some(source_zip_sha)
    {
        bail!("Icon fixture does not contain the icons.toml source zip SHA-256");
    }

    let mut manifest_mappings = BTreeMap::new();
    let mut manifest_usage = BTreeMap::<String, BTreeSet<String>>::new();
    for entry in icon_entries {
        if entry.get("label").and_then(toml::Value::as_str) != Some("parity") {
            continue;
        }
        let tabler = required_toml_string(entry, "upstream_tabler")?;
        let name = required_toml_string(entry, "name")?;
        if manifest_mappings.insert(tabler.clone(), name).is_some() {
            bail!("icons.toml duplicates upstream_tabler `{tabler}`");
        }
        let usage = entry
            .get("upstream_usage")
            .and_then(toml::Value::as_array)
            .ok_or_else(|| anyhow!("icons.toml `{tabler}` missing upstream_usage"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow!("icons.toml `{tabler}` has non-string upstream_usage"))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        if usage.is_empty() {
            bail!("icons.toml `{tabler}` has empty upstream_usage");
        }
        manifest_usage.insert(tabler, usage);
    }
    if manifest_mappings.len() != 46 {
        bail!(
            "icons.toml Lucide mapping count drift: expected 46, got {}",
            manifest_mappings.len()
        );
    }

    let brand_marks = manifest
        .get("brand")
        .and_then(|value| value.get("mark"))
        .and_then(toml::Value::as_array)
        .ok_or_else(|| anyhow!("icons.toml missing [[brand.mark]]"))?;
    let brand = brand_marks
        .iter()
        .find(|entry| {
            entry
                .get("upstream_tabler")
                .and_then(toml::Value::as_str)
                .is_some()
        })
        .ok_or_else(|| anyhow!("icons.toml missing upstream Tabler brand mapping"))?;
    if required_toml_string(brand, "upstream_tabler")? != "IconBrandGoogleDrive"
        || required_toml_string(brand, "name")? != "google-drive"
        || required_toml_string(brand, "file")? != "google-drive.svg"
        || required_toml_string(brand, "status")? != "todo"
    {
        bail!("Google Drive brand mapping/status drift in icons.toml");
    }

    let mut manifest_all = manifest_mappings.clone();
    manifest_all.insert(
        "IconBrandGoogleDrive".to_owned(),
        "brand/google-drive.svg".to_owned(),
    );
    if documented != manifest_all {
        bail!(
            "Icon fixture/icons.toml mapping drift: document_only={:?}, manifest_only={:?}",
            documented
                .iter()
                .filter(|(key, value)| manifest_all.get(*key) != Some(*value))
                .collect::<Vec<_>>(),
            manifest_all
                .iter()
                .filter(|(key, value)| documented.get(*key) != Some(*value))
                .collect::<Vec<_>>()
        );
    }

    let ledger_path = mapping_path;
    let ledger: serde_yaml::Value = serde_yaml::from_str(
        &fs::read_to_string(&ledger_path)
            .with_context(|| format!("read {}", ledger_path.display()))?,
    )?;
    let ledger_entries = ledger
        .get("entries")
        .and_then(serde_yaml::Value::as_sequence)
        .ok_or_else(|| anyhow!("fixtures/ui/icon-mappings.json missing entries"))?;
    let mut ledger_icons = BTreeMap::new();
    for entry in ledger_entries {
        let Some(id) = entry.get("id").and_then(serde_yaml::Value::as_str) else {
            continue;
        };
        let Some(tabler) = id.strip_prefix("icon-") else {
            continue;
        };
        if ledger_icons.insert(tabler.to_owned(), entry).is_some() {
            bail!("fixtures/ui/icon-mappings.json duplicates icon ledger `{tabler}`");
        }
    }
    if ledger_icons.len() != 47
        || ledger_icons.keys().cloned().collect::<BTreeSet<_>>()
            != documented.keys().cloned().collect::<BTreeSet<_>>()
    {
        bail!("fixtures/ui/icon-mappings.json icon ledger is not the exact 47-row fixture key set");
    }

    for (tabler, target_name) in &documented {
        let entry = ledger_icons.get(tabler).expect("exact key set was checked");
        let target = required_yaml_string(entry, "target")?;
        let status = required_yaml_string(entry, "status")?;
        let upstream = required_yaml_string(entry, "upstream")?;
        if !upstream.ends_with(&format!("::{tabler}")) {
            bail!("{tabler} ledger upstream does not end in its exact symbol");
        }
        if tabler == "IconBrandGoogleDrive" {
            if target != "openbot_ui::icons::brand::GoogleDrive" || status != "todo" {
                bail!("Google Drive brand ledger must remain exact todo until brand assets land");
            }
            continue;
        }

        let manifest_name = manifest_mappings
            .get(tabler)
            .ok_or_else(|| anyhow!("{tabler} missing from icons.toml Lucide mappings"))?;
        if manifest_name != target_name {
            bail!("{tabler} document/manifest target drift");
        }
        let expected_target = format!("openbot_ui::icons::Icon::{}", icon_variant(target_name));
        if target != expected_target {
            bail!("{tabler} ledger target `{target}` != `{expected_target}`");
        }
        if status != "done" {
            bail!("{tabler} has a closed Lucide mapping but ledger status is `{status}`");
        }
        let upstream_path = upstream
            .split("::")
            .next()
            .and_then(|path| path.strip_prefix("app/src/"))
            .ok_or_else(|| anyhow!("{tabler} ledger upstream path is not under app/src"))?;
        if !manifest_usage
            .get(tabler)
            .is_some_and(|usage| usage.contains(upstream_path))
        {
            bail!("{tabler} ledger first upstream path is absent from icons.toml usage");
        }
    }

    println!(
        "icon-mapping-join: ok (46/46 Lucide done; Google Drive brand 1/1 todo; fixture/manifest/contract exact)"
    );
    Ok(())
}

fn parse_icon_mappings(source: &str) -> Result<BTreeMap<String, String>> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct MappingFixture {
        source_zip_sha256: String,
        mappings: BTreeMap<String, String>,
        entries: Vec<serde_json::Value>,
    }
    let fixture: MappingFixture = serde_json::from_str(source)?;
    if fixture.source_zip_sha256.len() != 64
        || !fixture
            .source_zip_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
        || fixture.entries.is_empty()
        || fixture
            .mappings
            .iter()
            .any(|(key, value)| !key.starts_with("Icon") || value.is_empty())
    {
        bail!("invalid icon mapping fixture");
    }
    Ok(fixture.mappings)
}

fn required_toml_string(entry: &toml::Value, key: &str) -> Result<String> {
    entry
        .get(key)
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("TOML entry missing string `{key}`"))
}

fn required_yaml_string(entry: &serde_yaml::Value, key: &str) -> Result<String> {
    entry
        .get(key)
        .and_then(serde_yaml::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("YAML entry missing string `{key}`"))
}

fn icon_variant(name: &str) -> String {
    name.split('-')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut characters = part.chars();
            characters.next().map_or_else(String::new, |first| {
                first.to_ascii_uppercase().to_string() + characters.as_str()
            })
        })
        .collect()
}

fn source_class_literals(sources: &[(PathBuf, String)]) -> Result<BTreeSet<String>> {
    let literal = Regex::new(r#"\bclass\s*=\s*"([^"]*)""#)?;
    let assignment = Regex::new(r"\bclass\s*=")?;
    let mut classes = BTreeSet::new();
    for (path, source) in sources {
        for found in assignment.find_iter(source) {
            let rest = source[found.end()..].trim_start();
            if !rest.starts_with('"') && !rest.starts_with('(') {
                bail!(
                    "{} has non-literal class assignment near byte {}",
                    path.display(),
                    found.start()
                );
            }
        }
        for capture in literal.captures_iter(source) {
            classes.extend(
                capture
                    .get(1)
                    .expect("capture exists")
                    .as_str()
                    .split_ascii_whitespace()
                    .map(str::to_owned),
            );
        }
    }
    Ok(classes)
}

fn compiled_css_classes(css: &str) -> Result<BTreeSet<String>> {
    let selector = Regex::new(r"\.((?:\\.|[A-Za-z0-9_-])+)")?;
    Ok(selector
        .captures_iter(css)
        .filter_map(|capture| capture.get(1))
        .map(|value| value.as_str().replace("\\:", ":").replace("\\/", "/"))
        .collect())
}

fn parse_path_option(root: &Path, args: &[String], option: &str) -> Result<Option<PathBuf>> {
    match args {
        [] => Ok(None),
        [flag, path] if flag == option => {
            let path = PathBuf::from(path);
            Ok(Some(if path.is_absolute() {
                path
            } else {
                root.join(path)
            }))
        }
        _ => bail!("expected no arguments or `{option} <path>`"),
    }
}

fn unique_file_with_extension(dir: &Path, extension: &str) -> Result<PathBuf> {
    if !dir.is_dir() {
        bail!("artifact directory does not exist: {}", dir.display());
    }
    let mut files = WalkDir::new(dir)
        .sort_by_file_name()
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some(extension))
        .collect::<Vec<_>>();
    files.sort();
    match files.as_slice() {
        [file] => Ok(file.clone()),
        [] => bail!("no .{extension} artifact under {}", dir.display()),
        _ => bail!(
            "expected one .{extension} artifact under {}, got {files:?}",
            dir.display()
        ),
    }
}

fn file_len(path: &Path) -> Result<usize> {
    usize::try_from(
        fs::metadata(path)
            .with_context(|| format!("stat {}", path.display()))?
            .len(),
    )
    .context("artifact length does not fit usize")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_use_real_leptos_i18n_syntax() {
        assert_eq!(
            placeholder_names("Hello {{ name }}, {{ count }}").unwrap(),
            BTreeSet::from(["count".to_owned(), "name".to_owned()])
        );
        assert!(placeholder_names("Hello {name}").is_err());
        assert!(placeholder_names("Hello {{ 9name }}").is_err());
    }

    #[test]
    fn icon_variant_mapping_matches_build_script_contract() {
        assert_eq!(icon_variant("arrow-up-right"), "ArrowUpRight");
        assert_eq!(icon_variant("x"), "X");
    }

    #[test]
    fn icon_mapping_fixture_rejects_invalid_contract_data() {
        let source = include_str!("../../../../fixtures/ui/icon-mappings.json");
        assert_eq!(parse_icon_mappings(source).unwrap().len(), 47);
        let mut value: serde_json::Value = serde_json::from_str(source).unwrap();
        value["mappings"]["IconArrowDown"] = serde_json::Value::from("");
        assert!(parse_icon_mappings(&value.to_string()).is_err());
        value["mappings"]["IconArrowDown"] = serde_json::Value::from("arrow-down");
        value["source_zip_sha256"] = serde_json::Value::from("bad");
        assert!(parse_icon_mappings(&value.to_string()).is_err());
    }

    #[test]
    fn compiled_css_class_parser_unescapes_tailwind_selectors() {
        let classes =
            compiled_css_classes(".ob-card{display:block}.md\\:grid{display:grid}").unwrap();
        assert!(classes.contains("ob-card"));
        assert!(classes.contains("md:grid"));
    }
}
