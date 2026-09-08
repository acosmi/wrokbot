//! Static allowlist for the future clean-room Electron shim (R117).

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use sha2::{Digest as _, Sha256};

const SHIM_RELPATH: &str = "crates/openbot-desktop/engine-shim";
const PROTOCOL_HASH_RELPATH: &str = "crates/openbot-contracts/generated/engine-protocol.sha256";
const LOC_LIMIT: usize = 600;
const ALLOWED_FILES: [&str; 3] = ["generated/protocol.mjs", "main.mjs", "package.json"];
const PACKAGE_KEYS: [&str; 5] = ["main", "name", "private", "type", "version"];
const ELECTRON_IMPORTS: [&str; 5] = ["BrowserWindow", "app", "protocol", "session", "webContents"];
const NODE_IMPORTS: [&str; 3] = ["node:buffer", "node:net", "node:process"];
const FORBIDDEN_STRINGS: [&str; 22] = [
    "child_process",
    "node:fs",
    "node:http",
    "node:https",
    "node:dns",
    "executeJavaScript",
    "sendSync",
    "<webview",
    "autoUpdater",
    "--no-sandbox",
    "--disable-seccomp-filter-sandbox",
    "ELECTRON_RUN_AS_NODE",
    "remote-debugging-port",
    "require(",
    "import(",
    "process.env",
    "fetch(",
    "XMLHttpRequest",
    "WebSocket",
    "EventSource",
    "process.stderr",
    "console.",
];

pub(crate) fn run(root: &Path, args: &[String]) -> Result<()> {
    if !args.is_empty() {
        bail!("usage: cargo xtask electron-shim-check");
    }
    let report = check(root)?;
    if report.present {
        println!(
            "electron-shim-check: ok (files={}; non-empty LOC={}/{LOC_LIMIT}; package.json outside grok-bot=1; protocol hash=match)",
            report.files, report.nonempty_loc
        );
    } else {
        println!(
            "electron-shim-check: ok (P1 shim absent; allowlist rules active; package.json outside grok-bot=0; non-empty LOC=0/{LOC_LIMIT})"
        );
    }
    Ok(())
}

struct ShimReport {
    present: bool,
    files: usize,
    nonempty_loc: usize,
}

fn check(root: &Path) -> Result<ShimReport> {
    let shim = root.join(SHIM_RELPATH);
    let package_manifests = workspace_package_manifests(root)?;
    if !shim.exists() {
        if !package_manifests.is_empty() {
            bail!(
                "electron-shim-check: package.json outside grok-bot is forbidden before P1 shim: {:?}",
                package_manifests
            );
        }
        return Ok(ShimReport {
            present: false,
            files: 0,
            nonempty_loc: 0,
        });
    }
    if !shim.is_dir() {
        bail!("electron-shim-check: {SHIM_RELPATH} must be a directory");
    }

    let mut actual = BTreeSet::new();
    for entry in walkdir::WalkDir::new(&shim).sort_by_file_name() {
        let entry = entry.with_context(|| format!("walk {SHIM_RELPATH}"))?;
        if entry.file_type().is_file() {
            actual.insert(relative(&shim, entry.path()));
        }
    }
    let expected = ALLOWED_FILES
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if actual != expected {
        let missing = expected.difference(&actual).cloned().collect::<Vec<_>>();
        let extra = actual.difference(&expected).cloned().collect::<Vec<_>>();
        bail!("electron-shim-check: file allowlist mismatch; missing={missing:?}, extra={extra:?}");
    }
    let expected_manifest = format!("{SHIM_RELPATH}/package.json");
    if package_manifests != [expected_manifest.clone()].into_iter().collect() {
        bail!(
            "electron-shim-check: the only package.json outside grok-bot must be `{expected_manifest}`, got {package_manifests:?}"
        );
    }

    check_package_json(&shim.join("package.json"))?;
    let mut nonempty_loc = 0;
    for relative in ALLOWED_FILES {
        let path = shim.join(relative);
        let text = fs::read_to_string(&path)
            .with_context(|| format!("shim file must be UTF-8: {}", path.display()))?;
        nonempty_loc += text.lines().filter(|line| !line.trim().is_empty()).count();
        if relative.ends_with(".mjs") {
            check_javascript(relative, &text)?;
        }
    }
    if nonempty_loc > LOC_LIMIT {
        bail!("electron-shim-check: non-empty LOC {nonempty_loc} exceeds {LOC_LIMIT}");
    }
    check_protocol_hash(root, &shim.join("generated/protocol.mjs"))?;
    Ok(ShimReport {
        present: true,
        files: actual.len(),
        nonempty_loc,
    })
}

fn workspace_package_manifests(root: &Path) -> Result<BTreeSet<String>> {
    let mut manifests = BTreeSet::new();
    let walker = walkdir::WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| {
            if entry.depth() == 0 {
                return true;
            }
            let name = entry.file_name().to_string_lossy();
            !matches!(
                name.as_ref(),
                ".git" | "grok-bot" | "target" | "target-xtask"
            )
        });
    for entry in walker {
        let entry = entry.context("walk repository package manifests")?;
        if entry.file_type().is_file() && entry.file_name() == "package.json" {
            manifests.insert(relative(root, entry.path()));
        }
        if entry.file_type().is_file()
            && matches!(
                entry.file_name().to_string_lossy().as_ref(),
                "package-lock.json" | "npm-shrinkwrap.json" | "yarn.lock" | "pnpm-lock.yaml"
            )
        {
            bail!(
                "electron-shim-check: npm/Node lockfile outside grok-bot is forbidden: {}",
                relative(root, entry.path())
            );
        }
    }
    Ok(manifests)
}

fn check_package_json(path: &Path) -> Result<()> {
    let value: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?,
    )
    .context("parse engine-shim/package.json")?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("engine-shim/package.json must be an object"))?;
    let keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = PACKAGE_KEYS.into_iter().collect::<BTreeSet<_>>();
    if keys != expected {
        bail!("electron-shim-check: package.json keys must be exactly {expected:?}, got {keys:?}");
    }
    if object.get("main").and_then(serde_json::Value::as_str) != Some("main.mjs")
        || object.get("private").and_then(serde_json::Value::as_bool) != Some(true)
        || object.get("type").and_then(serde_json::Value::as_str) != Some("module")
    {
        bail!(
            "electron-shim-check: package.json must set main=main.mjs, private=true, type=module"
        );
    }
    for key in ["name", "version"] {
        if object
            .get(key)
            .and_then(serde_json::Value::as_str)
            .is_none_or(str::is_empty)
        {
            bail!("electron-shim-check: package.json `{key}` must be non-empty");
        }
    }
    Ok(())
}

fn check_javascript(relative: &str, text: &str) -> Result<()> {
    for forbidden in FORBIDDEN_STRINGS {
        if text.contains(forbidden) {
            bail!("electron-shim-check: `{relative}` contains forbidden string `{forbidden}`");
        }
    }
    for (pattern, label) in [
        (r"(?i)\bsandbox\s*:\s*false", "sandbox:false"),
        (r"(?i)\bwebviewTag\s*:\s*true", "webviewTag:true"),
        (r"(?i)\bnodeIntegration\s*:\s*true", "nodeIntegration:true"),
        (
            r"(?i)\bcontextIsolation\s*:\s*false",
            "contextIsolation:false",
        ),
        (r"(?i)\bwebSecurity\s*:\s*false", "webSecurity:false"),
        (r"(?m)(^|[^A-Za-z0-9_$])eval\s*\(", "eval"),
        (r"(?m)(^|[^A-Za-z0-9_$])require\s*\(", "require"),
        (r"(?m)(^|[^A-Za-z0-9_$])import\s*\(", "dynamic import"),
    ] {
        if Regex::new(pattern).expect("constant regex").is_match(text) {
            bail!("electron-shim-check: `{relative}` contains forbidden `{label}`");
        }
    }

    let import = Regex::new(r#"^\s*import\s+(.+?)\s+from\s+["']([^"']+)["']\s*;?\s*$"#)
        .expect("constant import regex");
    for line in text
        .lines()
        .filter(|line| line.trim_start().starts_with("import "))
    {
        let captures = import.captures(line).ok_or_else(|| {
            anyhow!(
                "electron-shim-check: `{relative}` has unsupported import syntax `{}`",
                line.trim()
            )
        })?;
        let bindings = captures.get(1).expect("binding capture").as_str();
        let specifier = captures.get(2).expect("specifier capture").as_str();
        match specifier {
            "electron" => check_electron_bindings(relative, bindings)?,
            specifier if NODE_IMPORTS.contains(&specifier) => {}
            "./generated/protocol.mjs" if relative == "main.mjs" => {}
            _ => bail!("electron-shim-check: `{relative}` imports forbidden module `{specifier}`"),
        }
    }
    if relative == "main.mjs" {
        for required in [
            "app.enableSandbox()",
            "nodeIntegration: false",
            "contextIsolation: true",
            "sandbox: true",
            "webSecurity: true",
            "webviewTag: false",
            "devTools: false",
            "setPermissionRequestHandler",
            "setPermissionCheckHandler",
            "setWindowOpenHandler",
            "webRequest.onBeforeRequest",
            "setProxy",
            "Page.startScreencast",
            "Page.stopScreencast",
            "Page.screencastFrameAck",
            "Page.screencastFrame",
            "Runtime.evaluate",
            "Input.dispatchMouseEvent",
            "Input.dispatchKeyEvent",
            "Input.insertText",
            "app.getAppMetrics()",
        ] {
            if !text.contains(required) {
                bail!(
                    "electron-shim-check: `main.mjs` lacks required security literal `{required}`"
                );
            }
        }
        check_cdp_methods(text)?;
    }
    Ok(())
}

fn check_cdp_methods(text: &str) -> Result<()> {
    let allowed = [
        "Input.dispatchKeyEvent",
        "Input.dispatchMouseEvent",
        "Input.insertText",
        "Page.enable",
        "Page.screencastFrameAck",
        "Page.startScreencast",
        "Page.stopScreencast",
        "Runtime.evaluate",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let literal = Regex::new(r#"sendCommand\(\s*"([^"]+)""#).expect("constant CDP regex");
    let methods = literal
        .captures_iter(text)
        .map(|capture| capture.get(1).expect("method capture").as_str())
        .collect::<Vec<_>>();
    if methods.len() != text.matches("sendCommand(").count() {
        bail!("electron-shim-check: every CDP sendCommand method must be a string literal");
    }
    let actual = methods.into_iter().collect::<BTreeSet<_>>();
    if actual != allowed {
        bail!(
            "electron-shim-check: CDP method allowlist drift: expected {allowed:?}, got {actual:?}"
        );
    }
    Ok(())
}

fn check_electron_bindings(relative: &str, bindings: &str) -> Result<()> {
    let trimmed = bindings.trim();
    let Some(inner) = trimmed
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
    else {
        bail!("electron-shim-check: `{relative}` must use named Electron imports only");
    };
    for binding in inner
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let original = binding.split_whitespace().next().unwrap_or_default();
        if !ELECTRON_IMPORTS.contains(&original) {
            bail!(
                "electron-shim-check: `{relative}` imports Electron API `{original}` outside {ELECTRON_IMPORTS:?}"
            );
        }
    }
    Ok(())
}

fn check_protocol_hash(root: &Path, protocol: &Path) -> Result<()> {
    let expected_module = crate::engine_protocol::render(root)?;
    let actual_module = fs::read(protocol)?;
    if actual_module != expected_module.as_bytes() {
        bail!(
            "electron-shim-check: generated/protocol.mjs differs from {DESCRIPTOR}; run `cargo xtask engine protocol`",
            DESCRIPTOR = crate::engine_protocol::DESCRIPTOR_RELPATH
        );
    }
    let expected_path = root.join(PROTOCOL_HASH_RELPATH);
    let expected = fs::read_to_string(&expected_path)
        .with_context(|| format!("read Rust-owned protocol hash {}", expected_path.display()))?;
    let expected = expected.trim();
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("electron-shim-check: {PROTOCOL_HASH_RELPATH} must contain one sha256");
    }
    let actual = format!("{:x}", Sha256::digest(&actual_module));
    if actual != expected {
        bail!(
            "electron-shim-check: generated/protocol.mjs sha256 {actual} != Rust-owned {expected}"
        );
    }
    Ok(())
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .expect("walked path remains under root")
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::{check_cdp_methods, check_electron_bindings, check_javascript};

    #[test]
    fn electron_and_node_import_domains_are_closed() {
        check_javascript(
            "fixture.mjs",
            "import { app, BrowserWindow, session } from 'electron';\nimport net from 'node:net';",
        )
        .expect("allowlisted imports");
        assert!(
            check_javascript("fixture.mjs", "import fs from 'node:fs';").is_err(),
            "forbidden Node built-in must fail"
        );
        assert!(
            check_electron_bindings("main.mjs", "{ app, autoUpdater }").is_err(),
            "forbidden Electron API must fail"
        );
    }

    #[test]
    fn dangerous_runtime_flags_and_eval_are_rejected() {
        for source in [
            "const options = { sandbox: false };",
            "const options = { webviewTag : true };",
            "eval(payload);",
            "contents.executeJavaScript(payload);",
        ] {
            assert!(check_javascript("fixture.mjs", source).is_err(), "{source}");
        }
    }

    #[test]
    fn cdp_methods_are_literal_and_exactly_allowlisted() {
        let source = [
            "Page.enable",
            "Runtime.evaluate",
            "Page.startScreencast",
            "Page.stopScreencast",
            "Page.screencastFrameAck",
            "Input.dispatchMouseEvent",
            "Input.dispatchKeyEvent",
            "Input.insertText",
        ]
        .map(|method| format!(r#"debugger.sendCommand("{method}")"#))
        .join("\n");
        check_cdp_methods(&source).expect("closed allowlist");
        assert!(check_cdp_methods("debugger.sendCommand(method)").is_err());
        assert!(check_cdp_methods("debugger.sendCommand(\"Network.enable\")").is_err());
    }
}
