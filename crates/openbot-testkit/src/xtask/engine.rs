//! Fetch and verify the pinned Electron engine release without npm (R117).

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use sha2::{Digest as _, Sha256};

const PINS_RELPATH: &str = "tools/engine-pins.toml";

pub(crate) fn run(root: &Path, args: &[String]) -> Result<()> {
    match args {
        [command] if command == "fetch" => fetch(root),
        [command] if command == "verify" => verify(root),
        [command, flag] if command == "verify" && flag == "--release" => {
            verify_raw(root)?;
            crate::engine_bundle::verify_release(root)
        }
        [command] if command == "protocol" => crate::engine_protocol::generate(root, false),
        [command, flag] if command == "protocol" && flag == "--check" => {
            crate::engine_protocol::generate(root, true)
        }
        [command] if command == "bundle" => crate::engine_bundle::bundle(root),
        [
            command,
            archive_flag,
            archive,
            sha_flag,
            sha,
            version_flag,
            version,
            rootfs_flag,
            rootfs,
        ] if command == "runsc-spike"
            && archive_flag == "--archive"
            && sha_flag == "--sha256"
            && version_flag == "--version"
            && rootfs_flag == "--rootfs" =>
        {
            crate::engine_runsc::run(root, Path::new(archive), sha, version, Path::new(rootfs))
        }
        _ => bail!(
            "usage: cargo xtask engine fetch|verify [--release]|protocol [--check]|bundle|runsc-spike --archive PATH --sha256 HEX --version release-YYYYMMDD.N --rootfs PATH"
        ),
    }
}

fn fetch(root: &Path) -> Result<()> {
    let pins = pins(root)?;
    let electron = electron(&pins)?;
    crosscheck_checksum_copy(root, electron)?;
    let platform = current_platform()?;
    let artifact = artifact(electron, platform)?;
    let archive = archive_path(root, artifact)?;
    let expected_sha = string(artifact, "sha256")?;
    let expected_size = positive_u64(artifact, "size_bytes")?;

    if archive.is_file()
        && verify_size(&archive, expected_size).is_ok()
        && verify_sha(&archive, expected_sha).is_ok()
    {
        println!(
            "engine fetch: reuse checksum-verified {}",
            archive.display()
        );
    } else {
        if let Some(parent) = archive.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        let partial = archive.with_extension("zip.part");
        if partial.exists() {
            fs::remove_file(&partial)
                .with_context(|| format!("remove stale {}", partial.display()))?;
        }
        let url = string(artifact, "url")?;
        if !url.starts_with("https://github.com/electron/electron/releases/download/") {
            bail!("engine artifact URL is outside the pinned Electron GitHub release path: {url}");
        }
        println!("engine fetch: download {url}");
        download(url, &partial)?;
        verify_size(&partial, expected_size)?;
        verify_sha(&partial, expected_sha)?;
        if archive.exists() {
            fs::remove_file(&archive).with_context(|| format!("replace {}", archive.display()))?;
        }
        fs::rename(&partial, &archive).with_context(|| format!("publish {}", archive.display()))?;
    }

    let install = install_dir(root, electron, platform)?;
    extract_zip(&archive, &install)?;
    println!(
        "engine fetch: installed electron {} for {platform} at {}",
        string(electron, "version")?,
        install.display()
    );
    verify_raw(root)
}

fn verify(root: &Path) -> Result<()> {
    verify_raw(root)?;
    crate::engine_bundle::verify_if_required(root)
}

fn verify_raw(root: &Path) -> Result<()> {
    let pins = pins(root)?;
    let electron = electron(&pins)?;
    crosscheck_checksum_copy(root, electron)?;
    let platform = current_platform()?;
    let artifact = artifact(electron, platform)?;
    let archive = archive_path(root, artifact)?;
    verify_size(&archive, positive_u64(artifact, "size_bytes")?)?;
    verify_sha(&archive, string(artifact, "sha256")?)?;

    let install = install_dir(root, electron, platform)?;
    let executable = electron_executable(&install)?;
    if !executable.is_file() {
        bail!(
            "engine verify: Electron executable is missing at {} (run `cargo xtask engine fetch`)",
            executable.display()
        );
    }
    let verify = table(electron, "verify")?;
    let args = string_array(verify, "args")?;
    let stdout_path = install.join(".openbot-version.stdout");
    let stderr_path = install.join(".openbot-version.stderr");
    let stdout =
        File::create(&stdout_path).with_context(|| format!("create {}", stdout_path.display()))?;
    let stderr =
        File::create(&stderr_path).with_context(|| format!("create {}", stderr_path.display()))?;
    let status = Command::new(&executable)
        .args(&args)
        .env_remove("ELECTRON_RUN_AS_NODE")
        .env_remove("NODE_OPTIONS")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .status()
        .with_context(|| format!("run {} {}", executable.display(), args.join(" ")))?;
    let stdout = fs::read_to_string(&stdout_path)
        .with_context(|| format!("read {}", stdout_path.display()))?;
    let stderr = fs::read_to_string(&stderr_path)
        .with_context(|| format!("read {}", stderr_path.display()))?;
    let _ = fs::remove_file(&stdout_path);
    let _ = fs::remove_file(&stderr_path);

    let expected_exit = integer(verify, "expect_exit_code")?;
    if i64::from(status.code().unwrap_or(-1)) != expected_exit {
        bail!(
            "engine verify: --version exit {:?}, expected {expected_exit}; stderr={:?}",
            status.code(),
            stderr.trim()
        );
    }
    let stream_name = string(verify, "stream")?;
    let stream = match stream_name {
        "stdout" => &stdout,
        "stderr" => &stderr,
        other => bail!("engine verify: unsupported verify.stream `{other}`"),
    };
    let expected = Regex::new(string(verify, "expect_regex")?)
        .context("compile engines.electron.verify.expect_regex")?;
    if !expected.is_match(stream) {
        bail!(
            "engine verify: {stream_name} {:?} does not match {}",
            stream,
            expected.as_str()
        );
    }
    println!(
        "engine verify: ok (electron {}; {platform}; sha256={}; --version={})",
        string(electron, "version")?,
        string(artifact, "sha256")?,
        stream.trim()
    );
    Ok(())
}

pub(crate) fn pins(root: &Path) -> Result<toml::Value> {
    let path = root.join(PINS_RELPATH);
    let value: toml::Value = toml::from_str(
        &fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?,
    )
    .context("parse tools/engine-pins.toml")?;
    if value.get("schema").and_then(toml::Value::as_str) != Some("engine-pins")
        || value
            .get("schema_version")
            .and_then(toml::Value::as_integer)
            != Some(1)
    {
        bail!("{PINS_RELPATH}: schema must be engine-pins v1");
    }
    Ok(value)
}

pub(crate) fn electron(pins: &toml::Value) -> Result<&toml::Table> {
    pins.get("engines")
        .and_then(|engines| engines.get("electron"))
        .and_then(toml::Value::as_table)
        .ok_or_else(|| anyhow!("{PINS_RELPATH}: engines.electron missing"))
}

pub(crate) fn artifact<'a>(electron: &'a toml::Table, platform: &str) -> Result<&'a toml::Table> {
    electron
        .get("artifacts")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| anyhow!("{PINS_RELPATH}: engines.electron.artifacts missing"))?
        .iter()
        .filter_map(toml::Value::as_table)
        .find(|artifact| artifact.get("platform").and_then(toml::Value::as_str) == Some(platform))
        .ok_or_else(|| anyhow!("{PINS_RELPATH}: no Electron artifact for `{platform}`"))
}

fn crosscheck_checksum_copy(root: &Path, electron: &toml::Table) -> Result<()> {
    let copy = root.join(string(electron, "checksums_manifest_copy")?);
    let text = fs::read_to_string(&copy)
        .with_context(|| format!("read checksum manifest copy {}", copy.display()))?;
    let checksums = text
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let sha256 = fields.next()?.to_owned();
            let asset = fields.next()?.trim_start_matches('*').to_owned();
            Some((asset, sha256))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let artifacts = electron
        .get("artifacts")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| anyhow!("{PINS_RELPATH}: artifacts missing"))?;
    if artifacts.len() != 5 {
        bail!("{PINS_RELPATH}: expected exactly five Electron artifacts");
    }
    for artifact in artifacts {
        let artifact = artifact
            .as_table()
            .ok_or_else(|| anyhow!("{PINS_RELPATH}: artifact is not a table"))?;
        let asset = string(artifact, "asset")?;
        let pinned = string(artifact, "sha256")?;
        if checksums.get(asset).map(String::as_str) != Some(pinned) {
            bail!(
                "engine verify: pin for `{asset}` does not match {}",
                copy.display()
            );
        }
    }
    Ok(())
}

pub(crate) fn archive_path(root: &Path, artifact: &toml::Table) -> Result<PathBuf> {
    Ok(root
        .join("target/engine/downloads")
        .join(string(artifact, "asset")?))
}

pub(crate) fn install_dir(root: &Path, electron: &toml::Table, platform: &str) -> Result<PathBuf> {
    Ok(root.join(format!(
        "target/engine/electron-{}/{platform}",
        string(electron, "version")?
    )))
}

pub(crate) fn electron_executable(install: &Path) -> Result<PathBuf> {
    let relative = if cfg!(target_os = "macos") {
        "Electron.app/Contents/MacOS/Electron"
    } else if cfg!(target_os = "windows") {
        "electron.exe"
    } else if cfg!(target_os = "linux") {
        "electron"
    } else {
        bail!("engine verify: unsupported operating system")
    };
    Ok(install.join(relative))
}

pub(crate) fn current_platform() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("macos-arm64"),
        ("macos", "x86_64") => Ok("macos-x64"),
        ("linux", "x86_64") => Ok("linux-x64"),
        ("linux", "aarch64") => Ok("linux-arm64"),
        ("windows", "x86_64") => Ok("windows-x64"),
        (os, arch) => bail!("engine: unsupported platform `{os}-{arch}`"),
    }
}

fn download(url: &str, destination: &Path) -> Result<()> {
    let status = Command::new("curl")
        .args([
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--retry",
            "3",
            "--retry-all-errors",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--output",
        ])
        .arg(destination)
        .arg(url)
        .status()
        .context("start curl for Electron release")?;
    if !status.success() {
        bail!("curl failed for {url} with {status}");
    }
    Ok(())
}

fn verify_size(path: &Path, expected: u64) -> Result<()> {
    let actual = fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .len();
    if actual != expected {
        bail!(
            "engine artifact size mismatch for {}: expected {expected}, got {actual}",
            path.display()
        );
    }
    Ok(())
}

pub(crate) fn verify_sha(path: &Path, expected: &str) -> Result<()> {
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid sha256 pin `{expected}`");
    }
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher).with_context(|| format!("hash {}", path.display()))?;
    let actual = format!("{:x}", hasher.finalize());
    if actual != expected {
        bail!(
            "engine artifact sha256 mismatch for {}: expected {expected}, got {actual}",
            path.display()
        );
    }
    Ok(())
}

fn extract_zip(archive: &Path, install: &Path) -> Result<()> {
    let parent = install
        .parent()
        .ok_or_else(|| anyhow!("engine install path has no parent"))?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let staging = parent.join(format!(
        ".{}-unpack-{}",
        install
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("electron"),
        std::process::id()
    ));
    if staging.exists() {
        fs::remove_dir_all(&staging)
            .with_context(|| format!("remove stale {}", staging.display()))?;
    }
    fs::create_dir_all(&staging).with_context(|| format!("create {}", staging.display()))?;

    let result = extract_zip_into(archive, &staging);
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }
    if install.exists() {
        fs::remove_dir_all(install).with_context(|| format!("replace {}", install.display()))?;
    }
    fs::rename(&staging, install).with_context(|| format!("publish {}", install.display()))?;
    Ok(())
}

fn extract_zip_into(archive: &Path, destination: &Path) -> Result<()> {
    let file = File::open(archive).with_context(|| format!("open {}", archive.display()))?;
    let mut zip = zip::ZipArchive::new(file).context("open Electron zip")?;
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index).context("read Electron zip entry")?;
        let enclosed = entry
            .enclosed_name()
            .ok_or_else(|| anyhow!("unsafe zip member `{}`", entry.name()))?
            .to_owned();
        let output = destination.join(&enclosed);
        if entry.is_dir() {
            fs::create_dir_all(&output)
                .with_context(|| format!("create zip directory {}", output.display()))?;
            continue;
        }
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create zip parent {}", parent.display()))?;
        }
        let mode = entry.unix_mode().unwrap_or(0o644);
        if mode & 0o170000 == 0o120000 {
            extract_symlink(&mut entry, destination, &enclosed, &output)?;
            continue;
        }
        let mut file = File::create(&output)
            .with_context(|| format!("create extracted file {}", output.display()))?;
        io::copy(&mut entry, &mut file).with_context(|| format!("extract {}", output.display()))?;
        set_mode(&output, mode)?;
    }
    Ok(())
}

fn extract_symlink<R: Read>(
    entry: &mut R,
    destination: &Path,
    enclosed: &Path,
    output: &Path,
) -> Result<()> {
    let mut target = String::new();
    entry
        .read_to_string(&mut target)
        .context("read zip symlink target")?;
    let target = Path::new(&target);
    if target.is_absolute() || !symlink_stays_inside(enclosed, target) {
        bail!(
            "unsafe zip symlink {} -> {}",
            enclosed.display(),
            target.display()
        );
    }
    #[cfg(unix)]
    {
        let _ = destination;
        std::os::unix::fs::symlink(target, output)
            .with_context(|| format!("create symlink {}", output.display()))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (destination, output);
        bail!("Electron archive contains a symlink on a platform without symlink extraction")
    }
}

fn symlink_stays_inside(enclosed: &Path, target: &Path) -> bool {
    let mut depth = enclosed
        .parent()
        .map_or(0, |parent| parent.components().count());
    for component in target.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(_) => depth += 1,
            Component::ParentDir if depth > 0 => depth -= 1,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    true
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777))
        .with_context(|| format!("set mode on {}", path.display()))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

pub(crate) fn string<'a>(table: &'a toml::Table, key: &str) -> Result<&'a str> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("{PINS_RELPATH}: non-empty string `{key}` missing"))
}

fn table<'a>(table: &'a toml::Table, key: &str) -> Result<&'a toml::Table> {
    table
        .get(key)
        .and_then(toml::Value::as_table)
        .ok_or_else(|| anyhow!("{PINS_RELPATH}: table `{key}` missing"))
}

fn integer(table: &toml::Table, key: &str) -> Result<i64> {
    table
        .get(key)
        .and_then(toml::Value::as_integer)
        .ok_or_else(|| anyhow!("{PINS_RELPATH}: integer `{key}` missing"))
}

pub(crate) fn positive_u64(table: &toml::Table, key: &str) -> Result<u64> {
    u64::try_from(integer(table, key)?).with_context(|| format!("{PINS_RELPATH}: `{key}` negative"))
}

fn string_array(table: &toml::Table, key: &str) -> Result<Vec<String>> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .ok_or_else(|| anyhow!("{PINS_RELPATH}: array `{key}` missing"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("{PINS_RELPATH}: `{key}` contains a non-string"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::symlink_stays_inside;
    use std::path::Path;

    #[test]
    fn zip_symlink_cannot_escape_staging_root() {
        assert!(symlink_stays_inside(
            Path::new("Electron.app/Versions/Current"),
            Path::new("A")
        ));
        assert!(symlink_stays_inside(
            Path::new("Electron.app/Resources"),
            Path::new("Versions/Current/Resources")
        ));
        assert!(!symlink_stays_inside(
            Path::new("Electron.app/link"),
            Path::new("../../outside")
        ));
    }
}
