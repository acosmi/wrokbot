//! Pinned GUI build-tool fetch and verification.

use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use flate2::read::GzDecoder;
use regex::Regex;
use sha2::{Digest as _, Sha256};

pub(crate) fn run(root: &Path, args: &[String]) -> Result<()> {
    match args {
        [command] if command == "fetch" => fetch(root),
        [command] if command == "verify" => verify(root),
        _ => bail!("usage: cargo xtask tools fetch|verify"),
    }
}

fn fetch(root: &Path) -> Result<()> {
    let pins = pins(root)?;
    let platform = current_platform()?;
    let tools_dir = root.join("target/tools");
    let bin_dir = tools_dir.join("bin");
    let lib_dir = tools_dir.join("lib");
    let downloads = tools_dir.join("downloads");
    fs::create_dir_all(&bin_dir)?;
    fs::create_dir_all(&lib_dir)?;
    fs::create_dir_all(&downloads)?;

    let tailwind = tool(&pins, "tailwindcss")?;
    let tailwind_artifact = artifact(tailwind, platform)?;
    let tailwind_download = fetch_artifact(&downloads, tailwind_artifact)?;
    install_file(&tailwind_download, &bin_dir.join(executable("tailwindcss")))?;

    let wasm_opt = tool(&pins, "wasm-opt")?;
    let wasm_opt_artifact = artifact(wasm_opt, platform)?;
    let wasm_opt_archive = fetch_artifact(&downloads, wasm_opt_artifact)?;
    let member = if cfg!(target_os = "windows") {
        tool_table(wasm_opt, "unpack")?
            .get("expected_member_windows")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| anyhow!("wasm-opt.unpack.expected_member_windows missing"))?
    } else {
        tool_table(wasm_opt, "unpack")?
            .get("expected_member")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| anyhow!("wasm-opt.unpack.expected_member missing"))?
    };
    let wasm_opt_bytes = archive_member(&wasm_opt_archive, member)?;
    install_bytes(&wasm_opt_bytes, &bin_dir.join(executable("wasm-opt")))?;
    if cfg!(target_os = "macos") {
        let library_member = string(tool_table(wasm_opt, "unpack")?, "expected_library_macos")?;
        let library = archive_member(&wasm_opt_archive, library_member)?;
        install_data_bytes(&library, &lib_dir.join("libbinaryen.dylib"))?;
    }

    let trunk = tool(&pins, "trunk")?;
    cargo_install(
        root,
        &tools_dir,
        string(trunk, "crate")?,
        string(trunk, "version")?,
        "trunk",
    )?;

    let bindgen_version = locked_wasm_bindgen_version(root)?;
    cargo_install(
        root,
        &tools_dir,
        "wasm-bindgen-cli",
        &bindgen_version,
        "wasm-bindgen",
    )?;

    println!(
        "tools fetch: installed current platform `{platform}` into {}",
        bin_dir.display()
    );
    verify(root)
}

fn verify(root: &Path) -> Result<()> {
    let pins = pins(root)?;
    let platform = current_platform()?;
    let tools_dir = root.join("target/tools");
    let bin_dir = tools_dir.join("bin");
    let lib_dir = tools_dir.join("lib");
    let downloads = tools_dir.join("downloads");

    let tailwind = tool(&pins, "tailwindcss")?;
    let tailwind_artifact = artifact(tailwind, platform)?;
    verify_sha(
        &bin_dir.join(executable("tailwindcss")),
        string(tailwind_artifact, "sha256")?,
    )?;
    verify_version(&bin_dir.join(executable("tailwindcss")), tailwind)?;

    let wasm_opt = tool(&pins, "wasm-opt")?;
    let wasm_opt_artifact = artifact(wasm_opt, platform)?;
    let archive = downloads.join(string(wasm_opt_artifact, "asset")?);
    verify_sha(&archive, string(wasm_opt_artifact, "sha256")?)?;
    let member = if cfg!(target_os = "windows") {
        string(tool_table(wasm_opt, "unpack")?, "expected_member_windows")?
    } else {
        string(tool_table(wasm_opt, "unpack")?, "expected_member")?
    };
    let expected_wasm_opt = archive_member(&archive, member)?;
    let installed_wasm_opt = fs::read(bin_dir.join(executable("wasm-opt")))?;
    if expected_wasm_opt != installed_wasm_opt {
        bail!("installed wasm-opt differs from the checksum-verified archive member");
    }
    if cfg!(target_os = "macos") {
        let library_member = string(tool_table(wasm_opt, "unpack")?, "expected_library_macos")?;
        let expected_library = archive_member(&archive, library_member)?;
        let installed_library = fs::read(lib_dir.join("libbinaryen.dylib"))?;
        if expected_library != installed_library {
            bail!("installed libbinaryen.dylib differs from the checksum-verified archive member");
        }
    }
    verify_version(&bin_dir.join(executable("wasm-opt")), wasm_opt)?;

    let trunk = tool(&pins, "trunk")?;
    verify_version(&bin_dir.join(executable("trunk")), trunk)?;

    let bindgen = tool(&pins, "wasm-bindgen-cli")?;
    let locked = locked_wasm_bindgen_version(root)?;
    let pinned = string(bindgen, "version")?;
    if pinned != locked {
        bail!("wasm-bindgen-cli pin `{pinned}` != Cargo.lock wasm-bindgen `{locked}`");
    }
    verify_version(&bin_dir.join(executable("wasm-bindgen")), bindgen)?;

    println!(
        "tools verify: ok ({platform}; tailwind {}, trunk {}, wasm-opt {}, wasm-bindgen {})",
        string(tailwind, "version")?,
        string(trunk, "version")?,
        string(wasm_opt, "version")?,
        locked
    );
    Ok(())
}

fn pins(root: &Path) -> Result<toml::Value> {
    let path = root.join("tools/pins.toml");
    toml::from_str(&fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?)
        .context("parse tools/pins.toml")
}

fn tool<'a>(pins: &'a toml::Value, id: &str) -> Result<&'a toml::Table> {
    pins.get("tools")
        .and_then(|tools| tools.get(id))
        .and_then(toml::Value::as_table)
        .ok_or_else(|| anyhow!("tools.pins missing tools.{id}"))
}

fn tool_table<'a>(tool: &'a toml::Table, key: &str) -> Result<&'a toml::Table> {
    tool.get(key)
        .and_then(toml::Value::as_table)
        .ok_or_else(|| anyhow!("tool table `{key}` missing"))
}

fn string<'a>(table: &'a toml::Table, key: &str) -> Result<&'a str> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .ok_or_else(|| anyhow!("tool string `{key}` missing"))
}

fn artifact<'a>(tool: &'a toml::Table, platform: &str) -> Result<&'a toml::Table> {
    tool.get("artifacts")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| anyhow!("download tool has no artifacts"))?
        .iter()
        .filter_map(toml::Value::as_table)
        .find(|entry| entry.get("platform").and_then(toml::Value::as_str) == Some(platform))
        .ok_or_else(|| anyhow!("tool has no artifact for `{platform}`"))
}

fn fetch_artifact(downloads: &Path, artifact: &toml::Table) -> Result<PathBuf> {
    let asset = string(artifact, "asset")?;
    let url = string(artifact, "url")?;
    let expected = string(artifact, "sha256")?;
    if !url.starts_with("https://github.com/") {
        bail!("tool artifact URL is not pinned GitHub HTTPS: {url}");
    }
    let destination = downloads.join(asset);
    if destination.is_file() && verify_sha(&destination, expected).is_ok() {
        println!(
            "tools fetch: reuse checksum-verified {}",
            destination.display()
        );
        return Ok(destination);
    }
    let partial = downloads.join(format!("{asset}.part"));
    if partial.exists() {
        fs::remove_file(&partial)?;
    }
    println!("tools fetch: download {url}");
    if let Some(size) = artifact.get("size_bytes").and_then(toml::Value::as_integer) {
        let size = u64::try_from(size).context("negative artifact size")?;
        if size >= 16 * 1024 * 1024 {
            download_parallel(url, &partial, size)?;
        } else {
            download_single(url, &partial)?;
        }
    } else {
        download_single(url, &partial)?;
    }
    verify_sha(&partial, expected)?;
    if destination.exists() {
        fs::remove_file(&destination)?;
    }
    fs::rename(&partial, &destination)?;
    Ok(destination)
}

fn download_single(url: &str, destination: &Path) -> Result<()> {
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
        .context("start curl")?;
    if !status.success() {
        bail!("curl failed for {url} with {status}");
    }
    Ok(())
}

fn download_parallel(url: &str, destination: &Path, size: u64) -> Result<()> {
    const PARTS: u64 = 8;
    let chunk = size.div_ceil(PARTS);
    let mut handles = Vec::new();
    let mut paths = Vec::new();
    for index in 0..PARTS {
        let start = index * chunk;
        if start >= size {
            break;
        }
        let end = (start + chunk - 1).min(size - 1);
        let part = destination.with_extension(format!("range-{index}"));
        paths.push((part.clone(), end - start + 1));
        let url = url.to_owned();
        handles.push(std::thread::spawn(move || -> Result<()> {
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
                    "--range",
                    &format!("{start}-{end}"),
                    "--output",
                ])
                .arg(&part)
                .arg(&url)
                .status()
                .with_context(|| format!("start range {start}-{end}"))?;
            if !status.success() {
                bail!("range {start}-{end} failed with {status}");
            }
            Ok(())
        }));
    }
    for handle in handles {
        handle
            .join()
            .map_err(|_| anyhow!("range download worker panicked"))??;
    }

    let mut combined = fs::File::create(destination)?;
    let mut total = 0_u64;
    for (part, expected) in &paths {
        let actual = fs::metadata(part)?.len();
        if actual != *expected {
            bail!(
                "range {} length {actual}, expected {expected}",
                part.display()
            );
        }
        let mut source = fs::File::open(part)?;
        total += std::io::copy(&mut source, &mut combined)?;
    }
    combined.flush()?;
    if total != size {
        bail!("combined artifact length {total}, expected {size}");
    }
    for (part, _) in paths {
        fs::remove_file(part)?;
    }
    Ok(())
}

fn cargo_install(
    root: &Path,
    install_root: &Path,
    package: &str,
    version: &str,
    binary: &str,
) -> Result<()> {
    let destination = install_root.join("bin").join(executable(binary));
    if destination.is_file() && binary_version_contains(&destination, version).unwrap_or(false) {
        println!("tools fetch: reuse {binary} {version}");
        return Ok(());
    }
    println!("tools fetch: cargo install {package} {version}");
    let status = Command::new("cargo")
        .args(["install", "--locked", "--root"])
        .arg(install_root)
        .args(["--version", version, "--force", package])
        .current_dir(root)
        .env_remove("CARGO_TARGET_DIR")
        .status()
        .with_context(|| format!("start cargo install {package}"))?;
    if !status.success() {
        bail!("cargo install {package} {version} failed with {status}");
    }
    if !destination.is_file() {
        bail!("cargo install did not create {}", destination.display());
    }
    Ok(())
}

fn verify_version(binary: &Path, tool: &toml::Table) -> Result<()> {
    if !binary.is_file() {
        bail!("tool binary missing: {}", binary.display());
    }
    let verify = tool_table(tool, "verify")?;
    let args = verify
        .get("args")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| anyhow!("verify.args missing"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| anyhow!("verify arg is not string"))
        })
        .collect::<Result<Vec<_>>>()?;
    let expected_exit = verify
        .get("expect_exit_code")
        .and_then(toml::Value::as_integer)
        .unwrap_or(0);
    let output = Command::new(binary)
        .args(args)
        .output()
        .with_context(|| format!("run {} version verification", binary.display()))?;
    if i64::from(output.status.code().unwrap_or(-1)) != expected_exit {
        bail!(
            "{} version command exit {:?}, expected {expected_exit}",
            binary.display(),
            output.status.code()
        );
    }
    let stream = string(verify, "stream")?;
    let bytes = match stream {
        "stdout" => output.stdout,
        "stderr" => output.stderr,
        _ => bail!("verify.stream must be stdout or stderr"),
    };
    let rendered = String::from_utf8(bytes).context("tool version stream is not UTF-8")?;
    let ansi = Regex::new(r"\x1b\[[0-9;]*m")?;
    let rendered = ansi.replace_all(&rendered, "");
    let expected = string(verify, "expect_regex")?;
    if expected.is_empty() || !Regex::new(expected)?.is_match(&rendered) {
        bail!(
            "{} version output did not match /{expected}/: {:?}",
            binary.display(),
            rendered.chars().take(240).collect::<String>()
        );
    }
    Ok(())
}

fn binary_version_contains(binary: &Path, version: &str) -> Result<bool> {
    let output = Command::new(binary).arg("--version").output()?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(output.status.success() && text.contains(version))
}

fn verify_sha(path: &Path, expected: &str) -> Result<()> {
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid pinned sha256 `{expected}`");
    }
    let actual = sha256(path)?;
    if actual != expected {
        bail!(
            "sha256 mismatch for {}: {actual} != {expected}",
            path.display()
        );
    }
    Ok(())
}

fn sha256(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn archive_member(path: &Path, expected_member: &str) -> Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut archive = tar::Archive::new(GzDecoder::new(file));
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.path()?.as_ref() == Path::new(expected_member) {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            if bytes.is_empty() {
                bail!("archive member `{expected_member}` is empty");
            }
            return Ok(bytes);
        }
    }
    bail!("archive {} lacks `{expected_member}`", path.display())
}

fn install_file(source: &Path, destination: &Path) -> Result<()> {
    install_bytes(&fs::read(source)?, destination)
}

fn install_bytes(bytes: &[u8], destination: &Path) -> Result<()> {
    install_bytes_with_mode(bytes, destination, true)
}

fn install_data_bytes(bytes: &[u8], destination: &Path) -> Result<()> {
    install_bytes_with_mode(bytes, destination, false)
}

fn install_bytes_with_mode(bytes: &[u8], destination: &Path, executable: bool) -> Result<()> {
    let partial = destination.with_extension("part");
    if partial.exists() {
        fs::remove_file(&partial)?;
    }
    fs::write(&partial, bytes)?;
    if executable {
        make_executable(&partial)?;
    }
    if destination.exists() {
        fs::remove_file(destination)?;
    }
    fs::rename(partial, destination)?;
    Ok(())
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

fn locked_wasm_bindgen_version(root: &Path) -> Result<String> {
    let lock: toml::Value = toml::from_str(&fs::read_to_string(root.join("Cargo.lock"))?)?;
    let versions = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| anyhow!("Cargo.lock has no package array"))?
        .iter()
        .filter_map(toml::Value::as_table)
        .filter(|package| package.get("name").and_then(toml::Value::as_str) == Some("wasm-bindgen"))
        .filter_map(|package| package.get("version").and_then(toml::Value::as_str))
        .collect::<Vec<_>>();
    match versions.as_slice() {
        [version] => Ok((*version).to_owned()),
        _ => bail!("Cargo.lock must contain exactly one wasm-bindgen package, got {versions:?}"),
    }
}

fn current_platform() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("linux-x64"),
        ("linux", "aarch64") => Ok("linux-arm64"),
        ("macos", "aarch64") => Ok("macos-arm64"),
        ("macos", "x86_64") => Ok("macos-x64"),
        ("windows", "x86_64") => Ok("windows-x64"),
        (os, arch) => bail!("unsupported GUI tool platform: {os}-{arch}"),
    }
}

fn executable(name: &str) -> String {
    if cfg!(target_os = "windows") {
        format!("{name}.exe")
    } else {
        name.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_contains_the_single_bindgen_version_used_by_the_cli() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap();
        assert_eq!(locked_wasm_bindgen_version(root).unwrap(), "0.2.127");
    }
}
