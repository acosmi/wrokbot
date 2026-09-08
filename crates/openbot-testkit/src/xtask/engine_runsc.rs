//! Ubuntu 24.04 x86_64 runsc + real Electron P1 spike driver (R121).

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const SPIKE_TIMEOUT: Duration = Duration::from_secs(90);
const PROBE_SCHEMA: &str = "openbot-runsc-engine-spike-v1";

pub(crate) fn run(
    root: &Path,
    archive: &Path,
    expected_sha256: &str,
    expected_version: &str,
    rootfs: &Path,
) -> Result<()> {
    require_ubuntu_host()?;
    validate_release_inputs(archive, expected_sha256, expected_version, rootfs)?;
    verify_sha256(archive, expected_sha256)?;

    let output_root = root.join(format!("target/runsc-spike/{expected_version}"));
    let runtime_dir = output_root.join("runtime");
    replace_directory(&runtime_dir)?;
    inspect_tar_paths(archive)?;
    let status = Command::new("/bin/tar")
        .args(["-xjf"])
        .arg(archive)
        .args(["-C"])
        .arg(&runtime_dir)
        .status()
        .context("extract verified gVisor release tarball")?;
    if !status.success() {
        bail!("runsc spike: gVisor tar extraction failed with {status}");
    }
    let runsc = runtime_dir.join("runsc");
    let sidecars = [runtime_dir.join("gvisor-bin"), runtime_dir.join("gvisor")]
        .into_iter()
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    if !runsc.is_file() || sidecars.len() != 1 || fs::read_dir(&sidecars[0])?.next().is_none() {
        bail!(
            "runsc spike: release must contain top-level runsc and exactly one nonempty sidecar directory"
        );
    }
    verify_runsc_version(&runsc, expected_version)?;

    build_probe(root)?;
    crate::engine_bundle::verify_if_required(root)?;
    let probe = root.join("target/release/examples/engine-runsc-probe");
    let engine = linux_engine_bundle(root)?;
    let manifest_digest = sha256(&engine.join("manifest.json"))?;
    if !probe.is_file() || !engine.is_dir() {
        bail!("runsc spike: build probe and Linux engine bundle before launch");
    }

    let payload = output_root.join("payload/bin");
    replace_directory(&payload)?;
    fs::copy(&probe, payload.join("engine-runsc-probe"))?;

    let oci = output_root.join("oci");
    replace_directory(&oci)?;
    let canonical_rootfs = rootfs.canonicalize()?;
    let canonical_probe = payload.canonicalize()?;
    let canonical_engine = engine.canonicalize()?;
    let xvfb_path = contained_rootfs_path(&canonical_rootfs, Path::new("usr/bin/Xvfb"))?;
    let xvfb_sha256 = sha256(&xvfb_path)?;
    let xvfb_package_version = dpkg_package_version(&canonical_rootfs, "xvfb")?;
    let config = oci_config(
        &canonical_rootfs,
        &canonical_probe,
        &canonical_engine,
        &manifest_digest,
        &xvfb_sha256,
    )?;
    fs::write(oci.join("config.json"), serde_json::to_vec_pretty(&config)?)?;

    let state = output_root.join("state");
    replace_directory(&state)?;
    let container_id = format!("openbot-p1-{}", std::process::id());
    let stdout_path = output_root.join("runsc.stdout");
    let stderr_path = output_root.join("runsc.stderr");
    let stdout_file = File::create(&stdout_path)?;
    let stderr_file = File::create(&stderr_path)?;
    let mut child = Command::new(&runsc)
        .arg(format!("--root={}", state.display()))
        .args([
            "--platform=systrap",
            "--network=none",
            "--host-uds=none",
            "--host-fifo=none",
            "--gvisor-marker-file=true",
            "--sidecar-release-enforcement-policy=ALWAYS",
            "--sidecar-usage-policy=STRICT",
            "run",
        ])
        .arg(format!("--bundle={}", oci.display()))
        .arg(&container_id)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .context("spawn pinned runsc")?;
    let status = wait_bounded(&mut child, SPIKE_TIMEOUT, &runsc, &state, &container_id);
    delete_container(&runsc, &state, &container_id);
    let status = status?;
    let stdout = fs::read(&stdout_path)?;
    let stderr = fs::read(&stderr_path)?;
    if !status.success() {
        bail!(
            "runsc spike failed: status={:?}; stdout={}; stderr={}",
            status.code(),
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        );
    }
    let report = stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .find(|value| value.get("schema").and_then(Value::as_str) == Some(PROBE_SCHEMA))
        .ok_or_else(|| anyhow!("runsc spike output did not contain the probe report"))?;
    verify_report(&report, &xvfb_sha256)?;

    println!(
        "runsc spike: PASS (version={expected_version}; archive_sha256={expected_sha256}; sidecars={}; roles=2; Seccomp=2; NoNewPrivs=1; layer1=yes; listeners=0; orphans=0)",
        sidecars[0]
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown")
    );
    println!("runsc pin candidate (apply only with this PASS evidence):");
    println!("version = \"{expected_version}\"");
    println!(
        "archive_sha256 = \"{}\"",
        expected_sha256.to_ascii_lowercase()
    );
    println!("xvfb_package_version = \"{xvfb_package_version}\"");
    println!("xvfb_sha256 = \"{xvfb_sha256}\"");
    Ok(())
}

fn require_ubuntu_host() -> Result<()> {
    if std::env::consts::OS != "linux" || std::env::consts::ARCH != "x86_64" {
        bail!("runsc spike requires a native Linux x86_64 host");
    }
    let release = parse_os_release(Path::new("/etc/os-release"))?;
    if release.get("ID").map(String::as_str) != Some("ubuntu")
        || release.get("VERSION_ID").map(String::as_str) != Some("24.04")
    {
        bail!("runsc spike requires Ubuntu 24.04 host");
    }
    let uid = Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .context("query effective uid")?;
    if !uid.status.success() || String::from_utf8_lossy(&uid.stdout).trim() != "0" {
        bail!(
            "runsc OCI spike requires root; build artifacts first, then run this command via sudo -E"
        );
    }
    Ok(())
}

fn validate_release_inputs(
    archive: &Path,
    expected_sha256: &str,
    expected_version: &str,
    rootfs: &Path,
) -> Result<()> {
    let version = Regex::new(r"^release-[0-9]{8}\.[0-9]+$").expect("fixed regex");
    if !archive.is_absolute()
        || !archive.is_file()
        || !rootfs.is_absolute()
        || !rootfs.is_dir()
        || expected_sha256.len() != 64
        || !expected_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !version.is_match(expected_version)
    {
        bail!("runsc spike arguments are not absolute/pinned/well formed");
    }
    let rootfs_release = parse_os_release(&rootfs.join("etc/os-release"))?;
    if rootfs_release.get("ID").map(String::as_str) != Some("ubuntu")
        || rootfs_release.get("VERSION_ID").map(String::as_str) != Some("24.04")
    {
        bail!("runsc spike rootfs must be Ubuntu 24.04");
    }
    for required in [
        "proc",
        "dev",
        "dev/pts",
        "dev/shm",
        "tmp",
        "sys",
        "opt/openbot/bin",
        "opt/openbot/engine",
    ] {
        if !contained_rootfs_path(rootfs, Path::new(required))?.is_dir() {
            bail!("runsc spike rootfs is missing mount destination `{required}`");
        }
    }
    if !contained_rootfs_path(rootfs, Path::new("usr/bin/Xvfb"))?.is_file() {
        bail!("runsc spike rootfs must contain /usr/bin/Xvfb");
    }
    Ok(())
}

fn parse_os_release(path: &Path) -> Result<BTreeMap<String, String>> {
    Ok(fs::read_to_string(path)?
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.trim_matches('"').to_owned()))
        .collect())
}

fn contained_rootfs_path(rootfs: &Path, relative: &Path) -> Result<PathBuf> {
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        bail!("rootfs relative path is unsafe: {}", relative.display());
    }
    let canonical_root = rootfs.canonicalize()?;
    let canonical = rootfs.join(relative).canonicalize()?;
    if !canonical.starts_with(&canonical_root) {
        bail!("rootfs entry escaped root: {}", relative.display());
    }
    Ok(canonical)
}

fn dpkg_package_version(rootfs: &Path, package: &str) -> Result<String> {
    let status = fs::read_to_string(rootfs.join("var/lib/dpkg/status"))?;
    for stanza in status.split("\n\n") {
        let fields = stanza
            .lines()
            .filter_map(|line| line.split_once(": "))
            .collect::<BTreeMap<_, _>>();
        if fields.get("Package") == Some(&package) && fields.get("Architecture") == Some(&"amd64") {
            let version = fields
                .get("Version")
                .filter(|value| !value.is_empty() && value.len() <= 128)
                .ok_or_else(|| anyhow!("rootfs package `{package}` has no bounded version"))?;
            return Ok((*version).to_owned());
        }
    }
    bail!("rootfs dpkg status has no amd64 `{package}` package")
}

fn inspect_tar_paths(archive: &Path) -> Result<()> {
    let output = Command::new("/bin/tar")
        .args(["-tjf"])
        .arg(archive)
        .output()
        .context("list verified gVisor tarball")?;
    if !output.status.success() {
        bail!("runsc spike: cannot list gVisor tarball");
    }
    for line in String::from_utf8(output.stdout)?.lines() {
        let path = Path::new(line.trim_end_matches('/'));
        if path.as_os_str().is_empty()
            || path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            bail!("runsc spike: unsafe tar path `{line}`");
        }
    }
    Ok(())
}

fn verify_runsc_version(runsc: &Path, expected_version: &str) -> Result<()> {
    let output = Command::new(runsc).arg("--version").output()?;
    let stdout = String::from_utf8(output.stdout)?;
    if !output.status.success()
        || !stdout
            .lines()
            .any(|line| line.trim() == format!("runsc version {expected_version}"))
    {
        bail!("runsc version output did not equal `{expected_version}`: {stdout:?}");
    }
    Ok(())
}

fn build_probe(root: &Path) -> Result<()> {
    let status = Command::new("cargo")
        .args([
            "build",
            "-p",
            "openbot-computer",
            "--example",
            "engine-runsc-probe",
            "--features",
            "runsc-spike",
            "--release",
            "--locked",
        ])
        .current_dir(root)
        .status()?;
    if !status.success() {
        bail!("runsc spike probe build failed with {status}");
    }
    Ok(())
}

fn linux_engine_bundle(root: &Path) -> Result<PathBuf> {
    let pins = crate::engine::pins(root)?;
    let electron = crate::engine::electron(&pins)?;
    let version = crate::engine::string(electron, "version")?;
    Ok(root.join(format!("target/engine/bundle/electron-{version}/linux-x64")))
}

fn oci_config(
    rootfs: &Path,
    probe: &Path,
    engine: &Path,
    manifest_digest: &str,
    xvfb_sha256: &str,
) -> Result<Value> {
    let utf8 = |path: &Path| {
        path.to_str()
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("OCI path is not UTF-8: {}", path.display()))
    };
    Ok(json!({
        "ociVersion": "1.1.0",
        "process": {
            "terminal": false,
            "user": { "uid": 0, "gid": 0 },
            "args": [
                "/opt/openbot/bin/engine-runsc-probe",
                "--bundle", "/opt/openbot/engine",
                "--manifest-sha256", manifest_digest,
                "--xvfb-sha256", xvfb_sha256
            ],
            "env": [
                "HOME=/tmp/openbot-home",
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "TMPDIR=/tmp"
            ],
            "cwd": "/",
            "capabilities": {
                "bounding": [], "effective": [], "inheritable": [], "permitted": [], "ambient": []
            },
            "rlimits": [{ "type": "RLIMIT_NOFILE", "hard": 4096, "soft": 4096 }],
            "noNewPrivileges": true
        },
        "root": { "path": utf8(rootfs)?, "readonly": true },
        "hostname": "openbot-p1-runsc",
        "mounts": [
            { "destination": "/proc", "type": "proc", "source": "proc" },
            { "destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"] },
            { "destination": "/dev/pts", "type": "devpts", "source": "devpts", "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"] },
            { "destination": "/dev/shm", "type": "tmpfs", "source": "shm", "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=256m"] },
            { "destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "mode=1777", "size=1g"] },
            { "destination": "/sys", "type": "sysfs", "source": "sysfs", "options": ["nosuid", "noexec", "nodev", "ro"] },
            { "destination": "/opt/openbot/bin", "type": "bind", "source": utf8(probe)?, "options": ["rbind", "ro", "nosuid", "nodev"] },
            { "destination": "/opt/openbot/engine", "type": "bind", "source": utf8(engine)?, "options": ["rbind", "ro", "nosuid", "nodev"] }
        ],
        "linux": {
            "devices": [
                { "path": "/dev/null", "type": "c", "major": 1, "minor": 3, "fileMode": 438, "uid": 0, "gid": 0 },
                { "path": "/dev/zero", "type": "c", "major": 1, "minor": 5, "fileMode": 438, "uid": 0, "gid": 0 },
                { "path": "/dev/full", "type": "c", "major": 1, "minor": 7, "fileMode": 438, "uid": 0, "gid": 0 },
                { "path": "/dev/random", "type": "c", "major": 1, "minor": 8, "fileMode": 438, "uid": 0, "gid": 0 },
                { "path": "/dev/urandom", "type": "c", "major": 1, "minor": 9, "fileMode": 438, "uid": 0, "gid": 0 }
            ],
            "resources": {
                "memory": { "limit": 6442450944_i64 },
                "pids": { "limit": 64 }
            },
            "namespaces": [
                { "type": "pid" }, { "type": "network" }, { "type": "ipc" },
                { "type": "uts" }, { "type": "mount" }
            ],
            "maskedPaths": [
                "/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys", "/proc/latency_stats",
                "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug", "/sys/firmware", "/sys/devices/virtual/powercap"
            ],
            "readonlyPaths": ["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"]
        }
    }))
}

fn wait_bounded(
    child: &mut Child,
    timeout: Duration,
    runsc: &Path,
    state: &Path,
    container_id: &str,
) -> Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = Command::new(runsc)
                .arg(format!("--root={}", state.display()))
                .args(["kill", container_id, "KILL"])
                .status();
            let _ = child.kill();
            let _ = child.wait();
            bail!("runsc spike exceeded {} seconds", timeout.as_secs());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn delete_container(runsc: &Path, state: &Path, container_id: &str) {
    let _ = Command::new(runsc)
        .arg(format!("--root={}", state.display()))
        .args(["delete", "--force", container_id])
        .status();
}

fn verify_report(report: &Value, expected_xvfb_sha256: &str) -> Result<()> {
    if report.get("schema").and_then(Value::as_str) != Some(PROBE_SCHEMA)
        || report.get("ubuntu").and_then(Value::as_str) != Some("24.04")
        || report.get("arch").and_then(Value::as_str) != Some("x86_64")
        || report.get("gvisor_marker").and_then(Value::as_bool) != Some(true)
        || report
            .get("xvfb_pid")
            .and_then(Value::as_u64)
            .is_none_or(|pid| pid == 0)
        || report.get("xvfb_sha256").and_then(Value::as_str) != Some(expected_xvfb_sha256)
        || report.get("xvfb_tcp_listeners").and_then(Value::as_u64) != Some(0)
        || report.get("final_extra_processes").and_then(Value::as_u64) != Some(0)
    {
        bail!("runsc probe host/rootfs attestation drift: {report}");
    }
    let roles = report
        .get("roles")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("runsc report roles missing"))?;
    if roles.len() != 2 {
        bail!("runsc report must contain exactly two roles");
    }
    let mut names = roles
        .iter()
        .filter_map(|role| role.get("role").and_then(Value::as_str))
        .collect::<Vec<_>>();
    names.sort_unstable();
    if names != ["browser", "component"] {
        bail!("runsc report role set drift: {names:?}");
    }
    for role in roles {
        let number = |key| role.get(key).and_then(Value::as_u64);
        let flag = |key| role.get(key).and_then(Value::as_bool);
        if number("seccomp") != Some(2)
            || number("main_seccomp") == Some(2)
            || number("main_seccomp").is_none()
            || number("no_new_privs") != Some(1)
            || number("frame_width") != Some(1280)
            || number("frame_height") != Some(800)
            || number("tcp_listeners") != Some(0)
            || number("orphan_processes") != Some(0)
            || number("profile_locks") != Some(0)
            || number("observed_processes").is_none_or(|count| count < 2)
            || !((flag("pid_namespace_isolated") == Some(true)
                && flag("network_namespace_isolated") == Some(true))
                || flag("user_namespace_isolated") == Some(true))
        {
            bail!("runsc role evidence failed closed: {role}");
        }
    }
    Ok(())
}

fn verify_sha256(path: &Path, expected: &str) -> Result<()> {
    let actual = sha256(path)?;
    if !actual.eq_ignore_ascii_case(expected) {
        bail!("runsc archive sha256 mismatch: expected {expected}, got {actual}");
    }
    Ok(())
}

fn sha256(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn replace_directory(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_dir_all(path)?;
    }
    fs::create_dir_all(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{PROBE_SCHEMA, oci_config, verify_report};
    use serde_json::json;
    use std::path::Path;

    #[test]
    fn oci_config_has_no_network_caps_or_mutable_host_mount() {
        let config = oci_config(
            Path::new("/rootfs"),
            Path::new("/probe"),
            Path::new("/engine"),
            &"ab".repeat(32),
            &"cd".repeat(32),
        )
        .expect("config");
        assert_eq!(config["process"]["noNewPrivileges"], true);
        assert_eq!(config["process"]["capabilities"]["bounding"], json!([]));
        assert_eq!(config["root"]["readonly"], true);
        assert_eq!(config["linux"]["devices"].as_array().unwrap().len(), 5);
        assert!(
            config["linux"]["namespaces"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["type"] == "network")
        );
        for mount in config["mounts"].as_array().unwrap() {
            if mount["type"] == "bind" {
                assert!(
                    mount["options"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|v| v == "ro")
                );
            }
        }
    }

    #[test]
    fn report_requires_both_roles_and_all_three_sandbox_dimensions() {
        let xvfb_sha256 = "cd".repeat(32);
        let role = |name: &str| {
            json!({
                "role": name,
                "main_seccomp": 0,
                "seccomp": 2,
                "no_new_privs": 1,
                "pid_namespace_isolated": true,
                "network_namespace_isolated": true,
                "user_namespace_isolated": false,
                "frame_width": 1280,
                "frame_height": 800,
                "observed_processes": 4,
                "tcp_listeners": 0,
                "orphan_processes": 0,
                "profile_locks": 0
            })
        };
        let report = json!({
            "schema": PROBE_SCHEMA,
            "ubuntu": "24.04",
            "arch": "x86_64",
            "gvisor_marker": true,
            "xvfb_pid": 2,
            "xvfb_sha256": xvfb_sha256,
            "xvfb_tcp_listeners": 0,
            "final_extra_processes": 0,
            "roles": [role("browser"), role("component")]
        });
        assert!(verify_report(&report, &"cd".repeat(32)).is_ok());
        let mut bad = report;
        bad["roles"][0]["seccomp"] = json!(0);
        assert!(verify_report(&bad, &"cd".repeat(32)).is_err());
    }
}
