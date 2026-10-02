//! Rust-only Electron bundle assembly: ASAR, rebrand, fuses, integrity and manifest (R117).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const MANIFEST_SCHEMA: &str = "openbot-engine-bundle";
const MANIFEST_VERSION: u64 = 2;
const MACOS_SIGNING_PROFILE: &str = "local-hardened-adhoc-fixture-v1";
const PRODUCT_NAME: &str = "Acosmi Engine Fixture";
const PRODUCT_SLUG: &str = "AcosmiEngine";
const BUNDLE_ID: &str = "com.acosmi.engine.fixture";
const ASAR_BLOCK_SIZE: usize = 4 * 1024 * 1024;
const CODESIGN_METADATA_LIMIT: usize = 64 * 1024;
const CODESIGN_ENTITLEMENTS_LIMIT: usize = 16 * 1024;
const FUSE_SENTINEL: &[u8] = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX";
const FUSE_VERSION: u8 = 1;
const FUSE_WIRE: &[u8; 9] = b"000011001";
const SHIM_FILES: [&str; 3] = ["generated/protocol.mjs", "main.mjs", "package.json"];

#[derive(Debug, Serialize, Deserialize)]
struct BundleManifest {
    schema: String,
    schema_version: u64,
    platform: String,
    arch: String,
    electron_version: String,
    release_epoch: u64,
    protocol_version: u64,
    product_name: String,
    bundle_id: String,
    executable: String,
    fuse_file: String,
    app_asar: String,
    asar_header_sha256: String,
    fuse_wire: String,
    signing_profile: String,
    files: BTreeMap<String, String>,
}

struct BundleLayout {
    root: PathBuf,
    executable: PathBuf,
    fuse_file: PathBuf,
    app_asar: PathBuf,
    app_bundle: Option<PathBuf>,
}

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct WindowsAsarIntegrity {
    file: String,
    alg: String,
    value: String,
}

pub(crate) fn bundle(root: &Path) -> Result<()> {
    crate::engine_protocol::generate(root, true)?;
    crate::electron_shim::run(root, &[])?;

    let pins = crate::engine::pins(root)?;
    let electron = crate::engine::electron(&pins)?;
    let platform = crate::engine::current_platform()?;
    let source = crate::engine::install_dir(root, electron, platform)?;
    if !source.is_dir() {
        bail!("engine bundle: raw engine is missing; run `cargo xtask engine fetch`");
    }
    let version = crate::engine::string(electron, "version")?;
    let release_epoch = crate::engine::positive_u64(electron, "release_epoch")?;
    let protocol_version = crate::engine::positive_u64(electron, "protocol_version")?;
    if release_epoch != 5 || protocol_version != 4 {
        bail!("engine bundle: engine pins release/protocol version drift from v4 contracts");
    }
    let parent = root.join(format!("target/engine/bundle/electron-{version}"));
    fs::create_dir_all(&parent)?;
    let destination = parent.join(platform);
    let staging = parent.join(format!(".{platform}-staging-{}", std::process::id()));
    if staging.exists() {
        fs::remove_dir_all(&staging)
            .with_context(|| format!("remove stale {}", staging.display()))?;
    }
    fs::create_dir_all(&staging)?;
    copy_tree(&source, &staging)?;

    let layout = rebrand(&staging, platform)?;
    let shim = root.join("crates/openbot-desktop/engine-shim");
    let asar = pack_asar(&shim, &layout.app_asar)?;
    remove_default_app(&layout)?;
    write_asar_integrity(&layout, &asar.header_sha256, platform)?;
    let fuse_count = write_fuses(&layout.fuse_file)?;
    if platform.starts_with("macos-") {
        codesign_adhoc(layout.app_bundle.as_ref().expect("macOS app bundle"))?;
    }

    let manifest = manifest(
        &layout,
        platform,
        version,
        release_epoch,
        protocol_version,
        &asar.header_sha256,
    )?;
    let manifest_path = layout.root.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    verify_layout(&layout.root, &manifest)?;

    if destination.exists() {
        fs::remove_dir_all(&destination)
            .with_context(|| format!("replace {}", destination.display()))?;
    }
    fs::rename(&staging, &destination)
        .with_context(|| format!("publish {}", destination.display()))?;
    println!(
        "engine bundle: ok ({}; app.asar={} bytes; header_sha256={}; fuse_sentinels={fuse_count}; release_epoch=5)",
        destination.display(),
        fs::metadata(destination.join(relative(&layout.root, &layout.app_asar)))?.len(),
        asar.header_sha256
    );
    Ok(())
}

pub(crate) fn verify_if_required(root: &Path) -> Result<()> {
    if !root.join("crates/openbot-desktop/engine-shim").is_dir() {
        return Ok(());
    }
    let pins = crate::engine::pins(root)?;
    let electron = crate::engine::electron(&pins)?;
    let platform = crate::engine::current_platform()?;
    let version = crate::engine::string(electron, "version")?;
    let bundle = root.join(format!(
        "target/engine/bundle/electron-{version}/{platform}"
    ));
    let manifest_path = bundle.join("manifest.json");
    let manifest: BundleManifest = serde_json::from_slice(
        &fs::read(&manifest_path)
            .with_context(|| format!("read {}; run engine bundle", manifest_path.display()))?,
    )
    .context("parse engine bundle manifest")?;
    verify_layout(&bundle, &manifest)?;
    println!(
        "engine bundle verify: local fixture ok, not release-qualified ({platform}; release_epoch={}; protocol={}; asar_header={})",
        manifest.release_epoch, manifest.protocol_version, manifest.asar_header_sha256
    );
    Ok(())
}

pub(crate) fn verify_release(root: &Path) -> Result<()> {
    verify_if_required(root)?;
    // Every currently accepted product identity and signing profile is explicitly a fixture.
    // A future release implementation must validate real identity/signing/provenance instead of
    // bypassing this with a CLI flag or treating a local ad-hoc signature as notarization.
    bail!(
        "engine release gate: current bundle is diagnostic-only; trusted release identity/signing and full gates are not satisfied"
    )
}

fn rebrand(root: &Path, platform: &str) -> Result<BundleLayout> {
    if platform.starts_with("macos-") {
        return rebrand_macos(root);
    }
    if platform.starts_with("linux-") {
        let old = root.join("electron");
        let executable = root.join("acosmi-engine-fixture");
        fs::rename(&old, &executable)?;
        return Ok(BundleLayout {
            root: root.to_path_buf(),
            executable,
            fuse_file: root.join("acosmi-engine-fixture"),
            app_asar: root.join("resources/app.asar"),
            app_bundle: None,
        });
    }
    if platform == "windows-x64" {
        let old = root.join("electron.exe");
        let executable = root.join("acosmi-engine-fixture.exe");
        fs::rename(&old, &executable)?;
        return Ok(BundleLayout {
            root: root.to_path_buf(),
            executable: executable.clone(),
            fuse_file: executable,
            app_asar: root.join("resources/app.asar"),
            app_bundle: None,
        });
    }
    bail!("engine bundle: unsupported platform `{platform}`")
}

fn rebrand_macos(root: &Path) -> Result<BundleLayout> {
    let old_app = root.join("Electron.app");
    let app = root.join(format!("{PRODUCT_SLUG}.app"));
    let old_executable = old_app.join("Contents/MacOS/Electron");
    let new_executable = old_app.join(format!("Contents/MacOS/{PRODUCT_SLUG}"));
    fs::rename(&old_executable, &new_executable)?;
    edit_plist(
        &old_app.join("Contents/Info.plist"),
        PRODUCT_NAME,
        PRODUCT_SLUG,
        BUNDLE_ID,
        true,
    )?;

    // Electron documents helper renaming as optional. P1 keeps the framework/helper internals at
    // their upstream names because their launch stubs are part of the signed external engine, while
    // the containing app, main executable and bundle identity are rebranded. Final helper display
    // branding belongs to G8 after the reviewed external identity exists.
    let icon = old_app.join("Contents/Resources/electron.icns");
    if icon.exists() {
        fs::remove_file(icon)?;
    }
    fs::rename(&old_app, &app)?;
    Ok(BundleLayout {
        root: root.to_path_buf(),
        executable: app.join(format!("Contents/MacOS/{PRODUCT_SLUG}")),
        fuse_file: app
            .join("Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework"),
        app_asar: app.join("Contents/Resources/app.asar"),
        app_bundle: Some(app),
    })
}

fn edit_plist(
    path: &Path,
    display_name: &str,
    executable: &str,
    identifier: &str,
    main: bool,
) -> Result<()> {
    let mut value =
        plist::Value::from_file(path).with_context(|| format!("read plist {}", path.display()))?;
    let dictionary = value
        .as_dictionary_mut()
        .ok_or_else(|| anyhow!("{} is not a plist dictionary", path.display()))?;
    dictionary.insert(
        "CFBundleDisplayName".to_owned(),
        plist::Value::String(display_name.to_owned()),
    );
    dictionary.insert(
        "CFBundleName".to_owned(),
        plist::Value::String(executable.to_owned()),
    );
    dictionary.insert(
        "CFBundleExecutable".to_owned(),
        plist::Value::String(executable.to_owned()),
    );
    dictionary.insert(
        "CFBundleIdentifier".to_owned(),
        plist::Value::String(identifier.to_owned()),
    );
    dictionary.remove("CFBundleIconFile");
    dictionary.remove("CFBundleIconName");
    if main {
        dictionary.remove("ElectronAsarIntegrity");
    }
    value
        .to_file_xml(path)
        .with_context(|| format!("write plist {}", path.display()))
}

fn write_asar_integrity(layout: &BundleLayout, hash: &str, platform: &str) -> Result<()> {
    if platform.starts_with("macos-") {
        let plist_path = layout
            .app_bundle
            .as_ref()
            .expect("macOS app")
            .join("Contents/Info.plist");
        let mut value = plist::Value::from_file(&plist_path)?;
        let dictionary = value
            .as_dictionary_mut()
            .ok_or_else(|| anyhow!("main Info.plist is not a dictionary"))?;
        let mut integrity = plist::Dictionary::new();
        let mut payload = plist::Dictionary::new();
        payload.insert(
            "algorithm".to_owned(),
            plist::Value::String("SHA256".to_owned()),
        );
        payload.insert("hash".to_owned(), plist::Value::String(hash.to_owned()));
        integrity.insert(
            "Resources/app.asar".to_owned(),
            plist::Value::Dictionary(payload),
        );
        dictionary.insert(
            "ElectronAsarIntegrity".to_owned(),
            plist::Value::Dictionary(integrity),
        );
        value.to_file_xml(plist_path)?;
        return Ok(());
    }
    if platform.starts_with("linux-") {
        return Ok(());
    }
    if platform == "windows-x64" {
        #[cfg(windows)]
        {
            let payload = windows_integrity_payload(hash)?;
            openbot_windows_sandbox::replace_pe_resource(
                &layout.executable,
                "Integrity",
                "ElectronAsar",
                &payload,
            )?;
            let actual = openbot_windows_sandbox::read_pe_resource(
                &layout.executable,
                "Integrity",
                "ElectronAsar",
            )?;
            if actual != payload {
                bail!("Windows ElectronAsar resource differs immediately after write");
            }
            return Ok(());
        }
        #[cfg(not(windows))]
        bail!("Windows PE resources may only be assembled on a Windows host");
    }
    bail!("ASAR integrity metadata is not implemented for `{platform}`")
}

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn windows_integrity_payload(hash: &str) -> Result<Vec<u8>> {
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("Windows ElectronAsar header hash is not SHA-256 hex");
    }
    Ok(serde_json::to_vec(&[WindowsAsarIntegrity {
        file: r"resources\app.asar".to_owned(),
        alg: "sha256".to_owned(),
        value: hash.to_ascii_lowercase(),
    }])?)
}

fn remove_default_app(layout: &BundleLayout) -> Result<()> {
    let resources = layout
        .app_asar
        .parent()
        .ok_or_else(|| anyhow!("app.asar has no resources parent"))?;
    let default_app = resources.join("default_app.asar");
    if default_app.exists() {
        fs::remove_file(default_app)?;
    }
    let unpacked_app = resources.join("app");
    if unpacked_app.exists() {
        fs::remove_dir_all(unpacked_app)?;
    }
    Ok(())
}

struct PackedAsar {
    header_sha256: String,
}

#[derive(Serialize, Deserialize)]
struct AsarDirectory {
    files: BTreeMap<String, AsarEntry>,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum AsarEntry {
    Directory(AsarDirectory),
    File(AsarFile),
}

#[derive(Serialize, Deserialize)]
struct AsarFile {
    offset: String,
    size: usize,
    integrity: AsarIntegrity,
}

#[derive(Serialize, Deserialize)]
struct AsarIntegrity {
    algorithm: String,
    hash: String,
    #[serde(rename = "blockSize")]
    block_size: usize,
    blocks: Vec<String>,
}

fn pack_asar(source: &Path, destination: &Path) -> Result<PackedAsar> {
    let mut root = AsarDirectory {
        files: BTreeMap::new(),
    };
    let mut payloads = Vec::new();
    let mut offset = 0_u64;
    for relative in SHIM_FILES {
        let bytes = fs::read(source.join(relative))?;
        let record = AsarFile {
            offset: offset.to_string(),
            size: bytes.len(),
            integrity: integrity(&bytes),
        };
        insert_asar(&mut root, &relative.split('/').collect::<Vec<_>>(), record)?;
        offset = offset
            .checked_add(u64::try_from(bytes.len())?)
            .ok_or_else(|| anyhow!("ASAR offset overflow"))?;
        payloads.push(bytes);
    }
    let json = serde_json::to_vec(&root)?;
    let header = pickle_string(&json)?;
    let size = pickle_u32(u32::try_from(header.len())?);
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut output = File::create(destination)?;
    output.write_all(&size)?;
    output.write_all(&header)?;
    for payload in payloads {
        output.write_all(&payload)?;
    }
    output.sync_all()?;
    Ok(PackedAsar {
        header_sha256: format!("{:x}", Sha256::digest(&json)),
    })
}

fn insert_asar(directory: &mut AsarDirectory, path: &[&str], file: AsarFile) -> Result<()> {
    let (name, rest) = path
        .split_first()
        .ok_or_else(|| anyhow!("empty ASAR path"))?;
    if name.is_empty() || matches!(*name, "." | "..") || name.contains(['/', '\\']) {
        bail!("invalid ASAR entry `{name}`");
    }
    if rest.is_empty() {
        if directory
            .files
            .insert((*name).to_owned(), AsarEntry::File(file))
            .is_some()
        {
            bail!("duplicate ASAR entry `{name}`");
        }
        return Ok(());
    }
    let entry = directory
        .files
        .entry((*name).to_owned())
        .or_insert_with(|| {
            AsarEntry::Directory(AsarDirectory {
                files: BTreeMap::new(),
            })
        });
    let AsarEntry::Directory(child) = entry else {
        bail!("ASAR path collides with file `{name}`")
    };
    insert_asar(child, rest, file)
}

fn integrity(bytes: &[u8]) -> AsarIntegrity {
    let blocks = if bytes.is_empty() {
        vec![format!("{:x}", Sha256::digest([]))]
    } else {
        bytes
            .chunks(ASAR_BLOCK_SIZE)
            .map(|block| format!("{:x}", Sha256::digest(block)))
            .collect()
    };
    AsarIntegrity {
        algorithm: "SHA256".to_owned(),
        hash: format!("{:x}", Sha256::digest(bytes)),
        block_size: ASAR_BLOCK_SIZE,
        blocks,
    }
}

fn pickle_u32(value: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8);
    bytes.extend_from_slice(&4_u32.to_le_bytes());
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes
}

fn pickle_string(value: &[u8]) -> Result<Vec<u8>> {
    let aligned = value.len().div_ceil(4) * 4;
    let payload = 4_usize
        .checked_add(aligned)
        .ok_or_else(|| anyhow!("ASAR header overflow"))?;
    let mut bytes = Vec::with_capacity(4 + payload);
    bytes.extend_from_slice(&u32::try_from(payload)?.to_le_bytes());
    bytes.extend_from_slice(&u32::try_from(value.len())?.to_le_bytes());
    bytes.extend_from_slice(value);
    bytes.resize(4 + payload, 0);
    Ok(bytes)
}

fn write_fuses(path: &Path) -> Result<usize> {
    let positions = find_fuse_sentinels(path)?;
    if positions.is_empty() || positions.len() > 2 {
        bail!("fuse sentinel count {} is outside 1..=2", positions.len());
    }
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    for position in &positions {
        file.seek(SeekFrom::Start(
            *position + u64::try_from(FUSE_SENTINEL.len())?,
        ))?;
        let mut header = [0_u8; 2];
        file.read_exact(&mut header)?;
        if header != [FUSE_VERSION, FUSE_WIRE.len() as u8] {
            bail!("unexpected fuse schema version/length: {header:?}");
        }
        let mut current = [0_u8; 9];
        file.read_exact(&mut current)?;
        if current
            .iter()
            .any(|state| !matches!(*state, b'0' | b'1' | b'r'))
        {
            bail!("invalid fuse state bytes: {current:?}");
        }
        if current.contains(&b'r') {
            bail!("Electron removed a fuse that P1 requires explicitly");
        }
        file.seek(SeekFrom::Start(
            *position + u64::try_from(FUSE_SENTINEL.len() + 2)?,
        ))?;
        file.write_all(FUSE_WIRE)?;
    }
    file.sync_all()?;
    Ok(positions.len())
}

fn find_fuse_sentinels(path: &Path) -> Result<Vec<u64>> {
    let mut file = File::open(path)?;
    let mut positions = Vec::new();
    let mut absolute = 0_u64;
    let mut carry = Vec::new();
    let mut buffer = vec![0_u8; 4 * 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let mut chunk = carry;
        chunk.extend_from_slice(&buffer[..read]);
        for index in find_subslice(&chunk, FUSE_SENTINEL) {
            let base = absolute.saturating_sub(u64::try_from(chunk.len() - read)?);
            let position = base + u64::try_from(index)?;
            if positions.last().copied() != Some(position) {
                positions.push(position);
            }
        }
        let overlap = FUSE_SENTINEL.len() - 1;
        carry = chunk[chunk.len().saturating_sub(overlap)..].to_vec();
        absolute += u64::try_from(read)?;
    }
    Ok(positions)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(|(index, window)| (window == needle).then_some(index))
        .collect()
}

fn macos_helpers(app: &Path) -> [PathBuf; 5] {
    let frameworks = app.join("Contents/Frameworks");
    [
        frameworks.join("Electron Helper.app/Contents/MacOS/Electron Helper"),
        frameworks.join("Electron Helper (GPU).app/Contents/MacOS/Electron Helper (GPU)"),
        frameworks.join("Electron Helper (Plugin).app/Contents/MacOS/Electron Helper (Plugin)"),
        frameworks.join("Electron Helper (Renderer).app/Contents/MacOS/Electron Helper (Renderer)"),
        frameworks.join("Electron Framework.framework/Versions/A/Helpers/chrome_crashpad_handler"),
    ]
}

fn fixture_entitlements() -> plist::Value {
    let mut values = plist::Dictionary::new();
    values.insert(
        "com.apple.security.cs.allow-jit".to_owned(),
        plist::Value::Boolean(true),
    );
    // An ad-hoc fixture has no Team ID and cannot validate its bundled framework. This exception
    // is explicitly diagnostic-only, never production release evidence. DYLD/debug/page-protection
    // and unsigned-executable-memory exceptions are deliberately absent.
    values.insert(
        "com.apple.security.cs.disable-library-validation".to_owned(),
        plist::Value::Boolean(true),
    );
    plist::Value::Dictionary(values)
}

fn codesign_adhoc(app: &Path) -> Result<()> {
    let entitlements = app
        .parent()
        .context("app parent")?
        .join("fixture-signing.entitlements");
    fixture_entitlements().to_file_xml(&entitlements)?;
    let status = Command::new("/usr/bin/codesign")
        .args([
            "--sign",
            "-",
            "--force",
            "--deep",
            "--options",
            "runtime",
            "--timestamp=none",
            "--entitlements",
        ])
        .arg(&entitlements)
        .arg(app)
        .status()?;
    fs::remove_file(&entitlements)?;
    if !status.success() {
        bail!("local hardened ad-hoc fixture signing failed with {status}");
    }
    verify_fixture_signing(app)?;
    Ok(())
}

fn verify_fixture_signing(app: &Path) -> Result<()> {
    let status = Command::new("/usr/bin/codesign")
        .args(["--verify", "--deep", "--strict"])
        .arg(app)
        .status()?;
    if !status.success() {
        bail!("fixture code signature verification failed");
    }
    let main = app.join(format!("Contents/MacOS/{PRODUCT_SLUG}"));
    for executable in std::iter::once(main).chain(macos_helpers(app)) {
        let information = fixture_codesign_output(
            Command::new("/usr/bin/codesign")
                .args(["-dv", "--verbose=4"])
                .arg(&executable),
            false,
            CODESIGN_METADATA_LIMIT,
        )?;
        verify_fixture_metadata(&information)?;
        let entitlements = fixture_codesign_output(
            Command::new("/usr/bin/codesign")
                .args(["-d", "--entitlements", "-", "--xml"])
                .arg(&executable),
            true,
            CODESIGN_ENTITLEMENTS_LIMIT,
        )?;
        verify_fixture_entitlements(&entitlements)?;
    }
    Ok(())
}

fn verify_fixture_metadata(information: &Output) -> Result<()> {
    if !information.status.success() || information.stderr.len() > CODESIGN_METADATA_LIMIT {
        bail!("bounded codesign metadata failed");
    }
    let text = std::str::from_utf8(&information.stderr)?;
    let flags = text
        .lines()
        .find(|line| line.starts_with("CodeDirectory "))
        .and_then(|line| line.split_once("flags=0x"))
        .and_then(|(_, rest)| rest.split_once('('))
        .and_then(|(digits, _)| u64::from_str_radix(digits, 16).ok())
        .context("CodeDirectory flags missing")?;
    if flags & 0x10002 != 0x10002 {
        bail!("fixture must be ad-hoc and hardened runtime");
    }
    Ok(())
}

fn verify_fixture_entitlements(entitlements: &Output) -> Result<()> {
    if !entitlements.status.success() || entitlements.stdout.len() > CODESIGN_ENTITLEMENTS_LIMIT {
        bail!("bounded entitlement inspection failed");
    }
    let actual = plist::Value::from_reader_xml(entitlements.stdout.as_slice())
        .context("parse fixture entitlements")?;
    if actual != fixture_entitlements() {
        bail!("fixture entitlement set differs from reviewed JIT/library-validation profile");
    }
    Ok(())
}

// Fixture signing runs on macOS. The Unix collector mirrors Rust 1.98's stdout-first poll and
// hard-read-error panic before wait, but retains only the parsed stream's existing limit + 1.
#[cfg(unix)]
fn fixture_codesign_output(
    command: &mut Command,
    retain_stdout: bool,
    limit: usize,
) -> io::Result<Output> {
    use std::process::Stdio;

    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().expect("requested stdout pipe");
    let stderr = child.stderr.take().expect("requested stderr pipe");
    collect_fixture_codesign_output(&mut child, stdout, stderr, retain_stdout, limit)
}

// No codesign maintenance is claimed for non-Unix hosts; their existing path stays unchanged.
#[cfg(not(unix))]
fn fixture_codesign_output(
    command: &mut Command,
    _retain_stdout: bool,
    _limit: usize,
) -> io::Result<Output> {
    command.output()
}

#[cfg(unix)]
fn collect_fixture_codesign_output(
    child: &mut std::process::Child,
    mut out: impl io::Read + std::os::fd::AsFd,
    mut err: impl io::Read + std::os::fd::AsFd,
    retain_stdout: bool,
    limit: usize,
) -> io::Result<Output> {
    let (out_limit, err_limit) = if retain_stdout {
        (limit + 1, 0)
    } else {
        (0, limit + 1)
    };
    let mut stdout = Vec::with_capacity(out_limit);
    let mut stderr = Vec::with_capacity(err_limit);
    let read_result = drain_fixture_codesign_pipes(
        &mut out,
        &mut stdout,
        out_limit,
        &mut err,
        &mut stderr,
        err_limit,
    );
    drop((out, err));
    finish_fixture_codesign_output(read_result, stdout, stderr, || child.wait())
}

#[cfg(unix)]
fn finish_fixture_codesign_output(
    read_result: io::Result<()>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    wait: impl FnOnce() -> io::Result<std::process::ExitStatus>,
) -> io::Result<Output> {
    // Match Rust 1.98 Command::output: a hard read error panics and does not wait. A budget
    // overflow is not a read error: both streams reach EOF before this exact Child is waited.
    read_result.unwrap();
    let status = wait()?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

#[cfg(unix)]
fn drain_fixture_codesign_pipes(
    out: &mut (impl io::Read + std::os::fd::AsFd),
    stdout: &mut Vec<u8>,
    out_limit: usize,
    err: &mut (impl io::Read + std::os::fd::AsFd),
    stderr: &mut Vec<u8>,
    err_limit: usize,
) -> io::Result<()> {
    use rustix::event::{PollFd, PollFlags, poll};
    set_fixture_pipe_nonblocking(&*out, true)?;
    set_fixture_pipe_nonblocking(&*err, true)?;
    loop {
        let ready = {
            let mut fds = [
                PollFd::new(out, PollFlags::IN),
                PollFd::new(err, PollFlags::IN),
            ];
            loop {
                match poll(&mut fds, None) {
                    Ok(_) => break,
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            // HUP can accompany buffered bytes; ERR/NVAL must reach read and its original
            // error path. Only read returning zero establishes EOF.
            [!fds[0].revents().is_empty(), !fds[1].revents().is_empty()]
        };
        if ready[0] && drain_fixture_codesign_reader(out, stdout, out_limit)? {
            set_fixture_pipe_nonblocking(&*err, false)?;
            return drain_fixture_codesign_reader(err, stderr, err_limit).map(|_| ());
        }
        if ready[1] && drain_fixture_codesign_reader(err, stderr, err_limit)? {
            set_fixture_pipe_nonblocking(&*out, false)?;
            return drain_fixture_codesign_reader(out, stdout, out_limit).map(|_| ());
        }
    }
}

#[cfg(unix)]
fn set_fixture_pipe_nonblocking(pipe: &impl std::os::fd::AsFd, enabled: bool) -> io::Result<()> {
    use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};

    let old = fcntl_getfl(pipe)?;
    let new = if enabled {
        old | OFlags::NONBLOCK
    } else {
        old & !OFlags::NONBLOCK
    };
    if new != old {
        fcntl_setfl(pipe, new)?;
    }
    Ok(())
}

#[cfg(unix)]
fn drain_fixture_codesign_reader(
    reader: &mut impl io::Read,
    retained: &mut Vec<u8>,
    keep: usize,
) -> io::Result<bool> {
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                let available = keep.saturating_sub(retained.len());
                retained.extend_from_slice(&buffer[..count.min(available)]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error),
        }
    }
}

fn manifest(
    layout: &BundleLayout,
    platform: &str,
    electron_version: &str,
    release_epoch: u64,
    protocol_version: u64,
    asar_header_sha256: &str,
) -> Result<BundleManifest> {
    let mut files = BTreeMap::new();
    let mut paths = vec![
        layout.executable.clone(),
        layout.fuse_file.clone(),
        layout.app_asar.clone(),
    ];
    if let Some(app) = &layout.app_bundle {
        paths.extend(macos_helpers(app));
    }
    for path in paths {
        files.insert(relative(&layout.root, &path), sha256(&path)?);
    }
    Ok(BundleManifest {
        schema: MANIFEST_SCHEMA.to_owned(),
        schema_version: MANIFEST_VERSION,
        platform: platform.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        electron_version: electron_version.to_owned(),
        release_epoch,
        protocol_version,
        product_name: PRODUCT_NAME.to_owned(),
        bundle_id: BUNDLE_ID.to_owned(),
        executable: relative(&layout.root, &layout.executable),
        fuse_file: relative(&layout.root, &layout.fuse_file),
        app_asar: relative(&layout.root, &layout.app_asar),
        asar_header_sha256: asar_header_sha256.to_owned(),
        fuse_wire: String::from_utf8(FUSE_WIRE.to_vec()).expect("ASCII fuse wire"),
        signing_profile: if platform.starts_with("macos-") {
            MACOS_SIGNING_PROFILE
        } else {
            "platform-fixture"
        }
        .to_owned(),
        files,
    })
}

fn verify_layout(root: &Path, manifest: &BundleManifest) -> Result<()> {
    if manifest.schema != MANIFEST_SCHEMA
        || manifest.schema_version != MANIFEST_VERSION
        || manifest.platform != crate::engine::current_platform()?
        || manifest.release_epoch != 5
        || manifest.protocol_version != 4
        || manifest.product_name != PRODUCT_NAME
        || manifest.bundle_id != BUNDLE_ID
        || manifest.signing_profile
            != if manifest.platform.starts_with("macos-") {
                MACOS_SIGNING_PROFILE
            } else {
                "platform-fixture"
            }
        || manifest.fuse_wire.as_bytes() != FUSE_WIRE
    {
        bail!("engine bundle manifest fixed fields drift: {manifest:?}");
    }
    verify_manifest_paths(manifest)?;
    for (path, expected) in &manifest.files {
        let path = root.join(path);
        let actual = sha256(&path)?;
        if &actual != expected {
            bail!("bundle digest mismatch for {}", path.display());
        }
    }
    let fuse_path = root.join(&manifest.fuse_file);
    verify_fuses(&fuse_path)?;
    let asar_path = root.join(&manifest.app_asar);
    let header = verify_asar(&asar_path)?;
    if header != manifest.asar_header_sha256 {
        bail!("ASAR header hash differs from manifest");
    }
    let resources = asar_path.parent().expect("resources parent");
    if resources.join("default_app.asar").exists() || resources.join("app").exists() {
        bail!("OnlyLoadAppFromAsar invariant violated by fallback app source");
    }
    if manifest.platform.starts_with("macos-") {
        verify_macos(root, manifest)?;
    }
    if manifest.platform == "windows-x64" {
        verify_windows(root, manifest)?;
    }
    Ok(())
}

fn verify_manifest_paths(manifest: &BundleManifest) -> Result<()> {
    let expected = match manifest.platform.as_str() {
        "macos-arm64" | "macos-x64" => (
            "AcosmiEngine.app/Contents/MacOS/AcosmiEngine",
            "AcosmiEngine.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework",
            "AcosmiEngine.app/Contents/Resources/app.asar",
        ),
        "windows-x64" => (
            "acosmi-engine-fixture.exe",
            "acosmi-engine-fixture.exe",
            "resources/app.asar",
        ),
        "linux-arm64" | "linux-x64" => (
            "acosmi-engine-fixture",
            "acosmi-engine-fixture",
            "resources/app.asar",
        ),
        _ => bail!("unsupported engine manifest platform"),
    };
    if (
        manifest.executable.as_str(),
        manifest.fuse_file.as_str(),
        manifest.app_asar.as_str(),
    ) != expected
    {
        bail!("engine manifest executable/fuse/ASAR paths are not the fixed bundle layout");
    }
    let mut required = [
        expected.0.to_owned(),
        expected.1.to_owned(),
        expected.2.to_owned(),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if manifest.platform.starts_with("macos-") {
        for helper in macos_helpers(Path::new("AcosmiEngine.app")) {
            required.insert(relative(Path::new(""), &helper));
        }
    }
    if required != manifest.files.keys().cloned().collect() {
        bail!("engine manifest must hash exactly every executable, fuse, ASAR and required helper");
    }
    Ok(())
}

fn verify_fuses(path: &Path) -> Result<()> {
    let positions = find_fuse_sentinels(path)?;
    if positions.is_empty() || positions.len() > 2 {
        bail!("bundle fuse sentinel count invalid: {}", positions.len());
    }
    let mut file = File::open(path)?;
    for position in positions {
        file.seek(SeekFrom::Start(
            position + u64::try_from(FUSE_SENTINEL.len())?,
        ))?;
        let mut bytes = [0_u8; 11];
        file.read_exact(&mut bytes)?;
        if bytes[..2] != [FUSE_VERSION, FUSE_WIRE.len() as u8] || &bytes[2..] != FUSE_WIRE {
            bail!("bundle fuse wire drift: {bytes:?}");
        }
    }
    Ok(())
}

fn verify_asar(path: &Path) -> Result<String> {
    let bytes = fs::read(path)?;
    if bytes.len() < 16 || u32::from_le_bytes(bytes[0..4].try_into()?) != 4 {
        bail!("ASAR size pickle is invalid");
    }
    let header_size = usize::try_from(u32::from_le_bytes(bytes[4..8].try_into()?))?;
    if header_size < 8 || 8 + header_size > bytes.len() {
        bail!("ASAR header size is invalid");
    }
    let payload_size = usize::try_from(u32::from_le_bytes(bytes[8..12].try_into()?))?;
    let json_size = usize::try_from(u32::from_le_bytes(bytes[12..16].try_into()?))?;
    if payload_size + 4 != header_size || 16 + json_size > 8 + header_size {
        bail!("ASAR header pickle is invalid");
    }
    let json = &bytes[16..16 + json_size];
    let header: AsarDirectory = serde_json::from_slice(json)?;
    let content_start = 8 + header_size;
    verify_asar_directory(&header, &bytes, content_start)?;
    Ok(format!("{:x}", Sha256::digest(json)))
}

fn verify_asar_directory(directory: &AsarDirectory, bytes: &[u8], content: usize) -> Result<()> {
    for entry in directory.files.values() {
        match entry {
            AsarEntry::Directory(child) => verify_asar_directory(child, bytes, content)?,
            AsarEntry::File(file) => {
                if file.integrity.algorithm != "SHA256"
                    || file.integrity.block_size != ASAR_BLOCK_SIZE
                {
                    bail!("ASAR integrity metadata drift");
                }
                let offset = file.offset.parse::<usize>()?;
                let end = content
                    .checked_add(offset)
                    .and_then(|start| start.checked_add(file.size))
                    .ok_or_else(|| anyhow!("ASAR file bounds overflow"))?;
                if end > bytes.len() {
                    bail!("ASAR file exceeds archive");
                }
                let payload = &bytes[content + offset..end];
                if format!("{:x}", Sha256::digest(payload)) != file.integrity.hash {
                    bail!("ASAR file hash mismatch");
                }
                let blocks = integrity(payload).blocks;
                if blocks != file.integrity.blocks {
                    bail!("ASAR block hash mismatch");
                }
            }
        }
    }
    Ok(())
}

fn verify_macos(root: &Path, manifest: &BundleManifest) -> Result<()> {
    let app = root.join(format!("{PRODUCT_SLUG}.app"));
    let plist_path = app.join("Contents/Info.plist");
    let plist = plist::Value::from_file(&plist_path)?;
    let dictionary = plist
        .as_dictionary()
        .ok_or_else(|| anyhow!("main plist is not a dictionary"))?;
    if dictionary
        .get("CFBundleIdentifier")
        .and_then(plist::Value::as_string)
        != Some(BUNDLE_ID)
        || dictionary
            .get("CFBundleExecutable")
            .and_then(plist::Value::as_string)
            != Some(PRODUCT_SLUG)
    {
        bail!("macOS rebrand plist drift");
    }
    let integrity = dictionary
        .get("ElectronAsarIntegrity")
        .and_then(plist::Value::as_dictionary)
        .and_then(|value| value.get("Resources/app.asar"))
        .and_then(plist::Value::as_dictionary)
        .ok_or_else(|| anyhow!("ElectronAsarIntegrity missing"))?;
    if integrity.get("algorithm").and_then(plist::Value::as_string) != Some("SHA256")
        || integrity.get("hash").and_then(plist::Value::as_string)
            != Some(manifest.asar_header_sha256.as_str())
    {
        bail!("ElectronAsarIntegrity drift");
    }
    verify_fixture_signing(&app)?;
    Ok(())
}

fn verify_windows(root: &Path, manifest: &BundleManifest) -> Result<()> {
    if manifest.executable != "acosmi-engine-fixture.exe"
        || manifest.fuse_file != manifest.executable
    {
        bail!("Windows fixture executable/rebrand drift");
    }
    #[cfg(windows)]
    {
        let executable = root.join(&manifest.executable);
        let resource =
            openbot_windows_sandbox::read_pe_resource(&executable, "Integrity", "ElectronAsar")?;
        if resource != windows_integrity_payload(&manifest.asar_header_sha256)? {
            bail!("Windows ElectronAsar/Integrity resource drift");
        }
        let decoded: Vec<WindowsAsarIntegrity> = serde_json::from_slice(&resource)?;
        if decoded.len() != 1
            || decoded[0].file != r"resources\app.asar"
            || decoded[0].alg != "sha256"
            || decoded[0].value != manifest.asar_header_sha256
        {
            bail!("Windows ElectronAsar resource shape drift");
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = root;
        bail!("Windows PE resources may only be verified on a Windows host");
    }
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    for entry in walkdir::WalkDir::new(source).follow_links(false) {
        let entry = entry?;
        let relative = entry.path().strip_prefix(source)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        let target = destination.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)?;
        } else if entry.file_type().is_symlink() {
            copy_symlink(entry.path(), &target)?;
        } else if entry.file_type().is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), &target)?;
            fs::set_permissions(&target, fs::metadata(entry.path())?.permissions())?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn copy_symlink(source: &Path, target: &Path) -> Result<()> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    std::os::unix::fs::symlink(fs::read_link(source)?, target)?;
    Ok(())
}

#[cfg(windows)]
fn copy_symlink(_source: &Path, _target: &Path) -> Result<()> {
    bail!("engine bundle: unexpected symlink in Windows Electron archive")
}

fn sha256(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .expect("bundle path remains under root")
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::{
        FUSE_SENTINEL, FUSE_WIRE, WindowsAsarIntegrity, find_subslice, integrity, pickle_string,
        pickle_u32, windows_integrity_payload,
    };

    #[cfg(unix)]
    mod codesign_capture {
        use std::io::{self, Cursor, Read, Write};
        use std::os::fd::{AsFd, BorrowedFd};
        use std::os::unix::process::ExitStatusExt as _;
        use std::process::{Command, ExitStatus, Output, Stdio};

        use super::super::{
            CODESIGN_ENTITLEMENTS_LIMIT, CODESIGN_METADATA_LIMIT, collect_fixture_codesign_output,
            drain_fixture_codesign_reader, finish_fixture_codesign_output, fixture_codesign_output,
            fixture_entitlements, verify_fixture_entitlements, verify_fixture_metadata,
        };

        fn shell(script: &str) -> Command {
            let mut command = Command::new("/bin/sh");
            command
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .args(["-c", script]);
            command
        }

        fn output(status: i32, stdout: Vec<u8>, stderr: Vec<u8>) -> Output {
            Output {
                status: ExitStatus::from_raw(status << 8),
                stdout,
                stderr,
            }
        }

        #[test]
        fn existing_metadata_boundary_and_rejections_precede_utf8_and_flags() {
            let mut bytes = b"CodeDirectory flags=0x10002(adhoc,runtime)\n".to_vec();
            bytes.resize(CODESIGN_METADATA_LIMIT, b' ');
            verify_fixture_metadata(&output(0, vec![], bytes.clone())).expect("exact 64 KiB");
            bytes.push(0xff);
            assert_eq!(
                verify_fixture_metadata(&output(0, vec![], bytes))
                    .unwrap_err()
                    .to_string(),
                "bounded codesign metadata failed"
            );
            assert_eq!(
                verify_fixture_metadata(&output(1, vec![], vec![0xff]))
                    .unwrap_err()
                    .to_string(),
                "bounded codesign metadata failed"
            );
            assert!(verify_fixture_metadata(&output(0, vec![], vec![0xff])).is_err());
            assert_eq!(
                verify_fixture_metadata(&output(0, vec![], b"invalid".to_vec()))
                    .unwrap_err()
                    .to_string(),
                "CodeDirectory flags missing"
            );
            assert_eq!(
                verify_fixture_metadata(&output(
                    0,
                    vec![],
                    b"CodeDirectory flags=0x2(adhoc)".to_vec()
                ))
                .unwrap_err()
                .to_string(),
                "fixture must be ad-hoc and hardened runtime"
            );
        }

        #[test]
        fn existing_entitlement_boundary_and_rejections_precede_plist() {
            let mut bytes = Vec::new();
            fixture_entitlements()
                .to_writer_xml(&mut bytes)
                .expect("fixture XML");
            bytes.resize(CODESIGN_ENTITLEMENTS_LIMIT, b' ');
            verify_fixture_entitlements(&output(0, bytes.clone(), vec![])).expect("exact 16 KiB");
            bytes.push(0xff);
            assert_eq!(
                verify_fixture_entitlements(&output(0, bytes, vec![]))
                    .unwrap_err()
                    .to_string(),
                "bounded entitlement inspection failed"
            );
            assert_eq!(
                verify_fixture_entitlements(&output(1, vec![0xff], vec![]))
                    .unwrap_err()
                    .to_string(),
                "bounded entitlement inspection failed"
            );
            assert_eq!(
                verify_fixture_entitlements(&output(0, vec![0xff], vec![]))
                    .unwrap_err()
                    .to_string(),
                "parse fixture entitlements"
            );
            let wrong = b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict/></plist>";
            assert_eq!(
                verify_fixture_entitlements(&output(0, wrong.to_vec(), vec![]))
                    .unwrap_err()
                    .to_string(),
                "fixture entitlement set differs from reviewed JIT/library-validation profile"
            );
        }

        struct GrowingReader {
            cursor: Cursor<Vec<u8>>,
            growth: Option<Vec<u8>>,
        }

        impl Read for GrowingReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if self.cursor.position() == self.cursor.get_ref().len() as u64
                    && let Some(growth) = self.growth.take()
                {
                    self.cursor.get_mut().extend_from_slice(&growth);
                }
                self.cursor.read(buffer)
            }
        }

        #[test]
        fn retention_stops_at_existing_limit_plus_sentinel_while_growth_is_drained() {
            for limit in [CODESIGN_METADATA_LIMIT, CODESIGN_ENTITLEMENTS_LIMIT] {
                let mut reader = GrowingReader {
                    cursor: Cursor::new(vec![b'a'; limit]),
                    growth: Some(vec![b'b'; 1024 * 1024]),
                };
                let mut retained = Vec::with_capacity(limit + 1);
                assert!(
                    drain_fixture_codesign_reader(&mut reader, &mut retained, limit + 1).unwrap()
                );
                assert_eq!(retained.len(), limit + 1);
                assert_eq!(retained.capacity(), limit + 1);
                assert_eq!(retained[limit], b'b');
                assert_eq!(reader.cursor.position(), (limit + 1024 * 1024) as u64);
                assert!(reader.growth.is_none());
            }
        }

        #[test]
        fn ignored_stream_keeps_no_bytes_but_reaches_eof() {
            let mut reader = Cursor::new(vec![b'x'; 1024 * 1024]);
            let mut retained = Vec::new();
            assert!(drain_fixture_codesign_reader(&mut reader, &mut retained, 0).unwrap());
            assert_eq!(reader.position(), 1024 * 1024);
            assert_eq!(retained.len(), 0);
            assert_eq!(retained.capacity(), 0);
        }

        struct InterruptedThenError {
            interrupted: bool,
            cursor: Cursor<Vec<u8>>,
        }

        impl Read for InterruptedThenError {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                if self.cursor.position() == self.cursor.get_ref().len() as u64 {
                    return Err(io::Error::other("late read fault"));
                }
                self.cursor.read(buffer)
            }
        }

        #[test]
        fn interrupted_reads_retry_and_late_faults_are_preserved_after_overflow() {
            let keep = CODESIGN_ENTITLEMENTS_LIMIT + 1;
            let mut reader = InterruptedThenError {
                interrupted: false,
                cursor: Cursor::new(vec![b'x'; 2 * keep]),
            };
            let mut retained = Vec::with_capacity(keep);
            let error =
                drain_fixture_codesign_reader(&mut reader, &mut retained, keep).unwrap_err();
            assert!(reader.interrupted);
            assert_eq!(reader.cursor.position(), (2 * keep) as u64);
            assert_eq!(retained.len(), keep);
            assert_eq!(retained.capacity(), keep);
            assert_eq!(error.to_string(), "late read fault");
        }

        #[test]
        fn both_large_pipe_orders_are_drained_with_only_the_selected_prefix_retained() {
            let first = "x".repeat(1024);
            let second = "y".repeat(1024);
            for stdout_first in [true, false] {
                let redirections = if stdout_first {
                    ["", " >&2"]
                } else {
                    [" >&2", ""]
                };
                let script = format!(
                    "set -e; i=0; while [ \"$i\" -lt 2048 ]; do printf '%s' '{first}'{}; i=$((i + 1)); done; i=0; while [ \"$i\" -lt 2048 ]; do printf '%s' '{second}'{}; i=$((i + 1)); done; exit 23",
                    redirections[0], redirections[1],
                );
                for retain_stdout in [true, false] {
                    let limit = if retain_stdout {
                        CODESIGN_ENTITLEMENTS_LIMIT
                    } else {
                        CODESIGN_METADATA_LIMIT
                    };
                    let captured =
                        fixture_codesign_output(&mut shell(&script), retain_stdout, limit)
                            .expect("both pipes drain without deadlock");
                    assert_eq!(captured.status.code(), Some(23));
                    let (retained, discarded) = if retain_stdout {
                        (&captured.stdout, &captured.stderr)
                    } else {
                        (&captured.stderr, &captured.stdout)
                    };
                    assert_eq!(retained.len(), limit + 1);
                    assert_eq!(retained.capacity(), limit + 1);
                    let expected = if retain_stdout == stdout_first {
                        b'x'
                    } else {
                        b'y'
                    };
                    assert!(retained.iter().all(|byte| *byte == expected));
                    assert_eq!(discarded.len(), 0);
                    assert_eq!(discarded.capacity(), 0);
                }
            }
        }

        #[test]
        fn overflow_waits_original_child_even_when_both_pipes_close_before_exit() {
            let script = "printf '%s' overflow; printf '%s' discarded >&2; exec 1>&- 2>&-; sleep 0.05; exit 29";
            let mut child = shell(script)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("owned child");
            let pid = child.id();
            let stdout = child.stdout.take().unwrap();
            let stderr = child.stderr.take().unwrap();
            let captured = collect_fixture_codesign_output(&mut child, stdout, stderr, true, 3)
                .expect("wait original child after both EOFs");
            assert_eq!(captured.stdout, b"over");
            assert!(captured.stderr.is_empty());
            assert_eq!(captured.status.code(), Some(29));
            assert_eq!(child.id(), pid);
            assert_eq!(child.try_wait().unwrap(), Some(captured.status));
            assert_eq!(child.wait().unwrap(), captured.status);
        }

        #[test]
        fn hup_with_buffered_bytes_is_read_before_eof_and_wait() {
            for retain_stdout in [true, false] {
                let mut child = shell("exit 0")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("owned child");
                let (stdout, mut stdout_writer) = io::pipe().unwrap();
                let (stderr, mut stderr_writer) = io::pipe().unwrap();
                stdout_writer.write_all(b"stdout tail").unwrap();
                stderr_writer.write_all(b"stderr tail").unwrap();
                drop((stdout_writer, stderr_writer));
                let captured =
                    collect_fixture_codesign_output(&mut child, stdout, stderr, retain_stdout, 64)
                        .expect("read buffered data even with writers closed");
                assert!(captured.status.success());
                if retain_stdout {
                    assert_eq!(captured.stdout, b"stdout tail");
                    assert!(captured.stderr.is_empty());
                } else {
                    assert_eq!(captured.stderr, b"stderr tail");
                    assert!(captured.stdout.is_empty());
                }
            }
        }

        struct ReadFault<R> {
            reader: R,
            message: &'static str,
        }

        impl<R: AsFd> AsFd for ReadFault<R> {
            fn as_fd(&self) -> BorrowedFd<'_> {
                self.reader.as_fd()
            }
        }

        impl<R> Read for ReadFault<R> {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other(self.message))
            }
        }

        #[test]
        fn hard_read_fault_panics_stdout_first_before_wait_without_retry() {
            let mut child = shell("read ignored; exit 27")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("owned child");
            let (stdout, mut stdout_writer) = io::pipe().unwrap();
            let (stderr, mut stderr_writer) = io::pipe().unwrap();
            stdout_writer.write_all(b"out").unwrap();
            stderr_writer.write_all(b"err").unwrap();
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                collect_fixture_codesign_output(
                    &mut child,
                    ReadFault {
                        reader: stdout,
                        message: "stdout read fault",
                    },
                    ReadFault {
                        reader: stderr,
                        message: "stderr read fault",
                    },
                    false,
                    CODESIGN_METADATA_LIMIT,
                )
            }));
            let before_wait = child.try_wait().unwrap();
            drop(child.stdin.take());
            let cleaned = child.wait().expect("clean up original owned child");
            let payload = panic.expect_err("original hard-read panic");
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap();
            assert!(message.contains("stdout read fault"), "{message}");
            assert_eq!(before_wait, None);
            assert_eq!(cleaned.code(), Some(27));
        }

        #[test]
        fn successful_reads_preserve_wait_error_and_read_fault_precedes_wait_error() {
            let wait_error = finish_fixture_codesign_output(Ok(()), vec![], vec![], || {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "wait fault",
                ))
            })
            .unwrap_err();
            assert_eq!(wait_error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(wait_error.to_string(), "wait fault");
            let called = std::cell::Cell::new(false);
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                finish_fixture_codesign_output(
                    Err(io::Error::other("read fault")),
                    vec![],
                    vec![],
                    || {
                        called.set(true);
                        Err(io::Error::other("wait fault"))
                    },
                )
            }));
            assert!(panic.is_err());
            assert!(!called.get());
        }
    }

    #[test]
    fn manifest_inventory_requires_helpers_and_fixed_launch_paths_before_file_reads() {
        let main = "AcosmiEngine.app/Contents/MacOS/AcosmiEngine";
        let framework = "AcosmiEngine.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework";
        let asar = "AcosmiEngine.app/Contents/Resources/app.asar";
        let helper = "AcosmiEngine.app/Contents/Frameworks/Electron Helper.app/Contents/MacOS/Electron Helper";
        let paths = [
            main,
            framework,
            asar,
            helper,
            "AcosmiEngine.app/Contents/Frameworks/Electron Helper (GPU).app/Contents/MacOS/Electron Helper (GPU)",
            "AcosmiEngine.app/Contents/Frameworks/Electron Helper (Plugin).app/Contents/MacOS/Electron Helper (Plugin)",
            "AcosmiEngine.app/Contents/Frameworks/Electron Helper (Renderer).app/Contents/MacOS/Electron Helper (Renderer)",
            "AcosmiEngine.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Helpers/chrome_crashpad_handler",
        ];
        let mut manifest = super::BundleManifest {
            schema: super::MANIFEST_SCHEMA.to_owned(),
            schema_version: 2,
            platform: "macos-arm64".to_owned(),
            arch: "aarch64".to_owned(),
            electron_version: "43.3.0".to_owned(),
            release_epoch: 5,
            protocol_version: 4,
            product_name: super::PRODUCT_NAME.to_owned(),
            bundle_id: super::BUNDLE_ID.to_owned(),
            executable: main.to_owned(),
            fuse_file: framework.to_owned(),
            app_asar: asar.to_owned(),
            asar_header_sha256: "a".repeat(64),
            fuse_wire: "000011001".to_owned(),
            signing_profile: super::MACOS_SIGNING_PROFILE.to_owned(),
            files: paths
                .into_iter()
                .map(|path| (path.to_owned(), "b".repeat(64)))
                .collect(),
        };
        super::verify_manifest_paths(&manifest).expect("full fixed inventory");
        manifest.files.remove(helper);
        assert!(
            super::verify_manifest_paths(&manifest).is_err(),
            "missing helper hash"
        );
        manifest.files.insert(helper.to_owned(), "b".repeat(64));
        manifest.executable = helper.to_owned();
        manifest.files.remove(main);
        assert!(
            super::verify_manifest_paths(&manifest).is_err(),
            "helper cannot become entry point"
        );
        manifest.executable = main.to_owned();
        manifest.files.insert(main.to_owned(), "b".repeat(64));
        manifest
            .files
            .insert("../outside".to_owned(), "b".repeat(64));
        assert!(
            super::verify_manifest_paths(&manifest).is_err(),
            "no out-of-root hash reads"
        );
    }

    #[test]
    fn pickle_layout_matches_official_asar_shape() {
        let json = br#"{"files":{}}"#;
        let header = pickle_string(json).expect("header");
        let outer = pickle_u32(u32::try_from(header.len()).expect("small"));
        assert_eq!(outer.len(), 8);
        assert_eq!(u32::from_le_bytes(outer[0..4].try_into().unwrap()), 4);
        assert_eq!(
            usize::try_from(u32::from_le_bytes(outer[4..8].try_into().unwrap())).unwrap(),
            header.len()
        );
        assert_eq!(
            u32::from_le_bytes(header[4..8].try_into().unwrap()),
            json.len() as u32
        );
    }

    #[test]
    fn file_integrity_has_whole_and_four_mib_blocks() {
        let bytes = vec![7_u8; 4 * 1024 * 1024 + 1];
        let value = integrity(&bytes);
        assert_eq!(value.blocks.len(), 2);
        assert_eq!(value.hash.len(), 64);
    }

    #[test]
    fn fuse_scanner_handles_overlap_and_wire_is_strict_v1() {
        let mut bytes = vec![0_u8; 7];
        bytes.extend_from_slice(FUSE_SENTINEL);
        bytes.extend_from_slice(FUSE_SENTINEL);
        assert_eq!(
            find_subslice(&bytes, FUSE_SENTINEL),
            vec![7, 7 + FUSE_SENTINEL.len()]
        );
        assert_eq!(FUSE_WIRE, b"000011001");
    }

    #[test]
    fn windows_integrity_resource_is_the_official_closed_shape() {
        let hash = "ab".repeat(32);
        let payload = windows_integrity_payload(&hash).expect("payload");
        assert_eq!(
            serde_json::from_slice::<Vec<WindowsAsarIntegrity>>(&payload).unwrap(),
            vec![WindowsAsarIntegrity {
                file: r"resources\app.asar".to_owned(),
                alg: "sha256".to_owned(),
                value: hash,
            }]
        );
        assert!(windows_integrity_payload("not-a-hash").is_err());
    }
}
