//! Fetch and verify the exact official PostgreSQL source used by Desktop sidecar builds.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use sha2::{Digest as _, Sha256};

const PINS_RELPATH: &str = "tools/postgres-pins.toml";
const CHECKSUM_RELPATH: &str = "tools/postgresql-17.11.tar.gz.sha256";
const SOURCE_ROOT: &str = "postgresql-17.11";
const MAX_ARCHIVE_ENTRIES: usize = 20_000;
const MAX_UNCOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;

pub(crate) fn run(root: &Path, args: &[String]) -> Result<()> {
    match args {
        [command] if command == "fetch-source" => fetch(root),
        [command] if command == "verify-source" => verify(root),
        _ => bail!("usage: cargo xtask postgres fetch-source|verify-source"),
    }
}

fn fetch(root: &Path) -> Result<()> {
    let pin = source_pin(root)?;
    let archive = archive_path(root, &pin.archive);
    if archive.is_file()
        && verify_size(&archive, pin.size_bytes).is_ok()
        && verify_sha(&archive, &pin.sha256).is_ok()
    {
        println!("postgres fetch-source: reuse {}", archive.display());
        return verify(root);
    }
    let parent = archive
        .parent()
        .context("PostgreSQL source target has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let partial = archive.with_extension("tar.gz.part");
    if partial.exists() {
        fs::remove_file(&partial).with_context(|| format!("remove {}", partial.display()))?;
    }
    download(&pin.url, &partial)?;
    verify_size(&partial, pin.size_bytes)?;
    verify_sha(&partial, &pin.sha256)?;
    if archive.exists() {
        fs::remove_file(&archive).with_context(|| format!("replace {}", archive.display()))?;
    }
    fs::rename(&partial, &archive).with_context(|| format!("publish {}", archive.display()))?;
    verify(root)
}

fn verify(root: &Path) -> Result<()> {
    let pin = source_pin(root)?;
    let archive = archive_path(root, &pin.archive);
    verify_size(&archive, pin.size_bytes)?;
    verify_sha(&archive, &pin.sha256)?;
    verify_archive(&archive)?;
    println!(
        "postgres verify-source: ok (version={}; bytes={}; sha256={})",
        pin.version, pin.size_bytes, pin.sha256
    );
    Ok(())
}

struct SourcePin {
    version: String,
    archive: String,
    url: String,
    size_bytes: u64,
    sha256: String,
}

fn source_pin(root: &Path) -> Result<SourcePin> {
    let path = root.join(PINS_RELPATH);
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let pins: toml::Value =
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    if pins.get("schema").and_then(toml::Value::as_str) != Some("openbot-postgres-pins")
        || pins.get("schema_version").and_then(toml::Value::as_integer) != Some(1)
    {
        bail!("PostgreSQL pins schema drift");
    }
    let source = pins
        .get("source")
        .and_then(toml::Value::as_table)
        .context("PostgreSQL pins missing [source]")?;
    let version = string(source, "version")?.to_owned();
    let archive = string(source, "archive")?.to_owned();
    let url = string(source, "url")?.to_owned();
    let size_bytes = positive_u64(source, "size_bytes")?;
    let sha256 = string(source, "sha256")?.to_owned();
    let checksum_url = string(source, "checksum_url")?;
    if version != "17.11"
        || source.get("major").and_then(toml::Value::as_integer) != Some(17)
        || archive != "postgresql-17.11.tar.gz"
        || url != "https://ftp.postgresql.org/pub/source/v17.11/postgresql-17.11.tar.gz"
        || checksum_url
            != "https://ftp.postgresql.org/pub/source/v17.11/postgresql-17.11.tar.gz.sha256"
        || size_bytes != 28_397_423
        || !valid_sha256(&sha256)
    {
        bail!("PostgreSQL 17.11 source pin fixed fields drift");
    }
    let checksum = fs::read_to_string(root.join(CHECKSUM_RELPATH))
        .context("read PostgreSQL official checksum copy")?;
    if checksum != format!("{sha256}  {archive}\n") {
        bail!("PostgreSQL pin differs from official checksum copy");
    }
    let bundle = pins
        .get("bundle")
        .and_then(toml::Value::as_table)
        .context("PostgreSQL pins missing [bundle]")?;
    // xtask also builds as a standalone tool without the application's dev-dependencies.
    // Read the reviewed literal from the runtime source rather than pulling core crates into it.
    let engine_source = fs::read_to_string(root.join("crates/openbot-contracts/src/engine.rs"))
        .context("read runtime release epoch")?;
    let epoch_pattern =
        regex::Regex::new(r"(?m)^pub const ENGINE_RELEASE_EPOCH: u64 = ([0-9]+);$")?;
    let runtime_epoch = epoch_pattern
        .captures(&engine_source)
        .context("runtime release epoch must remain an explicit reviewed literal")?[1]
        .parse::<i64>()
        .context("runtime release epoch does not fit the manifest integer")?;
    let programs = bundle
        .get("required_programs")
        .and_then(toml::Value::as_array)
        .context("PostgreSQL bundle programs missing")?
        .iter()
        .map(|value| value.as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    if string(bundle, "manifest_schema")? != "openbot-postgres-sidecar-bundle"
        || bundle
            .get("manifest_schema_version")
            .and_then(toml::Value::as_integer)
            != Some(1)
        || bundle
            .get("release_epoch")
            .and_then(toml::Value::as_integer)
            != Some(runtime_epoch)
        || programs != ["postgres", "initdb", "pg_ctl"]
    {
        bail!("PostgreSQL bundle contract drift");
    }
    let desktop = fs::read_to_string(root.join("crates/openbot-desktop/src/postgres_sidecar.rs"))
        .context("read Desktop PostgreSQL bundle verifier")?;
    if !desktop.contains(&format!(
        "pub const POSTGRES_VERSION: &str = \"{version}\";"
    )) || !desktop.contains(&sha256)
    {
        bail!("PostgreSQL pin and Desktop runtime constants drift");
    }
    Ok(SourcePin {
        version,
        archive,
        url,
        size_bytes,
        sha256,
    })
}

fn verify_archive(path: &Path) -> Result<()> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let decoder = GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    let mut required = [
        format!("{SOURCE_ROOT}/COPYRIGHT"),
        format!("{SOURCE_ROOT}/configure"),
        format!("{SOURCE_ROOT}/src/backend/tcop/postgres.c"),
        format!("{SOURCE_ROOT}/src/bin/initdb/initdb.c"),
        format!("{SOURCE_ROOT}/src/bin/pg_ctl/pg_ctl.c"),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let mut entries = 0_usize;
    let mut uncompressed = 0_u64;
    let mut pax_global_seen = false;
    for entry in archive
        .entries()
        .context("read PostgreSQL source tar index")?
    {
        let entry = entry.context("read PostgreSQL source tar entry")?;
        entries += 1;
        if entries > MAX_ARCHIVE_ENTRIES {
            bail!("PostgreSQL source archive has too many entries");
        }
        let path = entry.path().context("read PostgreSQL tar path")?;
        if path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            bail!("PostgreSQL source archive path escapes its root");
        }
        let normalized = path
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        let kind = entry.header().entry_type();
        if kind.is_pax_global_extensions() {
            if pax_global_seen || normalized != "pax_global_header" || entry.size() > 4096 {
                bail!("PostgreSQL source archive PAX global header drift");
            }
            pax_global_seen = true;
            continue;
        }
        if normalized != SOURCE_ROOT && !normalized.starts_with(&format!("{SOURCE_ROOT}/")) {
            bail!("PostgreSQL source archive has a second top-level root: {normalized:?}");
        }
        if !(kind.is_file() || kind.is_dir()) {
            bail!("PostgreSQL source archive contains a non-file/non-directory entry");
        }
        uncompressed = uncompressed
            .checked_add(entry.size())
            .context("PostgreSQL source size overflow")?;
        if uncompressed > MAX_UNCOMPRESSED_BYTES {
            bail!("PostgreSQL source archive expands beyond the fixed budget");
        }
        required.remove(&normalized);
        if normalized == format!("{SOURCE_ROOT}/COPYRIGHT") {
            let mut copyright = String::new();
            entry
                .take(4096)
                .read_to_string(&mut copyright)
                .context("read PostgreSQL COPYRIGHT")?;
            if !copyright.contains("PostgreSQL Global Development Group")
                || !copyright.contains("Permission to use, copy, modify, and distribute")
            {
                bail!("PostgreSQL source COPYRIGHT drift");
            }
        }
    }
    if entries < 1000 || !pax_global_seen || !required.is_empty() {
        bail!("PostgreSQL source archive is incomplete: missing={required:?}");
    }
    Ok(())
}

fn download(url: &str, output: &Path) -> Result<()> {
    if !url.starts_with("https://ftp.postgresql.org/pub/source/v17.11/") {
        bail!("PostgreSQL source URL is outside the exact PGDG release directory");
    }
    let status = Command::new("curl")
        .args([
            "--proto",
            "=https",
            "--tlsv1.2",
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--output",
        ])
        .arg(output)
        .arg(url)
        .stdin(Stdio::null())
        .status()
        .context("run curl for PostgreSQL source")?;
    if !status.success() {
        bail!("PostgreSQL source download failed: {status}");
    }
    Ok(())
}

fn verify_size(path: &Path, expected: u64) -> Result<()> {
    let actual = fs::metadata(path)
        .with_context(|| format!("stat {}; run postgres fetch-source", path.display()))?
        .len();
    if actual != expected {
        bail!("PostgreSQL source size mismatch: expected {expected}, got {actual}");
    }
    Ok(())
}

fn verify_sha(path: &Path, expected: &str) -> Result<()> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    let actual = format!("{:x}", hash.finalize());
    if actual != expected {
        bail!("PostgreSQL source sha256 mismatch: expected {expected}, got {actual}");
    }
    Ok(())
}

fn archive_path(root: &Path, archive: &str) -> PathBuf {
    root.join("target/postgres/source").join(archive)
}

fn string<'a>(table: &'a toml::Table, key: &str) -> Result<&'a str> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .with_context(|| format!("PostgreSQL pin `{key}` must be a string"))
}

fn positive_u64(table: &toml::Table, key: &str) -> Result<u64> {
    let value = table
        .get(key)
        .and_then(toml::Value::as_integer)
        .with_context(|| format!("PostgreSQL pin `{key}` must be an integer"))?;
    if value <= 0 {
        bail!("PostgreSQL pin `{key}` must be positive");
    }
    u64::try_from(value).context("PostgreSQL pin integer overflow")
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_in_pin_checksum_and_runtime_constants_join() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap();
        let pin = source_pin(root).unwrap();
        assert_eq!(pin.version, "17.11");
        assert_eq!(pin.size_bytes, 28_397_423);
        assert_eq!(
            pin.sha256,
            "5367f6fb2ec97efe1eb2e0c7926bb33438e51b0bd3a9733b88498056a7dc9a7e"
        );
    }

    #[test]
    fn sha_and_pin_shapes_reject_case_truncation_and_zero() {
        assert!(valid_sha256(&"a1".repeat(32)));
        assert!(!valid_sha256(&"A1".repeat(32)));
        assert!(!valid_sha256("a1"));
        let mut table = toml::Table::new();
        table.insert("size".to_owned(), toml::Value::Integer(0));
        assert!(positive_u64(&table, "size").is_err());
    }
}
