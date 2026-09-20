use super::record::{HelperJournalPhase, HelperJournalRecord, HelperKind};
use super::*;
use crate::postgres_sidecar::{PostgresBundleDigest, PostgresStartLock};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use wrokbot_macos_process::ProcessIdentity;

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Harness {
    root: PathBuf,
    data_dir: PathBuf,
    instance: String,
    lock: Option<PostgresStartLock>,
}

impl Harness {
    fn new(tag: &str) -> Self {
        let instance = "d".repeat(64);
        let root = std::env::temp_dir().join(format!(
            "wrokbot-helper-journal-{tag}-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let lock =
            PostgresStartLock::acquire(&root, &instance, PostgresBundleDigest([0x4a; 32])).unwrap();
        Self {
            root,
            data_dir,
            instance,
            lock: Some(lock),
        }
    }

    fn lock(&self) -> &PostgresStartLock {
        self.lock.as_ref().unwrap()
    }

    fn lock_mut(&mut self) -> &mut PostgresStartLock {
        self.lock.as_mut().unwrap()
    }

    fn journal_path(&self) -> PathBuf {
        self.root
            .join(format!(".postgresql-17-{}.helper-v1.json", self.instance))
    }

    fn prepare(&self) -> HelperJournalPreparation {
        HelperJournalPreparation::inspect(self.lock(), &self.data_dir).unwrap()
    }

    fn begin(&mut self) -> HelperJournal {
        let preparation = self.prepare();
        self.lock_mut().preserve_on_drop();
        preparation
            .begin_helper(self.lock(), HelperKind::VersionPostgres)
            .unwrap()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if std::thread::panicking() {
            if let Some(lock) = self.lock.as_mut() {
                lock.preserve_on_drop();
            }
            eprintln!(
                "helper journal test preserved failure evidence at {}",
                self.root.display()
            );
            return;
        }
        drop(self.lock.take());
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct OwnedChild(Option<Child>);

impl OwnedChild {
    fn sleeping() -> Self {
        Self(Some(
            Command::new("/bin/sleep")
                .env_clear()
                .arg("0.25")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        ))
    }

    fn identity(&self) -> ProcessIdentity {
        ProcessIdentity::capture(self.0.as_ref().unwrap().id()).unwrap()
    }

    fn wait_success(&mut self) {
        let mut child = self.0.take().unwrap();
        assert!(child.wait().unwrap().success());
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true).mode(0o600);
    let mut file = options.open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}

fn exited_child_observation() -> String {
    let mut child = OwnedChild::sleeping();
    let identity = child.identity();
    let bytes = identity.evidence_bytes().unwrap();
    child.wait_success();
    encode_hex(&bytes)
}

fn complete_record(
    harness: &Harness,
    kind: HelperKind,
    child_observation: &str,
) -> HelperJournalRecord {
    let preparation = HelperJournalPreparation::inspect(harness.lock(), &harness.data_dir).unwrap();
    HelperJournalRecord {
        schema: "openbot-postgres-helper".to_owned(),
        schema_version: 1,
        instance_id: harness.instance.clone(),
        data_dir_name: format!("postgresql-17-{}", harness.instance),
        data_dir_device: preparation.data_dir_device,
        data_dir_inode: preparation.data_dir_inode,
        attempt_id: "12".repeat(16),
        start_evidence_sha256: start_evidence_sha256(harness.lock()),
        owner_observation: encode_hex(&preparation.owner_observation),
        helper_kind: kind,
        child_observation: Some(child_observation.to_owned()),
        phase: HelperJournalPhase::HelpersComplete,
    }
}

fn write_complete(harness: &Harness, kind: HelperKind, child_observation: &str) -> Vec<u8> {
    let record = complete_record(harness, kind, child_observation);
    let bytes = encode_record(&record).unwrap();
    write_private(&harness.journal_path(), &bytes);
    bytes
}

fn assert_invalid_record(mutator: impl FnOnce(&mut serde_json::Value)) {
    let harness = Harness::new("invalid-record");
    let child = exited_child_observation();
    let record = complete_record(&harness, HelperKind::VersionPgCtl, &child);
    let mut value = serde_json::to_value(record).unwrap();
    mutator(&mut value);
    write_private(
        &harness.journal_path(),
        &serde_json::to_vec(&value).unwrap(),
    );
    assert!(matches!(
        HelperJournalPreparation::inspect(harness.lock(), &harness.data_dir),
        Err(HelperJournalError::Invalid)
    ));
    assert!(harness.journal_path().exists());
}

#[test]
fn owned_helper_child_is_observed_then_confirmed() {
    let mut child = OwnedChild::sleeping();
    let identity = child.identity();
    let mut harness = Harness::new("owned-helper-wait");
    let mut journal = harness.begin();
    journal.record_child(harness.lock(), &identity).unwrap();
    child.wait_success();
    journal.confirm_exit(harness.lock()).unwrap();
    assert_eq!(journal.record.phase, HelperJournalPhase::ExitConfirmed);
    assert_eq!(journal.record.helper_kind, HelperKind::VersionPostgres);
    let on_disk = fs::read(harness.journal_path()).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&on_disk).unwrap();
    assert_eq!(parsed["schema"], "openbot-postgres-helper");
    assert!(parsed.get("secret").is_none());
    assert!(parsed.get("stdout").is_none());
    assert!(parsed.as_object().unwrap().values().all(|value| {
        value
            .as_str()
            .map(|text| !text.starts_with('/'))
            .unwrap_or(true)
    }));
}

#[test]
fn kind_and_phase_gates_are_closed_and_monotonic() {
    let mut harness = Harness::new("kind-phase");
    let preparation = harness.prepare();
    harness.lock_mut().preserve_on_drop();
    assert!(matches!(
        preparation.begin_helper(harness.lock(), HelperKind::Initdb),
        Err(HelperJournalError::Invalid)
    ));

    let mut journal = harness.begin();
    let first_attempt = journal.record.attempt_id.clone();
    assert_eq!(journal.record.phase, HelperJournalPhase::SpawnEntered);
    assert!(journal.record.child_observation.is_none());
    assert!(matches!(
        journal.confirm_exit(harness.lock()),
        Err(HelperJournalError::ReconciliationRequired)
    ));
    assert!(matches!(
        journal.begin_next_helper(harness.lock(), HelperKind::VersionInitdb),
        Err(HelperJournalError::ReconciliationRequired)
    ));
    assert!(matches!(
        journal.mark_complete(harness.lock()),
        Err(HelperJournalError::ReconciliationRequired)
    ));

    let mut child = OwnedChild::sleeping();
    let identity = child.identity();
    journal.record_child(harness.lock(), &identity).unwrap();
    assert!(matches!(
        journal.record_child(harness.lock(), &identity),
        Err(HelperJournalError::ReconciliationRequired)
    ));
    child.wait_success();
    journal.confirm_exit(harness.lock()).unwrap();
    assert!(matches!(
        journal.begin_next_helper(harness.lock(), HelperKind::VersionPgCtl),
        Err(HelperJournalError::ReconciliationRequired)
    ));
    assert!(matches!(
        journal.begin_next_helper(harness.lock(), HelperKind::Initdb),
        Err(HelperJournalError::ReconciliationRequired)
    ));
    assert!(matches!(
        journal.mark_complete(harness.lock()),
        Err(HelperJournalError::ReconciliationRequired)
    ));

    journal
        .begin_next_helper(harness.lock(), HelperKind::VersionInitdb)
        .unwrap();
    assert_eq!(journal.record.attempt_id, first_attempt);
    assert_eq!(journal.record.helper_kind, HelperKind::VersionInitdb);
    assert_eq!(journal.record.phase, HelperJournalPhase::SpawnEntered);
    assert!(journal.record.child_observation.is_none());

    let mut child = OwnedChild::sleeping();
    let identity = child.identity();
    journal.record_child(harness.lock(), &identity).unwrap();
    child.wait_success();
    journal.confirm_exit(harness.lock()).unwrap();
    journal
        .begin_next_helper(harness.lock(), HelperKind::VersionPgCtl)
        .unwrap();
    let mut child = OwnedChild::sleeping();
    let identity = child.identity();
    journal.record_child(harness.lock(), &identity).unwrap();
    child.wait_success();
    journal.confirm_exit(harness.lock()).unwrap();
    journal.mark_complete(harness.lock()).unwrap();
    assert_eq!(journal.record.phase, HelperJournalPhase::HelpersComplete);
    assert_eq!(journal.record.helper_kind, HelperKind::VersionPgCtl);
    assert_eq!(journal.record.attempt_id, first_attempt);

    let retired = HelperJournalPreparation::inspect(harness.lock(), &harness.data_dir).unwrap();
    let next = retired
        .begin_helper(harness.lock(), HelperKind::VersionPostgres)
        .unwrap();
    assert_eq!(next.record.phase, HelperJournalPhase::SpawnEntered);
    assert_ne!(next.record.attempt_id, first_attempt);
    assert!(matches!(
        HelperJournalPreparation::inspect(harness.lock(), &harness.data_dir),
        Err(HelperJournalError::RecoveryRequired)
    ));
}

#[test]
fn unfinished_helper_is_recovery_required_and_does_not_rewrite() {
    let mut harness = Harness::new("unfinished");
    let journal = harness.begin();
    let original = fs::read(harness.journal_path()).unwrap();
    drop(journal);
    assert_eq!(fs::read(harness.journal_path()).unwrap(), original);
    assert!(matches!(
        HelperJournalPreparation::inspect(harness.lock(), &harness.data_dir),
        Err(HelperJournalError::RecoveryRequired)
    ));
    assert_eq!(fs::read(harness.journal_path()).unwrap(), original);
}

#[test]
fn record_is_closed_canonical_and_bounded() {
    let child = exited_child_observation();
    let harness = Harness::new("record-boundary");
    let valid = write_complete(&harness, HelperKind::VersionPgCtl, &child);
    assert!(valid.len() < JOURNAL_MAX_BYTES);
    assert!(HelperJournalPreparation::inspect(harness.lock(), &harness.data_dir).is_ok());

    let mut exact = valid.clone();
    exact.resize(JOURNAL_MAX_BYTES, b' ');
    write_private(&harness.journal_path(), &exact);
    assert_eq!(fs::metadata(harness.journal_path()).unwrap().len(), 2048);
    assert!(HelperJournalPreparation::inspect(harness.lock(), &harness.data_dir).is_ok());
    exact.push(b' ');
    write_private(&harness.journal_path(), &exact);
    assert!(matches!(
        HelperJournalPreparation::inspect(harness.lock(), &harness.data_dir),
        Err(HelperJournalError::Invalid)
    ));

    assert_invalid_record(|value| {
        value.as_object_mut().unwrap().remove("attemptId");
    });
    assert_invalid_record(|value| {
        value.as_object_mut().unwrap().remove("childObservation");
    });
    assert_invalid_record(|value| value["unknown"] = serde_json::json!(true));
    assert_invalid_record(|value| value["schemaVersion"] = serde_json::json!(2));
    assert_invalid_record(|value| value["phase"] = serde_json::json!("unknown"));
    assert_invalid_record(|value| value["helperKind"] = serde_json::json!("postgres"));
    assert_invalid_record(|value| value["attemptId"] = serde_json::json!("AA".repeat(16)));
    assert_invalid_record(|value| value["childObservation"] = serde_json::Value::Null);
    assert_invalid_record(|value| {
        value["phase"] = serde_json::json!("spawn_entered");
    });
}

#[test]
fn mark_complete_only_from_last_version_or_initdb_exit() {
    let mut harness = Harness::new("complete-gate");
    let mut journal = harness.begin();
    let mut child = OwnedChild::sleeping();
    let identity = child.identity();
    journal.record_child(harness.lock(), &identity).unwrap();
    child.wait_success();
    journal.confirm_exit(harness.lock()).unwrap();
    assert!(matches!(
        journal.mark_complete(harness.lock()),
        Err(HelperJournalError::ReconciliationRequired)
    ));
    journal
        .begin_next_helper(harness.lock(), HelperKind::VersionInitdb)
        .unwrap();
    let mut child = OwnedChild::sleeping();
    let identity = child.identity();
    journal.record_child(harness.lock(), &identity).unwrap();
    child.wait_success();
    journal.confirm_exit(harness.lock()).unwrap();
    assert!(matches!(
        journal.mark_complete(harness.lock()),
        Err(HelperJournalError::ReconciliationRequired)
    ));
    journal
        .begin_next_helper(harness.lock(), HelperKind::VersionPgCtl)
        .unwrap();
    let mut child = OwnedChild::sleeping();
    let identity = child.identity();
    journal.record_child(harness.lock(), &identity).unwrap();
    child.wait_success();
    journal.confirm_exit(harness.lock()).unwrap();
    journal.mark_complete(harness.lock()).unwrap();
}
