//! Private owned-FS preparation checks. The PG immutable binding and actor/source authority are
//! exercised separately; preparing a syntactically valid marker does not establish either.

use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::Write as _;
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _, symlink,
};
use std::path::{Path, PathBuf};

use uuid::Uuid;

use super::{
    ArtifactRootPhysicalBinding, ArtifactStoreError, MARKER_NAME, MAX_MARKER_BYTES, StoreMarker,
    open_trusted_host_root, open_trusted_installation_artifact_root, prepare_root, read_marker,
};

struct OwnedRoot {
    container: PathBuf,
    root: PathBuf,
}

impl OwnedRoot {
    fn new() -> Self {
        let container =
            std::env::temp_dir().join(format!("openbot-artifact-root-{}", Uuid::now_v7()));
        DirBuilder::new().mode(0o700).create(&container).unwrap();
        // macOS may expose the temporary directory through an alias. Positive paths explicitly
        // resolve only our new container; negative tests then create their own symlink components.
        let container = fs::canonicalize(container).unwrap();
        let root = container.join("root");
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        Self { container, root }
    }

    fn open(&self) -> File {
        File::open(&self.root).unwrap()
    }

    fn marker_path(&self) -> PathBuf {
        self.root.join(MARKER_NAME)
    }
}

impl Drop for OwnedRoot {
    fn drop(&mut self) {
        let outcome = fs::remove_dir_all(&self.container);
        let absent = !self.container.exists();
        eprintln!(
            "ARTIFACT_ROOT_UNIT_CLEANUP removed={} absent={absent}",
            outcome.is_ok()
        );
        if !std::thread::panicking() {
            assert!(outcome.is_ok() && absent, "owned root cleanup failed");
        }
    }
}

fn namespace() -> (String, String, String) {
    (
        "owned-test-deployment".to_owned(),
        "owned-test-tenant".to_owned(),
        "018f0000-aaaa-7aaa-8aaa-aaaaaaaaaaaa".to_owned(),
    )
}

fn marker() -> StoreMarker {
    let ns = namespace();
    StoreMarker {
        schema: 1,
        deployment_id: ns.0,
        tenant_id: ns.1,
        dataset_id: ns.2,
        store_id: "018f0000-bbbb-7bbb-8bbb-bbbbbbbbbbbb".to_owned(),
    }
}

fn actual_file(path: &Path, bytes: &[u8], mode: u32) {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn empty_private_root_gets_a_sealed_canonical_marker_and_reopens_without_minting_identity() {
    let owned = OwnedRoot::new();
    let prepared = prepare_root(owned.open(), namespace()).unwrap();
    let actual = prepared.root.metadata().unwrap();
    assert!(prepared.fresh_marker);
    assert_eq!(actual.mode() & 0o7777, 0o700);
    assert_eq!(actual.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(prepared.physical.device(), actual.dev().to_string());
    assert_eq!(prepared.physical.inode(), actual.ino().to_string());
    assert_eq!(prepared.physical.uid(), actual.uid().to_string());
    let marker_metadata = fs::symlink_metadata(owned.marker_path()).unwrap();
    assert!(marker_metadata.is_file());
    assert_eq!(marker_metadata.mode() & 0o7777, 0o400);
    assert_eq!(marker_metadata.nlink(), 1);
    assert_eq!(marker_metadata.uid(), actual.uid());
    let id = Uuid::parse_str(&prepared.marker.store_id).unwrap();
    assert_eq!(id.get_version_num(), 7);
    assert_eq!(id.get_variant(), uuid::Variant::RFC4122);
    assert_eq!(id.to_string(), prepared.marker.store_id);
    assert_eq!(prepared.marker.schema, 1);
    assert_eq!(
        fs::read(owned.marker_path()).unwrap(),
        prepared.marker_bytes
    );
    assert_eq!(
        serde_json::to_vec(&prepared.marker).unwrap(),
        prepared.marker_bytes
    );
    let bytes = prepared.marker_bytes.clone();
    let physical = prepared.physical.clone();
    drop(prepared);
    let reopened = prepare_root(owned.open(), namespace()).unwrap();
    assert!(!reopened.fresh_marker);
    assert_eq!(reopened.marker_bytes, bytes);
    assert_eq!(reopened.physical, physical);
}

#[test]
fn actual_independently_opened_descriptor_cannot_acquire_a_live_kernel_owner_lock() {
    let owned = OwnedRoot::new();
    let first = prepare_root(owned.open(), namespace()).unwrap();
    assert!(matches!(
        prepare_root(owned.open(), namespace()),
        Err(ArtifactStoreError::Busy)
    ));
    drop(first);
    assert!(prepare_root(owned.open(), namespace()).is_ok());
}

#[test]
fn actual_root_modes_must_be_exactly_private_and_do_not_create_markers_on_refusal() {
    let owned = OwnedRoot::new();
    for mode in [0o600, 0o755, 0o777, 0o1700] {
        fs::set_permissions(&owned.root, Permissions::from_mode(mode)).unwrap();
        let result = prepare_root(owned.open(), namespace());
        fs::set_permissions(&owned.root, Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(result, Err(ArtifactStoreError::UnsafeRoot)));
        assert!(!owned.marker_path().exists());
    }
}

#[test]
fn a_regular_file_descriptor_is_not_a_directory_root() {
    let owned = OwnedRoot::new();
    let path = owned.container.join("regular-file");
    actual_file(&path, b"owned content", 0o700);
    assert!(matches!(
        prepare_root(File::open(path).unwrap(), namespace()),
        Err(ArtifactStoreError::UnsafeRoot)
    ));
    assert!(!owned.marker_path().exists());
}

#[test]
fn nonempty_unmarked_root_is_refused_without_adopting_existing_data() {
    let owned = OwnedRoot::new();
    let existing = owned.root.join("existing-owned-data");
    actual_file(&existing, b"existing content", 0o600);
    assert!(matches!(
        prepare_root(owned.open(), namespace()),
        Err(ArtifactStoreError::BindingMismatch)
    ));
    assert_eq!(fs::read(existing).unwrap(), b"existing content");
    assert!(!owned.marker_path().exists());
}

#[test]
fn each_changed_namespace_component_refuses_the_unchanged_sealed_marker() {
    let owned = OwnedRoot::new();
    let original = prepare_root(owned.open(), namespace()).unwrap();
    let bytes = original.marker_bytes.clone();
    drop(original);
    for changed in [
        (
            "changed-deployment".to_owned(),
            namespace().1,
            namespace().2,
        ),
        (namespace().0, "changed-tenant".to_owned(), namespace().2),
        (
            namespace().0,
            namespace().1,
            "018f0000-cccc-7ccc-8ccc-cccccccccccc".to_owned(),
        ),
    ] {
        assert!(matches!(
            prepare_root(owned.open(), changed),
            Err(ArtifactStoreError::BindingMismatch)
        ));
        assert_eq!(fs::read(owned.marker_path()).unwrap(), bytes);
    }
}

#[test]
fn copying_a_valid_marker_does_not_copy_the_actual_physical_root_tuple() {
    let original = OwnedRoot::new();
    let prepared = prepare_root(original.open(), namespace()).unwrap();
    let bytes = prepared.marker_bytes.clone();
    let physical = prepared.physical.clone();
    let store_id = prepared.marker.store_id.clone();
    drop(prepared);
    let copied = OwnedRoot::new();
    actual_file(&copied.marker_path(), &bytes, 0o400);
    // This private preparation helper parses local syntax. The actual PG factory separately
    // rejects the different root tuple; marker syntax alone must never be reported as that GO.
    let local = prepare_root(copied.open(), namespace()).unwrap();
    assert!(!local.fresh_marker);
    assert_eq!(local.marker.store_id, store_id);
    assert_eq!(local.marker_bytes, bytes);
    assert_ne!(local.physical, physical);
}

#[test]
fn invalid_json_unknown_fields_and_noncanonical_serialization_are_refused() {
    let canonical = serde_json::to_vec(&marker()).unwrap();
    let mut unknown = serde_json::to_value(marker()).unwrap();
    unknown["callerRoot"] = serde_json::Value::String("untrusted".to_owned());
    let mut trailing_whitespace = canonical.clone();
    trailing_whitespace.push(b'\n');
    let fixtures = [
        b"not JSON".to_vec(),
        serde_json::to_vec(&unknown).unwrap(),
        serde_json::to_vec_pretty(&marker()).unwrap(),
        trailing_whitespace,
    ];
    for bytes in fixtures {
        let owned = OwnedRoot::new();
        actual_file(&owned.marker_path(), &bytes, 0o400);
        assert!(matches!(
            prepare_root(owned.open(), namespace()),
            Err(ArtifactStoreError::BindingMismatch)
        ));
        assert_eq!(fs::read(owned.marker_path()).unwrap(), bytes);
    }
}

#[test]
fn marker_schema_uuid_version_variant_and_canonical_case_are_checked() {
    let mut bad_schema = marker();
    bad_schema.schema = 2;
    let mut wrong_version = marker();
    wrong_version.store_id = "018f0000-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_owned();
    let mut wrong_variant = marker();
    wrong_variant.store_id = "018f0000-bbbb-7bbb-0bbb-bbbbbbbbbbbb".to_owned();
    let mut wrong_case = marker();
    wrong_case.store_id = wrong_case.store_id.to_ascii_uppercase();
    let mut invalid_id = marker();
    invalid_id.store_id = "opaque-store-id".to_owned();
    for fixture in [
        bad_schema,
        wrong_version,
        wrong_variant,
        wrong_case,
        invalid_id,
    ] {
        let owned = OwnedRoot::new();
        let bytes = serde_json::to_vec(&fixture).unwrap();
        actual_file(&owned.marker_path(), &bytes, 0o400);
        assert!(matches!(
            prepare_root(owned.open(), namespace()),
            Err(ArtifactStoreError::BindingMismatch)
        ));
        assert_eq!(fs::read(owned.marker_path()).unwrap(), bytes);
    }
}

#[test]
fn actual_marker_mode_must_be_exactly_read_only_for_the_current_owner() {
    let bytes = serde_json::to_vec(&marker()).unwrap();
    for mode in [0o600, 0o444, 0o640, 0o700] {
        let owned = OwnedRoot::new();
        actual_file(&owned.marker_path(), &bytes, mode);
        assert!(matches!(
            read_marker(&owned.open()),
            Err(ArtifactStoreError::UnsafeRoot)
        ));
        assert_eq!(fs::read(owned.marker_path()).unwrap(), bytes);
    }
}

#[test]
fn actual_marker_symlink_is_refused_and_its_owned_target_is_unchanged() {
    let owned = OwnedRoot::new();
    let target = owned.container.join("target-marker");
    let bytes = serde_json::to_vec(&marker()).unwrap();
    actual_file(&target, &bytes, 0o400);
    symlink(&target, owned.marker_path()).unwrap();
    assert!(matches!(
        prepare_root(owned.open(), namespace()),
        Err(ArtifactStoreError::UnsafeRoot)
    ));
    assert_eq!(fs::read(target).unwrap(), bytes);
    assert!(
        fs::symlink_metadata(owned.marker_path())
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn a_second_actual_hard_link_prevents_marker_acceptance() {
    let owned = OwnedRoot::new();
    let bytes = serde_json::to_vec(&marker()).unwrap();
    actual_file(&owned.marker_path(), &bytes, 0o400);
    fs::hard_link(owned.marker_path(), owned.container.join("second-link")).unwrap();
    assert_eq!(fs::metadata(owned.marker_path()).unwrap().nlink(), 2);
    assert!(matches!(
        read_marker(&owned.open()),
        Err(ArtifactStoreError::UnsafeRoot)
    ));
}

#[test]
fn empty_or_oversized_actual_marker_is_unsafe_instead_of_an_absent_marker() {
    for length in [0, MAX_MARKER_BYTES + 1] {
        let owned = OwnedRoot::new();
        actual_file(&owned.marker_path(), &vec![b'x'; length as usize], 0o400);
        assert!(matches!(
            read_marker(&owned.open()),
            Err(ArtifactStoreError::UnsafeRoot)
        ));
        assert_eq!(fs::metadata(owned.marker_path()).unwrap().len(), length);
    }
}

#[test]
fn a_directory_at_the_marker_name_is_not_a_marker() {
    let owned = OwnedRoot::new();
    DirBuilder::new()
        .mode(0o700)
        .create(owned.marker_path())
        .unwrap();
    assert!(matches!(
        read_marker(&owned.open()),
        Err(ArtifactStoreError::UnsafeRoot)
    ));
}

#[test]
fn trusted_host_open_uses_the_actual_current_uid_and_rejects_relative_or_parent_paths() {
    let owned = OwnedRoot::new();
    let actual = open_trusted_host_root(&owned.root).unwrap();
    let observed = ArtifactRootPhysicalBinding::observe(&actual).unwrap();
    assert_eq!(
        observed.uid(),
        rustix::process::geteuid().as_raw().to_string()
    );
    assert_eq!(
        observed.inode(),
        fs::metadata(&owned.root).unwrap().ino().to_string()
    );
    assert!(matches!(
        open_trusted_host_root(Path::new("relative-owned-root")),
        Err(ArtifactStoreError::UnsafeRoot)
    ));
    let with_parent = owned.container.join("root/../root");
    assert!(matches!(
        open_trusted_host_root(&with_parent),
        Err(ArtifactStoreError::UnsafeRoot)
    ));
}

#[test]
fn trusted_host_open_refuses_a_real_symlink_in_a_parent_component() {
    let owned = OwnedRoot::new();
    let alias = owned.container.join("alias-parent");
    symlink(&owned.container, &alias).unwrap();
    assert!(matches!(
        open_trusted_host_root(&alias.join("root")),
        Err(ArtifactStoreError::UnsafeRoot)
    ));
    assert_eq!(fs::metadata(&owned.root).unwrap().mode() & 0o7777, 0o700);
    assert!(!owned.marker_path().exists());
}

#[test]
fn trusted_host_open_refuses_a_real_symlink_for_the_final_directory() {
    let owned = OwnedRoot::new();
    let alias = owned.container.join("alias-root");
    symlink(&owned.root, &alias).unwrap();
    assert!(matches!(
        open_trusted_host_root(&alias),
        Err(ArtifactStoreError::UnsafeRoot)
    ));
    assert!(!owned.marker_path().exists());
}

#[test]
fn trusted_installation_creates_only_the_private_fixed_child_and_reopens_its_identity() {
    let owned = OwnedRoot::new();
    let first = open_trusted_installation_artifact_root(&owned.root).unwrap();
    let child = owned.root.join("artifacts");
    let first_metadata = first.metadata().unwrap();
    assert_eq!(first_metadata.mode() & 0o7777, 0o700);
    assert_eq!(first_metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(first_metadata.ino(), fs::metadata(&child).unwrap().ino());
    assert_eq!(
        first_metadata.dev(),
        fs::metadata(&owned.root).unwrap().dev()
    );
    let entries = fs::read_dir(&owned.root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(entries, vec![std::ffi::OsString::from("artifacts")]);
    drop(first);
    let reopened = open_trusted_installation_artifact_root(&owned.root).unwrap();
    assert_eq!(reopened.metadata().unwrap().ino(), first_metadata.ino());
    assert_eq!(reopened.metadata().unwrap().dev(), first_metadata.dev());
}

#[test]
fn trusted_installation_refuses_an_existing_symlink_child_without_replacing_it() {
    let owned = OwnedRoot::new();
    let target = owned.container.join("owned-child-target");
    DirBuilder::new().mode(0o700).create(&target).unwrap();
    let existing = target.join("keep");
    actual_file(&existing, b"keep", 0o600);
    let child = owned.root.join("artifacts");
    symlink(&target, &child).unwrap();
    assert!(matches!(
        open_trusted_installation_artifact_root(&owned.root),
        Err(ArtifactStoreError::UnsafeRoot)
    ));
    assert!(
        fs::symlink_metadata(child)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(existing).unwrap(), b"keep");
}

#[test]
fn trusted_installation_refuses_an_existing_nonprivate_child_without_changing_mode() {
    let owned = OwnedRoot::new();
    let child = owned.root.join("artifacts");
    DirBuilder::new().mode(0o755).create(&child).unwrap();
    assert!(matches!(
        open_trusted_installation_artifact_root(&owned.root),
        Err(ArtifactStoreError::UnsafeRoot)
    ));
    assert_eq!(fs::metadata(child).unwrap().mode() & 0o7777, 0o755);
}
