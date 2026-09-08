//! macOS HostLocal Engine driver and profile lifetime, without transport or product authority.
//!
//! The host must supply verified scope/instance facts and advance generation after retirement.
//! This module is not a PG authorizer, execution-realm fallback, real-navigation implementation,
//! or A3 acceptance. It still opens only the engine's fixed internal page. The current shim's
//! persistent partition still includes workspace; directory/lock reuse here does not prove or
//! implement cross-workspace website cookie/session continuity.

use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use openbot_contracts::auth::AuthContext;
use openbot_contracts::ids::TabId;
use openbot_contracts::screen::ScreenSessionTarget;
use tokio::sync::{Mutex, watch};

use crate::browser::BrowserInput;
use crate::control::{ControlService, HumanInputTicket};
use crate::engine::{
    EngineBundle, EngineLaunchConfig, EngineProcess, EngineRole, EngineSandboxFidelity,
    ScreenAudience,
};
use crate::manager::{
    BrowserDriverFuture, BrowserInstance, BrowserLease, BrowserRetirementReason,
    BrowserRuntimeBudget, BrowserRuntimeDriver, BrowserRuntimeError, BrowserRuntimeManager,
};
use crate::screen::ScreenHub;
use crate::screen::engine_owner::{ScreenEngineError, ScreenEngineOwner, ScreenEngineState};

const START_BOUND: Duration = Duration::from_secs(15);
const STOP_BOUND: Duration = Duration::from_secs(3);
const LIFECYCLE_WAIT_BOUND: Duration = Duration::from_secs(18);
// Darwin fcntl.h: O_NOFOLLOW. This module is intentionally macOS-only; do not reuse on Linux.
const NOFOLLOW: i32 = 0x0000_0100;

/// Explicit macOS host inputs. No renderer, URL, free environment or realm selector is accepted.
pub struct HostLocalRuntimeConfig {
    /// Already digest-verified bundle owned by the host release.
    pub bundle: EngineBundle,
    /// Private canonical host-owned root, separate from product DB/Vault roots.
    pub root: PathBuf,
    /// One verified local actor and auth generation for the lifetime of this runtime.
    pub audience: ScreenAudience,
    /// Existing typed residency limits.
    pub budget: BrowserRuntimeBudget,
}

/// Read-only selected target; scope/principal/path/process identity never appear in this projection.
#[derive(Clone, Debug)]
pub struct HostLocalTarget {
    /// Exact target to echo. It is not permission to drive or view it.
    pub target: ScreenSessionTarget,
    /// Actual launched process fidelity.
    pub fidelity: EngineSandboxFidelity,
    /// Current owner state, including failure/closure.
    pub state: ScreenEngineState,
}

/// Stable codes only, including unknown operation outcomes after a transport boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HostLocalRuntimeError {
    /// Root/lock is missing authority-private filesystem shape or contains a symlink.
    #[error("host_local_root_invalid")]
    Root,
    /// A different process still owns this exact persistent profile.
    #[error("host_local_profile_busy")]
    ProfileBusy,
    /// Requested target/actor/generation is not the exact owned instance.
    #[error("host_local_target_refused")]
    Refused,
    /// The runtime or session has retired and cannot accept new work.
    #[error("host_local_runtime_closed")]
    Closed,
    /// A bounded queue/residency limit refused admission before effect.
    #[error("host_local_runtime_busy")]
    Busy,
    /// Engine/lifecycle failed. An already dispatched input must not be automatically retried.
    #[error("host_local_runtime_unavailable")]
    Unavailable,
}

/// Single host facade over the existing residency manager. It has no second process registry.
/// Lifecycle serialization orders profile switches; the manager remains the only handle owner.
pub struct HostLocalBrowserRuntime {
    manager: BrowserRuntimeManager<HostLocalEngineDriver>,
    lifecycle: Mutex<()>,
    stop: watch::Sender<bool>,
    audience: ScreenAudience,
}

impl HostLocalBrowserRuntime {
    /// Validate/create the private root and share the caller's exact ScreenHub.
    pub fn new(
        config: HostLocalRuntimeConfig,
        hub: ScreenHub,
    ) -> Result<Self, HostLocalRuntimeError> {
        private_directory(&config.root)?;
        private_directory(&config.root.join("profiles"))?;
        private_directory(&config.root.join("workspaces"))?;
        private_directory(&config.root.join("locks"))?;
        let (stop, stopped) = watch::channel(false);
        let audience = config.audience.clone();
        Ok(Self {
            manager: BrowserRuntimeManager::new(
                HostLocalEngineDriver {
                    bundle: config.bundle,
                    root: config.root,
                    audience: config.audience,
                    hub,
                    stopped,
                },
                config.budget,
            ),
            lifecycle: Mutex::new(()),
            stop,
            audience,
        })
    }

    /// Reuse an exact instance or retire its inactive profile owner before launching a replacement.
    /// The caller owns durable generation minting. A stopped instance must never be reminted with
    /// the same ComputerId/generation; this execution adapter does not invent a second PG ledger.
    pub async fn ensure(
        &self,
        instance: BrowserInstance,
        now_ms: u64,
    ) -> Result<HostLocalTarget, HostLocalRuntimeError> {
        let _lifecycle = self.lifecycle.lock().await;
        self.ensure_open()?;
        self.ensure_tenant(&instance)?;
        for current in self.manager.resident_instances().map_err(runtime_error)? {
            if current.scope().profile_digest() != instance.scope().profile_digest() {
                continue;
            }
            if current == instance {
                let lease = self.lease(&instance, now_ms)?;
                let browser = lease.lock().await;
                let target = browser.snapshot();
                if matches!(
                    target.state,
                    ScreenEngineState::Closed | ScreenEngineState::Failed
                ) {
                    return Err(HostLocalRuntimeError::Closed);
                }
                return Ok(target);
            }
            let current_scope = EngineRole::BrowserComputer(current.scope().clone()).scope_digest();
            let wanted_scope = EngineRole::BrowserComputer(instance.scope().clone()).scope_digest();
            if current_scope == wanted_scope
                && (current.computer_id() != instance.computer_id()
                    || instance.generation() <= current.generation())
            {
                return Err(HostLocalRuntimeError::Refused);
            }
            // Ensure never implicitly cancels activity. The manager atomically refuses Busy
            // before removing the entry or sending shutdown; the host must explicitly Stop a
            // HumanLease/input before switching its profile. For inactive profiles, close first
            // so Chromium releases its lock before launch. A failed replacement is not restored.
            self.manager.stop(&current).await.map_err(runtime_error)?;
        }
        let lease = self
            .manager
            .ensure(instance, now_ms)
            .await
            .map_err(runtime_error)?;
        let target = lease.lock().await.snapshot();
        Ok(target)
    }

    /// Inspect an existing exact instance; never starts a missing or stale target.
    pub async fn target(
        &self,
        instance: &BrowserInstance,
        now_ms: u64,
    ) -> Result<HostLocalTarget, HostLocalRuntimeError> {
        self.ensure_open()?;
        let lease = self.lease(instance, now_ms)?;
        let target = lease.lock().await.snapshot();
        Ok(target)
    }

    /// Host-authorized takeover only; a transport must perform policy/audit before this call.
    /// The owner task holds the residency lease until release/expiry/Stop, even if the caller drops.
    pub async fn take_control(
        &self,
        instance: &BrowserInstance,
        auth: AuthContext,
        expires_at: time::OffsetDateTime,
        now_ms: u64,
    ) -> Result<HumanInputTicket, HostLocalRuntimeError> {
        self.authorize_actor(&auth)?;
        let lease = self.lease(instance, now_ms)?;
        let client = lease.lock().await.owner.client();
        client
            .take_control(auth, expires_at, Box::new(lease))
            .await
            .map_err(screen_error)
    }

    /// Release only the exact actor/instance/epoch echoed by the current HumanLease.
    pub async fn release_control(
        &self,
        instance: &BrowserInstance,
        auth: AuthContext,
        ticket: HumanInputTicket,
        now_ms: u64,
    ) -> Result<(), HostLocalRuntimeError> {
        self.authorize_actor(&auth)?;
        let lease = self.lease(instance, now_ms)?;
        let client = lease.lock().await.owner.client();
        client
            .release_control(auth, ticket, Box::new(lease))
            .await
            .map_err(screen_error)
    }

    /// Queue typed input with a residency lease owned by the queue, not by the awaiting caller.
    /// Already dispatched failures are unknown outcomes; this method never retries input.
    pub async fn apply_input(
        &self,
        instance: &BrowserInstance,
        auth: AuthContext,
        ticket: HumanInputTicket,
        input: BrowserInput,
        now_ms: u64,
    ) -> Result<(), HostLocalRuntimeError> {
        self.authorize_actor(&auth)?;
        let lease = self.lease(instance, now_ms)?;
        let client = lease.lock().await.owner.client();
        client
            .apply_input(auth, ticket, input, Box::new(lease))
            .await
            .map_err(screen_error)
    }

    /// Freeze input, revoke the source and drain queue-owned leases before manager retirement.
    /// An old instance never stops a newer same-profile replacement.
    pub async fn stop(&self, instance: &BrowserInstance) -> Result<bool, HostLocalRuntimeError> {
        self.ensure_tenant(instance)?;
        // Freeze this exact existing target before waiting behind an unrelated cold start.
        // No target means no action; cancelling an ensure that has not returned a target is not
        // this API's contract. Shutdown separately signals every in-flight host owner.
        if !self.freeze_instance(instance).await? {
            return Ok(false);
        }
        let _lifecycle = tokio::time::timeout(LIFECYCLE_WAIT_BOUND, self.lifecycle.lock())
            .await
            .map_err(|_| HostLocalRuntimeError::Unavailable)?;
        self.finish_stop(instance).await
    }

    /// Idle eviction continues to use the original manager and skips input/HumanLease activity.
    pub async fn sweep_idle(&self, now_ms: u64) -> Result<usize, HostLocalRuntimeError> {
        let _lifecycle = self.lifecycle.lock().await;
        self.ensure_open()?;
        self.manager.sweep_idle(now_ms).await.map_err(runtime_error)
    }

    /// Stop admission synchronously, then join every manager-owned session.
    pub async fn shutdown(&self) -> Result<usize, HostLocalRuntimeError> {
        self.stop.send_replace(true);
        let _lifecycle = tokio::time::timeout(LIFECYCLE_WAIT_BOUND, self.lifecycle.lock())
            .await
            .map_err(|_| HostLocalRuntimeError::Unavailable)?;
        let instances = self.manager.resident_instances().map_err(runtime_error)?;
        let mut first_error = None;
        for instance in &instances {
            if let Err(error) = self.stop_inner(instance).await {
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        self.manager.close_all().await.map_err(runtime_error)?;
        Ok(instances.len())
    }

    async fn stop_inner(&self, instance: &BrowserInstance) -> Result<bool, HostLocalRuntimeError> {
        if !self.freeze_instance(instance).await? {
            return Ok(false);
        }
        self.finish_stop(instance).await
    }

    async fn freeze_instance(
        &self,
        instance: &BrowserInstance,
    ) -> Result<bool, HostLocalRuntimeError> {
        let lease = self
            .manager
            .acquire_existing(instance, 0)
            .map_err(runtime_error)?;
        let Some(lease) = lease else {
            return Ok(false);
        };
        let client = lease.lock().await.owner.client();
        client.request_shutdown();
        drop(lease);
        Ok(true)
    }

    // Caller holds the outer lifecycle lock. If a concurrent exact Stop or inactive replacement
    // retired the original while we waited, the old target is already stopped; never touch the
    // newer instance. A cleanup timeout after the signal is Unknown/Unavailable, not pre-effect Busy.
    async fn finish_stop(&self, instance: &BrowserInstance) -> Result<bool, HostLocalRuntimeError> {
        match self.manager.stop_after_drain(instance, STOP_BOUND).await {
            Ok(_)
            | Err(
                BrowserRuntimeError::StaleGeneration | BrowserRuntimeError::ScopeIdentityConflict,
            ) => Ok(true),
            Err(BrowserRuntimeError::Busy) => Err(HostLocalRuntimeError::Unavailable),
            Err(error) => Err(runtime_error(error)),
        }
    }

    fn lease(
        &self,
        instance: &BrowserInstance,
        now_ms: u64,
    ) -> Result<BrowserLease<HostLocalEngineDriver>, HostLocalRuntimeError> {
        self.ensure_open()?;
        self.ensure_tenant(instance)?;
        self.manager
            .acquire_existing(instance, now_ms)
            .map_err(runtime_error)?
            .ok_or(HostLocalRuntimeError::Refused)
    }
    fn ensure_open(&self) -> Result<(), HostLocalRuntimeError> {
        if *self.stop.borrow() {
            Err(HostLocalRuntimeError::Closed)
        } else {
            Ok(())
        }
    }
    fn ensure_tenant(&self, instance: &BrowserInstance) -> Result<(), HostLocalRuntimeError> {
        if EngineRole::BrowserComputer(instance.scope().clone()).tenant_id()
            != self.audience.tenant_id()
        {
            Err(HostLocalRuntimeError::Refused)
        } else {
            Ok(())
        }
    }
    fn authorize_actor(&self, auth: &AuthContext) -> Result<(), HostLocalRuntimeError> {
        self.ensure_open()?;
        if auth.tenant() != self.audience.tenant_id()
            || auth.actor() != self.audience.actor_id()
            || auth.auth_generation() != self.audience.auth_generation()
        {
            Err(HostLocalRuntimeError::Refused)
        } else {
            Ok(())
        }
    }
}

impl Drop for HostLocalBrowserRuntime {
    fn drop(&mut self) {
        // Queue-owned activity leases may outlive this facade. The parent signal still reaches
        // the unique task and releases them, the process and profile lock through bounded cleanup.
        self.stop.send_replace(true);
    }
}

struct HostLocalEngineDriver {
    bundle: EngineBundle,
    root: PathBuf,
    audience: ScreenAudience,
    hub: ScreenHub,
    stopped: watch::Receiver<bool>,
}
struct HostLocalBrowser {
    owner: ScreenEngineOwner,
    target: ScreenSessionTarget,
    fidelity: EngineSandboxFidelity,
}
impl HostLocalBrowser {
    fn snapshot(&self) -> HostLocalTarget {
        HostLocalTarget {
            target: self.target.clone(),
            fidelity: self.fidelity,
            state: *self.owner.observe().borrow(),
        }
    }
}
impl BrowserRuntimeDriver for HostLocalEngineDriver {
    type Browser = HostLocalBrowser;
    type Error = HostLocalRuntimeError;
    fn launch<'a>(
        &'a self,
        instance: &'a BrowserInstance,
    ) -> BrowserDriverFuture<'a, Self::Browser, Self::Error> {
        Box::pin(async move {
            if *self.stopped.borrow() {
                return Err(HostLocalRuntimeError::Closed);
            }
            let profile_key = hex(&instance.scope().profile_digest());
            let scope_key =
                hex(&EngineRole::BrowserComputer(instance.scope().clone()).scope_digest());
            let lock = ProfileLock::acquire(&self.root.join("locks").join(&profile_key))?;
            let profile = self.root.join("profiles").join(&profile_key);
            let temp = self.root.join("workspaces").join(&scope_key);
            private_directory(&profile)?;
            private_directory(&temp)?;
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random).map_err(|_| HostLocalRuntimeError::Unavailable)?;
            let tab = TabId::new(format!("host-tab-{}", hex(&random)));
            let control = Arc::new(Mutex::new(ControlService::new(
                instance.computer_id().clone(),
                tab.clone(),
                instance.generation(),
                time::OffsetDateTime::now_utc(),
            )));
            let config = EngineLaunchConfig::new(
                self.bundle.clone(),
                EngineRole::BrowserComputer(instance.scope().clone()),
                self.audience.clone(),
                instance.computer_id().clone(),
                instance.generation(),
                profile,
                temp,
            );
            let started = tokio::time::timeout(START_BOUND, async {
                let mut engine = EngineProcess::launch(config)
                    .await
                    .map_err(|_| HostLocalRuntimeError::Unavailable)?;
                engine
                    .start_session(tab.clone())
                    .await
                    .map_err(|_| HostLocalRuntimeError::Unavailable)?;
                let fidelity = engine.sandbox_fidelity();
                let owner = ScreenEngineOwner::attach_with_lifetime(
                    engine,
                    self.hub.clone(),
                    control,
                    Box::new(lock),
                    Some(self.stopped.clone()),
                )
                .await
                .map_err(screen_error)?;
                Ok(HostLocalBrowser {
                    owner,
                    target: ScreenSessionTarget {
                        computer_id: instance.computer_id().clone(),
                        computer_generation: instance.generation(),
                        tab_id: tab,
                    },
                    fidelity,
                })
            })
            .await;
            started.map_err(|_| HostLocalRuntimeError::Unavailable)?
        })
    }
    fn close<'a>(
        &'a self,
        browser: Self::Browser,
        _reason: BrowserRetirementReason,
    ) -> BrowserDriverFuture<'a, (), Self::Error> {
        Box::pin(async move { browser.owner.shutdown().await.map_err(screen_error) })
    }
}

struct ProfileLock(File);
impl ProfileLock {
    fn acquire(path: &Path) -> Result<Self, HostLocalRuntimeError> {
        validate_directory(path.parent().ok_or(HostLocalRuntimeError::Root)?)?;
        if let Ok(metadata) = fs::symlink_metadata(path)
            && (!metadata.is_file() || metadata.file_type().is_symlink() || metadata.nlink() != 1)
        {
            return Err(HostLocalRuntimeError::Root);
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(NOFOLLOW)
            .open(path)
            .map_err(|_| HostLocalRuntimeError::Root)?;
        let opened = file.metadata().map_err(|_| HostLocalRuntimeError::Root)?;
        let named = fs::symlink_metadata(path).map_err(|_| HostLocalRuntimeError::Root)?;
        if !opened.is_file()
            || opened.permissions().mode() & 0o777 != 0o600
            || opened.nlink() != 1
            || named.file_type().is_symlink()
            || opened.ino() != named.ino()
            || opened.dev() != named.dev()
        {
            return Err(HostLocalRuntimeError::Root);
        }
        file.try_lock().map_err(|error| match error {
            fs::TryLockError::WouldBlock => HostLocalRuntimeError::ProfileBusy,
            fs::TryLockError::Error(_) => HostLocalRuntimeError::Root,
        })?;
        Ok(Self(file))
    }
}
impl Drop for ProfileLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}
fn private_directory(path: &Path) -> Result<(), HostLocalRuntimeError> {
    if !path.is_absolute() {
        return Err(HostLocalRuntimeError::Root);
    }
    if !path.exists() {
        validate_directory_parent(path.parent().ok_or(HostLocalRuntimeError::Root)?)?;
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(HostLocalRuntimeError::Root),
        }
    }
    validate_directory(path)
}
fn validate_directory_parent(path: &Path) -> Result<(), HostLocalRuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| HostLocalRuntimeError::Root)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || path
            .canonicalize()
            .map_err(|_| HostLocalRuntimeError::Root)?
            != path
    {
        return Err(HostLocalRuntimeError::Root);
    }
    Ok(())
}
fn validate_directory(path: &Path) -> Result<(), HostLocalRuntimeError> {
    validate_directory_parent(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| HostLocalRuntimeError::Root)?;
    if metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(HostLocalRuntimeError::Root);
    }
    Ok(())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn screen_error(error: ScreenEngineError) -> HostLocalRuntimeError {
    match error {
        ScreenEngineError::Busy => HostLocalRuntimeError::Busy,
        ScreenEngineError::Closed => HostLocalRuntimeError::Closed,
        ScreenEngineError::InputRefused => HostLocalRuntimeError::Refused,
        ScreenEngineError::Unavailable => HostLocalRuntimeError::Unavailable,
    }
}
fn runtime_error(error: BrowserRuntimeError<HostLocalRuntimeError>) -> HostLocalRuntimeError {
    match error {
        BrowserRuntimeError::Closed => HostLocalRuntimeError::Closed,
        BrowserRuntimeError::Busy => HostLocalRuntimeError::Busy,
        BrowserRuntimeError::StaleGeneration | BrowserRuntimeError::ScopeIdentityConflict => {
            HostLocalRuntimeError::Refused
        }
        BrowserRuntimeError::Launch(error) => error,
        BrowserRuntimeError::Retirement(_) | BrowserRuntimeError::Invariant => {
            HostLocalRuntimeError::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct Root(PathBuf);
    impl Root {
        fn new() -> Self {
            let mut random = [0_u8; 8];
            getrandom::fill(&mut random).unwrap();
            let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "ob-host-lock-{}-{}",
                std::process::id(),
                hex(&random)
            ));
            private_directory(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn profile_lock_is_owned_not_a_lock_file_presence_flag() {
        let root = Root::new();
        let path = root.0.join("profile-lock");
        let first = ProfileLock::acquire(&path).unwrap();
        assert!(matches!(
            ProfileLock::acquire(&path),
            Err(HostLocalRuntimeError::ProfileBusy)
        ));
        drop(first);
        assert!(path.exists());
        drop(ProfileLock::acquire(&path).expect("OS release makes the existing lock reusable"));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn root_and_lock_reject_symlinks_and_non_private_permissions() {
        let root = Root::new();
        let actual = root.0.join("actual");
        private_directory(&actual).unwrap();
        let linked = root.0.join("linked");
        symlink(&actual, &linked).unwrap();
        assert_eq!(private_directory(&linked), Err(HostLocalRuntimeError::Root));
        let secret = root.0.join("untouched");
        fs::write(&secret, b"untouched").unwrap();
        let link = root.0.join("lock-link");
        symlink(&secret, &link).unwrap();
        assert!(matches!(
            ProfileLock::acquire(&link),
            Err(HostLocalRuntimeError::Root)
        ));
        assert_eq!(fs::read(&secret).unwrap(), b"untouched");
        fs::set_permissions(&actual, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(private_directory(&actual), Err(HostLocalRuntimeError::Root));
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            ProfileLock::acquire(&secret),
            Err(HostLocalRuntimeError::Root)
        ));
    }

    #[test]
    fn lock_excludes_other_process_and_kernel_close_releases_it() {
        let root = Root::new();
        let path = root.0.join("cross-process-lock");
        let lock = ProfileLock::acquire(&path).unwrap();
        let run = |busy: bool| {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "host_local_runtime::tests::lock_child",
                    "--exact",
                    "--ignored",
                    "--test-threads=1",
                ])
                .env_clear()
                .env("OB_HOST_LOCK_CHILD_PATH", &path)
                .env("OB_HOST_LOCK_CHILD_BUSY", if busy { "1" } else { "0" })
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status.success();
                }
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("owned lock probe timed out");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        assert!(run(true));
        drop(lock);
        assert!(run(false));
        // The child exited without running the Rust lock destructor; the OS closed its handle.
        drop(ProfileLock::acquire(&path).unwrap());
    }

    #[test]
    #[ignore = "subprocess helper; without its explicit parent input it performs no filesystem operation"]
    fn lock_child() {
        let Some(path) = std::env::var_os("OB_HOST_LOCK_CHILD_PATH") else {
            return;
        };
        let path = PathBuf::from(path);
        assert_eq!(path.file_name().unwrap(), "cross-process-lock");
        let parent = path.parent().unwrap();
        assert!(
            parent
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("ob-host-lock-")
        );
        assert!(
            path.is_file(),
            "parent must create lock before child starts"
        );
        let busy = std::env::var("OB_HOST_LOCK_CHILD_BUSY").unwrap() == "1";
        let result = ProfileLock::acquire(&path);
        assert_eq!(
            matches!(result, Err(HostLocalRuntimeError::ProfileBusy)),
            busy
        );
        if !busy {
            let _lock = result.unwrap();
            // Isolated subprocess only: bypass Rust Drop to prove kernel release on process exit.
            std::process::exit(0);
        }
    }
}
