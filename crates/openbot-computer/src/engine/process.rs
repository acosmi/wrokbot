//! Digest-before-spawn engine lifecycle with one-shot stdin boot and OS peer credentials.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};
#[cfg(unix)]
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use openbot_contracts::engine::{
    ENGINE_PROTOCOL_VERSION, ENGINE_RELEASE_EPOCH, MAX_ENGINE_CONTROL_FRAME_BYTES,
};
use openbot_contracts::ids::{ComputerGeneration, ComputerId, TabId};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::browser::{BrowserInput, CdpInputPlan, CdpInputPlanError};
use crate::control::AuthorizedHumanInput;

use super::frame::{EngineFrame, EngineFrameError, EngineFrameReader, read_frame_hello};
use super::protocol::{
    BootCapability, BootToken, EngineCommandWire, EngineEventWire, EngineInputKindWire,
    EngineOperationId, EngineProtocolError, encode_command,
};
use super::scope::{EngineRole, ScreenAudience};

#[cfg(windows)]
use openbot_windows_sandbox::{
    NamedPipeConnection, NamedPipeListener, RestrictedChild, SpawnPolicy,
};
#[cfg(any(unix, windows))]
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(unix)]
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
#[cfg(unix)]
use tokio::process::{Child, Command};
#[cfg(any(unix, windows))]
use tokio::sync::{Mutex, watch};
#[cfg(any(unix, windows))]
use tokio::task::JoinHandle;

#[cfg(unix)]
type EngineChild = Child;
#[cfg(windows)]
type EngineChild = RestrictedChild;
#[cfg(unix)]
type EnginePipeListener = UnixListener;
#[cfg(windows)]
type EnginePipeListener = NamedPipeListener;
#[cfg(unix)]
type EnginePipeConnection = tokio::net::UnixStream;
#[cfg(windows)]
type EnginePipeConnection = NamedPipeConnection;
#[cfg(unix)]
type EnginePipeReadHalf = OwnedReadHalf;
#[cfg(unix)]
type EnginePipeWriteHalf = OwnedWriteHalf;
#[cfg(windows)]
type EnginePipeReadHalf = tokio::io::ReadHalf<NamedPipeConnection>;
#[cfg(windows)]
type EnginePipeWriteHalf = tokio::io::WriteHalf<NamedPipeConnection>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(windows)]
const WINDOWS_JOB_MAX_PROCESSES: u32 = 32;
#[cfg(windows)]
const WINDOWS_JOB_MAX_MEMORY_BYTES: usize = 4 * 1024 * 1024 * 1024;

#[derive(Clone, Copy)]
enum EngineLaunchBoundary {
    PlatformDefault,
    #[cfg(target_os = "linux")]
    Runsc,
}

/// Positive in-container proof that the P1 probe is running under the authority-created runsc
/// bundle, not silently launching an unconfined Linux Engine on the host.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
pub struct RunscAttestation {
    _private: (),
}

#[cfg(target_os = "linux")]
impl RunscAttestation {
    /// Require the exact P1 host/rootfs and runsc marker before direct Engine spawn is enabled.
    pub fn detect() -> Result<Self, EngineProcessError> {
        if std::env::consts::ARCH != "x86_64"
            || !Path::new("/proc/gvisor/kernel_is_gvisor").is_file()
        {
            return Err(EngineProcessError::SandboxUnavailable);
        }
        let os_release = fs::read_to_string("/etc/os-release")?;
        let fields = os_release
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(key, value)| (key, value.trim_matches('"')))
            .collect::<BTreeMap<_, _>>();
        if fields.get("ID") != Some(&"ubuntu") || fields.get("VERSION_ID") != Some(&"24.04") {
            return Err(EngineProcessError::SandboxUnavailable);
        }
        Ok(Self { _private: () })
    }
}

/// Expected SHA-256 of the release-owned sidecar manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EngineBundleDigest([u8; 32]);

impl EngineBundleDigest {
    /// Parse one exact lowercase/uppercase SHA-256 string from signed release metadata.
    pub fn from_hex(value: &str) -> Result<Self, EngineProcessError> {
        if value.len() != 64 {
            return Err(EngineProcessError::BundleDigest);
        }
        let mut bytes = [0_u8; 32];
        let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
        if !remainder.is_empty() {
            return Err(EngineProcessError::BundleDigest);
        }
        for (index, pair) in pairs.iter().enumerate() {
            bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
        }
        Ok(Self(bytes))
    }
}

/// A bundle whose signed manifest and all named executable/ASAR/fuse files were hash-verified.
#[derive(Clone, Debug)]
pub struct EngineBundle {
    root: PathBuf,
    executable: PathBuf,
    manifest_sha256: [u8; 32],
}

impl EngineBundle {
    /// Load and verify a bundle against the release-owned manifest digest before any spawn.
    pub fn open(
        root: impl Into<PathBuf>,
        expected: EngineBundleDigest,
    ) -> Result<Self, EngineProcessError> {
        let root = root.into();
        let manifest_path = root.join("manifest.json");
        let manifest_bytes = fs::read(&manifest_path).map_err(EngineProcessError::Io)?;
        let manifest_sha256: [u8; 32] = Sha256::digest(&manifest_bytes).into();
        if manifest_sha256 != expected.0 {
            return Err(EngineProcessError::BundleDigest);
        }
        let manifest: BundleManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|_| EngineProcessError::BundleShape)?;
        if manifest.schema != "openbot-engine-bundle"
            || manifest.schema_version != 2
            || manifest.platform != expected_platform()
            || manifest.arch != std::env::consts::ARCH
            || manifest.electron_version != "43.3.0"
            || manifest.release_epoch != ENGINE_RELEASE_EPOCH
            || manifest.protocol_version != u64::from(ENGINE_PROTOCOL_VERSION)
            || manifest.product_name != "Acosmi Engine Fixture"
            || manifest.bundle_id != "com.acosmi.engine.fixture"
            || manifest.signing_profile
                != if cfg!(target_os = "macos") {
                    "local-hardened-adhoc-fixture-v1"
                } else {
                    "platform-fixture"
                }
            || manifest.fuse_wire != "000011001"
            || EngineBundleDigest::from_hex(&manifest.asar_header_sha256).is_err()
            || (
                manifest.executable.as_str(),
                manifest.fuse_file.as_str(),
                manifest.app_asar.as_str(),
            ) != expected_bundle_paths()
        {
            return Err(EngineProcessError::BundleShape);
        }
        let mut required_files = [
            manifest.executable.clone(),
            manifest.fuse_file.clone(),
            manifest.app_asar.clone(),
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
        #[cfg(target_os = "macos")]
        {
            for helper in macos_bundle_helpers(&root) {
                let relative = helper
                    .strip_prefix(&root)
                    .map_err(|_| EngineProcessError::BundleShape)?
                    .to_str()
                    .ok_or(EngineProcessError::BundleShape)?
                    .to_owned();
                required_files.insert(relative);
            }
        }
        #[cfg(not(target_os = "macos"))]
        let _ = &mut required_files;
        let manifest_files = manifest
            .files
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        if manifest_files != required_files {
            return Err(EngineProcessError::BundleShape);
        }
        for (relative, expected) in &manifest.files {
            let path = safe_join(&root, relative)?;
            if sha256_file(&path)? != *expected {
                return Err(EngineProcessError::BundleDigest);
            }
        }
        let executable = safe_join(&root, &manifest.executable)?;
        if !executable.is_file()
            || !safe_join(&root, &manifest.fuse_file)?.is_file()
            || !safe_join(&root, &manifest.app_asar)?.is_file()
        {
            return Err(EngineProcessError::BundleShape);
        }
        Ok(Self {
            root,
            executable,
            manifest_sha256,
        })
    }

    /// Verified bundle root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Verified main executable.
    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// Manifest digest checked before spawn.
    #[must_use]
    pub const fn manifest_sha256(&self) -> [u8; 32] {
        self.manifest_sha256
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Platform sandbox fidelity surfaced to readiness/diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineSandboxFidelity {
    /// OS sandbox profile applied; P1 macOS implementation.
    Enforced,
    /// Partial platform constraints only. It must be visible but may run browser/component roles.
    Degraded,
    /// No constraints could be applied; engine launch is refused.
    Unavailable,
}

/// Complete authority-owned launch input.
pub struct EngineLaunchConfig {
    bundle: EngineBundle,
    role: EngineRole,
    screen_audience: ScreenAudience,
    computer_id: ComputerId,
    generation: ComputerGeneration,
    profile_dir: PathBuf,
    temp_dir: PathBuf,
    #[cfg(target_os = "linux")]
    runsc_virtual_display: bool,
}

impl EngineLaunchConfig {
    /// Construct launch state. Paths are canonicalized/created before the sandbox profile is minted.
    #[must_use]
    pub fn new(
        bundle: EngineBundle,
        role: EngineRole,
        screen_audience: ScreenAudience,
        computer_id: ComputerId,
        generation: ComputerGeneration,
        profile_dir: impl Into<PathBuf>,
        temp_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            bundle,
            role,
            screen_audience,
            computer_id,
            generation,
            profile_dir: profile_dir.into(),
            temp_dir: temp_dir.into(),
            #[cfg(target_os = "linux")]
            runsc_virtual_display: false,
        }
    }

    /// Bind the P1 runsc probe to its fixed in-container Xvfb display without accepting a free
    /// DISPLAY string or inheriting host environment.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn with_runsc_probe_display(mut self) -> Self {
        self.runsc_virtual_display = true;
        self
    }
}

/// One role session's actual renderer/frame evidence.
pub struct StartedSession {
    /// Rust-validated JPEG frame.
    pub frame: EngineFrame,
    /// OS renderer PID reported by Electron and used only for conformance diagnostics.
    pub renderer_pid: u32,
    /// OS process creation time paired with PID to prevent PID-reuse ambiguity.
    pub renderer_creation_time: f64,
    /// Electron ProcessMetric OS-level sandbox result; required true on macOS/Windows.
    pub renderer_sandboxed: bool,
    /// Internal opaque origin; never a caller-provided URL.
    pub origin: String,
}

/// Counters for the Rust-owned size-one latest-frame ingress.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScreenIngressStats {
    received_frames: u64,
    dropped_before_consume: u64,
    acknowledged_frames: u64,
}

impl ScreenIngressStats {
    #[must_use]
    pub const fn received_frames(self) -> u64 {
        self.received_frames
    }

    #[must_use]
    pub const fn dropped_before_consume(self) -> u64 {
        self.dropped_before_consume
    }

    #[must_use]
    pub const fn acknowledged_frames(self) -> u64 {
        self.acknowledged_frames
    }
}

/// Verified Page.stopScreencast result joined to local ingress counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScreenStopReceipt {
    stats: ScreenIngressStats,
    replayed: bool,
}

/// Complete immutable identity of one engine screen stream.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScreenStreamKey {
    scope_digest: [u8; 32],
    computer_id: ComputerId,
    generation: ComputerGeneration,
    tab_id: TabId,
}

impl ScreenStreamKey {
    #[cfg(any(test, feature = "testkit"))]
    pub(crate) fn for_test(
        scope_digest: [u8; 32],
        computer_id: ComputerId,
        generation: ComputerGeneration,
        tab_id: TabId,
    ) -> Self {
        Self {
            scope_digest,
            computer_id,
            generation,
            tab_id,
        }
    }

    /// Opaque full security-scope digest.
    #[must_use]
    pub const fn scope_digest(&self) -> &[u8; 32] {
        &self.scope_digest
    }

    /// Computer identity.
    #[must_use]
    pub fn computer_id(&self) -> &ComputerId {
        &self.computer_id
    }

    /// Computer generation.
    #[must_use]
    pub const fn generation(&self) -> ComputerGeneration {
        self.generation
    }

    /// Active tab identity.
    #[must_use]
    pub fn tab_id(&self) -> &TabId {
        &self.tab_id
    }
}

/// Single attachable source for a [`crate::screen::ScreenHub`].
#[cfg(any(unix, windows))]
pub struct EngineScreenSource {
    key: ScreenStreamKey,
    audience: ScreenAudience,
    receiver: watch::Receiver<Option<Arc<EngineFrame>>>,
    state: Arc<Mutex<ScreenIngressState>>,
}

#[cfg(any(unix, windows))]
impl EngineScreenSource {
    /// Exact stream identity exposed to the Rust ScreenHub owner, never to a renderer.
    #[must_use]
    pub fn stream_key(&self) -> &ScreenStreamKey {
        &self.key
    }

    #[cfg(any(test, feature = "testkit"))]
    pub(crate) fn for_test(
        key: ScreenStreamKey,
        audience: ScreenAudience,
        receiver: watch::Receiver<Option<Arc<EngineFrame>>>,
    ) -> Self {
        Self {
            key,
            audience,
            receiver,
            state: Arc::new(Mutex::new(ScreenIngressState::default())),
        }
    }

    /// Stream key.
    pub(crate) fn key(&self) -> &ScreenStreamKey {
        self.stream_key()
    }

    /// Host-authorized audience.
    pub(crate) fn audience(&self) -> &ScreenAudience {
        &self.audience
    }

    /// Current latest frame, marking it observed for this source.
    pub(crate) async fn latest(&mut self) -> Result<Arc<EngineFrame>, EngineProcessError> {
        let frame = self
            .receiver
            .borrow_and_update()
            .as_ref()
            .cloned()
            .ok_or(EngineProcessError::ScreenIngressClosed)?;
        let mut state = self.state.lock().await;
        if state.failed {
            return Err(EngineProcessError::ScreenIngressClosed);
        }
        state.consumed_sequence = state.consumed_sequence.max(frame.sequence());
        Ok(frame)
    }

    /// Wait for the next latest frame.
    pub(crate) async fn next(&mut self) -> Result<Arc<EngineFrame>, EngineProcessError> {
        self.receiver
            .changed()
            .await
            .map_err(|_| EngineProcessError::ScreenIngressClosed)?;
        self.latest().await
    }
}

impl ScreenStopReceipt {
    #[must_use]
    pub const fn stats(self) -> ScreenIngressStats {
        self.stats
    }

    #[must_use]
    pub const fn replayed(self) -> bool {
        self.replayed
    }
}

#[cfg(any(unix, windows))]
#[derive(Default)]
struct ScreenIngressState {
    consumed_sequence: u64,
    published_sequence: u64,
    stats: ScreenIngressStats,
    failed: bool,
}

#[cfg(any(unix, windows))]
struct ScreenIngress {
    receiver: watch::Receiver<Option<Arc<EngineFrame>>>,
    state: Arc<Mutex<ScreenIngressState>>,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<()>,
}

#[cfg(any(unix, windows))]
impl ScreenIngress {
    async fn start(
        frame_reader: BufReader<EnginePipeReadHalf>,
        decoder: EngineFrameReader,
        control_writer: Arc<Mutex<EnginePipeWriteHalf>>,
        computer_id: ComputerId,
        generation: ComputerGeneration,
        tab_id: TabId,
        first_frame: &EngineFrame,
    ) -> Result<Self, EngineProcessError> {
        let (sender, mut receiver) = watch::channel(Some(Arc::new(first_frame.clone())));
        receiver.borrow_and_update();
        let state = Arc::new(Mutex::new(ScreenIngressState {
            consumed_sequence: first_frame.sequence(),
            published_sequence: first_frame.sequence(),
            stats: ScreenIngressStats {
                received_frames: 1,
                dropped_before_consume: 0,
                acknowledged_frames: 0,
            },
            failed: false,
        }));
        write_frame_ack(
            &control_writer,
            &computer_id,
            generation,
            &tab_id,
            first_frame,
        )
        .await?;
        state.lock().await.stats.acknowledged_frames = 1;

        let (shutdown, shutdown_receiver) = watch::channel(false);
        let task_state = Arc::clone(&state);
        let task = tokio::spawn(run_screen_ingress(
            frame_reader,
            decoder,
            control_writer,
            computer_id,
            generation,
            tab_id,
            sender,
            task_state,
            shutdown_receiver,
        ));
        Ok(Self {
            receiver,
            state,
            shutdown,
            task,
        })
    }

    async fn next_frame(&mut self) -> Result<EngineFrame, EngineProcessError> {
        self.receiver
            .changed()
            .await
            .map_err(|_| EngineProcessError::ScreenIngressClosed)?;
        let mut state = self.state.lock().await;
        if state.failed {
            return Err(EngineProcessError::ScreenIngressClosed);
        }
        let frame = self
            .receiver
            .borrow_and_update()
            .as_ref()
            .cloned()
            .ok_or(EngineProcessError::ScreenIngressClosed)?;
        state.consumed_sequence = state.consumed_sequence.max(frame.sequence());
        Ok((*frame).clone())
    }

    async fn stats(&self) -> Result<ScreenIngressStats, EngineProcessError> {
        let state = self.state.lock().await;
        if state.failed {
            Err(EngineProcessError::ScreenIngressClosed)
        } else {
            Ok(state.stats)
        }
    }

    async fn stop(self) -> Result<ScreenIngressStats, EngineProcessError> {
        self.shutdown.send_replace(true);
        if self.task.await.is_err() {
            return Err(EngineProcessError::ScreenIngressClosed);
        }
        let state = self.state.lock().await;
        if state.failed {
            Err(EngineProcessError::ScreenIngressClosed)
        } else {
            Ok(state.stats)
        }
    }
}

#[cfg(any(unix, windows))]
#[allow(clippy::too_many_arguments)]
async fn run_screen_ingress(
    mut frame_reader: BufReader<EnginePipeReadHalf>,
    mut decoder: EngineFrameReader,
    control_writer: Arc<Mutex<EnginePipeWriteHalf>>,
    computer_id: ComputerId,
    generation: ComputerGeneration,
    tab_id: TabId,
    sender: watch::Sender<Option<Arc<EngineFrame>>>,
    state: Arc<Mutex<ScreenIngressState>>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let frame = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
            frame = decoder.read(&mut frame_reader) => match frame {
                Ok(frame) => frame,
                Err(_) => {
                    state.lock().await.failed = true;
                    break;
                }
            }
        };
        let sequence = frame.sequence();
        {
            let mut locked = state.lock().await;
            let Some(received) = locked.stats.received_frames.checked_add(1) else {
                locked.failed = true;
                break;
            };
            locked.stats.received_frames = received;
            if locked.published_sequence > locked.consumed_sequence {
                let Some(dropped) = locked.stats.dropped_before_consume.checked_add(1) else {
                    locked.failed = true;
                    break;
                };
                locked.stats.dropped_before_consume = dropped;
            }
            locked.published_sequence = sequence;
            sender.send_replace(Some(Arc::new(frame.clone())));
        }
        if write_frame_ack(&control_writer, &computer_id, generation, &tab_id, &frame)
            .await
            .is_err()
        {
            state.lock().await.failed = true;
            break;
        }
        let mut locked = state.lock().await;
        let Some(acknowledged) = locked.stats.acknowledged_frames.checked_add(1) else {
            locked.failed = true;
            break;
        };
        locked.stats.acknowledged_frames = acknowledged;
    }
}

#[cfg(any(unix, windows))]
async fn write_frame_ack(
    writer: &Arc<Mutex<EnginePipeWriteHalf>>,
    computer_id: &ComputerId,
    generation: ComputerGeneration,
    tab_id: &TabId,
    frame: &EngineFrame,
) -> Result<(), EngineProcessError> {
    let command = EngineCommandWire::frame_ack(
        computer_id,
        generation,
        tab_id,
        frame.sequence(),
        frame.screencast_session_id(),
    );
    writer
        .lock()
        .await
        .write_all(&encode_command(&command)?)
        .await
        .map_err(Into::into)
}

#[cfg(any(unix, windows))]
/// Live engine process. Drop kills the child; normal shutdown additionally proves bounded cleanup.
pub struct EngineProcess {
    child: EngineChild,
    child_pid: u32,
    main_creation_time: f64,
    control_reader: BufReader<EnginePipeReadHalf>,
    control_writer: Arc<Mutex<EnginePipeWriteHalf>>,
    frame_reader: Option<BufReader<EnginePipeReadHalf>>,
    _frame_writer: EnginePipeWriteHalf,
    role: EngineRole,
    screen_audience: ScreenAudience,
    computer_id: ComputerId,
    generation: ComputerGeneration,
    _runtime: RuntimeDirectory,
    operation_sequence: AtomicU64,
    active_tab: Option<TabId>,
    session_started: bool,
    screen: Option<ScreenIngress>,
    screen_source_issued: bool,
    screen_casting: bool,
    last_stop: Option<(TabId, ScreenStopReceipt)>,
    fidelity: EngineSandboxFidelity,
}

#[cfg(not(any(unix, windows)))]
/// Placeholder type for unsupported targets; partial launch is refused.
pub struct EngineProcess;

#[cfg(any(unix, windows))]
impl EngineProcess {
    /// Spawn, authenticate both UDS connections, and complete hello/ready.
    pub async fn launch(config: EngineLaunchConfig) -> Result<Self, EngineProcessError> {
        Self::launch_with(config, EngineLaunchBoundary::PlatformDefault).await
    }

    /// P1 probe-only Linux launch after the surrounding runsc bundle has been positively attested.
    #[cfg(target_os = "linux")]
    pub async fn launch_inside_runsc(
        config: EngineLaunchConfig,
        _attestation: RunscAttestation,
    ) -> Result<Self, EngineProcessError> {
        if !config.runsc_virtual_display {
            return Err(EngineProcessError::SandboxUnavailable);
        }
        Self::launch_with(config, EngineLaunchBoundary::Runsc).await
    }

    async fn launch_with(
        config: EngineLaunchConfig,
        boundary: EngineLaunchBoundary,
    ) -> Result<Self, EngineProcessError> {
        if config.screen_audience.tenant_id() != config.role.tenant_id()
            || config
                .role
                .component_actor_id()
                .is_some_and(|actor| actor != config.screen_audience.actor_id())
        {
            return Err(EngineProcessError::ScreenAudience);
        }
        fs::create_dir_all(&config.profile_dir).map_err(EngineProcessError::Io)?;
        fs::create_dir_all(&config.temp_dir).map_err(EngineProcessError::Io)?;
        let profile_dir = config
            .profile_dir
            .canonicalize()
            .map_err(EngineProcessError::Io)?;
        let temp_dir = config
            .temp_dir
            .canonicalize()
            .map_err(EngineProcessError::Io)?;
        let bundle_root = config
            .bundle
            .root
            .canonicalize()
            .map_err(EngineProcessError::Io)?;

        let token = BootToken::random()?;
        let runtime = RuntimeDirectory::create(&token)?;
        let control_listener = bind_listener(&runtime.control_pipe)?;
        let frame_listener = bind_listener(&runtime.frame_pipe)?;
        let boot = BootCapability::new(
            &runtime.control_pipe,
            &runtime.frame_pipe,
            &token,
            &config.role,
            &config.computer_id,
            config.generation,
        )?;

        let (mut child, fidelity) = spawn_engine(
            &config.bundle.executable,
            &bundle_root,
            &profile_dir,
            &temp_dir,
            &runtime,
            boundary,
            #[cfg(target_os = "linux")]
            config.runsc_virtual_display,
        )?;
        let child_pid = child_pid(&child)?;
        write_boot(&mut child, &boot.line()?).await?;

        let (control, frame) = tokio::time::timeout(CONNECT_TIMEOUT, async {
            tokio::try_join!(
                accept_listener(control_listener),
                accept_listener(frame_listener)
            )
        })
        .await
        .map_err(|_| EngineProcessError::ConnectTimeout)??;
        verify_peer(&control, &mut child, child_pid)?;
        verify_peer(&frame, &mut child, child_pid)?;
        let (control_read, control_writer) = split_connection(control);
        let (frame_read, frame_writer) = split_connection(frame);
        let mut control_reader = BufReader::new(control_read);
        let mut frame_reader = BufReader::new(frame_read);
        tokio::time::timeout(CONNECT_TIMEOUT, read_frame_hello(&mut frame_reader, &token))
            .await
            .map_err(|_| EngineProcessError::FrameHelloTimeout)??;
        let hello = tokio::time::timeout(CONNECT_TIMEOUT, read_event(&mut control_reader))
            .await
            .map_err(|_| EngineProcessError::HelloTimeout)??;
        match hello {
            EngineEventWire::Hello { token: echoed } if echoed == token.hex() => {}
            _ => return Err(EngineProcessError::HelloAuthentication),
        }
        let ready = tokio::time::timeout(CONNECT_TIMEOUT, read_event(&mut control_reader))
            .await
            .map_err(|_| EngineProcessError::ReadyTimeout)??;
        let main_creation_time = match ready {
            EngineEventWire::Ready {
                main_pid,
                main_creation_time,
                protocol_version,
            } => {
                if main_pid != child_pid {
                    return Err(EngineProcessError::ReadyPid);
                }
                verify_main_creation_time(&child, main_creation_time)?;
                if protocol_version != ENGINE_PROTOCOL_VERSION {
                    return Err(EngineProcessError::ReadyProtocol);
                }
                main_creation_time
            }
            EngineEventWire::Error { code, .. } => return Err(reported(code)),
            _ => return Err(EngineProcessError::ReadyIdentity),
        };

        Ok(Self {
            child,
            child_pid,
            main_creation_time,
            control_reader,
            control_writer: Arc::new(Mutex::new(control_writer)),
            frame_reader: Some(frame_reader),
            _frame_writer: frame_writer,
            role: config.role,
            screen_audience: config.screen_audience,
            computer_id: config.computer_id,
            generation: config.generation,
            _runtime: runtime,
            operation_sequence: AtomicU64::new(0),
            active_tab: None,
            session_started: false,
            screen: None,
            screen_source_issued: false,
            screen_casting: false,
            last_stop: None,
            fidelity,
        })
    }

    /// Main process PID authenticated by UDS peer credentials.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.child_pid
    }

    /// OS process creation time paired with the peer-authenticated main PID.
    #[must_use]
    pub const fn main_creation_time(&self) -> f64 {
        self.main_creation_time
    }

    /// Platform confinement fidelity.
    #[must_use]
    pub const fn sandbox_fidelity(&self) -> EngineSandboxFidelity {
        self.fidelity
    }

    /// Start the one allowed P1 session, concurrently validating control outcome and binary frame.
    pub async fn start_session(
        &mut self,
        tab_id: TabId,
    ) -> Result<StartedSession, EngineProcessError> {
        if self.session_started {
            return Err(EngineProcessError::SessionAlreadyStarted);
        }
        let operation = self.next_operation()?;
        let command =
            EngineCommandWire::start(&operation, &self.computer_id, self.generation, &tab_id);
        self.control_writer
            .lock()
            .await
            .write_all(&encode_command(&command)?)
            .await?;
        let mut decoder = EngineFrameReader::new(
            self.role.kind(),
            self.computer_id.clone(),
            self.generation,
            tab_id.clone(),
        );
        let (event, frame) = read_operation_frame(
            &mut self.control_reader,
            self.frame_reader
                .as_mut()
                .ok_or(EngineProcessError::ScreenIngressClosed)?,
            &mut decoder,
            &operation,
        )
        .await?;
        match event {
            EngineEventWire::Started {
                operation_id,
                tab_id: echoed_tab,
                renderer_pid,
                renderer_creation_time,
                renderer_sandboxed,
                node_exposed,
                origin,
            } if operation_id == operation.as_str()
                && echoed_tab == tab_id.as_str()
                && renderer_pid != 0
                && renderer_identity_matches(&self.child, renderer_pid, renderer_creation_time)
                && renderer_sandbox_signal_matches(renderer_sandboxed)
                && !node_exposed
                && internal_origin_matches(self.role.kind(), &origin) =>
            {
                let frame_reader = self
                    .frame_reader
                    .take()
                    .ok_or(EngineProcessError::ScreenIngressClosed)?;
                let screen = ScreenIngress::start(
                    frame_reader,
                    decoder,
                    Arc::clone(&self.control_writer),
                    self.computer_id.clone(),
                    self.generation,
                    tab_id.clone(),
                    &frame,
                )
                .await?;
                self.active_tab = Some(tab_id);
                self.session_started = true;
                self.screen = Some(screen);
                self.screen_casting = true;
                Ok(StartedSession {
                    frame,
                    renderer_pid,
                    renderer_creation_time,
                    renderer_sandboxed,
                    origin,
                })
            }
            _ => Err(EngineProcessError::StartedIdentity),
        }
    }

    /// Apply one freshly authorized ordinary input through protocol-v4 and require an exact
    /// operation-bound acknowledgement. Frames remain on the independent [`Self::next_frame`]
    /// channel. `SecretInsert` is rejected before any control-pipe write.
    pub async fn apply_human_input(
        &mut self,
        authorization: AuthorizedHumanInput,
        input: &BrowserInput,
        now: time::OffsetDateTime,
    ) -> Result<(), EngineProcessError> {
        if authorization.computer_id() != &self.computer_id
            || authorization.computer_generation() != self.generation
            || self.active_tab.as_ref() != Some(authorization.tab_id())
            || now >= authorization.expires_at()
        {
            return Err(EngineProcessError::InputAuthority);
        }
        let plan = CdpInputPlan::try_from(input).map_err(EngineProcessError::InputPlan)?;
        let expected_kind = EngineInputKindWire::from_plan(&plan);
        let operation = self.next_operation()?;
        let command = EngineCommandWire::input(
            &operation,
            &self.computer_id,
            self.generation,
            authorization.tab_id(),
            &plan,
        );
        let bytes = encode_command(&command)?;
        self.control_writer.lock().await.write_all(&bytes).await?;
        let event = tokio::time::timeout(COMMAND_TIMEOUT, read_event(&mut self.control_reader))
            .await
            .map_err(|_| EngineProcessError::CommandTimeout)??;
        match event {
            EngineEventWire::InputApplied {
                operation_id,
                tab_id,
                input_kind,
            } if operation_id == operation.as_str()
                && tab_id == authorization.tab_id().as_str()
                && input_kind == expected_kind =>
            {
                Ok(())
            }
            EngineEventWire::Error { operation_id, code } => {
                Err(reported_for(&operation, operation_id, code))
            }
            _ => Err(EngineProcessError::InputAppliedIdentity),
        }
    }

    /// Read the next independently framed image for the active session. Input acknowledgements and
    /// Screen delivery intentionally remain separate channels so Page.startScreencast can replace
    /// the current conformance capture without changing the authority API.
    pub async fn next_frame(&mut self) -> Result<EngineFrame, EngineProcessError> {
        self.screen
            .as_mut()
            .ok_or(EngineProcessError::ScreenIngressClosed)?
            .next_frame()
            .await
    }

    /// Current exact size-one ingress counters.
    pub async fn screen_stats(&self) -> Result<ScreenIngressStats, EngineProcessError> {
        self.screen
            .as_ref()
            .ok_or(EngineProcessError::ScreenIngressClosed)?
            .stats()
            .await
    }

    /// Pause/resume only capture for this exact live tab. The renderer, document, input state,
    /// ingress decoder and monotonically increasing frame sequence all survive a pause.
    pub async fn set_screencast(
        &mut self,
        tab_id: &TabId,
        enabled: bool,
    ) -> Result<(), EngineProcessError> {
        if self.active_tab.as_ref() != Some(tab_id) {
            return Err(EngineProcessError::ScreencastIdentity);
        }
        let replay = self.screen_casting == enabled;
        let operation = self.next_operation()?;
        let command = EngineCommandWire::screencast(
            &operation,
            &self.computer_id,
            self.generation,
            tab_id,
            enabled,
        );
        self.control_writer
            .lock()
            .await
            .write_all(&encode_command(&command)?)
            .await?;
        let event = tokio::time::timeout(COMMAND_TIMEOUT, read_event(&mut self.control_reader))
            .await
            .map_err(|_| EngineProcessError::CommandTimeout)??;
        match event {
            EngineEventWire::ScreencastState {
                operation_id,
                tab_id: echoed_tab,
                enabled: echoed_enabled,
                received_frames,
                acknowledged_frames,
                replayed,
            } if operation_id == operation.as_str()
                && echoed_tab == tab_id.as_str()
                && echoed_enabled == enabled
                && replayed == replay =>
            {
                let received = parse_counter(&received_frames)?;
                let acknowledged = parse_counter(&acknowledged_frames)?;
                if acknowledged > received {
                    return Err(EngineProcessError::ScreencastIdentity);
                }
                if !enabled {
                    let local = self.screen_stats().await?;
                    if received != acknowledged
                        || received != local.received_frames
                        || acknowledged != local.acknowledged_frames
                    {
                        return Err(EngineProcessError::ScreencastIdentity);
                    }
                }
                self.screen_casting = enabled;
                Ok(())
            }
            EngineEventWire::Error { operation_id, code } => {
                Err(reported_for(&operation, operation_id, code))
            }
            _ => Err(EngineProcessError::ScreencastIdentity),
        }
    }

    /// Take the sole attachable ScreenHub source for this active engine session.
    pub fn take_screen_source(&mut self) -> Result<EngineScreenSource, EngineProcessError> {
        if self.screen_source_issued {
            return Err(EngineProcessError::ScreenSourceAlreadyIssued);
        }
        let tab_id = self
            .active_tab
            .clone()
            .ok_or(EngineProcessError::ScreenIngressClosed)?;
        let receiver = self
            .screen
            .as_ref()
            .ok_or(EngineProcessError::ScreenIngressClosed)?
            .receiver
            .clone();
        self.screen_source_issued = true;
        Ok(EngineScreenSource {
            key: ScreenStreamKey {
                scope_digest: self.role.scope_digest(),
                computer_id: self.computer_id.clone(),
                generation: self.generation,
                tab_id,
            },
            audience: self.screen_audience.clone(),
            receiver,
            state: Arc::clone(
                &self
                    .screen
                    .as_ref()
                    .ok_or(EngineProcessError::ScreenIngressClosed)?
                    .state,
            ),
        })
    }

    /// Stop one exact tab and require an operation-bound acknowledgement plus joined frame stats.
    /// Repeating the exact stop is idempotent and returns the frozen receipt with `replayed=true`.
    pub async fn stop_session(
        &mut self,
        tab_id: &TabId,
    ) -> Result<ScreenStopReceipt, EngineProcessError> {
        let replay = self.active_tab.is_none()
            && self
                .last_stop
                .as_ref()
                .is_some_and(|(stopped, _)| stopped == tab_id);
        if !replay && self.active_tab.as_ref() != Some(tab_id) {
            return Err(EngineProcessError::StoppedIdentity);
        }
        let operation = self.next_operation()?;
        let command =
            EngineCommandWire::stop(&operation, &self.computer_id, self.generation, tab_id);
        self.control_writer
            .lock()
            .await
            .write_all(&encode_command(&command)?)
            .await?;
        let event = tokio::time::timeout(COMMAND_TIMEOUT, read_event(&mut self.control_reader))
            .await
            .map_err(|_| EngineProcessError::CommandTimeout)??;
        match event {
            EngineEventWire::Stopped {
                operation_id,
                tab_id: echoed_tab,
                received_frames,
                acknowledged_frames,
                replayed,
            } if operation_id == operation.as_str() && echoed_tab == tab_id.as_str() => {
                let remote_received = parse_counter(&received_frames)?;
                let remote_acknowledged = parse_counter(&acknowledged_frames)?;
                if remote_received != remote_acknowledged || replayed != replay {
                    return Err(EngineProcessError::StoppedIdentity);
                }
                if replay {
                    let stored = self
                        .last_stop
                        .as_ref()
                        .map(|(_, receipt)| *receipt)
                        .ok_or(EngineProcessError::StoppedIdentity)?;
                    if stored.stats.received_frames != remote_received
                        || stored.stats.acknowledged_frames != remote_acknowledged
                    {
                        return Err(EngineProcessError::StoppedIdentity);
                    }
                    return Ok(ScreenStopReceipt {
                        stats: stored.stats,
                        replayed: true,
                    });
                }
                let local = self
                    .screen
                    .take()
                    .ok_or(EngineProcessError::ScreenIngressClosed)?
                    .stop()
                    .await?;
                if local.received_frames != remote_received
                    || local.acknowledged_frames != remote_acknowledged
                {
                    return Err(EngineProcessError::StoppedIdentity);
                }
                self.active_tab = None;
                self.screen_casting = false;
                let receipt = ScreenStopReceipt {
                    stats: local,
                    replayed: false,
                };
                self.last_stop = Some((tab_id.clone(), receipt));
                Ok(receipt)
            }
            EngineEventWire::Error { operation_id, code } => {
                Err(reported_for(&operation, operation_id, code))
            }
            _ => Err(EngineProcessError::StoppedIdentity),
        }
    }

    /// Graceful bounded shutdown. Timeout kills the process and returns a hard failure.
    pub async fn shutdown(mut self) -> Result<(), EngineProcessError> {
        if let Some(tab_id) = self.active_tab.clone() {
            let _ = self.stop_session(&tab_id).await?;
        }
        let operation = self.next_operation()?;
        self.control_writer
            .lock()
            .await
            .write_all(&encode_command(&EngineCommandWire::shutdown(&operation))?)
            .await?;
        let event = tokio::time::timeout(COMMAND_TIMEOUT, read_event(&mut self.control_reader))
            .await
            .map_err(|_| EngineProcessError::CommandTimeout)??;
        match event {
            EngineEventWire::ShutdownComplete { operation_id }
                if operation_id == operation.as_str() => {}
            EngineEventWire::Error { operation_id, code } => {
                return Err(reported_for(&operation, operation_id, code));
            }
            _ => return Err(EngineProcessError::ShutdownIdentity),
        }
        let status = match tokio::time::timeout(SHUTDOWN_TIMEOUT, wait_child(&mut self.child)).await
        {
            Ok(status) => status?,
            Err(_) => {
                kill_child(&mut self.child).await?;
                return Err(EngineProcessError::ShutdownTimeout);
            }
        };
        if !status.success() {
            return Err(EngineProcessError::Exited);
        }
        Ok(())
    }

    fn next_operation(&self) -> Result<EngineOperationId, EngineProcessError> {
        let previous = self
            .operation_sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| EngineProcessError::OperationExhausted)?;
        EngineOperationId::new(format!("op-{}", previous + 1)).map_err(Into::into)
    }
}

#[cfg(any(unix, windows))]
async fn read_operation_frame(
    control_reader: &mut BufReader<EnginePipeReadHalf>,
    frame_reader: &mut BufReader<EnginePipeReadHalf>,
    decoder: &mut EngineFrameReader,
    operation: &EngineOperationId,
) -> Result<(EngineEventWire, EngineFrame), EngineProcessError> {
    tokio::time::timeout(COMMAND_TIMEOUT, async {
        let event = read_event(control_reader);
        let frame = decoder.read(frame_reader);
        tokio::pin!(event);
        tokio::pin!(frame);
        tokio::select! {
            event = &mut event => {
                let event = event?;
                if let EngineEventWire::Error { operation_id, code } = &event {
                    return Err(reported_for(operation, operation_id.clone(), code.clone()));
                }
                let frame = frame.await?;
                Ok((event, frame))
            }
            frame = &mut frame => {
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(frame_error) => {
                        if let Ok(Ok(EngineEventWire::Error { operation_id, code })) =
                            tokio::time::timeout(Duration::from_secs(1), &mut event).await
                        {
                            return Err(reported_for(operation, operation_id, code));
                        }
                        return Err(frame_error.into());
                    }
                };
                let event = event.await?;
                Ok((event, frame))
            }
        }
    })
    .await
    .map_err(|_| EngineProcessError::CommandTimeout)?
}

#[cfg(not(any(unix, windows)))]
impl EngineProcess {
    /// Unsupported targets never fall back to an unconfined Engine.
    pub async fn launch(_config: EngineLaunchConfig) -> Result<Self, EngineProcessError> {
        Err(EngineProcessError::UnsupportedPlatform)
    }
}

#[cfg(unix)]
fn bind_listener(path: &Path) -> Result<EnginePipeListener, EngineProcessError> {
    let listener = UnixListener::bind(path)?;
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

#[cfg(windows)]
fn bind_listener(path: &Path) -> Result<EnginePipeListener, EngineProcessError> {
    NamedPipeListener::bind(path).map_err(|_| EngineProcessError::SandboxUnavailable)
}

#[cfg(unix)]
async fn accept_listener(
    listener: EnginePipeListener,
) -> Result<EnginePipeConnection, EngineProcessError> {
    listener
        .accept()
        .await
        .map(|(stream, _)| stream)
        .map_err(Into::into)
}

#[cfg(windows)]
async fn accept_listener(
    listener: EnginePipeListener,
) -> Result<EnginePipeConnection, EngineProcessError> {
    listener
        .accept()
        .await
        .map_err(|_| EngineProcessError::SandboxUnavailable)
}

#[cfg(unix)]
fn split_connection(connection: EnginePipeConnection) -> (EnginePipeReadHalf, EnginePipeWriteHalf) {
    connection.into_split()
}

#[cfg(windows)]
fn split_connection(connection: EnginePipeConnection) -> (EnginePipeReadHalf, EnginePipeWriteHalf) {
    tokio::io::split(connection)
}

#[cfg(unix)]
fn verify_peer(
    stream: &EnginePipeConnection,
    child: &mut EngineChild,
    child_pid: u32,
) -> Result<(), EngineProcessError> {
    let credential = stream.peer_cred()?;
    if credential.pid().and_then(|pid| u32::try_from(pid).ok()) != Some(child_pid) {
        return Err(EngineProcessError::PeerCredential);
    }
    if child.try_wait()?.is_some() {
        return Err(EngineProcessError::Exited);
    }
    // Holding the live Child and observing it still running prevents PID reuse between spawn and
    // credential verification; the OS cannot reuse a PID while that exact child remains alive.
    Ok(())
}

#[cfg(windows)]
fn verify_peer(
    stream: &EnginePipeConnection,
    child: &mut EngineChild,
    child_pid: u32,
) -> Result<(), EngineProcessError> {
    if child.identity().pid() != child_pid {
        return Err(EngineProcessError::SpawnIdentity);
    }
    stream
        .verify_peer(child.identity())
        .map_err(|_| EngineProcessError::PeerCredential)?;
    if child
        .try_wait()
        .map_err(|_| EngineProcessError::SandboxUnavailable)?
        .is_some()
    {
        return Err(EngineProcessError::Exited);
    }
    Ok(())
}

async fn read_event<R>(reader: &mut R) -> Result<EngineEventWire, EngineProcessError>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut line = Vec::new();
    let read = reader.read_until(b'\n', &mut line).await?;
    if read == 0 || line.last() != Some(&b'\n') || line.len() > MAX_ENGINE_CONTROL_FRAME_BYTES {
        return Err(EngineProcessError::ControlFrame);
    }
    line.pop();
    serde_json::from_slice(&line).map_err(|_| EngineProcessError::ControlFrame)
}

#[cfg(unix)]
fn spawn_engine(
    executable: &Path,
    bundle_root: &Path,
    profile_dir: &Path,
    temp_dir: &Path,
    runtime: &RuntimeDirectory,
    boundary: EngineLaunchBoundary,
    #[cfg(target_os = "linux")] runsc_virtual_display: bool,
) -> Result<(EngineChild, EngineSandboxFidelity), EngineProcessError> {
    let (mut command, fidelity) = launch_command(
        executable,
        bundle_root,
        profile_dir,
        temp_dir,
        runtime,
        boundary,
        #[cfg(target_os = "linux")]
        runsc_virtual_display,
    )?;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    command
        .spawn()
        .map(|child| (child, fidelity))
        .map_err(EngineProcessError::Io)
}

#[cfg(windows)]
fn spawn_engine(
    executable: &Path,
    bundle_root: &Path,
    profile_dir: &Path,
    temp_dir: &Path,
    _runtime: &RuntimeDirectory,
    boundary: EngineLaunchBoundary,
) -> Result<(EngineChild, EngineSandboxFidelity), EngineProcessError> {
    if !matches!(boundary, EngineLaunchBoundary::PlatformDefault) {
        return Err(EngineProcessError::SandboxUnavailable);
    }
    let policy = SpawnPolicy::new(
        executable,
        engine_args(profile_dir, temp_dir),
        bundle_root,
        profile_dir,
        temp_dir,
        WINDOWS_JOB_MAX_PROCESSES,
        WINDOWS_JOB_MAX_MEMORY_BYTES,
    )
    .map_err(|_| EngineProcessError::SandboxUnavailable)?;
    openbot_windows_sandbox::spawn_restricted(&policy)
        .map(|child| (child, EngineSandboxFidelity::Degraded))
        .map_err(|_| EngineProcessError::SandboxUnavailable)
}

#[cfg(unix)]
fn child_pid(child: &EngineChild) -> Result<u32, EngineProcessError> {
    child.id().ok_or(EngineProcessError::SpawnIdentity)
}

#[cfg(windows)]
fn child_pid(child: &EngineChild) -> Result<u32, EngineProcessError> {
    let pid = child.identity().pid();
    (pid != 0)
        .then_some(pid)
        .ok_or(EngineProcessError::SpawnIdentity)
}

#[cfg(unix)]
async fn write_boot(child: &mut EngineChild, line: &[u8]) -> Result<(), EngineProcessError> {
    let mut stdin = child.stdin.take().ok_or(EngineProcessError::BootPipe)?;
    stdin.write_all(line).await?;
    stdin.shutdown().await?;
    Ok(())
}

#[cfg(windows)]
async fn write_boot(child: &mut EngineChild, line: &[u8]) -> Result<(), EngineProcessError> {
    use std::io::Write as _;

    let mut stdin = child.take_stdin().ok_or(EngineProcessError::BootPipe)?;
    stdin.write_all(line)?;
    stdin.flush()?;
    drop(stdin);
    Ok(())
}

#[cfg(unix)]
fn verify_main_creation_time(
    _child: &EngineChild,
    reported: f64,
) -> Result<(), EngineProcessError> {
    (reported.is_finite() && reported > 0.0)
        .then_some(())
        .ok_or(EngineProcessError::ReadyCreationTime)
}

#[cfg(windows)]
fn verify_main_creation_time(child: &EngineChild, reported: f64) -> Result<(), EngineProcessError> {
    let expected = child
        .identity()
        .creation_unix_millis()
        .map_err(|_| EngineProcessError::ReadyCreationTime)?;
    (reported.is_finite() && reported == expected)
        .then_some(())
        .ok_or(EngineProcessError::ReadyCreationTime)
}

#[cfg(unix)]
fn renderer_identity_matches(_child: &EngineChild, pid: u32, creation_time: f64) -> bool {
    pid != 0 && creation_time.is_finite() && creation_time > 0.0
}

#[cfg(windows)]
fn renderer_identity_matches(child: &EngineChild, pid: u32, creation_time: f64) -> bool {
    child.verify_job_member(pid, creation_time).is_ok()
}

#[cfg(target_os = "linux")]
fn renderer_sandbox_signal_matches(reported: bool) -> bool {
    // Electron intentionally does not expose ProcessMetric.sandboxed on Linux. The P1 runsc probe
    // must keep this false and independently prove namespaces + Seccomp/NoNewPrivs from /proc.
    !reported
}

#[cfg(not(target_os = "linux"))]
fn renderer_sandbox_signal_matches(reported: bool) -> bool {
    reported
}

#[cfg(unix)]
async fn wait_child(
    child: &mut EngineChild,
) -> Result<std::process::ExitStatus, EngineProcessError> {
    child.wait().await.map_err(Into::into)
}

#[cfg(windows)]
async fn wait_child(
    child: &mut EngineChild,
) -> Result<std::process::ExitStatus, EngineProcessError> {
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| EngineProcessError::SandboxUnavailable)?
        {
            return Ok(status);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[cfg(unix)]
async fn kill_child(child: &mut EngineChild) -> Result<(), EngineProcessError> {
    child.kill().await.map_err(Into::into)
}

#[cfg(windows)]
async fn kill_child(child: &mut EngineChild) -> Result<(), EngineProcessError> {
    child
        .kill()
        .map_err(|_| EngineProcessError::SandboxUnavailable)
}

#[cfg(unix)]
fn launch_command(
    executable: &Path,
    bundle_root: &Path,
    profile_dir: &Path,
    temp_dir: &Path,
    runtime: &RuntimeDirectory,
    boundary: EngineLaunchBoundary,
    #[cfg(target_os = "linux")] runsc_virtual_display: bool,
) -> Result<(Command, EngineSandboxFidelity), EngineProcessError> {
    #[cfg(target_os = "macos")]
    {
        if !matches!(boundary, EngineLaunchBoundary::PlatformDefault) {
            return Err(EngineProcessError::SandboxUnavailable);
        }
        let profile = sandbox_profile(
            executable,
            bundle_root,
            profile_dir,
            temp_dir,
            &runtime.root,
        )?;
        fs::write(&runtime.sandbox_profile, profile)?;
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command
            .arg("-f")
            .arg(&runtime.sandbox_profile)
            .arg(executable);
        append_engine_args(&mut command, profile_dir, temp_dir);
        Ok((command, EngineSandboxFidelity::Enforced))
    }
    #[cfg(target_os = "linux")]
    {
        if !matches!(boundary, EngineLaunchBoundary::Runsc) || !runsc_virtual_display {
            return Err(EngineProcessError::SandboxUnavailable);
        }
        let _ = (bundle_root, runtime);
        let mut command = Command::new(executable);
        append_engine_args(&mut command, profile_dir, temp_dir);
        command.env("DISPLAY", ":99").env_remove("XAUTHORITY");
        Ok((command, EngineSandboxFidelity::Enforced))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (
            executable,
            bundle_root,
            profile_dir,
            temp_dir,
            runtime,
            boundary,
        );
        Err(EngineProcessError::SandboxUnavailable)
    }
}

#[cfg(unix)]
fn append_engine_args(command: &mut Command, profile_dir: &Path, temp_dir: &Path) {
    command
        .args(engine_args(profile_dir, temp_dir))
        // This changes only the child environment, never the host's HOME or other variables.
        // A blacklist of Electron switches leaked unrelated provider/DB credentials and loader
        // settings. Build this leaf process's complete environment from authority-owned paths.
        .env_clear()
        .env("HOME", profile_dir)
        .env("TMPDIR", temp_dir)
        .env("TEMP", temp_dir)
        .env("TMP", temp_dir)
        .env("PATH", "/usr/bin:/bin")
        .current_dir(profile_dir);
}

fn engine_args(profile_dir: &Path, temp_dir: &Path) -> Vec<OsString> {
    [
        format!("--user-data-dir={}", profile_dir.display()),
        format!("--disk-cache-dir={}", temp_dir.join("cache").display()),
        "--disable-background-networking".into(),
        "--disable-component-update".into(),
        "--disable-default-apps".into(),
        "--disable-features=WebRtcAllowInputVolumeAdjustment".into(),
        "--disable-quic".into(),
        "--disable-sync".into(),
        "--no-default-browser-check".into(),
        "--no-first-run".into(),
        "--proxy-server=http=127.0.0.1:1;https=127.0.0.1:1".into(),
        "--proxy-bypass-list=<-loopback>".into(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

#[cfg(target_os = "macos")]
fn macos_bundle_helpers(bundle: &Path) -> [PathBuf; 5] {
    let app = bundle.join("AcosmiEngine.app/Contents");
    [
        app.join("Frameworks/Electron Helper.app/Contents/MacOS/Electron Helper"),
        app.join("Frameworks/Electron Helper (GPU).app/Contents/MacOS/Electron Helper (GPU)"),
        app.join("Frameworks/Electron Helper (Plugin).app/Contents/MacOS/Electron Helper (Plugin)"),
        app.join(
            "Frameworks/Electron Helper (Renderer).app/Contents/MacOS/Electron Helper (Renderer)",
        ),
        app.join(
            "Frameworks/Electron Framework.framework/Versions/A/Helpers/chrome_crashpad_handler",
        ),
    ]
}

#[cfg(target_os = "macos")]
fn sandbox_profile(
    executable: &Path,
    bundle: &Path,
    profile: &Path,
    temp: &Path,
    runtime: &Path,
) -> Result<String, EngineProcessError> {
    let helpers = macos_bundle_helpers(bundle);
    for path in std::iter::once(executable)
        .chain(std::iter::once(bundle))
        .chain(std::iter::once(profile))
        .chain(std::iter::once(temp))
        .chain(std::iter::once(runtime))
        .chain(helpers.iter().map(PathBuf::as_path))
    {
        let value = path
            .to_str()
            .ok_or(EngineProcessError::SandboxUnavailable)?;
        if value.contains(['"', '\\', '\n', '\r', '\0']) {
            return Err(EngineProcessError::SandboxUnavailable);
        }
    }
    // Allow only scoped content and narrowly named OS resources. In particular, /System as a
    // whole includes /System/Volumes/Data and must never be a read-data allowlist entry.
    let os_roots = [
        "/System/Library",
        "/System/Cryptexes",
        "/System/Volumes/Preboot/Cryptexes/OS",
        "/System/Volumes/Preboot/Cryptexes/Incoming/OS",
        "/System/Volumes/Preboot/Cryptexes/App/System",
        "/usr/lib",
        "/usr/share",
        "/Library/Apple/System/Library",
        "/Library/Fonts",
        "/Library/ColorSync/Profiles",
        "/private/var/db/timezone",
    ];
    let content_roots = [bundle, profile, temp, runtime];
    // Current dyld/libignition opens the root directory as an openat anchor. A literal root
    // permits that directory handle only; it is deliberately not a subpath grant.
    let os_files = [
        "/",
        "/usr/bin/sandbox-exec",
        "/dev/null",
        "/dev/random",
        "/dev/urandom",
        "/private/etc/passwd",
        "/private/etc/hosts",
        "/private/etc/resolv.conf",
    ];
    let mut metadata = std::collections::BTreeSet::new();
    for path in content_roots
        .iter()
        .copied()
        .chain(os_roots.iter().map(Path::new))
        .chain(os_files.iter().map(Path::new))
        .chain(std::iter::once(executable))
    {
        for ancestor in path.ancestors() {
            metadata.insert(ancestor.to_path_buf());
        }
    }
    let mut reads = String::from("(deny file-read*)\n");
    for path in metadata {
        reads.push_str(&format!(
            "(allow file-read-metadata (literal \"{}\"))\n",
            path.display()
        ));
    }
    for path in content_roots
        .iter()
        .copied()
        .chain(os_roots.iter().map(Path::new))
    {
        reads.push_str(&format!(
            "(allow file-read* (subpath \"{}\"))\n",
            path.display()
        ));
    }
    for path in os_files
        .iter()
        .map(Path::new)
        .chain(std::iter::once(executable))
    {
        reads.push_str(&format!(
            "(allow file-read* (literal \"{}\"))\n",
            path.display()
        ));
    }
    Ok(format!(
        "(version 1)\n\
         (allow default)\n\
         {reads}\
         (deny file-write*)\n\
         (allow file-write* (subpath \"{}\") (subpath \"{}\") (subpath \"{}\") (literal \"/dev/null\"))\n\
         (deny network-inbound)\n\
         (deny network-outbound)\n\
         (allow network-outbound (literal \"{}\") (literal \"{}\"))\n\
         (deny process-exec*)\n\
         (allow process-exec* (literal \"{}\"))\n\
         (allow process-exec* (with no-sandbox) (literal \"{}\") (literal \"{}\") (literal \"{}\") (literal \"{}\") (literal \"{}\"))\n",
        profile.display(),
        temp.display(),
        runtime.display(),
        runtime.join("control.sock").display(),
        runtime.join("frame.sock").display(),
        executable.display(),
        helpers[0].display(),
        helpers[1].display(),
        helpers[2].display(),
        helpers[3].display(),
        helpers[4].display(),
    ))
}

#[cfg(unix)]
struct RuntimeDirectory {
    root: PathBuf,
    control_pipe: PathBuf,
    frame_pipe: PathBuf,
    #[cfg(target_os = "macos")]
    sandbox_profile: PathBuf,
}

#[cfg(unix)]
impl RuntimeDirectory {
    fn create(token: &BootToken) -> Result<Self, EngineProcessError> {
        #[cfg(target_os = "macos")]
        let base = Path::new("/private/tmp");
        #[cfg(not(target_os = "macos"))]
        let base = Path::new("/tmp");
        let root = base.join(format!("ob-eng-{}", &token.hex()[..16]));
        fs::create_dir(&root)?;
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            control_pipe: root.join("control.sock"),
            frame_pipe: root.join("frame.sock"),
            #[cfg(target_os = "macos")]
            sandbox_profile: root.join("engine.sb"),
            root,
        })
    }
}

#[cfg(unix)]
impl Drop for RuntimeDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.control_pipe);
        let _ = fs::remove_file(&self.frame_pipe);
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(windows)]
struct RuntimeDirectory {
    control_pipe: PathBuf,
    frame_pipe: PathBuf,
}

#[cfg(windows)]
impl RuntimeDirectory {
    fn create(token: &BootToken) -> Result<Self, EngineProcessError> {
        let nonce = token.hex();
        if nonce.len() != 32 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(EngineProcessError::SandboxUnavailable);
        }
        Ok(Self {
            control_pipe: PathBuf::from(format!(r"\\.\pipe\ob-eng-{nonce}.control")),
            frame_pipe: PathBuf::from(format!(r"\\.\pipe\ob-eng-{nonce}.frame")),
        })
    }
}

fn internal_origin_matches(role: super::scope::EngineRoleKind, origin: &str) -> bool {
    match role {
        super::scope::EngineRoleKind::BrowserComputer => origin == "acosmi-engine://session",
        super::scope::EngineRoleKind::SandboxedComponent => origin == "component://session",
    }
}

fn reported(code: String) -> EngineProcessError {
    if code.is_empty()
        || code.len() > 64
        || !code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        EngineProcessError::ControlFrame
    } else {
        EngineProcessError::EngineReported(code)
    }
}

fn reported_for(
    operation: &EngineOperationId,
    echoed: Option<String>,
    code: String,
) -> EngineProcessError {
    if echoed
        .as_deref()
        .is_some_and(|value| value != operation.as_str())
    {
        EngineProcessError::ControlFrame
    } else {
        reported(code)
    }
}

fn parse_counter(value: &str) -> Result<u64, EngineProcessError> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(EngineProcessError::StoppedIdentity);
    }
    value
        .parse::<u64>()
        .map_err(|_| EngineProcessError::StoppedIdentity)
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, EngineProcessError> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(EngineProcessError::BundleShape);
    }
    Ok(root.join(path))
}

fn expected_bundle_paths() -> (&'static str, &'static str, &'static str) {
    match std::env::consts::OS {
        "macos" => (
            "AcosmiEngine.app/Contents/MacOS/AcosmiEngine",
            "AcosmiEngine.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework",
            "AcosmiEngine.app/Contents/Resources/app.asar",
        ),
        "windows" => (
            "acosmi-engine-fixture.exe",
            "acosmi-engine-fixture.exe",
            "resources/app.asar",
        ),
        _ => (
            "acosmi-engine-fixture",
            "acosmi-engine-fixture",
            "resources/app.asar",
        ),
    }
}

fn expected_platform() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "macos-arm64",
        ("macos", "x86_64") => "macos-x64",
        ("linux", "aarch64") => "linux-arm64",
        ("linux", "x86_64") => "linux-x64",
        ("windows", "x86_64") => "windows-x64",
        _ => "unsupported",
    }
}

fn sha256_file(path: &Path) -> Result<String, EngineProcessError> {
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

fn hex_nibble(value: u8) -> Result<u8, EngineProcessError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(EngineProcessError::BundleDigest),
    }
}

/// Stable lifecycle/bundle failures.
#[derive(Debug, thiserror::Error)]
pub enum EngineProcessError {
    /// Capture state acknowledgement did not bind to the current tab/operation and exact counters.
    #[error("engine_screencast_identity")]
    ScreencastIdentity,
    /// Filesystem/socket/process operation failed.
    #[error("engine_io")]
    Io(#[from] std::io::Error),
    /// Boot/control protocol construction failed.
    #[error("engine_protocol")]
    Protocol(#[from] EngineProtocolError),
    /// Binary frame was malformed, stale, or unauthenticated.
    #[error("engine_frame")]
    Frame(#[from] EngineFrameError),
    /// Pure BrowserInput→CDP plan rejected a non-ordinary input before any pipe write.
    #[error("engine_input_plan")]
    InputPlan(#[source] CdpInputPlanError),
    /// Signed manifest digest or a named file digest did not match.
    #[error("engine_bundle_digest")]
    BundleDigest,
    /// Manifest/path/fixed release fields were malformed.
    #[error("engine_bundle_shape")]
    BundleShape,
    /// Child PID was unavailable immediately after spawn.
    #[error("engine_spawn_identity")]
    SpawnIdentity,
    /// Child stdin was not available for the one-line boot capability.
    #[error("engine_boot_pipe")]
    BootPipe,
    /// Engine failed to connect both private pipes within the deadline.
    #[error("engine_connect_timeout")]
    ConnectTimeout,
    /// Connected frame pipe did not send its token preface within the deadline.
    #[error("engine_frame_hello_timeout")]
    FrameHelloTimeout,
    /// Connected control pipe did not send its token hello within the deadline.
    #[error("engine_hello_timeout")]
    HelloTimeout,
    /// Authenticated shim did not reach Electron ready within the deadline.
    #[error("engine_ready_timeout")]
    ReadyTimeout,
    /// UDS/Named Pipe peer credential did not equal the live spawned child.
    #[error("engine_peer_credential")]
    PeerCredential,
    /// Control hello token was wrong.
    #[error("engine_hello_authentication")]
    HelloAuthentication,
    /// Ready protocol/PID did not match Rust-owned state.
    #[error("engine_ready_identity")]
    ReadyIdentity,
    /// Ready main PID differed from the peer-authenticated spawned PID.
    #[error("engine_ready_pid")]
    ReadyPid,
    /// Ready main process creation time was absent/non-finite.
    #[error("engine_ready_creation_time")]
    ReadyCreationTime,
    /// Ready protocol version differed from the Rust constant.
    #[error("engine_ready_protocol")]
    ReadyProtocol,
    /// Control frame was oversized, malformed, unknown, or truncated.
    #[error("engine_control_frame")]
    ControlFrame,
    /// Session command exceeded its deadline.
    #[error("engine_command_timeout")]
    CommandTimeout,
    /// Started event did not echo the exact operation/tab or exposed Node.
    #[error("engine_started_identity")]
    StartedIdentity,
    /// This P1 engine process already consumed its single session lifecycle.
    #[error("engine_session_already_started")]
    SessionAlreadyStarted,
    /// Fresh HumanLease receipt did not match this process/generation/active tab.
    #[error("engine_input_authority")]
    InputAuthority,
    /// Host-provided screen audience did not match the Rust-owned engine role scope.
    #[error("engine_screen_audience")]
    ScreenAudience,
    /// Input acknowledgement did not echo the exact operation/tab/kind.
    #[error("engine_input_applied_identity")]
    InputAppliedIdentity,
    /// The authenticated frame ingress stopped or failed before the caller consumed a frame.
    #[error("engine_screen_ingress_closed")]
    ScreenIngressClosed,
    /// A second ScreenHub tried to attach to the same engine stream.
    #[error("engine_screen_source_already_issued")]
    ScreenSourceAlreadyIssued,
    /// Stop acknowledgement did not match the operation.
    #[error("engine_stopped_identity")]
    StoppedIdentity,
    /// Shutdown acknowledgement did not match the operation.
    #[error("engine_shutdown_identity")]
    ShutdownIdentity,
    /// Graceful process cleanup exceeded five seconds.
    #[error("engine_shutdown_timeout")]
    ShutdownTimeout,
    /// Child exited unexpectedly or non-zero.
    #[error("engine_exited")]
    Exited,
    /// Engine returned one bounded stable error code.
    #[error("engine_reported:{0}")]
    EngineReported(String),
    /// Operation counter exhausted rather than wrapping.
    #[error("engine_operation_exhausted")]
    OperationExhausted,
    /// Required macOS/Windows/Linux process confinement could not be applied.
    #[error("engine_sandbox_unavailable")]
    SandboxUnavailable,
    /// Platform implementation is intentionally absent rather than silently unconfined.
    #[error("engine_platform_unsupported")]
    UnsupportedPlatform,
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{EngineBundle, EngineBundleDigest, EngineProcessError, safe_join};

    #[test]
    fn bundle_digest_parser_and_relative_paths_fail_closed() {
        assert!(EngineBundleDigest::from_hex(&"00".repeat(32)).is_ok());
        assert!(EngineBundleDigest::from_hex("00").is_err());
        assert!(matches!(
            safe_join(std::path::Path::new("/tmp/root"), "../escape"),
            Err(EngineProcessError::BundleShape)
        ));
    }

    #[test]
    fn manifest_digest_is_checked_before_manifest_shape() {
        let root = std::env::temp_dir().join(format!(
            "openbot-engine-bundle-negative-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("root");
        fs::write(root.join("manifest.json"), b"{}").expect("manifest");
        let result = EngineBundle::open(&root, EngineBundleDigest([0; 32]));
        assert!(matches!(result, Err(EngineProcessError::BundleDigest)));
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_profile_confines_main_and_releases_only_bundle_helpers_to_chromium_sandbox() {
        let profile = super::sandbox_profile(
            std::path::Path::new("/Applications/AcosmiEngine.app/Contents/MacOS/AcosmiEngine"),
            std::path::Path::new("/Applications/AcosmiEngine.app"),
            std::path::Path::new("/private/tmp/profile"),
            std::path::Path::new("/private/tmp/temp"),
            std::path::Path::new("/private/tmp/runtime"),
        )
        .expect("profile");
        for required in [
            "(deny file-write*)",
            "(deny network-inbound)",
            "(deny network-outbound)",
            "(literal \"/private/tmp/runtime/control.sock\")",
            "(literal \"/private/tmp/runtime/frame.sock\")",
            "(deny process-exec*)",
            "(with no-sandbox)",
            "(literal \"/Applications/AcosmiEngine.app/Contents/MacOS/AcosmiEngine\")",
            "Electron Helper (Renderer).app/Contents/MacOS/Electron Helper (Renderer)",
            "chrome_crashpad_handler",
        ] {
            assert!(profile.contains(required), "missing `{required}`");
        }
        assert_eq!(profile.matches("(with no-sandbox)").count(), 1);
        assert!(!profile.contains("(remote unix-socket)"));
        assert!(!profile.contains("localhost:*"));
        assert!(
            super::sandbox_profile(
                std::path::Path::new("/Applications/bad\"name.app/Contents/MacOS/AcosmiEngine"),
                std::path::Path::new("/Applications/bad\"name.app"),
                std::path::Path::new("/tmp/profile"),
                std::path::Path::new("/tmp/temp"),
                std::path::Path::new("/tmp/runtime"),
            )
            .is_err()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires macOS sandbox-exec; tests only owned synthetic files through the production policy generator"]
    fn macos_main_read_policy_blocks_sibling_symlink_and_data_volume_alias() {
        use std::os::unix::fs::symlink;
        use std::path::{Path, PathBuf};
        use std::process::Command;

        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../fixtures/computer/macos-engine-main-read-v1.json"
        ))
        .expect("read-boundary fixture");
        assert_eq!(fixture["schema"], "openbot-macos-engine-main-read-v1");
        assert!(
            fixture["remaining"]
                .as_object()
                .expect("unfinished boundaries")
                .values()
                .all(|value| value == false)
        );

        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let root =
            std::env::temp_dir().join(format!("openbot-macos-read-policy-{}", std::process::id()));
        assert!(
            !root.exists(),
            "test directory must not overwrite prior evidence"
        );
        fs::create_dir(&root).expect("owned test root");
        let root = root.canonicalize().expect("canonical root");
        let _cleanup = Cleanup(root.clone());
        let bundle = root.join("bundle");
        let profile = root.join("profile");
        let temp = root.join("temp");
        let runtime = root.join("runtime");
        let sibling = root.join("profile-other");
        for path in [&bundle, &profile, &temp, &runtime, &sibling] {
            fs::create_dir(path).expect("owned directory");
        }
        let inside = profile.join("inside.txt");
        let outside = sibling.join("canary.txt");
        fs::write(&inside, b"owned-readable-fixture").expect("inside fixture");
        fs::write(&outside, b"outside-synthetic-canary").expect("outside fixture");
        let link = profile.join("link-to-outside");
        symlink(&outside, &link).expect("owned test symlink");
        // This is a native policy probe, not an Electron substitute: only the approved main
        // executable is /bin/cat. Scope/bundle/OS rules come from the production generator.
        let rules =
            super::sandbox_profile(Path::new("/bin/cat"), &bundle, &profile, &temp, &runtime)
                .expect("production policy");
        let inspect = |path: &Path| {
            let child = Command::new("/usr/bin/sandbox-exec")
                .args(["-p", &rules, "/bin/cat"])
                .arg(path)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .current_dir(&profile)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("native policy probe");
            println!("main-read-policy owned_probe_pid={}", child.id());
            child.wait_with_output().expect("wait native policy probe")
        };
        let allowed = inspect(&inside);
        assert!(
            allowed.status.success(),
            "owned-file positive control failed ({:?}): {}",
            allowed.status,
            String::from_utf8_lossy(&allowed.stderr[..allowed.stderr.len().min(2048)])
        );
        assert!(allowed.stdout == b"owned-readable-fixture");
        let mut failures = 0;
        for (name, path) in [("sibling", outside.clone()), ("symlink", link)] {
            let result = inspect(&path);
            let leaked = result.status.success() || !result.stdout.is_empty();
            println!("main-read-policy case={name} outside_readable={leaked}");
            failures += usize::from(leaked);
        }
        let alias = Path::new("/System/Volumes/Data")
            .join(outside.strip_prefix("/").expect("absolute fixture"));
        if alias.exists() {
            let result = inspect(&alias);
            let leaked = result.status.success() || !result.stdout.is_empty();
            println!("main-read-policy case=data-volume-alias outside_readable={leaked}");
            failures += usize::from(leaked);
        } else {
            println!("main-read-policy case=data-volume-alias unavailable=true");
        }
        let list_rules =
            super::sandbox_profile(Path::new("/bin/ls"), &bundle, &profile, &temp, &runtime)
                .expect("list policy");
        let own_listing = Command::new("/usr/bin/sandbox-exec")
            .args(["-p", &list_rules, "/bin/ls"])
            .arg(&profile)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&profile)
            .output()
            .expect("own directory positive control");
        assert!(own_listing.status.success());
        assert!(
            own_listing
                .stdout
                .windows(b"inside.txt".len())
                .any(|bytes| bytes == b"inside.txt")
        );
        let listed = Command::new("/usr/bin/sandbox-exec")
            .args(["-p", &list_rules, "/bin/ls"])
            .arg(&sibling)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&profile)
            .output()
            .expect("directory read probe");
        let enumerated = listed.status.success() || !listed.stdout.is_empty();
        println!("main-read-policy case=sibling-listing outside_readable={enumerated}");
        failures += usize::from(enumerated);

        let hardlink = profile.join("hardlink-to-outside");
        fs::hard_link(&outside, &hardlink).expect("filesystem hardlink positive control");
        fs::remove_file(&hardlink).expect("reset hardlink control");
        let link_rules =
            super::sandbox_profile(Path::new("/bin/ln"), &bundle, &profile, &temp, &runtime)
                .expect("link policy");
        let own_hardlink = profile.join("hardlink-to-inside");
        let own_linked = Command::new("/usr/bin/sandbox-exec")
            .args(["-p", &link_rules, "/bin/ln"])
            .arg(&inside)
            .arg(&own_hardlink)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&profile)
            .output()
            .expect("own hardlink positive control");
        assert!(own_linked.status.success());
        assert!(fs::read(&own_hardlink).expect("own linked data") == b"owned-readable-fixture");
        let linked = Command::new("/usr/bin/sandbox-exec")
            .args(["-p", &link_rules, "/bin/ln"])
            .arg(&outside)
            .arg(&hardlink)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&profile)
            .output()
            .expect("hardlink creation probe");
        let linked_outside = linked.status.success() || hardlink.exists();
        println!("main-read-policy case=hardlink-creation outside_linkable={linked_outside}");
        failures += usize::from(linked_outside);
        assert_eq!(
            failures, 0,
            "outside reads must be denied without returning any canary bytes"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires native macOS sandbox-exec and task-owned sockets; not an Engine/helper compromise claim"]
    fn macos_main_network_policy_only_connects_its_two_owned_pipes() {
        use std::net::TcpListener;
        use std::os::unix::net::UnixListener;
        use std::path::{Path, PathBuf};
        use std::process::Command;

        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../fixtures/computer/macos-engine-main-network-v1.json"
        ))
        .expect("main network fixture");
        assert_eq!(fixture["schema"], "openbot-macos-engine-main-network-v1");
        assert!(
            fixture["allowed_tcp_ports"]
                .as_array()
                .expect("TCP ports")
                .is_empty()
        );
        assert!(
            fixture["remaining"]
                .as_object()
                .expect("unfinished boundaries")
                .values()
                .all(|v| v == false)
        );

        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let root = Path::new("/private/tmp").join(format!("ob-net-{}", std::process::id()));
        assert!(!root.exists());
        fs::create_dir(&root).expect("own root");
        let root = root.canonicalize().expect("canonical root");
        let _cleanup = Cleanup(root.clone());
        let bundle = root.join("bundle");
        let profile = root.join("profile");
        let temp = root.join("temp");
        let runtime = root.join("runtime");
        let sibling = root.join("sibling");
        for path in [&bundle, &profile, &temp, &runtime, &sibling] {
            fs::create_dir(path).expect("own directory");
        }
        let control = runtime.join("control.sock");
        let frame = runtime.join("frame.sock");
        let other = runtime.join("other.sock");
        let foreign = sibling.join("control.sock");
        let control_listener = UnixListener::bind(&control).expect("own control");
        let frame_listener = UnixListener::bind(&frame).expect("own frame");
        let other_listener = UnixListener::bind(&other).expect("wrong owned-directory socket");
        let foreign_listener = UnixListener::bind(&foreign).expect("foreign socket");
        for listener in [
            &control_listener,
            &frame_listener,
            &other_listener,
            &foreign_listener,
        ] {
            listener.set_nonblocking(true).expect("bounded accept");
        }
        let tcp = TcpListener::bind("127.0.0.1:0").expect("own TCP target");
        tcp.set_nonblocking(true).expect("bounded TCP accept");
        let executable = std::env::current_exe().expect("probe test executable");
        let rules = super::sandbox_profile(&executable, &bundle, &profile, &temp, &runtime)
            .expect("production network rules");
        let invoke = |kind: &str, address: &str, confined: bool| {
            let mut command = if confined {
                let mut c = Command::new("/usr/bin/sandbox-exec");
                c.args(["-p", &rules]).arg(&executable);
                c
            } else {
                Command::new(&executable)
            };
            command
                .args([
                    "--exact",
                    "engine::process::tests::macos_network_probe_child",
                    "--ignored",
                    "--test-threads=1",
                ])
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("OPENBOT_NATIVE_NETWORK_PROBE_KIND", kind)
                .env("OPENBOT_NATIVE_NETWORK_PROBE_ADDRESS", address)
                .current_dir(&profile)
                .output()
                .expect("owned Rust socket probe")
        };
        for (path, listener) in [(&control, &control_listener), (&frame, &frame_listener)] {
            let result = invoke("uds", path.to_str().expect("path"), true);
            assert!(result.status.success(), "owned pipe connection must work");
            assert!(listener.accept().is_ok());
        }
        let mut failures = 0;
        for (name, path, listener) in [
            ("extra-runtime-socket", &other, &other_listener),
            ("sibling-socket", &foreign, &foreign_listener),
        ] {
            let address = path.to_str().expect("path");
            assert!(
                invoke("uds", address, false).status.success(),
                "unconfined endpoint positive"
            );
            assert!(listener.accept().is_ok());
            let result = invoke("uds", address, true);
            let accepted = listener.accept().is_ok();
            let connected = result.status.success() || accepted;
            println!("main-network-policy case={name} unintended_connected={connected}");
            failures += usize::from(connected);
        }
        let address = tcp.local_addr().expect("TCP address").to_string();
        assert!(
            invoke("tcp", &address, false).status.success(),
            "unconfined TCP positive"
        );
        assert!(tcp.accept().is_ok());
        let result = invoke("tcp", &address, true);
        let accepted = tcp.accept().is_ok();
        let connected = result.status.success() || accepted;
        println!("main-network-policy case=other-loopback-port unintended_connected={connected}");
        failures += usize::from(connected);
        assert_eq!(
            failures, 0,
            "network authority must be limited to exact owned pipes"
        );
    }
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "subprocess-only child of native network policy conformance"]
    fn macos_network_probe_child() {
        let kind = std::env::var("OPENBOT_NATIVE_NETWORK_PROBE_KIND").expect("owned probe kind");
        let address =
            std::env::var("OPENBOT_NATIVE_NETWORK_PROBE_ADDRESS").expect("owned probe address");
        let connected = match kind.as_str() {
            "uds" => std::os::unix::net::UnixStream::connect(address).is_ok(),
            "tcp" => std::net::TcpStream::connect_timeout(
                &address.parse().expect("numeric probe address"),
                std::time::Duration::from_secs(1),
            )
            .is_ok(),
            _ => false,
        };
        assert!(connected, "owned socket probe was refused");
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires real macOS Engine helper, cc and sandbox-exec; synthetic loader fixture only"]
    fn macos_helper_rejects_loader_injection_after_parent_profile_release() {
        use std::path::{Path, PathBuf};
        use std::process::Command;
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let root = Path::new("/private/tmp").join(format!("ob-helper-{}", std::process::id()));
        assert!(!root.exists());
        fs::create_dir(&root).expect("owned loader test root");
        let _cleanup = Cleanup(root.clone());
        let profile = root.join("profile");
        let temp = root.join("temp");
        let runtime = root.join("runtime");
        let sibling = root.join("sibling");
        for path in [&profile, &temp, &runtime, &sibling] {
            fs::create_dir(path).expect("owned fixture directory");
        }
        let marker = sibling.join("synthetic-marker");
        let library = profile.join("native-attack-fixture.dylib");
        let source = profile.join("native-attack-fixture.c");
        // Deliberately untrusted native test data, compiled only into the owned temporary folder.
        // It touches exactly one synthetic path then exits before Electron startup; no user data,
        // network, shell, persistence, or production native implementation is involved.
        let literal =
            serde_json::to_string(marker.to_str().expect("synthetic path")).expect("path literal");
        fs::write(&source,format!("#include <fcntl.h>\n#include <unistd.h>\n__attribute__((constructor)) static void probe(void) {{ int f=open({literal},O_WRONLY|O_CREAT|O_EXCL,0600); if(f>=0){{write(f,\"fixture\",7);close(f);_exit(0);}} _exit(42); }}\n")).expect("untrusted fixture source");
        assert!(
            Command::new("/usr/bin/cc")
                .args(["-dynamiclib", "-o"])
                .arg(&library)
                .arg(&source)
                .status()
                .expect("fixture compiler")
                .success()
        );
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace");
        let bundle = std::env::var_os("OPENBOT_ENGINE_LOADER_FIXTURE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| workspace.join("target/engine/bundle/electron-43.3.0/macos-arm64"));
        let helper=bundle.join("AcosmiEngine.app/Contents/Frameworks/Electron Helper.app/Contents/MacOS/Electron Helper");
        assert!(helper.is_file(), "real fixed helper bundle required");
        // A normal ad-hoc test binary is the positive control for the loader fixture itself.
        let positive = Command::new(std::env::current_exe().expect("test executable"))
            .env_clear()
            .env("DYLD_INSERT_LIBRARIES", &library)
            .output()
            .expect("fixture positive");
        assert!(
            positive.status.success() && marker.exists(),
            "native loader fixture must execute without protection"
        );
        fs::remove_file(&marker).expect("reset marker");
        let rules = super::sandbox_profile(
            Path::new("/usr/bin/env"),
            &bundle,
            &profile,
            &temp,
            &runtime,
        )
        .expect("production parent policy");
        let env_arg = format!("DYLD_INSERT_LIBRARIES={}", library.display());
        // env sets DYLD after sandbox-exec has applied the parent policy, modelling a compromised
        // main's own child environment construction, not inherited host credentials.
        let result = Command::new("/usr/bin/sandbox-exec")
            .args(["-p", &rules, "/usr/bin/env"])
            .arg(env_arg)
            .arg(&helper)
            .arg("--version")
            .env_clear()
            .env("HOME", &profile)
            .env("TMPDIR", &temp)
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&profile)
            .output()
            .expect("owned helper loader probe");
        let escaped = marker.exists();
        println!(
            "helper-loader synthetic_outside_marker={escaped} exited={}",
            result.status.success()
        );
        assert!(
            !escaped,
            "approved helper must not execute a scope-controlled injected library outside the parent policy"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires generated epoch-5 bundle; tests only copied/hardlinked fixture files"]
    fn bundle_rejects_legacy_schema_missing_helper_and_modified_helper_bytes() {
        use sha2::Digest as _;
        use std::path::{Path, PathBuf};
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace");
        let source = std::env::var_os("OPENBOT_ENGINE_LOADER_FIXTURE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                workspace.join(format!(
                    "target/engine/bundle/electron-43.3.0/{}",
                    super::expected_platform()
                ))
            });
        let original: serde_json::Value =
            serde_json::from_slice(&fs::read(source.join("manifest.json")).expect("real bundle"))
                .expect("manifest");
        let root = std::env::temp_dir().join(format!("ob-bundle-integrity-{}", std::process::id()));
        assert!(!root.exists());
        fs::create_dir(&root).expect("owned root");
        let _cleanup = Cleanup(root.clone());
        let write_manifest = |value: &serde_json::Value| {
            let bytes = serde_json::to_vec(value).expect("manifest JSON");
            fs::write(root.join("manifest.json"), &bytes).expect("manifest write");
            super::EngineBundleDigest(sha2::Sha256::digest(bytes).into())
        };
        let mut stale = original.clone();
        stale["schema_version"] = serde_json::json!(1);
        assert!(matches!(
            super::EngineBundle::open(&root, write_manifest(&stale)),
            Err(super::EngineProcessError::BundleShape)
        ));
        let helper = "AcosmiEngine.app/Contents/Frameworks/Electron Helper.app/Contents/MacOS/Electron Helper";
        let mut redirected = original.clone();
        let main = redirected["executable"]
            .as_str()
            .expect("main path")
            .to_owned();
        redirected["executable"] = serde_json::json!(helper);
        redirected["files"]
            .as_object_mut()
            .expect("files")
            .remove(&main);
        assert!(matches!(
            super::EngineBundle::open(&root, write_manifest(&redirected)),
            Err(super::EngineProcessError::BundleShape)
        ));
        let mut missing = original.clone();
        missing["files"]
            .as_object_mut()
            .expect("files")
            .remove(helper);
        assert!(matches!(
            super::EngineBundle::open(&root, write_manifest(&missing)),
            Err(super::EngineProcessError::BundleShape)
        ));
        for path in original["files"].as_object().expect("files").keys() {
            let target = root.join(path);
            fs::create_dir_all(target.parent().expect("parent")).expect("target directories");
            if path == helper {
                fs::copy(source.join(path), &target).expect("isolated helper copy");
            } else {
                fs::hard_link(source.join(path), &target).expect("read-only fixture reference");
            }
        }
        let digest = write_manifest(&original);
        assert!(super::EngineBundle::open(&root, digest).is_ok());
        use std::io::Write as _;
        fs::OpenOptions::new()
            .append(true)
            .open(root.join(helper))
            .expect("own helper copy")
            .write_all(b"tamper")
            .expect("tamper fixture");
        assert!(matches!(
            super::EngineBundle::open(&root, digest),
            Err(super::EngineProcessError::BundleDigest)
        ));
    }
}
