//! P1-only dual-role Chromium sandbox example, executed as the runsc container init process.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("engine-runsc-probe requires Linux");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    linux::run().await
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::io::Read as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use openbot_computer::engine::{
        ComponentRenderScope, ComputerSecurityScope, DesktopWindowSessionId, EngineBundle,
        EngineBundleDigest, EngineLaunchConfig, EngineProcess, EngineRole, EngineSandboxFidelity,
        RunscAttestation, ScreenAudience, WorkspaceScope,
    };
    use openbot_contracts::auth::AuthGeneration;
    use openbot_contracts::ids::{
        ActorId, BotId, ChannelId, ComputerGeneration, ComputerId, CredentialPrincipalId, TabId,
        TenantId,
    };
    use serde::Serialize;
    use sha2::{Digest as _, Sha256};

    #[derive(Serialize)]
    struct ProbeReport {
        schema: &'static str,
        ubuntu: &'static str,
        arch: &'static str,
        gvisor_marker: bool,
        xvfb_pid: u32,
        xvfb_sha256: String,
        xvfb_tcp_listeners: usize,
        final_extra_processes: usize,
        roles: Vec<RoleReport>,
    }

    #[derive(Serialize)]
    struct RoleReport {
        role: &'static str,
        main_pid: u32,
        renderer_pid: u32,
        main_seccomp: u32,
        seccomp: u32,
        no_new_privs: u32,
        pid_namespace_isolated: bool,
        network_namespace_isolated: bool,
        user_namespace_isolated: bool,
        frame_width: u32,
        frame_height: u32,
        observed_processes: usize,
        tcp_listeners: usize,
        orphan_processes: usize,
        profile_locks: usize,
    }

    pub(super) async fn run() -> Result<(), Box<dyn std::error::Error>> {
        let (bundle_path, manifest_digest, xvfb_sha256) = parse_args()?;
        let attestation = RunscAttestation::detect()?;
        let bundle =
            EngineBundle::open(bundle_path, EngineBundleDigest::from_hex(&manifest_digest)?)?;
        let mut display = VirtualDisplay::start(&xvfb_sha256)?;
        let xvfb_pid = display.pid();
        let roles = vec![
            run_role(
                "browser",
                bundle.clone(),
                EngineRole::BrowserComputer(ComputerSecurityScope::new(
                    TenantId::new("tenant-runsc-browser"),
                    BotId::new("bot-runsc-browser"),
                    CredentialPrincipalId::new("principal-runsc-browser"),
                    WorkspaceScope::Channel(ChannelId::new("channel-runsc-browser")),
                )),
                attestation,
                xvfb_pid,
            )
            .await?,
            run_role(
                "component",
                bundle,
                EngineRole::SandboxedComponent(ComponentRenderScope::new(
                    TenantId::new("tenant-runsc-component"),
                    ActorId::new("actor-runsc-component"),
                    DesktopWindowSessionId::new("window-runsc-component")?,
                )),
                attestation,
                xvfb_pid,
            )
            .await?,
        ];
        let xvfb_tcp_listeners = tcp_listener_count(xvfb_pid)?;
        if xvfb_tcp_listeners != 0 {
            return Err("Xvfb opened a TCP listener despite -nolisten tcp".into());
        }
        display.shutdown()?;
        let final_extra_processes = wait_for_quiescence(None);
        if final_extra_processes != 0 {
            return Err("runsc probe left a process after Xvfb shutdown".into());
        }
        println!(
            "{}",
            serde_json::to_string(&ProbeReport {
                schema: "openbot-runsc-engine-spike-v1",
                ubuntu: "24.04",
                arch: "x86_64",
                gvisor_marker: Path::new("/proc/gvisor/kernel_is_gvisor").is_file(),
                xvfb_pid,
                xvfb_sha256,
                xvfb_tcp_listeners,
                final_extra_processes,
                roles,
            })?
        );
        Ok(())
    }

    async fn run_role(
        tag: &'static str,
        bundle: EngineBundle,
        role: EngineRole,
        attestation: RunscAttestation,
        xvfb_pid: u32,
    ) -> Result<RoleReport, Box<dyn std::error::Error>> {
        let directories = TestDirectories::new(tag)?;
        let generation = ComputerGeneration::new(1);
        let audience = ScreenAudience::new(
            role.tenant_id().clone(),
            role.component_actor_id()
                .cloned()
                .unwrap_or_else(|| ActorId::new("actor-runsc-browser")),
            AuthGeneration::new(1),
        );
        let mut process = EngineProcess::launch_inside_runsc(
            EngineLaunchConfig::new(
                bundle,
                role,
                audience,
                ComputerId::new(format!("computer-runsc-{tag}")),
                generation,
                &directories.profile,
                &directories.temp,
            )
            .with_runsc_probe_display(),
            attestation,
        )
        .await?;
        if process.sandbox_fidelity() != EngineSandboxFidelity::Enforced {
            return Err("runsc Engine did not report Enforced fidelity".into());
        }
        let main_pid = process.pid();
        let tab = TabId::new(format!("tab-runsc-{tag}"));
        let started = process.start_session(tab.clone()).await?;
        if started.renderer_sandboxed {
            return Err(
                "Linux must use /proc evidence, not Electron ProcessMetric.sandboxed".into(),
            );
        }
        if started.frame.width() != 1280
            || started.frame.height() != 800
            || !started.frame.bytes().starts_with(&[0xff, 0xd8, 0xff])
            || !started.frame.bytes().ends_with(&[0xff, 0xd9])
        {
            return Err("runsc frame shape is not the P1 JPEG fixture".into());
        }

        let sandbox = renderer_sandbox(main_pid, started.renderer_pid)?;
        let mut observed = descendants(main_pid)?;
        observed.insert(main_pid);
        if !observed.contains(&started.renderer_pid) {
            return Err("renderer is not a descendant of the authenticated main process".into());
        }
        let listener_count = observed
            .iter()
            .try_fold(0usize, |count, pid| -> Result<_, std::io::Error> {
                Ok(count + tcp_listener_count(*pid)?)
            })?;
        if listener_count != 0 {
            return Err("Engine process tree opened a TCP listener".into());
        }

        process.stop_session(&tab).await?;
        process.shutdown().await?;
        let orphan_processes = wait_for_quiescence(Some(xvfb_pid));
        let profile_locks = ["SingletonLock", "SingletonSocket", "SingletonCookie"]
            .into_iter()
            .filter(|name| directories.profile.join(name).exists())
            .count();
        if orphan_processes != 0 || profile_locks != 0 {
            return Err("runsc Engine left an orphan process or profile lock".into());
        }

        Ok(RoleReport {
            role: tag,
            main_pid,
            renderer_pid: started.renderer_pid,
            main_seccomp: sandbox.main_seccomp,
            seccomp: sandbox.seccomp,
            no_new_privs: sandbox.no_new_privs,
            pid_namespace_isolated: sandbox.pid_namespace_isolated,
            network_namespace_isolated: sandbox.network_namespace_isolated,
            user_namespace_isolated: sandbox.user_namespace_isolated,
            frame_width: started.frame.width(),
            frame_height: started.frame.height(),
            observed_processes: observed.len(),
            tcp_listeners: listener_count,
            orphan_processes,
            profile_locks,
        })
    }

    struct RendererSandbox {
        main_seccomp: u32,
        seccomp: u32,
        no_new_privs: u32,
        pid_namespace_isolated: bool,
        network_namespace_isolated: bool,
        user_namespace_isolated: bool,
    }

    fn renderer_sandbox(
        main_pid: u32,
        renderer_pid: u32,
    ) -> Result<RendererSandbox, Box<dyn std::error::Error>> {
        let main_status = status_fields(main_pid)?;
        let status = status_fields(renderer_pid)?;
        let main_seccomp = required_u32(&main_status, "Seccomp")?;
        let seccomp = required_u32(&status, "Seccomp")?;
        let no_new_privs = required_u32(&status, "NoNewPrivs")?;
        if main_seccomp == 2 || seccomp != 2 || no_new_privs != 1 {
            return Err(format!(
                "renderer sandbox layer-2 failed: main Seccomp={main_seccomp} renderer Seccomp={seccomp} NoNewPrivs={no_new_privs}"
            )
            .into());
        }
        let pid_namespace_isolated = namespace(main_pid, "pid")? != namespace(renderer_pid, "pid")?;
        let network_namespace_isolated =
            namespace(main_pid, "net")? != namespace(renderer_pid, "net")?;
        let user_namespace_isolated =
            namespace(main_pid, "user")? != namespace(renderer_pid, "user")?;
        if !((pid_namespace_isolated && network_namespace_isolated) || user_namespace_isolated) {
            return Err("renderer has no positive Chromium layer-1 namespace separation".into());
        }
        Ok(RendererSandbox {
            main_seccomp,
            seccomp,
            no_new_privs,
            pid_namespace_isolated,
            network_namespace_isolated,
            user_namespace_isolated,
        })
    }

    fn status_fields(pid: u32) -> Result<BTreeMap<String, String>, std::io::Error> {
        Ok(fs::read_to_string(format!("/proc/{pid}/status"))?
            .lines()
            .filter_map(|line| line.split_once(':'))
            .map(|(key, value)| (key.to_owned(), value.trim().to_owned()))
            .collect())
    }

    fn required_u32(
        fields: &BTreeMap<String, String>,
        key: &str,
    ) -> Result<u32, Box<dyn std::error::Error>> {
        fields
            .get(key)
            .ok_or_else(|| format!("renderer status missing {key}").into())
            .and_then(|value| value.parse::<u32>().map_err(Into::into))
    }

    fn namespace(pid: u32, kind: &str) -> Result<PathBuf, std::io::Error> {
        fs::read_link(format!("/proc/{pid}/ns/{kind}"))
    }

    fn descendants(root: u32) -> Result<BTreeSet<u32>, std::io::Error> {
        let mut rows = Vec::new();
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|value| value.parse().ok())
            else {
                continue;
            };
            let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
                continue;
            };
            let Some(after_name) = stat.rsplit_once(") ").map(|(_, rest)| rest) else {
                continue;
            };
            let Some(ppid) = after_name
                .split_whitespace()
                .nth(1)
                .and_then(|value| value.parse::<u32>().ok())
            else {
                continue;
            };
            rows.push((pid, ppid));
        }
        let mut pending = vec![root];
        let mut found = BTreeSet::new();
        while let Some(parent) = pending.pop() {
            for (pid, ppid) in &rows {
                if *ppid == parent && found.insert(*pid) {
                    pending.push(*pid);
                }
            }
        }
        Ok(found)
    }

    fn tcp_listener_count(pid: u32) -> Result<usize, std::io::Error> {
        ["tcp", "tcp6"].into_iter().try_fold(0usize, |count, name| {
            let path = format!("/proc/{pid}/net/{name}");
            let text = match fs::read_to_string(path) {
                Ok(text) => text,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(count),
                Err(error) => return Err(error),
            };
            Ok(count
                + text
                    .lines()
                    .skip(1)
                    .filter(|line| line.split_whitespace().nth(3) == Some("0A"))
                    .count())
        })
    }

    fn wait_for_quiescence(allowed_background_pid: Option<u32>) -> usize {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = fs::read_dir("/proc").map_or(usize::MAX, |entries| {
                entries
                    .filter_map(Result::ok)
                    .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
                    .filter(|pid| *pid != std::process::id())
                    .filter(|pid| Some(*pid) != allowed_background_pid)
                    .count()
            });
            if remaining == 0 || Instant::now() >= deadline {
                return remaining;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    struct VirtualDisplay {
        child: Option<Child>,
    }

    impl VirtualDisplay {
        fn start(expected_sha256: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let executable = Path::new("/usr/bin/Xvfb");
            if !executable.is_file() {
                return Err("runsc rootfs is missing /usr/bin/Xvfb".into());
            }
            if sha256(executable)? != expected_sha256 {
                return Err("Xvfb digest differs from the outer authority".into());
            }
            let mut child = Command::new(executable)
                .args([
                    ":99",
                    "-screen",
                    "0",
                    "1280x800x24",
                    "-nolisten",
                    "tcp",
                    "-noreset",
                    "-ac",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            let deadline = Instant::now() + Duration::from_secs(10);
            let socket = Path::new("/tmp/.X11-unix/X99");
            loop {
                if socket.exists() {
                    break;
                }
                if let Some(status) = child.try_wait()? {
                    return Err(format!("Xvfb exited before ready: {status}").into());
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("Xvfb did not create its Unix socket in 10 seconds".into());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(Self { child: Some(child) })
        }

        fn pid(&self) -> u32 {
            self.child.as_ref().map_or(0, Child::id)
        }

        fn shutdown(&mut self) -> Result<(), std::io::Error> {
            if let Some(mut child) = self.child.take() {
                child.kill()?;
                let _ = child.wait()?;
            }
            Ok(())
        }
    }

    impl Drop for VirtualDisplay {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    fn parse_args() -> Result<(PathBuf, String, String), Box<dyn std::error::Error>> {
        let mut args = std::env::args_os().skip(1);
        if args.next().as_deref() != Some(std::ffi::OsStr::new("--bundle")) {
            return Err(
                "usage: engine-runsc-probe --bundle PATH --manifest-sha256 HEX --xvfb-sha256 HEX"
                    .into(),
            );
        }
        let bundle = args.next().ok_or("missing bundle path")?;
        if args.next().as_deref() != Some(std::ffi::OsStr::new("--manifest-sha256")) {
            return Err("missing --manifest-sha256".into());
        }
        let digest = args
            .next()
            .and_then(|value| value.into_string().ok())
            .ok_or("invalid manifest digest")?;
        if args.next().as_deref() != Some(std::ffi::OsStr::new("--xvfb-sha256")) {
            return Err("missing --xvfb-sha256".into());
        }
        let xvfb_sha256 = args
            .next()
            .and_then(|value| value.into_string().ok())
            .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or("invalid Xvfb digest")?;
        if args.next().is_some() {
            return Err("unexpected probe argument".into());
        }
        Ok((PathBuf::from(bundle), digest, xvfb_sha256))
    }

    fn sha256(path: &Path) -> Result<String, std::io::Error> {
        let mut file = fs::File::open(path)?;
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

    struct TestDirectories {
        root: PathBuf,
        profile: PathBuf,
        temp: PathBuf,
    }

    impl TestDirectories {
        fn new(tag: &str) -> Result<Self, std::io::Error> {
            let root = PathBuf::from(format!(
                "/tmp/openbot-runsc-engine-{tag}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            let profile = root.join("profile");
            let temp = root.join("temp");
            fs::create_dir_all(&profile)?;
            fs::create_dir_all(&temp)?;
            Ok(Self {
                root,
                profile,
                temp,
            })
        }
    }

    impl Drop for TestDirectories {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
