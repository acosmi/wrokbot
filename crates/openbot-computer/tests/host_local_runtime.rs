//! Explicit macOS real-Engine lifecycle acceptance for the host adapter, never a product A3 test.
#![cfg(target_os = "macos")]

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use openbot_computer::browser::BrowserInput;
use openbot_computer::engine::{
    ComputerSecurityScope, EngineBundle, EngineBundleDigest, ScreenAudience, WorkspaceScope,
};
use openbot_computer::host_local_runtime::{
    HostLocalBrowserRuntime, HostLocalRuntimeConfig, HostLocalRuntimeError,
};
use openbot_computer::manager::{BrowserInstance, BrowserRuntimeBudget};
use openbot_computer::screen::{ScreenHub, ScreenViewerBinding};
use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
use openbot_contracts::ids::{
    ActorId, BotId, ChannelId, ComputerGeneration, ComputerId, CredentialPrincipalId, DeploymentId,
    TenantId,
};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

fn auth(actor: &str) -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new("host-local-test"),
        TenantId::new("tenant"),
        ActorId::new(actor),
        [Role::User],
        AuthGeneration::new(1),
        true,
    )
}
fn instance(workspace: &str, generation: u64) -> BrowserInstance {
    BrowserInstance::new(
        ComputerSecurityScope::new(
            TenantId::new("tenant"),
            BotId::new("bot"),
            CredentialPrincipalId::new("principal"),
            WorkspaceScope::Channel(ChannelId::new(workspace)),
        ),
        ComputerId::new(format!("computer-{workspace}")),
        ComputerGeneration::new(generation),
    )
}
fn bundle() -> EngineBundle {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let root = std::env::var_os("OPENBOT_ENGINE_LOADER_FIXTURE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace.join("target/engine/bundle/electron-43.3.0/macos-arm64"));
    let digest = format!(
        "{:x}",
        Sha256::digest(
            fs::read(root.join("manifest.json")).expect("verified current bundle required")
        )
    );
    EngineBundle::open(root, EngineBundleDigest::from_hex(&digest).unwrap()).expect("bundle")
}
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let mut nonce = [0_u8; 8];
        getrandom::fill(&mut nonce).unwrap();
        let nonce = nonce.iter().map(|v| format!("{v:02x}")).collect::<String>();
        Self(
            std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("ob-host-live-{}-{nonce}", std::process::id())),
        )
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn runtime(root: &Root, bundle: &EngineBundle, hub: ScreenHub) -> HostLocalBrowserRuntime {
    HostLocalBrowserRuntime::new(
        HostLocalRuntimeConfig {
            bundle: bundle.clone(),
            root: root.0.clone(),
            audience: ScreenAudience::from_auth(&auth("actor")),
            budget: BrowserRuntimeBudget::new(1, 10).unwrap(),
        },
        hub,
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires the current verified macOS Engine bundle and real confined internal page"]
async fn real_profile_reuse_takeover_stop_replacement_and_old_target_fencing() {
    let root = Root::new();
    let bundle = bundle();
    let hub = ScreenHub::new(2).unwrap();
    let runtime = Arc::new(runtime(&root, &bundle, hub.clone()));
    let first = instance("first", 1);
    let (a, b) = tokio::join!(
        runtime.ensure(first.clone(), 0),
        runtime.ensure(first.clone(), 1)
    );
    let first_target = a.unwrap();
    assert_eq!(
        first_target.target,
        b.unwrap().target,
        "one exact launch was reused"
    );
    let other_host = self::runtime(&root, &bundle, ScreenHub::new(1).unwrap());
    assert!(matches!(
        other_host.ensure(first.clone(), 0).await,
        Err(HostLocalRuntimeError::ProfileBusy)
    ));
    drop(other_host);

    let binding = ScreenViewerBinding::verified_server("https://host-local.example.test").unwrap();
    let target = &first_target.target;
    let ticket = hub
        .issue_ticket_for_target(
            &auth("actor"),
            &target.computer_id,
            target.computer_generation,
            &target.tab_id,
            binding.clone(),
            OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
    let mut viewer = hub
        .consume_ticket(
            &auth("actor"),
            &binding,
            &ticket.ticket_protocol(),
            OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
    let before = viewer.current().unwrap().sequence();
    let control = runtime
        .take_control(
            &first,
            auth("actor"),
            OffsetDateTime::now_utc() + time::Duration::seconds(30),
            2,
        )
        .await
        .unwrap();
    assert_eq!(
        runtime.sweep_idle(1000).await.unwrap(),
        0,
        "HumanLease pins the real browser"
    );
    for replacement in [instance("first", 2), instance("other-workspace", 1)] {
        assert!(
            matches!(
                runtime.ensure(replacement, 1001).await,
                Err(HostLocalRuntimeError::Busy)
            ),
            "ensure may not cancel active HumanLease to switch profile"
        );
        assert_eq!(
            runtime.target(&first, 1002).await.unwrap().target,
            first_target.target
        );
        assert!(
            viewer.current().is_ok(),
            "busy replacement preserves old viewer"
        );
    }

    assert_eq!(
        runtime
            .apply_input(
                &first,
                auth("other"),
                control.clone(),
                BrowserInput::insert_text("forbidden"),
                3
            )
            .await
            .unwrap_err(),
        HostLocalRuntimeError::Refused
    );
    runtime
        .apply_input(
            &first,
            auth("actor"),
            control.clone(),
            BrowserInput::insert_text("runtime 日本語"),
            3,
        )
        .await
        .unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(2), viewer.next())
        .await
        .unwrap()
        .unwrap();
    assert!(frame.sequence() > before);
    let stop_at = Instant::now();
    assert!(runtime.stop(&first).await.unwrap());
    assert!(stop_at.elapsed() < Duration::from_secs(3));
    assert!(
        viewer.current().is_err(),
        "Stop revokes the attached viewer"
    );
    assert!(
        runtime
            .apply_input(
                &first,
                auth("actor"),
                control,
                BrowserInput::insert_text("stale"),
                4
            )
            .await
            .is_err()
    );

    let second = instance("first", 2);
    let second_target = runtime.ensure(second.clone(), 5).await.unwrap();
    assert_ne!(first_target.target, second_target.target);
    assert_eq!(
        runtime.stop(&first).await.unwrap_err(),
        HostLocalRuntimeError::Refused
    );
    assert_eq!(
        runtime.target(&second, 6).await.unwrap().target,
        second_target.target
    );
    let third = instance("other-workspace", 1);
    let third_target = runtime.ensure(third.clone(), 7).await.unwrap();
    assert!(
        !runtime.stop(&second).await.unwrap(),
        "old workspace cannot retire new profile owner"
    );
    assert_eq!(
        runtime.target(&third, 8).await.unwrap().target,
        third_target.target
    );
    assert_eq!(runtime.shutdown().await.unwrap(), 1);
    assert!(matches!(
        runtime.ensure(instance("later", 1), 9).await,
        Err(HostLocalRuntimeError::Closed)
    ));

    let fresh_host = self::runtime(&root, &bundle, ScreenHub::new(1).unwrap());
    fresh_host
        .ensure(instance("restart", 1), 0)
        .await
        .expect("same persistent profile lock is released after shutdown");
    fresh_host.shutdown().await.unwrap();
    println!(
        "host-runtime internal-page reuse=true profile-lock=true active-replacement-busy=true old-lease-survives=true input-ack=true viewer-revoked=true stop-under-3s=true generation-fence=true workspace-switch=true shutdown-reacquire=true production-assembly=false A3=false"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires the current macOS Engine bundle; proves bounded Drop with an active HumanLease"]
async fn dropping_runtime_retires_active_owner_and_releases_profile_lock() {
    let root = Root::new();
    let bundle = bundle();
    let hub = ScreenHub::new(1).unwrap();
    let runtime = self::runtime(&root, &bundle, hub.clone());
    let first = instance("drop", 1);
    let target = runtime.ensure(first.clone(), 0).await.unwrap().target;
    let binding = ScreenViewerBinding::verified_server("https://drop.example.test").unwrap();
    let ticket = hub
        .issue_ticket_for_target(
            &auth("actor"),
            &target.computer_id,
            target.computer_generation,
            &target.tab_id,
            binding.clone(),
            OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
    let mut viewer = hub
        .consume_ticket(
            &auth("actor"),
            &binding,
            &ticket.ticket_protocol(),
            OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
    let _input = runtime
        .take_control(
            &first,
            auth("actor"),
            OffsetDateTime::now_utc() + time::Duration::seconds(30),
            1,
        )
        .await
        .unwrap();
    drop(runtime);
    let next = self::runtime(&root, &bundle, ScreenHub::new(1).unwrap());
    let retired_at = Instant::now();
    loop {
        match next.ensure(instance("drop", 2), 0).await {
            Ok(_) => break,
            Err(HostLocalRuntimeError::ProfileBusy)
                if retired_at.elapsed() < Duration::from_secs(3) =>
            {
                tokio::time::sleep(Duration::from_millis(10)).await
            }
            result => panic!("Drop did not retire the owned profile: {result:?}"),
        }
    }
    assert!(viewer.current().is_err());
    next.shutdown().await.unwrap();
    println!("host-runtime drop-active-lease=true old-viewer-revoked=true profile-reacquired=true");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires the current macOS Engine bundle; mutates only a private test-owned workspace symlink"]
async fn failed_profile_replacement_does_not_restore_an_already_retired_engine() {
    use openbot_computer::engine::EngineRole;
    use std::os::unix::fs::{DirBuilderExt as _, symlink};
    let root = Root::new();
    let bundle = bundle();
    let runtime = self::runtime(&root, &bundle, ScreenHub::new(1).unwrap());
    let old = instance("before-failure", 1);
    runtime.ensure(old.clone(), 0).await.unwrap();
    let next = instance("bad-workspace", 1);
    let scope = EngineRole::BrowserComputer(next.scope().clone()).scope_digest();
    let scope = scope
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let target = root.0.join("owned-symlink-target");
    fs::DirBuilder::new().mode(0o700).create(&target).unwrap();
    let bad_workspace = root.0.join("workspaces").join(scope);
    symlink(&target, &bad_workspace).unwrap();
    assert!(matches!(
        runtime.ensure(next.clone(), 1).await,
        Err(HostLocalRuntimeError::Root)
    ));
    assert!(
        matches!(
            runtime.target(&old, 2).await,
            Err(HostLocalRuntimeError::Refused)
        ),
        "the old process was stopped, not restored"
    );
    let profile_key = next
        .scope()
        .profile_digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.0.join("locks").join(profile_key))
        .unwrap();
    lock.try_lock()
        .expect("failed launch releases its profile lock");
    drop(lock);
    fs::remove_file(&bad_workspace).unwrap();
    runtime.ensure(next, 3).await.unwrap();
    runtime.shutdown().await.unwrap();
    println!(
        "host-runtime failed-replacement=true old-not-restored=true failed-launch-lock-released=true retry-after-repair=true"
    );
}
