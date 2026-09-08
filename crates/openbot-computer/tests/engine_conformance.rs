//! Real Electron P1 conformance. Explicitly ignored by default because it needs a built host bundle.

#![cfg(any(target_os = "macos", target_os = "windows"))]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use openbot_computer::browser::{BrowserInput, ModifierMask, MouseButton};
use openbot_computer::control::{ControlError, ControlService, HumanInputTicket};
use openbot_computer::engine::{
    ComponentRenderScope, ComputerSecurityScope, DesktopWindowSessionId, EngineBundle,
    EngineBundleDigest, EngineFrame, EngineLaunchConfig, EngineProcess, EngineProcessError,
    EngineRole, EngineSandboxFidelity, ScreenAudience, WorkspaceScope,
};
use openbot_computer::screen::coordinates::{CanvasRect, DecodedFrameSize, ScreenCoordinateMap};
use openbot_computer::screen::{ScreenHub, ScreenHubError, ScreenViewerBinding};
use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
use openbot_contracts::ids::{
    ActorId, BotId, ChannelId, ComputerGeneration, ComputerId, CredentialPrincipalId, DeploymentId,
    DocumentGeneration, TabId, TenantId,
};
use sha2::{Digest as _, Sha256};
use time::{Duration, OffsetDateTime, macros::datetime};

const INPUT_TIME: OffsetDateTime = datetime!(2026-09-04 12:00 UTC);
const ENGINE_INPUT_FIXTURE: &str =
    include_str!("../../../fixtures/computer/engine-input-wire-v2.json");
const SCREENCAST_FIXTURE: &str =
    include_str!("../../../fixtures/computer/screencast-backpressure-v3.json");
const SCREEN_HUB_FIXTURE: &str =
    include_str!("../../../fixtures/computer/screen-hub-ticket-core-v1.json");
const SCREEN_COORDINATE_FIXTURE: &str =
    include_str!("../../../fixtures/computer/screen-coordinate-input-journey-v1.json");

#[test]
fn demand_fixture_keeps_protocol_and_production_boundary_explicit() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/computer/screen-demand-lifecycle-v4.json"
    ))
    .expect("demand fixture");
    assert_eq!(
        fixture["protocol"]["version"],
        openbot_contracts::engine::ENGINE_PROTOCOL_VERSION
    );
    // This frozen demand fixture was captured with epoch 4. Wire version is unchanged; current
    // packaging epochs are separately verified by EngineBundle and the new signing fixture.
    assert_eq!(fixture["protocol"]["releaseEpoch"], 4);
    assert_eq!(fixture["owner"]["pendingTicketsCountAsViewers"], false);
    assert_eq!(fixture["owner"]["queueStoresAuthorityReceipt"], false);
    assert_eq!(fixture["owner"]["lastViewerPausesWithinTwoSeconds"], true);
    for unfinished in [
        "productionComputerManagerAssembly",
        "productionAuthInvalidationHook",
        "desktopLoopbackTransport",
        "fpsAndCaptureToPaintLatency",
        "windowsRuntime",
        "linuxRunscRuntime",
    ] {
        assert_eq!(fixture["evidenceBoundary"][unfinished], false);
    }
}

#[test]
fn engine_input_fixture_locks_protocol_and_unfinished_platform_boundaries() {
    let fixture = serde_json::from_str::<serde_json::Value>(ENGINE_INPUT_FIXTURE)
        .expect("engine input fixture JSON");
    assert_eq!(fixture["schema"], "openbot-engine-input-wire-v2");
    assert_eq!(fixture["protocol"]["version"], 2);
    assert_eq!(fixture["protocol"]["releaseEpoch"], 2);
    assert_eq!(
        fixture["protocol"]["generatedModuleSha256"],
        "ef213bb4d8f9f66b0854ef4feb9a7718de5bae139348320ed3fe8f6641b9bdf6"
    );
    assert_eq!(
        fixture["liveMatrix"]["inputAckAndFrameChannelsIndependent"],
        true
    );
    assert_eq!(
        fixture["liveMatrix"]["conformanceCaptureFramePerAcceptedInput"],
        true
    );
    assert_eq!(fixture["liveMatrix"]["crossScopeReceiptFrames"], 0);
    assert_eq!(fixture["liveMatrix"]["expiredReceiptFrames"], 0);
    assert_eq!(fixture["liveMatrix"]["ordinarySecretFrames"], 0);
    assert_eq!(fixture["evidenceBoundary"]["macosArm64Actual"], true);
    for unfinished in [
        "windowsRuntime",
        "linuxRunscRuntime",
        "serverOrDesktopComputerAssembly",
        "secretTypedEffect",
        "screenHub",
        "pageStartScreencast",
    ] {
        assert_eq!(fixture["evidenceBoundary"][unfinished], false);
    }
}

#[test]
fn screencast_fixture_locks_ack_order_latest_buffer_and_remaining_screen_boundary() {
    let fixture =
        serde_json::from_str::<serde_json::Value>(SCREENCAST_FIXTURE).expect("screencast fixture");
    assert_eq!(fixture["schema"], "openbot-screencast-backpressure-v3");
    assert_eq!(fixture["protocol"]["version"], 3);
    assert_eq!(fixture["protocol"]["releaseEpoch"], 3);
    assert_eq!(fixture["protocol"]["frameMagic"], "OBFRAME2");
    assert_eq!(fixture["protocol"]["fixedHeaderBytes"], 76);
    assert_eq!(fixture["backpressure"]["rustLatestBufferCapacity"], 1);
    assert_eq!(fixture["backpressure"]["ackAfterRustPublish"], true);
    assert_eq!(fixture["backpressure"]["receivedEqualsAcknowledged"], true);
    assert_eq!(fixture["backpressure"]["slowConsumerDroppedAtLeast"], 1);
    assert_eq!(fixture["macosArm64Evidence"]["receivedAtLeast"], 2);
    assert_eq!(
        fixture["macosArm64Evidence"]["acknowledgedEqualsReceived"],
        true
    );
    assert_eq!(fixture["macosArm64Evidence"]["droppedAtLeast"], 1);
    for completed in [
        "pageStartScreencast",
        "pageStopScreencast",
        "pageScreencastFrameAck",
        "screenIngressLatestBuffer",
    ] {
        assert_eq!(fixture["evidenceBoundary"][completed], true);
    }
    for unfinished in [
        "viewerTicketOrWebSocket",
        "multiViewer",
        "fpsOrLatencyBudget",
        "captureScreenshotFallback",
        "serverOrDesktopComputerAssembly",
        "windowsRuntime",
        "linuxRunscRuntime",
    ] {
        assert_eq!(fixture["evidenceBoundary"][unfinished], false);
    }
}

#[test]
fn screen_hub_fixture_locks_ticket_and_production_transport_boundary() {
    let fixture =
        serde_json::from_str::<serde_json::Value>(SCREEN_HUB_FIXTURE).expect("ScreenHub fixture");
    assert_eq!(fixture["schema"], "openbot-screen-hub-ticket-core-v1");
    assert_eq!(fixture["ticket"]["entropyBits"], 128);
    assert_eq!(fixture["ticket"]["ttlSeconds"], 30);
    assert_eq!(fixture["ticket"]["storage"], "sha256-digest-only");
    assert_eq!(fixture["ticket"]["baseProtocol"], "openbot.screen.v1");
    assert_eq!(fixture["ticket"]["ticketInUrlOrQuery"], false);
    assert_eq!(fixture["ticket"]["upgradeResponseEchoesTicket"], false);
    assert_eq!(fixture["ticket"]["singleUse"], true);
    assert_eq!(fixture["latestFrame"]["combinedPerTabMaximum"], 2);
    assert_eq!(fixture["latestFrame"]["perViewerPendingMaximum"], 1);
    assert_eq!(fixture["latestFrame"]["viewerFrameMagic"], "OBSCRN01");
    assert_eq!(fixture["latestFrame"]["viewerFrameHeaderBytes"], 68);
    assert_eq!(fixture["macosArm64Evidence"]["viewersPerRole"], 2);
    for completed in [
        "engineBackedSource",
        "screenHubLatestCore",
        "multiViewerCore",
        "viewerTicketCore",
        "authGenerationInvalidationCore",
    ] {
        assert_eq!(fixture["evidenceBoundary"][completed], true);
    }
    for unfinished in [
        "serverAuthenticatedWebSocket",
        "desktopLoopbackWebSocket",
        "productionAuthInvalidationHook",
        "connectionFrameSizeBandwidthIdleLimits",
        "fpsOrLatencyBudget",
        "lastViewerStopsScreencastWithinTwoSeconds",
        "captureScreenshotFallback",
        "serverOrDesktopComputerAssembly",
        "windowsRuntime",
        "linuxRunscRuntime",
    ] {
        assert_eq!(fixture["evidenceBoundary"][unfinished], false);
    }
}

#[test]
fn screen_coordinate_fixture_locks_units_journeys_and_hardware_boundary() {
    let fixture = serde_json::from_str::<serde_json::Value>(SCREEN_COORDINATE_FIXTURE)
        .expect("screen coordinate fixture");
    assert_eq!(
        fixture["schema"],
        "openbot-screen-coordinate-input-journey-v1"
    );
    assert_eq!(
        fixture["officialCdpUnits"]["deviceWidthAndHeight"],
        "device-independent-pixels"
    );
    assert_eq!(
        fixture["officialCdpUnits"]["devtoolsFrontendCommit"],
        "036dd84bc4fdfb0fd4be2a5ddb3fe37ef24939cd"
    );
    assert_eq!(
        fixture["officialCdpUnits"]["inputModelGitBlob"],
        "cfa97617c47f1b01957429f1bfdc96ebd6fe07d7"
    );
    assert_eq!(
        fixture["officialCdpUnits"]["mouseCoordinates"],
        "main-frame-viewport-css-pixels"
    );
    assert_eq!(fixture["mapping"]["canvasFit"], "contain");
    assert_eq!(fixture["mapping"]["letterboxInput"], "reject");
    assert_eq!(fixture["mapping"]["frameSequenceCarried"], true);
    assert_eq!(
        fixture["mapping"]["pageScaleAppliedOnlyToDocumentHitTestCoordinates"],
        true
    );
    assert_eq!(fixture["pureMatrix"]["testsPassed"], 4);
    assert_eq!(fixture["pureMatrix"]["viewportPoint"]["x"], 80);
    assert_eq!(fixture["pureMatrix"]["viewportPoint"]["y"], 168);
    assert_eq!(
        fixture["macosArm64Evidence"]["dragSequence"],
        serde_json::json!(["mousePressed", "mouseMoved", "mouseReleased"])
    );
    assert_eq!(fixture["macosArm64Evidence"]["imePath"], "Input.insertText");
    for completed in [
        "pureCoordinateMatrix",
        "macosActualEngineJourney",
        "imeCompletedTextJourney",
        "downMoveUpJourney",
    ] {
        assert_eq!(fixture["evidenceBoundary"][completed], true);
    }
    for unfinished in [
        "nonUnitDeviceScaleHardware",
        "nonUnitPageScaleHardware",
        "nonZeroScrollPointerHardware",
        "leptosCanvasEventWiring",
        "staleDisplayedFrameTransportRejection",
        "serverOrDesktopWebSocket",
        "productionComputerAssembly",
        "resizeNavigationTabSwitch",
        "windowsRuntime",
        "linuxRunscRuntime",
    ] {
        assert_eq!(fixture["evidenceBoundary"][unfinished], false);
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires `cargo xtask engine bundle` and host permission to run the real confined Electron"]
async fn browser_role_start_frame_stop_has_no_debug_listener_or_orphan() {
    run_role(EngineRole::BrowserComputer(ComputerSecurityScope::new(
        TenantId::new("tenant-browser"),
        BotId::new("bot-browser"),
        CredentialPrincipalId::new("principal-browser"),
        WorkspaceScope::Channel(ChannelId::new("channel-browser")),
    )))
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires `cargo xtask engine bundle` and host permission to run the real confined Electron"]
async fn component_role_start_frame_stop_has_no_debug_listener_or_orphan() {
    run_role(EngineRole::SandboxedComponent(ComponentRenderScope::new(
        TenantId::new("tenant-component"),
        ActorId::new("actor-component"),
        DesktopWindowSessionId::new("window-component").expect("window session"),
    )))
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires real confined Electron bundle; proves automatic demand pause/resume in both roles"]
async fn both_roles_pause_on_last_viewer_and_resume_the_same_document() {
    for role in [
        EngineRole::BrowserComputer(ComputerSecurityScope::new(
            TenantId::new("demand-tenant"),
            BotId::new("demand-bot"),
            CredentialPrincipalId::new("demand-principal"),
            WorkspaceScope::Channel(ChannelId::new("demand-channel")),
        )),
        EngineRole::SandboxedComponent(ComponentRenderScope::new(
            TenantId::new("demand-tenant"),
            ActorId::new("demand-actor"),
            DesktopWindowSessionId::new("demand-window").expect("window"),
        )),
    ] {
        run_demand_role(role).await;
    }
}

async fn run_demand_role(role: EngineRole) {
    use openbot_computer::screen::engine_owner::{ScreenEngineOwner, ScreenEngineState};
    let root = fixture_bundle_root();
    let digest = format!(
        "{:x}",
        Sha256::digest(fs::read(root.join("manifest.json")).expect("manifest"))
    );
    let bundle = EngineBundle::open(
        &root,
        EngineBundleDigest::from_hex(&digest).expect("digest"),
    )
    .expect("bundle");
    let tag = if matches!(&role, EngineRole::BrowserComputer(_)) {
        "demand-browser"
    } else {
        "demand-component"
    };
    let dirs = TestDirectories::new(tag);
    let auth = AuthContext::for_test(
        DeploymentId::new("demand-deployment"),
        role.tenant_id().clone(),
        ActorId::new("demand-actor"),
        [Role::User],
        AuthGeneration::new(1),
        false,
    );
    let computer = ComputerId::new(tag);
    let generation = ComputerGeneration::new(1);
    let tab = TabId::new("demand-tab");
    let mut engine = EngineProcess::launch(EngineLaunchConfig::new(
        bundle,
        role,
        ScreenAudience::from_auth(&auth),
        computer.clone(),
        generation,
        &dirs.profile,
        &dirs.temp,
    ))
    .await
    .expect("engine");
    let pid = engine.pid();
    let started = engine.start_session(tab.clone()).await.expect("start");
    let children = descendant_pids(pid);
    assert!(children.contains(&started.renderer_pid));
    let now = OffsetDateTime::now_utc();
    let mut control = ControlService::new(computer.clone(), tab.clone(), generation, now);
    control
        .take(&auth, now + Duration::minutes(5), now)
        .expect("lease");
    let ticket = control.issue_human_input_ticket(now).expect("ticket");
    engine
        .set_screencast(&tab, false)
        .await
        .expect("pause without destroying document");
    engine
        .set_screencast(&tab, false)
        .await
        .expect("exact pause replay");
    assert!(
        engine
            .set_screencast(&TabId::new("wrong-tab"), true)
            .await
            .is_err()
    );
    let paused = engine.screen_stats().await.expect("paused counters");
    engine
        .apply_human_input(
            control
                .authorize_human_input_receipt(&auth, &ticket, now)
                .expect("receipt"),
            &BrowserInput::insert_text("screen pause keeps 日本語"),
            now,
        )
        .await
        .expect("input while paused");
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert_eq!(
        engine
            .screen_stats()
            .await
            .expect("still paused")
            .received_frames(),
        paused.received_frames()
    );
    engine.set_screencast(&tab, true).await.expect("resume");
    engine
        .set_screencast(&tab, true)
        .await
        .expect("exact resume replay");
    let mut sequence = started.frame.sequence();
    let typed = next_frame(&mut engine, &mut sequence).await;
    assert_ne!(
        frame_hash(&typed),
        frame_hash(&started.frame),
        "input survives paused capture"
    );
    engine
        .apply_human_input(
            control
                .authorize_human_input_receipt(&auth, &ticket, now)
                .expect("receipt"),
            &BrowserInput::wheel(
                900.0,
                700.0,
                0.0,
                400.0,
                ModifierMask::new(0).expect("modifiers"),
            )
            .expect("wheel"),
            now,
        )
        .await
        .expect("scroll");
    let scrolled = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let frame = engine.next_frame().await.expect("scroll frame");
            if frame.scroll_y() > 0.0 {
                break frame;
            }
        }
    })
    .await
    .expect("scroll visible");
    let hub = ScreenHub::new(2).expect("hub");
    let control = Arc::new(tokio::sync::Mutex::new(control));
    let owner = ScreenEngineOwner::attach(engine, hub.clone(), control.clone())
        .await
        .expect("sole owner");
    let mut status = owner.observe();
    wait_demand_state(&mut status, ScreenEngineState::Paused).await;
    let before = owner.stats().await.expect("owner ingress stats");
    assert_eq!(before.received_frames(), before.acknowledged_frames());
    let mut wrong = ControlService::new(
        ComputerId::new("other-computer"),
        tab.clone(),
        generation,
        now,
    );
    wrong
        .take(&auth, now + Duration::minutes(5), now)
        .expect("other control");
    let wrong_ticket = wrong.issue_human_input_ticket(now).expect("other ticket");
    assert_eq!(
        owner
            .apply_input(
                auth.clone(),
                wrong_ticket,
                BrowserInput::insert_text("must-not-enter-engine"),
            )
            .await,
        Err(openbot_computer::screen::engine_owner::ScreenEngineError::InputRefused)
    );
    let ticket = {
        let mut held = control.lock().await;
        let pending = owner.apply_input(
            auth.clone(),
            ticket.clone(),
            BrowserInput::wheel(
                900.0,
                700.0,
                0.0,
                200.0,
                ModifierMask::new(0).expect("modifiers"),
            )
            .expect("queued stale wheel"),
        );
        tokio::pin!(pending);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut pending)
                .await
                .is_err()
        );
        held.document_navigated()
            .expect("advance lease epoch before queued dispatch");
        let ticket = held
            .issue_human_input_ticket(now)
            .expect("fresh epoch ticket");
        drop(held);
        assert_eq!(
            pending.await,
            Err(openbot_computer::screen::engine_owner::ScreenEngineError::InputRefused)
        );
        ticket
    };
    owner
        .apply_input(
            auth.clone(),
            ticket.clone(),
            BrowserInput::mouse_move(
                900.0,
                700.0,
                MouseButton::Left,
                ModifierMask::new(0).expect("modifiers"),
            )
            .expect("owned pointer input"),
        )
        .await
        .expect("owner serializes valid input");
    assert_eq!(
        owner
            .stats()
            .await
            .expect("no capture effect")
            .received_frames(),
        before.received_frames()
    );
    let mut viewer_a = demand_viewer(&hub, &auth, &computer, &tab).await;
    let viewer_b = demand_viewer(&hub, &auth, &computer, &tab).await;
    wait_demand_state(&mut status, ScreenEngineState::Running).await;
    let resumed = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let frame = viewer_a.next().await.expect("resumed frame");
            if frame.sequence() > scrolled.sequence() {
                break frame;
            }
        }
    })
    .await
    .expect("resumed frame bound");
    assert_eq!(
        resumed.scroll_y(),
        scrolled.scroll_y(),
        "document scroll survives owner pause/resume"
    );
    drop(viewer_a);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        *status.borrow(),
        ScreenEngineState::Running,
        "second viewer keeps source running"
    );
    let dropped_at = tokio::time::Instant::now();
    drop(viewer_b);
    wait_demand_state(&mut status, ScreenEngineState::Paused).await;
    let elapsed = dropped_at.elapsed();
    assert!(elapsed < std::time::Duration::from_secs(2));
    let stopped = owner.stats().await.expect("drained pause");
    assert_eq!(stopped.received_frames(), stopped.acknowledged_frames());
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert_eq!(
        owner
            .stats()
            .await
            .expect("paused steady")
            .received_frames(),
        stopped.received_frames()
    );
    let mut viewer = demand_viewer(&hub, &auth, &computer, &tab).await;
    wait_demand_state(&mut status, ScreenEngineState::Running).await;
    let frame = tokio::time::timeout(std::time::Duration::from_secs(2), viewer.next())
        .await
        .expect("reconnect frame")
        .expect("frame");
    assert!(frame.sequence() > resumed.sequence());
    assert_eq!(frame.scroll_y(), scrolled.scroll_y());
    assert!(
        descendant_pids(pid).contains(&started.renderer_pid),
        "same renderer PID survives"
    );
    for child in &children {
        assert_no_tcp_listener(*child);
    }
    println!(
        "screen-demand role={tag} last_viewer_pause_ms={} retained_scroll={} paused_received={} paused_ack={}",
        elapsed.as_millis(),
        frame.scroll_y(),
        stopped.received_frames(),
        stopped.acknowledged_frames()
    );
    assert_eq!(
        hub.invalidate_actor(auth.tenant(), auth.actor(), AuthGeneration::new(2))
            .await,
        1
    );
    wait_demand_state(&mut status, ScreenEngineState::Closed).await;
    assert!(viewer.next().await.is_err());
    owner
        .shutdown()
        .await
        .expect("collect already retired owner");
    assert_process_gone(pid);
    for child in children {
        assert_process_gone(child);
    }
}

async fn wait_demand_state(
    state: &mut tokio::sync::watch::Receiver<
        openbot_computer::screen::engine_owner::ScreenEngineState,
    >,
    expected: openbot_computer::screen::engine_owner::ScreenEngineState,
) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if *state.borrow_and_update() == expected {
                return;
            }
            state
                .changed()
                .await
                .expect("owner live while awaiting state");
        }
    })
    .await
    .expect("demand transition deadline");
}

async fn demand_viewer(
    hub: &ScreenHub,
    auth: &AuthContext,
    computer: &ComputerId,
    tab: &TabId,
) -> openbot_computer::screen::ScreenViewer {
    let binding =
        ScreenViewerBinding::verified_server("https://app.example.test").expect("binding");
    let now = OffsetDateTime::now_utc();
    let ticket = hub
        .issue_ticket_for_target(
            auth,
            computer,
            ComputerGeneration::new(1),
            tab,
            binding.clone(),
            now,
        )
        .await
        .expect("viewer ticket");
    hub.consume_ticket(auth, &binding, &ticket.ticket_protocol(), now)
        .await
        .expect("viewer")
}

#[cfg(target_os = "macos")]
const PARENT_ENVIRONMENT_CANARY: &str = "OPENBOT_ENGINE_PARENT_ENVIRONMENT_CANARY";

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires real Engine bundle and host permission; spawns isolated canary test parents"]
fn both_roles_exclude_the_parent_environment_from_main_and_renderer() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/computer/engine-child-environment-v1.json"
    ))
    .expect("environment fixture");
    assert_eq!(fixture["schema"], "openbot-engine-child-environment-v1");
    assert!(
        fixture["canary_evidence"]["after"]
            .as_object()
            .expect("four observations")
            .values()
            .all(|value| value == false)
    );
    assert!(
        fixture["remaining"]
            .as_object()
            .expect("unfinished gates")
            .values()
            .all(|value| value == false)
    );
    let mut passed = true;
    for name in [
        "browser_role_start_frame_stop_has_no_debug_listener_or_orphan",
        "component_role_start_frame_stop_has_no_debug_listener_or_orphan",
    ] {
        let result = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                name,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(
                PARENT_ENVIRONMENT_CANARY,
                "non-secret-synthetic-inheritance-probe",
            )
            .output()
            .expect("isolated conformance parent");
        // Only these two exact, content-free observations may leave the subprocess capture.
        let observations: Vec<_> = result
            .stdout
            .split(|byte| *byte == b'\n')
            .filter(|line| {
                *line == b"engine-environment-inherited=true"
                    || *line == b"engine-environment-inherited=false"
            })
            .collect();
        for observation in &observations {
            println!(
                "environment-conformance case={name} {}",
                core::str::from_utf8(observation).expect("fixed observation")
            );
        }
        for line in result.stderr.split(|byte| *byte == b'\n') {
            if line.starts_with(b"thread '")
                && line.windows(12).any(|bytes| bytes == b"panicked at ")
                && line.len() < 300
            {
                println!(
                    "environment-conformance failure-location={}",
                    String::from_utf8_lossy(line)
                );
            }
        }
        passed &= result.status.success() && observations.len() == 2;
    }
    assert!(
        passed,
        "Engine environment conformance failed; arbitrary subprocess output is withheld"
    );
}

#[cfg(target_os = "macos")]
fn parent_environment_present(pid: u32) -> bool {
    if std::env::var_os(PARENT_ENVIRONMENT_CANARY).is_none() {
        return false;
    }
    let marker = format!("{PARENT_ENVIRONMENT_CANARY}=non-secret-synthetic-inheritance-probe");
    let inspect = |pid: u32| {
        let result = std::process::Command::new("/bin/ps")
            .args(["eww", "-p", &pid.to_string(), "-o", "command="])
            .output()
            .expect("inspect only an owned process environment");
        assert!(result.status.success());
        assert!(result.stdout.len() <= 1024 * 1024);
        result
            .stdout
            .windows(marker.len())
            .any(|bytes| bytes == marker.as_bytes())
    };
    assert!(
        inspect(std::process::id()),
        "positive parent environment control unavailable"
    );
    let inherited = inspect(pid);
    println!("\nengine-environment-inherited={inherited}");
    inherited
}

fn fixture_bundle_root() -> PathBuf {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    std::env::var_os("OPENBOT_ENGINE_LOADER_FIXTURE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            workspace.join(format!(
                "target/engine/bundle/electron-43.3.0/{}",
                bundle_platform()
            ))
        })
}

async fn run_role(role: EngineRole) {
    let bundle_root = fixture_bundle_root();
    let manifest = bundle_root.join("manifest.json");
    let digest = format!(
        "{:x}",
        Sha256::digest(fs::read(&manifest).expect("bundle manifest"))
    );
    let bundle = EngineBundle::open(
        &bundle_root,
        EngineBundleDigest::from_hex(&digest).expect("manifest digest"),
    )
    .expect("verified bundle");

    let tag = match &role {
        EngineRole::BrowserComputer(_) => "browser",
        EngineRole::SandboxedComponent(_) => "component",
    };
    let temp = TestDirectories::new(tag);
    let computer_id = ComputerId::new(format!("computer-{tag}"));
    let generation = ComputerGeneration::new(1);
    let auth = AuthContext::for_test(
        DeploymentId::new("deployment-input"),
        role.tenant_id().clone(),
        role.component_actor_id()
            .cloned()
            .unwrap_or_else(|| ActorId::new("actor-input")),
        [Role::User],
        AuthGeneration::new(9),
        false,
    );
    let mut process = EngineProcess::launch(EngineLaunchConfig::new(
        bundle,
        role,
        ScreenAudience::from_auth(&auth),
        computer_id.clone(),
        generation,
        &temp.profile,
        &temp.temp,
    ))
    .await
    .expect("launch + peer credential + ready");
    assert_eq!(process.sandbox_fidelity(), expected_fidelity());
    let pid = process.pid();
    #[cfg(target_os = "macos")]
    let mut inherited_environment = parent_environment_present(pid);
    assert!(process.main_creation_time().is_finite());
    assert!(process.main_creation_time() > 0.0);
    assert_no_tcp_listener(pid);

    let tab = TabId::new(format!("tab-{tag}"));
    let started = process
        .start_session(tab.clone())
        .await
        .expect("start + frame");
    assert_eq!((started.frame.width(), started.frame.height()), (1280, 800));
    assert!(started.frame.captured_at_ms() > 0);
    assert!(started.frame.device_scale_factor() > 0.0);
    assert!(started.frame.page_scale_factor() > 0.0);
    assert!(started.frame.scroll_x().is_finite());
    assert!(started.frame.scroll_y().is_finite());
    assert!(started.frame.bytes().starts_with(&[0xff, 0xd8, 0xff]));
    assert!(started.frame.bytes().ends_with(&[0xff, 0xd9]));
    assert!(started.renderer_pid > 0);
    #[cfg(target_os = "macos")]
    {
        inherited_environment |= parent_environment_present(started.renderer_pid);
    }
    assert!(started.renderer_creation_time.is_finite());
    assert!(started.renderer_creation_time > 0.0);
    assert!(started.renderer_sandboxed, "OS-level ProcessMetric sandbox");
    assert_eq!(
        started.origin,
        if tag == "browser" {
            "acosmi-engine://session"
        } else {
            "component://session"
        }
    );
    let mut control = ControlService::new(computer_id.clone(), tab.clone(), generation, INPUT_TIME);
    control
        .take(&auth, INPUT_TIME + Duration::minutes(5), INPUT_TIME)
        .expect("take control");
    let ticket = control
        .issue_human_input_ticket(INPUT_TIME)
        .expect("human input ticket");
    let slow_frame = prove_slow_engine_ingress(
        &mut process,
        &mut control,
        &auth,
        &ticket,
        started.frame.clone(),
    )
    .await;
    let source = process.take_screen_source().expect("sole ScreenHub source");
    let screen_key = source.stream_key().clone();
    assert!(process.take_screen_source().is_err());
    let hub = ScreenHub::new(3).expect("screen hub");
    hub.attach(source).await.expect("attach real engine source");
    let binding_a = if tag == "browser" {
        ScreenViewerBinding::verified_server("https://app.example.test").expect("server binding")
    } else {
        ScreenViewerBinding::verified_desktop("openbot://localhost", "component-a", 1)
            .expect("desktop binding")
    };
    let binding_b = if tag == "browser" {
        binding_a.clone()
    } else {
        ScreenViewerBinding::verified_desktop("openbot://localhost", "component-b", 2)
            .expect("desktop binding")
    };
    assert!(matches!(
        hub.issue_ticket(
            &AuthContext::for_test(
                auth.deployment().clone(),
                auth.tenant().clone(),
                ActorId::new("wrong-actor"),
                [Role::User],
                auth.auth_generation(),
                false,
            ),
            &screen_key,
            binding_a.clone(),
            INPUT_TIME,
        )
        .await,
        Err(ScreenHubError::NotVisible)
    ));
    let ticket_a = hub
        .issue_ticket(&auth, &screen_key, binding_a.clone(), INPUT_TIME)
        .await
        .expect("ticket a");
    let protocol_a = ticket_a.ticket_protocol();
    assert!(!format!("{ticket_a:?}").contains(&protocol_a));
    assert!(matches!(
        hub.consume_ticket(
            &auth,
            &ScreenViewerBinding::verified_server("https://wrong.example.test")
                .expect("wrong binding"),
            &protocol_a,
            INPUT_TIME,
        )
        .await,
        Err(ScreenHubError::NotVisible)
    ));
    let ticket_b = hub
        .issue_ticket(&auth, &screen_key, binding_b.clone(), INPUT_TIME)
        .await
        .expect("ticket b");
    let mut viewer_a = hub
        .consume_ticket(&auth, &binding_a, &protocol_a, INPUT_TIME)
        .await
        .expect("viewer a");
    let mut viewer_b = hub
        .consume_ticket(&auth, &binding_b, &ticket_b.ticket_protocol(), INPUT_TIME)
        .await
        .expect("viewer b");
    assert!(matches!(
        hub.consume_ticket(&auth, &binding_a, &protocol_a, INPUT_TIME)
            .await,
        Err(ScreenHubError::TicketInvalid)
    ));
    let viewer_initial_frame = viewer_a.current().expect("viewer a initial");
    let viewer_initial_sequence = viewer_initial_frame.sequence();
    assert_eq!(
        viewer_b.current().expect("viewer b initial").sequence(),
        viewer_initial_sequence
    );
    let coordinates = ScreenCoordinateMap::new(
        &viewer_initial_frame,
        DecodedFrameSize::new(viewer_initial_frame.width(), viewer_initial_frame.height())
            .expect("decoded frame size"),
        CanvasRect::new(100.0, 50.0, 640.0, 500.0).expect("letterboxed canvas"),
    )
    .expect("viewer coordinate map");
    assert_eq!(coordinates.frame_sequence(), viewer_initial_sequence);
    let descendants = descendant_pids(pid);
    assert!(
        descendants.contains(&started.renderer_pid),
        "renderer is not a descendant of the authenticated main process"
    );
    for process in std::iter::once(pid).chain(descendants.iter().copied()) {
        assert_no_tcp_listener(process);
    }

    run_live_input_matrix(
        &mut process,
        &mut control,
        &auth,
        &ticket,
        slow_frame,
        coordinates,
    )
    .await;
    let viewer_frame_a = tokio::time::timeout(std::time::Duration::from_secs(5), viewer_a.next())
        .await
        .expect("viewer a latest deadline")
        .expect("viewer a latest");
    let viewer_frame_b = tokio::time::timeout(std::time::Duration::from_secs(5), viewer_b.next())
        .await
        .expect("viewer b latest deadline")
        .expect("viewer b latest");
    assert_eq!(viewer_frame_a.sequence(), viewer_frame_b.sequence());
    assert!(Arc::ptr_eq(&viewer_frame_a, &viewer_frame_b));
    assert!(viewer_frame_a.sequence() > viewer_initial_sequence);
    assert!(viewer_a.skipped_frames() > 0);
    assert!(viewer_b.skipped_frames() > 0);
    assert_eq!(&viewer_frame_a.binary()[..8], b"OBSCRN01");
    assert_eq!(
        hub.invalidate_actor(auth.tenant(), auth.actor(), AuthGeneration::new(10),)
            .await,
        1
    );
    assert!(matches!(
        viewer_a.next().await,
        Err(ScreenHubError::ViewerRevoked)
    ));
    assert!(matches!(
        viewer_b.next().await,
        Err(ScreenHubError::ViewerRevoked)
    ));
    control.release(INPUT_TIME).expect("release control");
    assert!(matches!(
        control.authorize_human_input_receipt(&auth, &ticket, INPUT_TIME),
        Err(ControlError::TakeControlFirst)
    ));

    let stopped = process.stop_session(&tab).await.expect("stop");
    assert!(!stopped.replayed());
    assert_eq!(
        stopped.stats().received_frames(),
        stopped.stats().acknowledged_frames()
    );
    assert!(stopped.stats().dropped_before_consume() > 0);
    println!(
        "engine-screencast role={tag} received={} acknowledged={} dropped={} deviceScale={} pageScale={}",
        stopped.stats().received_frames(),
        stopped.stats().acknowledged_frames(),
        stopped.stats().dropped_before_consume(),
        started.frame.device_scale_factor(),
        started.frame.page_scale_factor(),
    );
    let replayed = process.stop_session(&tab).await.expect("idempotent stop");
    assert!(replayed.replayed());
    assert_eq!(replayed.stats(), stopped.stats());
    assert!(process.next_frame().await.is_err());
    process.shutdown().await.expect("shutdown in five seconds");
    assert_process_gone(pid);
    for child in descendants {
        assert_process_gone(child);
    }
    for lock in ["SingletonLock", "SingletonSocket", "SingletonCookie"] {
        assert!(
            !temp.profile.join(lock).exists(),
            "profile lock `{lock}` remained after shutdown"
        );
    }
    #[cfg(target_os = "macos")]
    assert!(
        !inherited_environment,
        "an Engine process inherited the synthetic parent canary"
    );
}

async fn prove_slow_engine_ingress(
    process: &mut EngineProcess,
    control: &mut ControlService,
    auth: &AuthContext,
    ticket: &HumanInputTicket,
    baseline: EngineFrame,
) -> EngineFrame {
    dispatch(
        process,
        control,
        auth,
        ticket,
        BrowserInput::mouse_move(
            80.0,
            70.0,
            MouseButton::Left,
            ModifierMask::new(0).expect("modifiers"),
        )
        .expect("hover"),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    let mut sequence = baseline.sequence();
    let hover = next_frame(process, &mut sequence).await;
    assert_ne!(
        frame_hash(&hover),
        frame_hash(&baseline),
        "mouseMoved must change :hover"
    );
    let slow_stats = wait_screen_caught_up(process).await;
    assert_eq!(
        slow_stats.received_frames(),
        slow_stats.acknowledged_frames()
    );
    assert!(
        slow_stats.dropped_before_consume() > 0,
        "size-one engine ingress must drop old animation frames for a slow consumer"
    );
    hover
}

async fn run_live_input_matrix(
    process: &mut EngineProcess,
    control: &mut ControlService,
    auth: &AuthContext,
    ticket: &HumanInputTicket,
    starting_frame: EngineFrame,
    coordinates: ScreenCoordinateMap,
) {
    let none = ModifierMask::new(0).expect("modifiers");
    let mut sequence = starting_frame.sequence();

    let mut wrong_scope = ControlService::new(
        ComputerId::new("other-computer"),
        ticket.tab_id().clone(),
        ticket.computer_generation(),
        INPUT_TIME,
    );
    wrong_scope
        .take(auth, INPUT_TIME + Duration::minutes(5), INPUT_TIME)
        .expect("wrong-scope lease");
    let wrong_ticket = wrong_scope
        .issue_human_input_ticket(INPUT_TIME)
        .expect("wrong-scope ticket");
    let wrong_receipt = wrong_scope
        .authorize_human_input_receipt(auth, &wrong_ticket, INPUT_TIME)
        .expect("wrong-scope receipt");
    assert!(matches!(
        process
            .apply_human_input(
                wrong_receipt,
                &BrowserInput::insert_text("must-not-cross-scope"),
                INPUT_TIME,
            )
            .await,
        Err(EngineProcessError::InputAuthority)
    ));

    let expired_receipt = control
        .authorize_human_input_receipt(auth, ticket, INPUT_TIME)
        .expect("receipt before authority-clock expiry");
    assert!(matches!(
        process
            .apply_human_input(
                expired_receipt,
                &BrowserInput::insert_text("must-not-dispatch"),
                ticket.expires_at(),
            )
            .await,
        Err(EngineProcessError::InputAuthority)
    ));

    let button = coordinates
        .map_point(140.0, 184.0)
        .expect("letterboxed button point");
    assert_eq!((button.viewport_x(), button.viewport_y()), (80.0, 168.0));
    dispatch(
        process,
        control,
        auth,
        ticket,
        BrowserInput::mouse_move(
            button.viewport_x(),
            button.viewport_y(),
            MouseButton::Left,
            none,
        )
        .expect("button hover"),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let button_hover = next_frame(process, &mut sequence).await;
    let pressed = apply(
        process,
        control,
        auth,
        ticket,
        BrowserInput::mouse_down(
            button.viewport_x(),
            button.viewport_y(),
            MouseButton::Left,
            None,
            none,
        )
        .expect("press"),
        &mut sequence,
    )
    .await;
    assert_ne!(
        frame_hash(&pressed),
        frame_hash(&button_hover),
        "mousePressed must change :active"
    );
    let drag_outside = coordinates
        .map_point(250.0, 184.0)
        .expect("letterboxed drag point");
    dispatch(
        process,
        control,
        auth,
        ticket,
        BrowserInput::mouse_move(
            drag_outside.viewport_x(),
            drag_outside.viewport_y(),
            MouseButton::Left,
            none,
        )
        .expect("drag move while pressed"),
    )
    .await;
    let released = apply(
        process,
        control,
        auth,
        ticket,
        BrowserInput::mouse_up(
            drag_outside.viewport_x(),
            drag_outside.viewport_y(),
            MouseButton::Left,
            None,
            none,
        )
        .expect("release after drag"),
        &mut sequence,
    )
    .await;
    assert_ne!(
        frame_hash(&released),
        frame_hash(&pressed),
        "mouseReleased must clear :active"
    );

    dispatch(
        process,
        control,
        auth,
        ticket,
        BrowserInput::mouse_move(80.0, 256.0, MouseButton::Left, none).expect("input hover"),
    )
    .await;
    let _ = apply(
        process,
        control,
        auth,
        ticket,
        BrowserInput::mouse_down(80.0, 256.0, MouseButton::Left, None, none).expect("input down"),
        &mut sequence,
    )
    .await;
    let focused = apply(
        process,
        control,
        auth,
        ticket,
        BrowserInput::mouse_up(80.0, 256.0, MouseButton::Left, None, none).expect("input up"),
        &mut sequence,
    )
    .await;
    let typed = apply(
        process,
        control,
        auth,
        ticket,
        BrowserInput::key_down("a", "KeyA", Some("a".to_owned()), none).expect("key down"),
        &mut sequence,
    )
    .await;
    assert_ne!(
        frame_hash(&typed),
        frame_hash(&focused),
        "keyDown text must alter input"
    );
    dispatch(
        process,
        control,
        auth,
        ticket,
        BrowserInput::key_up("a", "KeyA", none).expect("key up"),
    )
    .await;
    let erased = apply(
        process,
        control,
        auth,
        ticket,
        BrowserInput::key_down("Backspace", "Backspace", None, none).expect("raw key down"),
        &mut sequence,
    )
    .await;
    assert_ne!(
        frame_hash(&erased),
        frame_hash(&typed),
        "rawKeyDown Backspace must alter input"
    );
    dispatch(
        process,
        control,
        auth,
        ticket,
        BrowserInput::key_up("Backspace", "Backspace", none).expect("raw key up"),
    )
    .await;
    dispatch(
        process,
        control,
        auth,
        ticket,
        BrowserInput::key_down("F1", "F1", None, none).expect("unknown multi-unit key"),
    )
    .await;
    dispatch(
        process,
        control,
        auth,
        ticket,
        BrowserInput::key_up("F1", "F1", none).expect("unknown multi-unit key up"),
    )
    .await;

    control
        .request_secret(Some("OTP"), "field-1", DocumentGeneration::new(1))
        .expect("secret request");
    let secret = BrowserInput::secret_insert(
        control.pending_secret().expect("pending secret"),
        "never-on-ordinary-wire",
    )
    .expect("secret input");
    let receipt = control
        .authorize_human_input_receipt(auth, ticket, INPUT_TIME)
        .expect("secret receipt");
    assert!(matches!(
        process
            .apply_human_input(receipt, &secret, INPUT_TIME)
            .await,
        Err(EngineProcessError::InputPlan(_))
    ));

    let inserted = apply(
        process,
        control,
        auth,
        ticket,
        BrowserInput::insert_text("日本語🔐"),
        &mut sequence,
    )
    .await;
    assert_ne!(
        frame_hash(&inserted),
        frame_hash(&erased),
        "insertText must alter input"
    );

    let page_scroll = coordinates
        .map_point(550.0, 450.0)
        .expect("letterboxed page scroll point");
    let wheel_delta = coordinates
        .map_delta(0.0, 200.0)
        .expect("viewer wheel delta");
    assert_eq!(
        (page_scroll.viewport_x(), page_scroll.viewport_y()),
        (900.0, 700.0)
    );
    assert_eq!((wheel_delta.delta_x(), wheel_delta.delta_y()), (0.0, 400.0));
    dispatch(
        process,
        control,
        auth,
        ticket,
        BrowserInput::mouse_move(
            page_scroll.viewport_x(),
            page_scroll.viewport_y(),
            MouseButton::Left,
            none,
        )
        .expect("page scroll hover"),
    )
    .await;
    let scroll_hover = inserted.clone();
    dispatch(
        process,
        control,
        auth,
        ticket,
        BrowserInput::wheel(
            page_scroll.viewport_x(),
            page_scroll.viewport_y(),
            wheel_delta.delta_x(),
            wheel_delta.delta_y(),
            none,
        )
        .expect("wheel"),
    )
    .await;
    let scrolled = next_distinct_frame(process, &mut sequence, frame_hash(&scroll_hover)).await;
    assert_ne!(
        frame_hash(&scrolled),
        frame_hash(&scroll_hover),
        "mouseWheel must scroll"
    );
    assert!(scrolled.scroll_y() > scroll_hover.scroll_y());
}

async fn apply(
    process: &mut EngineProcess,
    control: &mut ControlService,
    auth: &AuthContext,
    ticket: &HumanInputTicket,
    input: BrowserInput,
    sequence: &mut u64,
) -> EngineFrame {
    dispatch(process, control, auth, ticket, input).await;
    next_frame(process, sequence).await
}

async fn dispatch(
    process: &mut EngineProcess,
    control: &mut ControlService,
    auth: &AuthContext,
    ticket: &HumanInputTicket,
    input: BrowserInput,
) {
    let receipt = control
        .authorize_human_input_receipt(auth, ticket, INPUT_TIME)
        .expect("fresh input authority");
    process
        .apply_human_input(receipt, &input, INPUT_TIME)
        .await
        .expect("authenticated live CDP input");
}

async fn next_frame(process: &mut EngineProcess, sequence: &mut u64) -> EngineFrame {
    let frame = tokio::time::timeout(std::time::Duration::from_secs(5), process.next_frame())
        .await
        .expect("next input frame deadline")
        .expect("next input frame");
    assert!(frame.sequence() > *sequence, "frame sequence must advance");
    *sequence = frame.sequence();
    frame
}

async fn next_distinct_frame(
    process: &mut EngineProcess,
    sequence: &mut u64,
    previous_hash: [u8; 32],
) -> EngineFrame {
    for _ in 0..50 {
        let frame = next_frame(process, sequence).await;
        if frame_hash(&frame) != previous_hash {
            return frame;
        }
    }
    panic!("no visually distinct screencast frame arrived");
}

async fn wait_screen_caught_up(
    process: &EngineProcess,
) -> openbot_computer::engine::ScreenIngressStats {
    for _ in 0..100 {
        let stats = process.screen_stats().await.expect("screen stats");
        if stats.received_frames() == stats.acknowledged_frames() {
            return stats;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("screen ingress did not acknowledge all received frames");
}

fn frame_hash(frame: &EngineFrame) -> [u8; 32] {
    Sha256::digest(frame.bytes()).into()
}

#[cfg(target_os = "macos")]
fn assert_no_tcp_listener(pid: u32) {
    let output = Command::new("/usr/sbin/lsof")
        .args(["-nP", "-a", "-p", &pid.to_string(), "-iTCP", "-sTCP:LISTEN"])
        .output()
        .expect("lsof");
    assert!(
        output.stdout.is_empty(),
        "engine opened a TCP listener: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(target_os = "windows")]
fn assert_no_tcp_listener(pid: u32) {
    let script = format!(
        "$items = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object {{ $_.OwningProcess -eq {pid} }}); if ($items.Count -ne 0) {{ $items | ConvertTo-Json -Compress; exit 7 }}"
    );
    let output = powershell(&script);
    assert!(
        output.status.success(),
        "engine opened a TCP listener or the probe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "macos")]
fn assert_process_gone(pid: u32) {
    let output = Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "pid="])
        .output()
        .expect("ps");
    assert!(
        String::from_utf8_lossy(&output.stdout).trim().is_empty(),
        "engine PID {pid} remained after shutdown"
    );
}

#[cfg(target_os = "windows")]
fn assert_process_gone(pid: u32) {
    let script = format!("if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) {{ exit 7 }}");
    for _ in 0..50 {
        if powershell(&script).status.success() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("engine PID {pid} remained after shutdown");
}

#[cfg(target_os = "macos")]
fn descendant_pids(root: u32) -> Vec<u32> {
    let output = Command::new("/bin/ps")
        .args(["-axo", "pid=,ppid="])
        .output()
        .expect("ps process tree");
    assert!(output.status.success());
    let rows = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            Some((
                fields.next()?.parse::<u32>().ok()?,
                fields.next()?.parse::<u32>().ok()?,
            ))
        })
        .collect::<Vec<_>>();
    let mut pending = vec![root];
    let mut descendants = Vec::new();
    while let Some(parent) = pending.pop() {
        for (pid, ppid) in &rows {
            if *ppid == parent && !descendants.contains(pid) {
                descendants.push(*pid);
                pending.push(*pid);
            }
        }
    }
    descendants
}

#[cfg(target_os = "windows")]
fn descendant_pids(root: u32) -> Vec<u32> {
    let output = powershell(
        "Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object { '{0} {1}' -f $_.ProcessId,$_.ParentProcessId }",
    );
    assert!(
        output.status.success(),
        "Win32 process-tree probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            Some((
                fields.next()?.parse::<u32>().ok()?,
                fields.next()?.parse::<u32>().ok()?,
            ))
        })
        .collect::<Vec<_>>();
    descendants_from_rows(root, &rows)
}

#[cfg(target_os = "windows")]
fn powershell(script: &str) -> std::process::Output {
    let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
    let executable =
        PathBuf::from(system_root).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    Command::new(executable)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .output()
        .expect("PowerShell host probe")
}

#[cfg(target_os = "windows")]
fn descendants_from_rows(root: u32, rows: &[(u32, u32)]) -> Vec<u32> {
    let mut pending = vec![root];
    let mut descendants = Vec::new();
    while let Some(parent) = pending.pop() {
        for (pid, ppid) in rows {
            if *ppid == parent && !descendants.contains(pid) {
                descendants.push(*pid);
                pending.push(*pid);
            }
        }
    }
    descendants
}

fn bundle_platform() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "macos-arm64"
    }
    #[cfg(target_os = "windows")]
    {
        "windows-x64"
    }
}

fn expected_fidelity() -> EngineSandboxFidelity {
    #[cfg(target_os = "macos")]
    {
        EngineSandboxFidelity::Enforced
    }
    #[cfg(target_os = "windows")]
    {
        EngineSandboxFidelity::Degraded
    }
}

struct TestDirectories {
    root: PathBuf,
    profile: PathBuf,
    temp: PathBuf,
}

impl TestDirectories {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "openbot-engine-conformance-{tag}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let profile = root.join("profile");
        let temp = root.join("temp");
        fs::create_dir_all(&profile).expect("profile");
        fs::create_dir_all(&temp).expect("temp");
        Self {
            root,
            profile,
            temp,
        }
    }
}

impl Drop for TestDirectories {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
