//! Bounded control/boot wire for the Rust-owned engine host.

use std::path::Path;

use openbot_contracts::engine::{
    ENGINE_PROTOCOL_VERSION, ENGINE_RELEASE_EPOCH, MAX_ENGINE_BOOT_BYTES,
    MAX_ENGINE_CONTROL_FRAME_BYTES,
};
use openbot_contracts::ids::{ComputerGeneration, ComputerId, TabId};
use serde::{Deserialize, Serialize};

use crate::browser::{CdpInputPlan, CdpKeyEventType, CdpMouseEventType, ModifierMask, MouseButton};

use super::scope::{EngineRole, EngineRoleKind};

/// Rust-minted operation identifier. Renderer/shim input can only echo it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineOperationId(String);

impl EngineOperationId {
    /// Construct a bounded operation ID from authority-owned state.
    pub fn new(value: impl Into<String>) -> Result<Self, EngineProtocolError> {
        let value = value.into();
        validate_string(&value, 128)
            .then_some(Self(value))
            .ok_or(EngineProtocolError::InvalidOperationId)
    }

    /// Borrow the wire value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct BootCapability {
    protocol_version: u16,
    release_epoch: String,
    control_pipe: String,
    frame_pipe: String,
    token: String,
    role: EngineRoleKind,
    scope_digest: String,
    computer_id: String,
    generation: String,
}

impl BootCapability {
    pub(crate) fn new(
        control_pipe: &Path,
        frame_pipe: &Path,
        token: &BootToken,
        role: &EngineRole,
        computer_id: &ComputerId,
        generation: ComputerGeneration,
    ) -> Result<Self, EngineProtocolError> {
        let control_pipe = control_pipe
            .to_str()
            .filter(|value| validate_string(value, 512))
            .ok_or(EngineProtocolError::InvalidPipePath)?
            .to_owned();
        let frame_pipe = frame_pipe
            .to_str()
            .filter(|value| validate_string(value, 512))
            .ok_or(EngineProtocolError::InvalidPipePath)?
            .to_owned();
        if !validate_string(computer_id.as_str(), 256) {
            return Err(EngineProtocolError::InvalidComputerId);
        }
        Ok(Self {
            protocol_version: ENGINE_PROTOCOL_VERSION,
            release_epoch: ENGINE_RELEASE_EPOCH.to_string(),
            control_pipe,
            frame_pipe,
            token: token.hex(),
            role: role.kind(),
            scope_digest: hex(&role.scope_digest()),
            computer_id: computer_id.as_str().to_owned(),
            generation: generation.get().to_string(),
        })
    }

    pub(crate) fn line(&self) -> Result<Vec<u8>, EngineProtocolError> {
        let mut line = serde_json::to_vec(self).map_err(|_| EngineProtocolError::EncodeFailed)?;
        line.push(b'\n');
        if line.len() > MAX_ENGINE_BOOT_BYTES {
            return Err(EngineProtocolError::BootTooLarge);
        }
        Ok(line)
    }
}

#[derive(Clone)]
pub(crate) struct BootToken([u8; 16]);

impl BootToken {
    pub(crate) fn random() -> Result<Self, EngineProtocolError> {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| EngineProtocolError::RandomFailed)?;
        Ok(Self(bytes))
    }

    pub(crate) fn bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub(crate) fn hex(&self) -> String {
        hex(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EngineInputKindWire {
    MouseMove,
    MouseDown,
    MouseUp,
    Wheel,
    KeyDown,
    RawKeyDown,
    KeyUp,
    InsertText,
}

impl EngineInputKindWire {
    pub(crate) fn from_plan(plan: &CdpInputPlan<'_>) -> Self {
        match plan {
            CdpInputPlan::Mouse(plan) => match plan.event_type() {
                CdpMouseEventType::MouseMoved => Self::MouseMove,
                CdpMouseEventType::MousePressed => Self::MouseDown,
                CdpMouseEventType::MouseReleased => Self::MouseUp,
            },
            CdpInputPlan::Wheel(_) => Self::Wheel,
            CdpInputPlan::Key(plan) => match plan.event_type() {
                CdpKeyEventType::KeyDown => Self::KeyDown,
                CdpKeyEventType::RawKeyDown => Self::RawKeyDown,
                CdpKeyEventType::KeyUp => Self::KeyUp,
            },
            CdpInputPlan::InsertText(_) => Self::InsertText,
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "input_kind", rename_all = "snake_case")]
pub(crate) enum EngineInputWire<'a> {
    MouseMove {
        x: f64,
        y: f64,
        button: &'static str,
        click_count: u32,
        modifiers: u8,
    },
    MouseDown {
        x: f64,
        y: f64,
        button: &'static str,
        click_count: u32,
        modifiers: u8,
    },
    MouseUp {
        x: f64,
        y: f64,
        button: &'static str,
        click_count: u32,
        modifiers: u8,
    },
    Wheel {
        x: f64,
        y: f64,
        delta_x: f64,
        delta_y: f64,
        modifiers: u8,
    },
    KeyDown {
        key: &'a str,
        code: &'a str,
        text: &'a str,
        windows_virtual_key_code: u32,
        native_virtual_key_code: u32,
        modifiers: u8,
    },
    RawKeyDown {
        key: &'a str,
        code: &'a str,
        windows_virtual_key_code: u32,
        native_virtual_key_code: u32,
        modifiers: u8,
    },
    KeyUp {
        key: &'a str,
        code: &'a str,
        windows_virtual_key_code: u32,
        native_virtual_key_code: u32,
        modifiers: u8,
    },
    InsertText {
        text: &'a str,
    },
}

impl<'a> EngineInputWire<'a> {
    fn from_plan(plan: &'a CdpInputPlan<'a>) -> Self {
        match plan {
            CdpInputPlan::Mouse(plan) => {
                let fields = (
                    plan.x(),
                    plan.y(),
                    mouse_button(plan.button()),
                    plan.click_count(),
                    modifier_bits(plan.modifiers()),
                );
                match plan.event_type() {
                    CdpMouseEventType::MouseMoved => Self::MouseMove {
                        x: fields.0,
                        y: fields.1,
                        button: fields.2,
                        click_count: fields.3,
                        modifiers: fields.4,
                    },
                    CdpMouseEventType::MousePressed => Self::MouseDown {
                        x: fields.0,
                        y: fields.1,
                        button: fields.2,
                        click_count: fields.3,
                        modifiers: fields.4,
                    },
                    CdpMouseEventType::MouseReleased => Self::MouseUp {
                        x: fields.0,
                        y: fields.1,
                        button: fields.2,
                        click_count: fields.3,
                        modifiers: fields.4,
                    },
                }
            }
            CdpInputPlan::Wheel(plan) => Self::Wheel {
                x: plan.x(),
                y: plan.y(),
                delta_x: plan.delta_x(),
                delta_y: plan.delta_y(),
                modifiers: modifier_bits(plan.modifiers()),
            },
            CdpInputPlan::Key(plan) => match plan.event_type() {
                CdpKeyEventType::KeyDown => Self::KeyDown {
                    key: plan.key(),
                    code: plan.code(),
                    text: plan.text().unwrap_or_default(),
                    windows_virtual_key_code: plan.windows_virtual_key_code(),
                    native_virtual_key_code: plan.native_virtual_key_code(),
                    modifiers: modifier_bits(plan.modifiers()),
                },
                CdpKeyEventType::RawKeyDown => Self::RawKeyDown {
                    key: plan.key(),
                    code: plan.code(),
                    windows_virtual_key_code: plan.windows_virtual_key_code(),
                    native_virtual_key_code: plan.native_virtual_key_code(),
                    modifiers: modifier_bits(plan.modifiers()),
                },
                CdpKeyEventType::KeyUp => Self::KeyUp {
                    key: plan.key(),
                    code: plan.code(),
                    windows_virtual_key_code: plan.windows_virtual_key_code(),
                    native_virtual_key_code: plan.native_virtual_key_code(),
                    modifiers: modifier_bits(plan.modifiers()),
                },
            },
            CdpInputPlan::InsertText(text) => Self::InsertText {
                text: text.expose_for_engine(),
            },
        }
    }
}

fn mouse_button(button: MouseButton) -> &'static str {
    match button {
        MouseButton::Left => "left",
        MouseButton::Right => "right",
        MouseButton::Middle => "middle",
    }
}

const fn modifier_bits(modifiers: ModifierMask) -> u8 {
    modifiers.get()
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum EngineCommandWire<'a> {
    Start {
        operation_id: &'a str,
        computer_id: &'a str,
        generation: String,
        tab_id: &'a str,
    },
    Stop {
        operation_id: &'a str,
        computer_id: &'a str,
        generation: String,
        tab_id: &'a str,
    },
    Input {
        operation_id: &'a str,
        computer_id: &'a str,
        generation: String,
        tab_id: &'a str,
        #[serde(flatten)]
        input: EngineInputWire<'a>,
    },
    FrameAck {
        computer_id: &'a str,
        generation: String,
        tab_id: &'a str,
        frame_sequence: String,
        screencast_session_id: u32,
    },
    Screencast {
        operation_id: &'a str,
        computer_id: &'a str,
        generation: String,
        tab_id: &'a str,
        enabled: bool,
    },
    Shutdown {
        operation_id: &'a str,
    },
}

impl<'a> EngineCommandWire<'a> {
    pub(crate) fn screencast(
        operation: &'a EngineOperationId,
        computer: &'a ComputerId,
        generation: ComputerGeneration,
        tab: &'a TabId,
        enabled: bool,
    ) -> Self {
        Self::Screencast {
            operation_id: operation.as_str(),
            computer_id: computer.as_str(),
            generation: generation.get().to_string(),
            tab_id: tab.as_str(),
            enabled,
        }
    }

    pub(crate) fn start(
        operation: &'a EngineOperationId,
        computer: &'a ComputerId,
        generation: ComputerGeneration,
        tab: &'a TabId,
    ) -> Self {
        Self::Start {
            operation_id: operation.as_str(),
            computer_id: computer.as_str(),
            generation: generation.get().to_string(),
            tab_id: tab.as_str(),
        }
    }

    pub(crate) fn stop(
        operation: &'a EngineOperationId,
        computer: &'a ComputerId,
        generation: ComputerGeneration,
        tab: &'a TabId,
    ) -> Self {
        Self::Stop {
            operation_id: operation.as_str(),
            computer_id: computer.as_str(),
            generation: generation.get().to_string(),
            tab_id: tab.as_str(),
        }
    }

    pub(crate) fn input(
        operation: &'a EngineOperationId,
        computer: &'a ComputerId,
        generation: ComputerGeneration,
        tab: &'a TabId,
        plan: &'a CdpInputPlan<'a>,
    ) -> Self {
        Self::Input {
            operation_id: operation.as_str(),
            computer_id: computer.as_str(),
            generation: generation.get().to_string(),
            tab_id: tab.as_str(),
            input: EngineInputWire::from_plan(plan),
        }
    }

    pub(crate) fn shutdown(operation: &'a EngineOperationId) -> Self {
        Self::Shutdown {
            operation_id: operation.as_str(),
        }
    }

    pub(crate) fn frame_ack(
        computer: &'a ComputerId,
        generation: ComputerGeneration,
        tab: &'a TabId,
        frame_sequence: u64,
        screencast_session_id: u32,
    ) -> Self {
        Self::FrameAck {
            computer_id: computer.as_str(),
            generation: generation.get().to_string(),
            tab_id: tab.as_str(),
            frame_sequence: frame_sequence.to_string(),
            screencast_session_id,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum EngineEventWire {
    Hello {
        token: String,
    },
    Ready {
        main_pid: u32,
        main_creation_time: f64,
        protocol_version: u16,
    },
    Started {
        operation_id: String,
        tab_id: String,
        renderer_pid: u32,
        renderer_creation_time: f64,
        renderer_sandboxed: bool,
        node_exposed: bool,
        origin: String,
    },
    InputApplied {
        operation_id: String,
        tab_id: String,
        input_kind: EngineInputKindWire,
    },
    ScreencastState {
        operation_id: String,
        tab_id: String,
        enabled: bool,
        received_frames: String,
        acknowledged_frames: String,
        replayed: bool,
    },
    Stopped {
        operation_id: String,
        tab_id: String,
        received_frames: String,
        acknowledged_frames: String,
        replayed: bool,
    },
    ShutdownComplete {
        operation_id: String,
    },
    Error {
        #[serde(default)]
        operation_id: Option<String>,
        code: String,
    },
}

/// Stable protocol construction/parsing failures.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum EngineProtocolError {
    /// Operation ID was empty, too long, or contained NUL.
    #[error("engine_operation_id_invalid")]
    InvalidOperationId,
    /// Boot pipe path was not bounded UTF-8.
    #[error("engine_pipe_path_invalid")]
    InvalidPipePath,
    /// Computer ID cannot fit the bounded wire.
    #[error("engine_computer_id_invalid")]
    InvalidComputerId,
    /// OS CSPRNG failed.
    #[error("engine_boot_random_failed")]
    RandomFailed,
    /// JSON encoding failed.
    #[error("engine_protocol_encode_failed")]
    EncodeFailed,
    /// Boot capability exceeded 4 KiB.
    #[error("engine_boot_too_large")]
    BootTooLarge,
    /// A control command exceeded the protocol's 64 KiB frame limit before any pipe write.
    #[error("engine_control_frame_too_large")]
    ControlFrameTooLarge,
}

pub(crate) fn encode_command(
    command: &EngineCommandWire<'_>,
) -> Result<Vec<u8>, EngineProtocolError> {
    let mut bytes = serde_json::to_vec(command).map_err(|_| EngineProtocolError::EncodeFailed)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_ENGINE_CONTROL_FRAME_BYTES {
        return Err(EngineProtocolError::ControlFrameTooLarge);
    }
    Ok(bytes)
}

fn validate_string(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.contains('\0')
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use openbot_contracts::engine::MAX_ENGINE_CONTROL_FRAME_BYTES;
    use openbot_contracts::ids::{
        BotId, ChannelId, ComputerGeneration, ComputerId, CredentialPrincipalId, TabId, TenantId,
    };

    use super::{
        BootCapability, BootToken, EngineCommandWire, EngineOperationId, EngineProtocolError,
        encode_command,
    };
    use crate::browser::{BrowserInput, CdpInputPlan, ModifierMask, MouseButton};
    use crate::engine::{ComputerSecurityScope, EngineRole, WorkspaceScope};

    #[test]
    fn boot_line_is_one_bounded_line_and_contains_no_actor_policy_or_intent() {
        let role = EngineRole::BrowserComputer(ComputerSecurityScope::new(
            TenantId::new("tenant"),
            BotId::new("bot"),
            CredentialPrincipalId::new("principal"),
            WorkspaceScope::Channel(ChannelId::new("channel")),
        ));
        let boot = BootCapability::new(
            std::path::Path::new("/tmp/control.sock"),
            std::path::Path::new("/tmp/frame.sock"),
            &BootToken([7; 16]),
            &role,
            &ComputerId::new("computer"),
            ComputerGeneration::new(3),
        )
        .expect("boot");
        let line = String::from_utf8(boot.line().expect("line")).expect("utf8");
        assert_eq!(line.matches('\n').count(), 1);
        for forbidden in ["actor_id", "policy", "intent", "decision"] {
            assert!(!line.contains(forbidden));
        }
    }

    #[test]
    fn operation_id_is_bounded() {
        assert!(EngineOperationId::new("op-1").is_ok());
        assert!(EngineOperationId::new("").is_err());
        assert!(EngineOperationId::new("x".repeat(129)).is_err());
    }

    #[test]
    fn protocol_v4_serializes_all_eight_closed_input_kinds_without_a_method_slot() {
        let none = ModifierMask::new(0).expect("modifiers");
        let inputs = [
            BrowserInput::mouse_move(1.0, 2.0, MouseButton::Left, none).expect("move"),
            BrowserInput::mouse_down(1.0, 2.0, MouseButton::Right, None, none).expect("down"),
            BrowserInput::mouse_up(1.0, 2.0, MouseButton::Middle, Some(2), none).expect("up"),
            BrowserInput::wheel(1.0, 2.0, 3.0, 4.0, none).expect("wheel"),
            BrowserInput::key_down("a", "KeyA", Some("a".to_owned()), none).expect("key down"),
            BrowserInput::key_down("Enter", "Enter", None, none).expect("raw key down"),
            BrowserInput::key_up("Enter", "Enter", none).expect("key up"),
            BrowserInput::insert_text("A中"),
        ];
        let operation = EngineOperationId::new("op-1").expect("operation");
        let computer = ComputerId::new("computer");
        let tab = TabId::new("tab");
        let mut kinds = Vec::new();
        for input in &inputs {
            let plan = CdpInputPlan::try_from(input).expect("ordinary input plan");
            let command = EngineCommandWire::input(
                &operation,
                &computer,
                ComputerGeneration::new(3),
                &tab,
                &plan,
            );
            let bytes = encode_command(&command).expect("bounded input frame");
            assert_eq!(bytes.last(), Some(&b'\n'));
            let value: serde_json::Value =
                serde_json::from_slice(&bytes[..bytes.len() - 1]).expect("wire JSON");
            assert_eq!(value["kind"], "input");
            assert_eq!(value["operation_id"], "op-1");
            assert_eq!(value["computer_id"], "computer");
            assert_eq!(value["generation"], "3");
            assert_eq!(value["tab_id"], "tab");
            assert!(value.get("method").is_none());
            kinds.push(value["input_kind"].as_str().expect("input kind").to_owned());
        }
        assert_eq!(
            kinds,
            [
                "mouse_move",
                "mouse_down",
                "mouse_up",
                "wheel",
                "key_down",
                "raw_key_down",
                "key_up",
                "insert_text",
            ]
        );
        let descriptor: serde_json::Value =
            serde_json::from_str(openbot_contracts::engine::ENGINE_PROTOCOL_DESCRIPTOR)
                .expect("protocol descriptor");
        assert_eq!(descriptor["input_kinds"], serde_json::json!(kinds));
        assert_eq!(
            descriptor["commands"],
            serde_json::json!([
                "start",
                "input",
                "frame_ack",
                "screencast",
                "stop",
                "shutdown"
            ])
        );
    }

    #[test]
    fn oversized_text_is_rejected_before_a_control_frame_can_be_written() {
        let input = BrowserInput::insert_text("x".repeat(MAX_ENGINE_CONTROL_FRAME_BYTES));
        let plan = CdpInputPlan::try_from(&input).expect("ordinary input plan");
        let operation = EngineOperationId::new("op-1").expect("operation");
        let computer = ComputerId::new("computer");
        let tab = TabId::new("tab");
        assert!(matches!(
            encode_command(&EngineCommandWire::input(
                &operation,
                &computer,
                ComputerGeneration::new(3),
                &tab,
                &plan,
            )),
            Err(EngineProtocolError::ControlFrameTooLarge)
        ));
    }

    #[test]
    fn frame_ack_has_no_operation_or_free_cdp_slot_and_preserves_u64_as_text() {
        let computer = ComputerId::new("computer");
        let tab = TabId::new("tab");
        let bytes = encode_command(&EngineCommandWire::frame_ack(
            &computer,
            ComputerGeneration::new(3),
            &tab,
            u64::MAX,
            u32::MAX,
        ))
        .expect("frame ack");
        let value: serde_json::Value =
            serde_json::from_slice(&bytes[..bytes.len() - 1]).expect("wire JSON");
        assert_eq!(value["kind"], "frame_ack");
        assert_eq!(value["frame_sequence"], u64::MAX.to_string());
        assert_eq!(value["screencast_session_id"], u64::from(u32::MAX));
        assert!(value.get("operation_id").is_none());
        assert!(value.get("method").is_none());
    }
}
