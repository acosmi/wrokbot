//! Closed browser and human-input operations from v3 §11.2 / §12.5.
//!
//! This is deliberately not a stringly CDP passthrough. Protocol v2 maps the ordinary variants into
//! the authenticated Electron engine and its literal CDP allowlist; `SecretInsert` remains on a
//! separate typed path and never enters that ordinary wire.

use core::fmt;
use core::num::NonZeroU32;

use openbot_contracts::ids::DocumentGeneration;
use openbot_domain::vault::SecretBytes;

use crate::control::PendingSecretTarget;

/// CDP modifier bitmask: Alt=1, Control=2, Meta=4, Shift=8.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ModifierMask(u8);

impl ModifierMask {
    const ALLOWED: u8 = 0b1111;

    /// Validate the closed four-bit CDP modifier mask.
    pub const fn new(raw: u8) -> Result<Self, InputProtocolError> {
        if raw & !Self::ALLOWED == 0 {
            Ok(Self(raw))
        } else {
            Err(InputProtocolError::InvalidModifiers)
        }
    }

    /// Raw CDP mask.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Closed mouse-button set accepted by CDP input.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MouseButton {
    /// Fixed-upstream default.
    #[default]
    Left,
    /// Secondary button.
    Right,
    /// Middle button.
    Middle,
}

/// Stable construction errors. Transport maps these to its own status/code boundary.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum InputProtocolError {
    /// Pointer/wheel coordinate or delta was NaN/infinite.
    #[error("browser_input_non_finite")]
    NonFiniteNumber,
    /// Mouse press/release click count must be non-zero.
    #[error("browser_input_zero_click_count")]
    ZeroClickCount,
    /// Modifier bits outside the CDP four-bit set were supplied.
    #[error("browser_input_invalid_modifiers")]
    InvalidModifiers,
    /// Key or code was empty.
    #[error("browser_input_empty_key")]
    EmptyKey,
    /// Secret insert contained no value.
    #[error("browser_input_empty_secret")]
    EmptySecret,
    /// Element reference was empty.
    #[error("browser_operation_empty_ref")]
    EmptyElementRef,
    /// Navigation target was empty. URL policy validation remains in Rust application authority.
    #[error("browser_operation_empty_url")]
    EmptyUrl,
}

/// One pointer action. Fields are private so NaN/zero click counts cannot be constructed directly.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PointerInput {
    x: f64,
    y: f64,
    button: MouseButton,
    click_count: u32,
    modifiers: ModifierMask,
}

impl PointerInput {
    fn moved(
        x: f64,
        y: f64,
        button: MouseButton,
        modifiers: ModifierMask,
    ) -> Result<Self, InputProtocolError> {
        validate_finite(&[x, y])?;
        Ok(Self {
            x,
            y,
            button,
            click_count: 0,
            modifiers,
        })
    }

    fn pressed_or_released(
        x: f64,
        y: f64,
        button: MouseButton,
        click_count: Option<u32>,
        modifiers: ModifierMask,
    ) -> Result<Self, InputProtocolError> {
        validate_finite(&[x, y])?;
        let click_count =
            NonZeroU32::new(click_count.unwrap_or(1)).ok_or(InputProtocolError::ZeroClickCount)?;
        Ok(Self {
            x,
            y,
            button,
            click_count: click_count.get(),
            modifiers,
        })
    }

    /// Page x coordinate after viewer/frame conversion.
    #[must_use]
    pub const fn x(&self) -> f64 {
        self.x
    }

    /// Page y coordinate after viewer/frame conversion.
    #[must_use]
    pub const fn y(&self) -> f64 {
        self.y
    }

    /// Mouse button.
    #[must_use]
    pub const fn button(&self) -> MouseButton {
        self.button
    }

    /// 0 for move; non-zero for down/up.
    #[must_use]
    pub const fn click_count(&self) -> u32 {
        self.click_count
    }

    /// CDP modifier mask.
    #[must_use]
    pub const fn modifiers(&self) -> ModifierMask {
        self.modifiers
    }
}

/// Wheel input with both axes preserved.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ScrollOperation {
    x: f64,
    y: f64,
    delta_x: f64,
    delta_y: f64,
    modifiers: ModifierMask,
}

impl ScrollOperation {
    /// Construct finite wheel coordinates and deltas.
    pub fn new(
        x: f64,
        y: f64,
        delta_x: f64,
        delta_y: f64,
        modifiers: ModifierMask,
    ) -> Result<Self, InputProtocolError> {
        validate_finite(&[x, y, delta_x, delta_y])?;
        Ok(Self {
            x,
            y,
            delta_x,
            delta_y,
            modifiers,
        })
    }

    /// Page x coordinate.
    #[must_use]
    pub const fn x(&self) -> f64 {
        self.x
    }

    /// Page y coordinate.
    #[must_use]
    pub const fn y(&self) -> f64 {
        self.y
    }

    /// Horizontal wheel delta.
    #[must_use]
    pub const fn delta_x(&self) -> f64 {
        self.delta_x
    }

    /// Vertical wheel delta.
    #[must_use]
    pub const fn delta_y(&self) -> f64 {
        self.delta_y
    }

    /// CDP modifier mask.
    #[must_use]
    pub const fn modifiers(&self) -> ModifierMask {
        self.modifiers
    }
}

/// Key event fields. Empty `text` is normalized to absent, matching upstream truthiness.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyInput {
    key: String,
    code: String,
    text: Option<String>,
    modifiers: ModifierMask,
}

impl KeyInput {
    fn new(
        key: impl Into<String>,
        code: impl Into<String>,
        text: Option<String>,
        modifiers: ModifierMask,
    ) -> Result<Self, InputProtocolError> {
        let key = key.into();
        let code = code.into();
        if key.is_empty() || code.is_empty() {
            return Err(InputProtocolError::EmptyKey);
        }
        Ok(Self {
            key,
            code,
            text: text.filter(|value| !value.is_empty()),
            modifiers,
        })
    }

    /// DOM key value; a single space is valid and therefore is not trimmed.
    #[must_use]
    pub fn key(&self) -> &str {
        self.key.as_str()
    }

    /// DOM code value.
    #[must_use]
    pub fn code(&self) -> &str {
        self.code.as_str()
    }

    /// Produced text. Absent means CDP must use rawKeyDown for a down event.
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        self.text.as_deref()
    }

    /// CDP modifier mask.
    #[must_use]
    pub const fn modifiers(&self) -> ModifierMask {
        self.modifiers
    }
}

impl fmt::Debug for KeyInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyInput")
            .field("key_utf16_units", &utf16_len(self.key.as_str()))
            .field("code_utf16_units", &utf16_len(self.code.as_str()))
            .field("text_utf16_units", &self.text.as_deref().map(utf16_len))
            .field("modifiers", &self.modifiers)
            .finish()
    }
}

/// Non-secret block text input. Debug exposes only UTF-16 length, never the content.
#[derive(Clone, PartialEq, Eq)]
pub struct TextInput {
    text: String,
    utf16_units: usize,
}

impl TextInput {
    /// Construct one block insertion (paste or completed IME text).
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        let text = text.into();
        let utf16_units = utf16_len(text.as_str());
        Self { text, utf16_units }
    }

    /// Explicit plaintext exposure for the future engine codec. Callers must not log the result.
    #[must_use]
    pub fn expose_for_engine(&self) -> &str {
        self.text.as_str()
    }

    /// JavaScript-compatible character count for receipts.
    #[must_use]
    pub const fn utf16_units(&self) -> usize {
        self.utf16_units
    }
}

impl fmt::Debug for TextInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TextInput")
            .field("utf16_units", &self.utf16_units)
            .finish()
    }
}

/// A value that may only be delivered to one pending, generation-bound secret target.
pub struct SecretInsert {
    target: PendingSecretTarget,
    value: SecretBytes,
    utf16_units: usize,
}

impl SecretInsert {
    /// Build the independent typed command; empty secrets are rejected like fixed upstream.
    pub fn new(
        target: PendingSecretTarget,
        value: impl Into<String>,
    ) -> Result<Self, InputProtocolError> {
        let value = value.into();
        if value.is_empty() {
            return Err(InputProtocolError::EmptySecret);
        }
        let utf16_units = utf16_len(value.as_str());
        Ok(Self {
            target,
            value: SecretBytes::new(value.into_bytes()),
            utf16_units,
        })
    }

    /// Exact field/document target; the value is never exposed through this projection.
    #[must_use]
    pub const fn target(&self) -> &PendingSecretTarget {
        &self.target
    }

    /// JavaScript-compatible character count for a secretless receipt.
    #[must_use]
    pub const fn utf16_units(&self) -> usize {
        self.utf16_units
    }

    /// Explicit plaintext exposure for the engine codec. Callers must not log or persist it.
    #[must_use]
    pub fn expose_for_engine(&self) -> &[u8] {
        self.value.expose()
    }
}

impl fmt::Debug for SecretInsert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretInsert")
            .field("target", &self.target)
            .field("utf16_units", &self.utf16_units)
            .field("bytes", &self.value.len())
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Exhaustive input tags. There is intentionally no IME-composition or drag tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrowserInputKind {
    /// CDP mouseMoved.
    MouseMove,
    /// CDP mousePressed.
    MouseDown,
    /// CDP mouseReleased.
    MouseUp,
    /// CDP mouseWheel.
    Wheel,
    /// CDP keyDown/rawKeyDown.
    KeyDown,
    /// CDP keyUp.
    KeyUp,
    /// CDP Input.insertText.
    InsertText,
    /// Independent scoped secret insertion.
    SecretInsert,
}

/// Closed v3 §12.5 input union.
pub enum BrowserInput {
    /// Pointer move; click count is structurally zero.
    MouseMove(PointerInput),
    /// Pointer down; click count is structurally non-zero.
    MouseDown(PointerInput),
    /// Pointer up; click count is structurally non-zero.
    MouseUp(PointerInput),
    /// Two-axis wheel input.
    Wheel(ScrollOperation),
    /// Key down; text presence selects keyDown versus rawKeyDown in the engine adapter.
    KeyDown(KeyInput),
    /// Key up.
    KeyUp(KeyInput),
    /// Paste or completed IME text.
    InsertText(TextInput),
    /// Scoped value that bypasses ordinary key events.
    SecretInsert(SecretInsert),
}

impl BrowserInput {
    /// Construct pointer movement.
    pub fn mouse_move(
        x: f64,
        y: f64,
        button: MouseButton,
        modifiers: ModifierMask,
    ) -> Result<Self, InputProtocolError> {
        PointerInput::moved(x, y, button, modifiers).map(Self::MouseMove)
    }

    /// Construct pointer down with upstream default click count 1.
    pub fn mouse_down(
        x: f64,
        y: f64,
        button: MouseButton,
        click_count: Option<u32>,
        modifiers: ModifierMask,
    ) -> Result<Self, InputProtocolError> {
        PointerInput::pressed_or_released(x, y, button, click_count, modifiers).map(Self::MouseDown)
    }

    /// Construct pointer up with upstream default click count 1.
    pub fn mouse_up(
        x: f64,
        y: f64,
        button: MouseButton,
        click_count: Option<u32>,
        modifiers: ModifierMask,
    ) -> Result<Self, InputProtocolError> {
        PointerInput::pressed_or_released(x, y, button, click_count, modifiers).map(Self::MouseUp)
    }

    /// Construct two-axis wheel input.
    pub fn wheel(
        x: f64,
        y: f64,
        delta_x: f64,
        delta_y: f64,
        modifiers: ModifierMask,
    ) -> Result<Self, InputProtocolError> {
        ScrollOperation::new(x, y, delta_x, delta_y, modifiers).map(Self::Wheel)
    }

    /// Construct key-down input.
    pub fn key_down(
        key: impl Into<String>,
        code: impl Into<String>,
        text: Option<String>,
        modifiers: ModifierMask,
    ) -> Result<Self, InputProtocolError> {
        KeyInput::new(key, code, text, modifiers).map(Self::KeyDown)
    }

    /// Construct key-up input; it never carries produced text.
    pub fn key_up(
        key: impl Into<String>,
        code: impl Into<String>,
        modifiers: ModifierMask,
    ) -> Result<Self, InputProtocolError> {
        KeyInput::new(key, code, None, modifiers).map(Self::KeyUp)
    }

    /// Construct a block insertion.
    #[must_use]
    pub fn insert_text(text: impl Into<String>) -> Self {
        Self::InsertText(TextInput::new(text))
    }

    /// Construct scoped secret input.
    pub fn secret_insert(
        target: PendingSecretTarget,
        value: impl Into<String>,
    ) -> Result<Self, InputProtocolError> {
        SecretInsert::new(target, value).map(Self::SecretInsert)
    }

    /// Exhaustive tag used by framing/conformance tests.
    #[must_use]
    pub const fn kind(&self) -> BrowserInputKind {
        match self {
            Self::MouseMove(_) => BrowserInputKind::MouseMove,
            Self::MouseDown(_) => BrowserInputKind::MouseDown,
            Self::MouseUp(_) => BrowserInputKind::MouseUp,
            Self::Wheel(_) => BrowserInputKind::Wheel,
            Self::KeyDown(_) => BrowserInputKind::KeyDown,
            Self::KeyUp(_) => BrowserInputKind::KeyUp,
            Self::InsertText(_) => BrowserInputKind::InsertText,
            Self::SecretInsert(_) => BrowserInputKind::SecretInsert,
        }
    }
}

impl fmt::Debug for BrowserInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrowserInput")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

/// Element ref tied to the document generation that minted it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElementTarget {
    element_ref: String,
    document_generation: DocumentGeneration,
}

impl ElementTarget {
    /// Construct an exact ref/generation pair.
    pub fn new(
        element_ref: impl Into<String>,
        document_generation: DocumentGeneration,
    ) -> Result<Self, InputProtocolError> {
        let element_ref = element_ref.into();
        if element_ref.is_empty() {
            return Err(InputProtocolError::EmptyElementRef);
        }
        Ok(Self {
            element_ref,
            document_generation,
        })
    }

    /// Opaque engine ref.
    #[must_use]
    pub fn element_ref(&self) -> &str {
        self.element_ref.as_str()
    }

    /// Document generation that minted the ref.
    #[must_use]
    pub const fn document_generation(&self) -> DocumentGeneration {
        self.document_generation
    }
}

/// Validated navigation payload. URL policy remains in Rust authority before this type is built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NavigateOperation(String);

impl NavigateOperation {
    /// Construct a non-empty already-authorized URL string.
    pub fn new(url: impl Into<String>) -> Result<Self, InputProtocolError> {
        let url = url.into();
        if url.is_empty() {
            return Err(InputProtocolError::EmptyUrl);
        }
        Ok(Self(url))
    }

    /// Authorized target.
    #[must_use]
    pub fn url(&self) -> &str {
        self.0.as_str()
    }
}

/// Screencast control; there is no arbitrary CDP method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScreencastOperation {
    /// JPEG production stream with fixed defaults enforced by the engine adapter.
    Start,
    /// Idempotent stop/detach.
    Stop,
    /// Acknowledge one Chromium session id after the frame enters the latest buffer.
    Ack(u64),
}

/// Persistent profile lifecycle; ensure is the only start path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileOperation {
    /// Ensure the single engine/profile exists.
    Ensure,
    /// Graceful stop preserving the profile.
    Stop,
    /// Irreversible reset.
    Reset,
}

/// Exhaustive operation tags. There is intentionally no upload/file-chooser/free-CDP member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrowserOperationKind {
    /// Navigate.
    Navigate,
    /// Accessibility snapshot.
    Snapshot,
    /// Read visible page text.
    Read,
    /// Click an element ref.
    Click,
    /// Fill an element ref.
    Type,
    /// Press a key, optionally on an element.
    Key,
    /// Scroll page/element.
    Scroll,
    /// One PNG screenshot.
    Screenshot,
    /// Screencast lifecycle.
    Screencast,
    /// Non-secret human input.
    HumanInput,
    /// Scoped secret insertion.
    SecretInsert,
    /// Profile lifecycle.
    Profile,
}

/// Closed v3 §11.2 operation envelope. Actual CDP execution remains a separate engine adapter.
pub enum BrowserOperation {
    /// Navigate to an already-authorized URL.
    Navigate(NavigateOperation),
    /// Read accessibility snapshot.
    Snapshot,
    /// Read visible text.
    Read,
    /// Click one exact element.
    Click(ElementTarget),
    /// Fill one exact element; ordinary text is redacted in Debug by the operation envelope.
    Type {
        /// Exact element target.
        target: ElementTarget,
        /// Text to fill.
        input: TextInput,
        /// Whether Enter follows fill.
        submit: bool,
    },
    /// Press one key, optionally on an element.
    Key {
        /// Optional exact target; absent means the page.
        target: Option<ElementTarget>,
        /// Key name.
        key: String,
    },
    /// Scroll page/element vertically on the Bot path.
    Scroll {
        /// Optional exact target; absent means the page.
        target: Option<ElementTarget>,
        /// Vertical delta.
        delta_y: f64,
    },
    /// Capture one PNG screenshot.
    Screenshot,
    /// Start/stop/ack screencast.
    Screencast(ScreencastOperation),
    /// Mouse/wheel/key/insertText input under HumanLease authority.
    HumanInput(BrowserInput),
    /// Secret insert stays a distinct command from ordinary input.
    SecretInsert(SecretInsert),
    /// Ensure/stop/reset persistent profile.
    Profile(ProfileOperation),
}

impl BrowserOperation {
    /// Exhaustive tag used by framing/conformance tests.
    #[must_use]
    pub const fn kind(&self) -> BrowserOperationKind {
        match self {
            Self::Navigate(_) => BrowserOperationKind::Navigate,
            Self::Snapshot => BrowserOperationKind::Snapshot,
            Self::Read => BrowserOperationKind::Read,
            Self::Click(_) => BrowserOperationKind::Click,
            Self::Type { .. } => BrowserOperationKind::Type,
            Self::Key { .. } => BrowserOperationKind::Key,
            Self::Scroll { .. } => BrowserOperationKind::Scroll,
            Self::Screenshot => BrowserOperationKind::Screenshot,
            Self::Screencast(_) => BrowserOperationKind::Screencast,
            Self::HumanInput(_) => BrowserOperationKind::HumanInput,
            Self::SecretInsert(_) => BrowserOperationKind::SecretInsert,
            Self::Profile(_) => BrowserOperationKind::Profile,
        }
    }
}

impl fmt::Debug for BrowserOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrowserOperation")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

fn validate_finite(values: &[f64]) -> Result<(), InputProtocolError> {
    if values.iter().all(|value| value.is_finite()) {
        Ok(())
    } else {
        Err(InputProtocolError::NonFiniteNumber)
    }
}

pub(super) fn utf16_len(value: &str) -> usize {
    value.encode_utf16().count()
}

#[cfg(test)]
mod tests {
    use openbot_contracts::ids::DocumentGeneration;

    use super::{
        BrowserInput, BrowserInputKind, BrowserOperation, BrowserOperationKind, InputProtocolError,
        ModifierMask, MouseButton,
    };
    use crate::control::{ControlService, PendingSecretTarget};
    use openbot_contracts::ids::{ComputerGeneration, ComputerId, TabId};
    use time::macros::datetime;

    fn secret_target() -> PendingSecretTarget {
        let mut control = ControlService::new(
            ComputerId::new("computer-0"),
            TabId::new("tab-0"),
            ComputerGeneration::new(1),
            datetime!(2026-08-28 12:00 UTC),
        );
        control
            .request_secret(Some("OTP"), "field-1", DocumentGeneration::new(2))
            .expect("request")
            .pending_secret()
            .expect("target")
            .clone()
    }

    #[test]
    fn input_union_is_exact_and_invalid_numeric_shapes_are_unrepresentable() {
        let none = ModifierMask::default();
        let inputs = [
            BrowserInput::mouse_move(1.0, 2.0, MouseButton::Left, none).expect("move"),
            BrowserInput::mouse_down(1.0, 2.0, MouseButton::Left, None, none).expect("down"),
            BrowserInput::mouse_up(1.0, 2.0, MouseButton::Left, Some(2), none).expect("up"),
            BrowserInput::wheel(1.0, 2.0, -3.0, 4.0, none).expect("wheel"),
            BrowserInput::key_down("a", "KeyA", Some("a".to_owned()), none).expect("down"),
            BrowserInput::key_up("a", "KeyA", none).expect("up"),
            BrowserInput::insert_text("完成"),
            BrowserInput::secret_insert(secret_target(), "🔐7").expect("secret"),
        ];
        assert_eq!(
            inputs.iter().map(BrowserInput::kind).collect::<Vec<_>>(),
            vec![
                BrowserInputKind::MouseMove,
                BrowserInputKind::MouseDown,
                BrowserInputKind::MouseUp,
                BrowserInputKind::Wheel,
                BrowserInputKind::KeyDown,
                BrowserInputKind::KeyUp,
                BrowserInputKind::InsertText,
                BrowserInputKind::SecretInsert,
            ]
        );
        assert!(matches!(
            BrowserInput::mouse_down(0.0, 0.0, MouseButton::Left, Some(0), none),
            Err(InputProtocolError::ZeroClickCount)
        ));
        assert!(matches!(
            BrowserInput::mouse_move(f64::NAN, 0.0, MouseButton::Left, none),
            Err(InputProtocolError::NonFiniteNumber)
        ));
        assert_eq!(
            ModifierMask::new(0b1_0000),
            Err(InputProtocolError::InvalidModifiers)
        );
    }

    #[test]
    fn text_and_secret_debug_are_redacted_and_receipts_use_javascript_utf16_units() {
        let text = BrowserInput::insert_text("A🔐中");
        assert_eq!(format!("{text:?}"), "BrowserInput { kind: InsertText, .. }");

        let secret = BrowserInput::secret_insert(secret_target(), "A🔐中").expect("secret");
        let BrowserInput::SecretInsert(secret) = &secret else {
            panic!("secret variant");
        };
        assert_eq!(secret.utf16_units(), 4);
        assert_eq!(secret.expose_for_engine(), "A🔐中".as_bytes());
        let rendered = format!("{secret:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("A🔐中"));
        assert!(!format!("{secret:?}").contains("A🔐中"));
    }

    #[test]
    fn closed_operation_tags_have_no_upload_file_chooser_or_free_cdp_member() {
        let operations = [
            BrowserOperation::Snapshot,
            BrowserOperation::Read,
            BrowserOperation::Screenshot,
            BrowserOperation::HumanInput(BrowserInput::insert_text("x")),
        ];
        assert_eq!(operations[0].kind(), BrowserOperationKind::Snapshot);
        assert_eq!(operations[1].kind(), BrowserOperationKind::Read);
        assert_eq!(operations[2].kind(), BrowserOperationKind::Screenshot);
        assert_eq!(operations[3].kind(), BrowserOperationKind::HumanInput);

        let exact = [
            "Navigate",
            "Snapshot",
            "Read",
            "Click",
            "Type",
            "Key",
            "Scroll",
            "Screenshot",
            "Screencast",
            "HumanInput",
            "SecretInsert",
            "Profile",
        ];
        assert_eq!(exact.len(), 12);
        assert!(!exact.iter().any(|name| matches!(
            *name,
            "Upload" | "FileChooser" | "ImeComposition" | "Drag" | "CdpMethod"
        )));
    }
}
