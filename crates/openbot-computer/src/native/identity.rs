//! Native target identity, coordinate bounds, and closed action categories (v5 §10.7 / PA-04).
//!
//! Native targets are strictly separated from browser/tab types. They bind the installation,
//! OS user, OS session, OS boot identity, PID + start time, window identity, display identity,
//! coordinate transform, and observation generation. Model/renderer cannot synthesize verified
//! targets from raw PID or untrusted JSON.

use core::fmt;
use time::OffsetDateTime;

/// OS session identifier (e.g. console session or loginwindow session).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OsSessionId(String);

impl OsSessionId {
    /// Construct an OS session identifier.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Return string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for OsSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// OS boot identifier to detect OS reboots across long-lived handles.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BootId(String);

impl BootId {
    /// Construct a boot ID.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Return string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for BootId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Native window identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NativeWindowId(String);

impl NativeWindowId {
    /// Construct a window ID.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Return string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for NativeWindowId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Native display identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NativeDisplayId(String);

impl NativeDisplayId {
    /// Construct a display ID.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Return string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for NativeDisplayId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Observation generation counter. Invalidated upon target drift, window change, or process restart.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObservationGeneration(u64);

impl ObservationGeneration {
    /// Construct an observation generation.
    #[must_use]
    pub const fn new(val: u64) -> Self {
        Self(val)
    }

    /// Return the raw counter.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Monotonically increment without wrapping.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl fmt::Display for ObservationGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Opaque handle exposed to callers referencing an internally verified native target.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NativeTargetHandle(String);

impl NativeTargetHandle {
    /// Construct an opaque handle.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow inner string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for NativeTargetHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Logical rectangle coordinates.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LogicalRect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl Eq for LogicalRect {}

/// Display coordinate transform and scale factors.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CoordinateTransform {
    pub scale_factor: f64,
    pub bounds: LogicalRect,
}

impl Eq for CoordinateTransform {}

/// Verified native OS target. Fields are strictly private and constructed only by trusted host adapter ports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeTarget {
    installation_id: String,
    os_user: String,
    os_session: OsSessionId,
    boot_id: BootId,
    pid: u32,
    process_start_time: OffsetDateTime,
    window_id: NativeWindowId,
    display_id: NativeDisplayId,
    coordinate_transform: CoordinateTransform,
    observation_generation: ObservationGeneration,
}

impl NativeTarget {
    /// Reject invalid host observations before exposing a usable handle.
    pub fn valid_identity(&self) -> bool {
        let b = self.coordinate_transform.bounds;
        [
            self.installation_id.as_str(),
            self.os_user.as_str(),
            self.os_session.as_str(),
            self.boot_id.as_str(),
            self.window_id.as_str(),
            self.display_id.as_str(),
        ]
        .iter()
        .all(|v| !v.is_empty() && v.len() <= 256)
            && self.pid > 0
            && self.coordinate_transform.scale_factor.is_finite()
            && self.coordinate_transform.scale_factor > 0.0
            && [b.x, b.y, b.width, b.height, b.x + b.width, b.y + b.height]
                .iter()
                .all(|v| v.is_finite())
            && b.width > 0.0
            && b.height > 0.0
    }

    /// Host metadata constructor; the checked platform port must still prove current authority.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn from_trusted_host(
        installation_id: impl Into<String>,
        os_user: impl Into<String>,
        os_session: OsSessionId,
        boot_id: BootId,
        pid: u32,
        process_start_time: OffsetDateTime,
        window_id: NativeWindowId,
        display_id: NativeDisplayId,
        coordinate_transform: CoordinateTransform,
        observation_generation: ObservationGeneration,
    ) -> Self {
        Self {
            installation_id: installation_id.into(),
            os_user: os_user.into(),
            os_session,
            boot_id,
            pid,
            process_start_time,
            window_id,
            display_id,
            coordinate_transform,
            observation_generation,
        }
    }

    /// Check if target belongs to the given OS session.
    #[must_use]
    pub fn matches_session(&self, session: &OsSessionId) -> bool {
        &self.os_session == session
    }

    /// Verify that the process and environment identity have not drifted or been recycled.
    #[must_use]
    pub fn matches_environment(&self, current: &NativeTarget) -> bool {
        self.installation_id == current.installation_id
            && self.os_user == current.os_user
            && self.os_session == current.os_session
            && self.boot_id == current.boot_id
            && self.pid == current.pid
            && self.process_start_time == current.process_start_time
            && self.window_id == current.window_id
            && self.display_id == current.display_id
    }

    /// Check if observation generation is stale.
    #[must_use]
    pub fn is_stale_observation(&self, current_gen: ObservationGeneration) -> bool {
        self.observation_generation < current_gen
    }

    /// Installation ID accessor.
    #[must_use]
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    /// OS user accessor.
    #[must_use]
    pub fn os_user(&self) -> &str {
        &self.os_user
    }

    /// OS session accessor.
    #[must_use]
    pub fn os_session(&self) -> &OsSessionId {
        &self.os_session
    }

    /// Boot ID accessor.
    #[must_use]
    pub fn boot_id(&self) -> &BootId {
        &self.boot_id
    }

    /// PID accessor.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Process start time accessor.
    #[must_use]
    pub fn process_start_time(&self) -> OffsetDateTime {
        self.process_start_time
    }

    /// Window ID accessor.
    #[must_use]
    pub fn window_id(&self) -> &NativeWindowId {
        &self.window_id
    }

    /// Display ID accessor.
    #[must_use]
    pub fn display_id(&self) -> &NativeDisplayId {
        &self.display_id
    }

    /// Coordinate transform accessor.
    #[must_use]
    pub fn coordinate_transform(&self) -> CoordinateTransform {
        self.coordinate_transform
    }

    /// Observation generation accessor.
    #[must_use]
    pub fn observation_generation(&self) -> ObservationGeneration {
        self.observation_generation
    }
}

/// Mouse buttons recognized for native input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

/// Native keyboard keys recognized for injection and state tracking.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NativeKey {
    Return,
    Space,
    Backspace,
    Tab,
    Escape,
    ArrowUp,
    ArrowDown,
    ArrowLeft,
    ArrowRight,
    Char(char),
    Modifier(NativeModifier),
}

impl fmt::Debug for NativeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Return => write!(f, "Return"),
            Self::Space => write!(f, "Space"),
            Self::Backspace => write!(f, "Backspace"),
            Self::Tab => write!(f, "Tab"),
            Self::Escape => write!(f, "Escape"),
            Self::ArrowUp => write!(f, "ArrowUp"),
            Self::ArrowDown => write!(f, "ArrowDown"),
            Self::ArrowLeft => write!(f, "ArrowLeft"),
            Self::ArrowRight => write!(f, "ArrowRight"),
            Self::Char(_) => write!(f, "Char('[REDACTED]')"),
            Self::Modifier(m) => write!(f, "Modifier({m:?})"),
        }
    }
}

/// Modifier keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NativeModifier {
    Shift,
    Control,
    Alt,
    Command,
}

/// Category of native action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NativeActionCategory {
    Pointer,
    Keyboard,
    Text,
    Accessibility,
}

/// Closed native action categories (§10.7).
///
/// Implements custom Debug to ensure text content and sensitive inputs are redacted.
#[derive(Clone, PartialEq)]
pub enum NativeAction {
    MouseMove { x: f64, y: f64 },
    MouseDown { button: MouseButton, x: f64, y: f64 },
    MouseUp { button: MouseButton, x: f64, y: f64 },
    MouseWheel { delta_x: f64, delta_y: f64 },
    KeyDown { key: NativeKey },
    KeyUp { key: NativeKey },
    InsertText { text: String },
    AxAction { action_name: String },
}

impl NativeAction {
    /// Return the broad category of this action.
    #[must_use]
    pub fn category(&self) -> NativeActionCategory {
        match self {
            Self::MouseMove { .. }
            | Self::MouseDown { .. }
            | Self::MouseUp { .. }
            | Self::MouseWheel { .. } => NativeActionCategory::Pointer,
            Self::KeyDown { .. } | Self::KeyUp { .. } => NativeActionCategory::Keyboard,
            Self::InsertText { .. } => NativeActionCategory::Text,
            Self::AxAction { .. } => NativeActionCategory::Accessibility,
        }
    }

    /// Validate action coordinates, payload bounds, and allowlist.
    pub fn validate(&self, bounds: Option<&LogicalRect>) -> Result<(), &'static str> {
        match self {
            Self::MouseMove { x, y } => {
                if !x.is_finite() || !y.is_finite() {
                    return Err("non_finite_coordinates");
                }
                if let Some(b) = bounds.filter(|b| {
                    *x < b.x || *x > (b.x + b.width) || *y < b.y || *y > (b.y + b.height)
                }) {
                    let _ = b;
                    return Err("coordinates_out_of_bounds");
                }
            }
            Self::MouseDown { x, y, .. } | Self::MouseUp { x, y, .. } => {
                if !x.is_finite() || !y.is_finite() {
                    return Err("non_finite_coordinates");
                }
                if let Some(b) = bounds.filter(|b| {
                    *x < b.x || *x > (b.x + b.width) || *y < b.y || *y > (b.y + b.height)
                }) {
                    let _ = b;
                    return Err("coordinates_out_of_bounds");
                }
            }
            Self::MouseWheel { delta_x, delta_y } => {
                if !delta_x.is_finite() || !delta_y.is_finite() {
                    return Err("non_finite_wheel_delta");
                }
            }
            Self::InsertText { text } => {
                if text.len() > 4096 {
                    return Err("insert_text_payload_too_large");
                }
            }
            Self::AxAction { action_name } => {
                if action_name.len() > 128 {
                    return Err("ax_action_name_too_long");
                }
                const ALLOWED_AX_ACTIONS: &[&str] = &[
                    "AXPress",
                    "AXShowMenu",
                    "AXIncrement",
                    "AXDecrement",
                    "AXConfirm",
                    "AXCancel",
                    "AXRaise",
                    "AXPick",
                ];
                if !ALLOWED_AX_ACTIONS.contains(&action_name.as_str()) {
                    return Err("ax_action_not_allowed");
                }
            }
            Self::KeyDown { .. } | Self::KeyUp { .. } => {}
        }
        Ok(())
    }
}

impl fmt::Debug for NativeAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MouseMove { x, y } => f
                .debug_struct("MouseMove")
                .field("x", x)
                .field("y", y)
                .finish(),
            Self::MouseDown { button, x, y } => f
                .debug_struct("MouseDown")
                .field("button", button)
                .field("x", x)
                .field("y", y)
                .finish(),
            Self::MouseUp { button, x, y } => f
                .debug_struct("MouseUp")
                .field("button", button)
                .field("x", x)
                .field("y", y)
                .finish(),
            Self::MouseWheel { delta_x, delta_y } => f
                .debug_struct("MouseWheel")
                .field("delta_x", delta_x)
                .field("delta_y", delta_y)
                .finish(),
            Self::KeyDown { key } => f.debug_struct("KeyDown").field("key", key).finish(),
            Self::KeyUp { key } => f.debug_struct("KeyUp").field("key", key).finish(),
            Self::InsertText { .. } => f
                .debug_struct("InsertText")
                .field("text", &"[REDACTED_TEXT]")
                .finish(),
            Self::AxAction { action_name } => f
                .debug_struct("AxAction")
                .field("action_name", action_name)
                .finish(),
        }
    }
}
