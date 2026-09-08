//! `BrowserInput` 到 Chrome DevTools Protocol 输入参数的纯映射。
//!
//! 本模块只生成封闭计划，不执行 CDP、不修改 engine wire，也不持有 `SecretInsert`。

use core::fmt;

use super::{
    BrowserInput, ModifierMask, MouseButton, PointerInput, ScrollOperation, TextInput,
    protocol::utf16_len,
};

/// 固定上游 `screencast.ts` 中显式列出的 17 个 virtual-key-code。
///
/// 空格虽也会被单 UTF-16 code unit fallback算成32，但它仍是上游表的显式成员；删掉会让
/// source-identity fixture失真。来源固定于`CopilotKit/openbot@891df72f…`、blob `9bc27c11…`。
const NAMED_VIRTUAL_KEY_CODES: [(&str, u32); 17] = [
    ("Backspace", 8),
    ("Tab", 9),
    ("Enter", 13),
    ("Shift", 16),
    ("Control", 17),
    ("Alt", 18),
    ("Escape", 27),
    (" ", 32),
    ("PageUp", 33),
    ("PageDown", 34),
    ("End", 35),
    ("Home", 36),
    ("ArrowLeft", 37),
    ("ArrowUp", 38),
    ("ArrowRight", 39),
    ("ArrowDown", 40),
    ("Delete", 46),
];

/// 封闭的 CDP 鼠标事件类型。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CdpMouseEventType {
    /// `Input.dispatchMouseEvent` 的 `mouseMoved`。
    MouseMoved,
    /// `Input.dispatchMouseEvent` 的 `mousePressed`。
    MousePressed,
    /// `Input.dispatchMouseEvent` 的 `mouseReleased`。
    MouseReleased,
}

/// 封闭的 CDP 键盘事件类型。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CdpKeyEventType {
    /// 有文本的按下事件。
    KeyDown,
    /// 无文本的按下事件。
    RawKeyDown,
    /// 抬起事件。
    KeyUp,
}

/// 一个 `Input.dispatchMouseEvent` 鼠标计划。
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CdpMousePlan {
    event_type: CdpMouseEventType,
    x: f64,
    y: f64,
    button: MouseButton,
    click_count: u32,
    modifiers: ModifierMask,
}

impl CdpMousePlan {
    /// CDP 鼠标事件类型。
    #[must_use]
    pub const fn event_type(self) -> CdpMouseEventType {
        self.event_type
    }

    /// 页面 x 坐标。
    #[must_use]
    pub const fn x(self) -> f64 {
        self.x
    }

    /// 页面 y 坐标。
    #[must_use]
    pub const fn y(self) -> f64 {
        self.y
    }

    /// 鼠标按钮。
    #[must_use]
    pub const fn button(self) -> MouseButton {
        self.button
    }

    /// move 固定为 0；down/up 保证非零。
    #[must_use]
    pub const fn click_count(self) -> u32 {
        self.click_count
    }

    /// CDP modifier bitmask。
    #[must_use]
    pub const fn modifiers(self) -> ModifierMask {
        self.modifiers
    }
}

/// 一个 `Input.dispatchKeyEvent` 计划。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CdpKeyPlan<'a> {
    event_type: CdpKeyEventType,
    key: &'a str,
    code: &'a str,
    text: Option<&'a str>,
    windows_virtual_key_code: u32,
    native_virtual_key_code: u32,
    modifiers: ModifierMask,
}

impl<'a> CdpKeyPlan<'a> {
    /// CDP 键盘事件类型。
    #[must_use]
    pub const fn event_type(self) -> CdpKeyEventType {
        self.event_type
    }

    /// DOM `key`；调用方不得记录其内容。
    #[must_use]
    pub const fn key(self) -> &'a str {
        self.key
    }

    /// DOM `code`；调用方不得记录其内容。
    #[must_use]
    pub const fn code(self) -> &'a str {
        self.code
    }

    /// 仅有文本的 keyDown 携带该字段。
    #[must_use]
    pub const fn text(self) -> Option<&'a str> {
        self.text
    }

    /// CDP `windowsVirtualKeyCode`。
    #[must_use]
    pub const fn windows_virtual_key_code(self) -> u32 {
        self.windows_virtual_key_code
    }

    /// CDP `nativeVirtualKeyCode`；固定与 Windows 值相同。
    #[must_use]
    pub const fn native_virtual_key_code(self) -> u32 {
        self.native_virtual_key_code
    }

    /// CDP modifier bitmask。
    #[must_use]
    pub const fn modifiers(self) -> ModifierMask {
        self.modifiers
    }
}

impl fmt::Debug for CdpKeyPlan<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CdpKeyPlan")
            .field("event_type", &self.event_type)
            .field("key_utf16_units", &utf16_len(self.key))
            .field("code_utf16_units", &utf16_len(self.code))
            .field("text_utf16_units", &self.text.map(utf16_len))
            .field("modifiers", &self.modifiers)
            .finish()
    }
}

/// 封闭的普通 CDP 输入计划。
///
/// variant 决定唯一允许的 CDP Input 调用；不存在自由 method。`SecretInsert` 构造性拒绝。
#[derive(Clone, Copy, PartialEq)]
pub enum CdpInputPlan<'a> {
    /// `Input.dispatchMouseEvent` 的 move/down/up。
    Mouse(CdpMousePlan),
    /// `Input.dispatchMouseEvent` 的 `mouseWheel`。
    Wheel(ScrollOperation),
    /// `Input.dispatchKeyEvent`。
    Key(CdpKeyPlan<'a>),
    /// `Input.insertText`。
    InsertText(&'a TextInput),
}

impl fmt::Debug for CdpInputPlan<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mouse(plan) => formatter.debug_tuple("Mouse").field(plan).finish(),
            Self::Wheel(plan) => formatter.debug_tuple("Wheel").field(plan).finish(),
            Self::Key(plan) => formatter.debug_tuple("Key").field(plan).finish(),
            Self::InsertText(text) => formatter
                .debug_struct("InsertText")
                .field("text_utf16_units", &text.utf16_units())
                .finish(),
        }
    }
}

/// CDP 输入计划映射失败。
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CdpInputPlanError {
    /// down/up 的 click count 必须非零。
    #[error("cdp_input_zero_click_count")]
    ZeroClickCount,
    /// secret 只能走独立、generation-bound typed command。
    #[error("cdp_input_secret_requires_typed_path")]
    SecretInsertRequiresTypedPath,
}

impl<'a> TryFrom<&'a BrowserInput> for CdpInputPlan<'a> {
    type Error = CdpInputPlanError;

    fn try_from(input: &'a BrowserInput) -> Result<Self, Self::Error> {
        match input {
            BrowserInput::MouseMove(pointer) => Ok(Self::Mouse(CdpMousePlan {
                event_type: CdpMouseEventType::MouseMoved,
                x: pointer.x(),
                y: pointer.y(),
                button: pointer.button(),
                click_count: 0,
                modifiers: pointer.modifiers(),
            })),
            BrowserInput::MouseDown(pointer) => {
                map_pressed_or_released(pointer, CdpMouseEventType::MousePressed).map(Self::Mouse)
            }
            BrowserInput::MouseUp(pointer) => {
                map_pressed_or_released(pointer, CdpMouseEventType::MouseReleased).map(Self::Mouse)
            }
            BrowserInput::Wheel(wheel) => Ok(Self::Wheel(*wheel)),
            BrowserInput::KeyDown(key) => {
                let text = key.text();
                let event_type = if text.is_some() {
                    CdpKeyEventType::KeyDown
                } else {
                    CdpKeyEventType::RawKeyDown
                };
                Ok(Self::Key(map_key(
                    key.key(),
                    key.code(),
                    text,
                    key.modifiers(),
                    event_type,
                )))
            }
            BrowserInput::KeyUp(key) => Ok(Self::Key(map_key(
                key.key(),
                key.code(),
                None,
                key.modifiers(),
                CdpKeyEventType::KeyUp,
            ))),
            BrowserInput::InsertText(text) => Ok(Self::InsertText(text)),
            BrowserInput::SecretInsert(_) => Err(CdpInputPlanError::SecretInsertRequiresTypedPath),
        }
    }
}

fn map_pressed_or_released(
    pointer: &PointerInput,
    event_type: CdpMouseEventType,
) -> Result<CdpMousePlan, CdpInputPlanError> {
    if pointer.click_count() == 0 {
        return Err(CdpInputPlanError::ZeroClickCount);
    }
    Ok(CdpMousePlan {
        event_type,
        x: pointer.x(),
        y: pointer.y(),
        button: pointer.button(),
        click_count: pointer.click_count(),
        modifiers: pointer.modifiers(),
    })
}

fn map_key<'a>(
    key: &'a str,
    code: &'a str,
    text: Option<&'a str>,
    modifiers: ModifierMask,
    event_type: CdpKeyEventType,
) -> CdpKeyPlan<'a> {
    let virtual_key_code = virtual_key_code(key);
    CdpKeyPlan {
        event_type,
        key,
        code,
        text,
        windows_virtual_key_code: virtual_key_code,
        native_virtual_key_code: virtual_key_code,
        modifiers,
    }
}

fn virtual_key_code(key: &str) -> u32 {
    if let Some((_, code)) = NAMED_VIRTUAL_KEY_CODES
        .iter()
        .find(|(candidate, _)| *candidate == key)
    {
        return *code;
    }

    let utf16_units = utf16_len(key);
    if utf16_units != 1 {
        // Preserve the fixed upstream's observable fallback exactly. The engine may still pass an
        // unknown named key through CDP with a zero virtual key code; narrowing that behavior needs
        // a separate v4 replacement decision, not an implementation-time guess.
        return 0;
    }

    // BrowserInput rejects empty keys, so a single UTF-16 unit always has a scalar. Keep the helper
    // independently fail-closed anyway. Rust uppercase can expand (for example ß -> SS); JS
    // charCodeAt(0) likewise takes the first resulting unit.
    let Some(character) = key.chars().next() else {
        return 0;
    };
    let Some(upper) = character.to_uppercase().next() else {
        return 0;
    };
    let mut encoded = [0_u16; 2];
    u32::from(upper.encode_utf16(&mut encoded)[0])
}

#[cfg(test)]
mod tests {
    use openbot_contracts::ids::{ComputerGeneration, ComputerId, DocumentGeneration, TabId};
    use time::macros::datetime;

    use super::{
        CdpInputPlan, CdpInputPlanError, CdpKeyEventType, CdpMouseEventType,
        NAMED_VIRTUAL_KEY_CODES,
    };
    use crate::{
        browser::{BrowserInput, InputProtocolError, ModifierMask, MouseButton},
        control::ControlService,
    };

    const CDP_INPUT_PLAN_FIXTURE: &str =
        include_str!("../../../../fixtures/computer/cdp-input-plan.json");

    fn no_modifiers() -> ModifierMask {
        ModifierMask::new(0).expect("zero modifiers")
    }

    #[test]
    fn maps_mouse_move_down_and_up_with_exact_click_count_rules() {
        let modifiers = ModifierMask::new(15).expect("all modifiers");
        let move_input =
            BrowserInput::mouse_move(1.25, -2.5, MouseButton::Middle, modifiers).expect("move");
        let move_plan = CdpInputPlan::try_from(&move_input).expect("move plan");
        let CdpInputPlan::Mouse(move_plan) = move_plan else {
            panic!("mouse move plan");
        };
        assert_eq!(move_plan.event_type(), CdpMouseEventType::MouseMoved);
        assert_eq!(move_plan.click_count(), 0);
        assert_eq!((move_plan.x(), move_plan.y()), (1.25, -2.5));
        assert_eq!(move_plan.button(), MouseButton::Middle);
        assert_eq!(move_plan.modifiers().get(), 15);

        let down_input =
            BrowserInput::mouse_down(f64::MAX, f64::MIN, MouseButton::Right, None, no_modifiers())
                .expect("down");
        let CdpInputPlan::Mouse(down_plan) =
            CdpInputPlan::try_from(&down_input).expect("down plan")
        else {
            panic!("mouse down plan");
        };
        assert_eq!(down_plan.event_type(), CdpMouseEventType::MousePressed);
        assert_eq!(down_plan.click_count(), 1);

        let up_input =
            BrowserInput::mouse_up(0.0, -0.0, MouseButton::Left, Some(u32::MAX), no_modifiers())
                .expect("up");
        let CdpInputPlan::Mouse(up_plan) = CdpInputPlan::try_from(&up_input).expect("up plan")
        else {
            panic!("mouse up plan");
        };
        assert_eq!(up_plan.event_type(), CdpMouseEventType::MouseReleased);
        assert_eq!(up_plan.click_count(), u32::MAX);

        assert!(matches!(
            BrowserInput::mouse_down(0.0, 0.0, MouseButton::Left, Some(0), no_modifiers()),
            Err(InputProtocolError::ZeroClickCount)
        ));
    }

    #[test]
    fn numeric_and_modifier_boundaries_fail_before_mapping() {
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(matches!(
                BrowserInput::mouse_move(value, 0.0, MouseButton::Left, no_modifiers()),
                Err(InputProtocolError::NonFiniteNumber)
            ));
            assert!(matches!(
                BrowserInput::wheel(0.0, 0.0, value, 0.0, no_modifiers()),
                Err(InputProtocolError::NonFiniteNumber)
            ));
        }
        assert_eq!(ModifierMask::new(15).expect("maximum mask").get(), 15);
        assert_eq!(
            ModifierMask::new(16),
            Err(InputProtocolError::InvalidModifiers)
        );
        assert_eq!(
            ModifierMask::new(u8::MAX),
            Err(InputProtocolError::InvalidModifiers)
        );
    }

    #[test]
    fn maps_wheel_axes_coordinates_and_modifiers() {
        let input = BrowserInput::wheel(
            -10.5,
            20.25,
            f64::MIN_POSITIVE,
            -f64::MAX,
            ModifierMask::new(10).expect("modifiers"),
        )
        .expect("wheel");
        let CdpInputPlan::Wheel(plan) = CdpInputPlan::try_from(&input).expect("wheel plan") else {
            panic!("wheel plan");
        };
        assert_eq!((plan.x(), plan.y()), (-10.5, 20.25));
        assert_eq!(
            (plan.delta_x(), plan.delta_y()),
            (f64::MIN_POSITIVE, -f64::MAX)
        );
        assert_eq!(plan.modifiers().get(), 10);
    }

    #[test]
    fn key_down_selects_key_down_or_raw_key_down_and_key_up_is_key_up() {
        let with_text = BrowserInput::key_down(
            "a",
            "KeyA",
            Some("a".to_owned()),
            ModifierMask::new(8).expect("shift"),
        )
        .expect("key down");
        let CdpInputPlan::Key(with_text) =
            CdpInputPlan::try_from(&with_text).expect("key down plan")
        else {
            panic!("key plan");
        };
        assert_eq!(with_text.event_type(), CdpKeyEventType::KeyDown);
        assert_eq!(with_text.text(), Some("a"));
        assert_eq!((with_text.key(), with_text.code()), ("a", "KeyA"));
        assert_eq!(with_text.modifiers().get(), 8);

        let empty_text =
            BrowserInput::key_down("Enter", "Enter", Some(String::new()), no_modifiers())
                .expect("raw key down");
        let CdpInputPlan::Key(empty_text) =
            CdpInputPlan::try_from(&empty_text).expect("raw key plan")
        else {
            panic!("key plan");
        };
        assert_eq!(empty_text.event_type(), CdpKeyEventType::RawKeyDown);
        assert_eq!(empty_text.text(), None);

        let up = BrowserInput::key_up("Enter", "Enter", no_modifiers()).expect("key up");
        let CdpInputPlan::Key(up) = CdpInputPlan::try_from(&up).expect("key up plan") else {
            panic!("key plan");
        };
        assert_eq!(up.event_type(), CdpKeyEventType::KeyUp);
        assert_eq!(up.text(), None);
    }

    #[test]
    fn named_virtual_key_code_table_matches_all_seventeen_fixed_upstream_entries() {
        const EXPECTED: [(&str, u32); 17] = [
            ("Backspace", 8),
            ("Tab", 9),
            ("Enter", 13),
            ("Shift", 16),
            ("Control", 17),
            ("Alt", 18),
            ("Escape", 27),
            (" ", 32),
            ("PageUp", 33),
            ("PageDown", 34),
            ("End", 35),
            ("Home", 36),
            ("ArrowLeft", 37),
            ("ArrowUp", 38),
            ("ArrowRight", 39),
            ("ArrowDown", 40),
            ("Delete", 46),
        ];
        assert_eq!(NAMED_VIRTUAL_KEY_CODES, EXPECTED);
        for &(key, expected) in &NAMED_VIRTUAL_KEY_CODES {
            let input = BrowserInput::key_down(key, key, None, no_modifiers()).expect("named key");
            let CdpInputPlan::Key(plan) = CdpInputPlan::try_from(&input).expect("named plan")
            else {
                panic!("key plan");
            };
            assert_eq!(plan.windows_virtual_key_code(), expected, "{key}");
            assert_eq!(plan.native_virtual_key_code(), expected, "{key}");
        }
    }

    #[test]
    fn single_utf16_unit_uses_uppercased_first_code_unit() {
        for (key, expected) in [("a", 65), ("1", 49), ("é", 201), ("ß", 83)] {
            let input = BrowserInput::key_down(key, "Code", None, no_modifiers()).expect("key");
            let CdpInputPlan::Key(plan) = CdpInputPlan::try_from(&input).expect("single unit")
            else {
                panic!("key plan");
            };
            assert_eq!(plan.windows_virtual_key_code(), expected, "{key:?}");
            assert_eq!(plan.native_virtual_key_code(), expected, "{key:?}");
        }
    }

    #[test]
    fn unknown_multi_unit_keys_preserve_the_fixed_upstream_zero_fallback() {
        for key in ["F1", "Meta", "🔐"] {
            let input = BrowserInput::key_down(key, "Code", None, no_modifiers()).expect("key");
            let CdpInputPlan::Key(plan) = CdpInputPlan::try_from(&input).expect("key plan") else {
                panic!("key plan");
            };
            assert_eq!(plan.windows_virtual_key_code(), 0, "{key:?}");
            assert_eq!(plan.native_virtual_key_code(), 0, "{key:?}");
        }
        assert!(matches!(
            BrowserInput::key_down("", "Code", None, no_modifiers()),
            Err(InputProtocolError::EmptyKey)
        ));
        assert!(matches!(
            BrowserInput::key_down("a", "", None, no_modifiers()),
            Err(InputProtocolError::EmptyKey)
        ));
    }

    #[test]
    fn insert_text_preserves_empty_and_unicode_text_without_key_events() {
        for text in ["", "A🔐中"] {
            let input = BrowserInput::insert_text(text);
            let CdpInputPlan::InsertText(plan) =
                CdpInputPlan::try_from(&input).expect("insert text")
            else {
                panic!("insert text plan");
            };
            assert_eq!(plan.expose_for_engine(), text);
        }
    }

    #[test]
    fn secret_insert_cannot_enter_an_ordinary_cdp_plan() {
        let mut control = ControlService::new(
            ComputerId::new("computer-0"),
            TabId::new("tab-0"),
            ComputerGeneration::new(1),
            datetime!(2026-09-04 12:00 UTC),
        );
        let target = control
            .request_secret(Some("OTP"), "field-1", DocumentGeneration::new(2))
            .expect("request")
            .pending_secret()
            .expect("target")
            .clone();
        let input = BrowserInput::secret_insert(target, "secret-value").expect("secret input");
        assert_eq!(
            CdpInputPlan::try_from(&input),
            Err(CdpInputPlanError::SecretInsertRequiresTypedPath)
        );
    }

    #[test]
    fn debug_redacts_key_code_text_and_inserted_content() {
        let key_input = BrowserInput::key_down(
            "sensitive-key",
            "sensitive-code",
            Some("sensitive-text".to_owned()),
            no_modifiers(),
        )
        .expect("key input");
        let CdpInputPlan::Key(plan) = CdpInputPlan::try_from(&key_input).expect("key plan") else {
            panic!("key plan");
        };
        assert_eq!(plan.windows_virtual_key_code(), 0);
        let rendered = format!("{plan:?}");
        for secret in ["sensitive-key", "sensitive-code", "sensitive-text"] {
            assert!(!rendered.contains(secret));
        }

        let key_input = BrowserInput::key_down(
            "€",
            "sensitive-code",
            Some("sensitive-text".to_owned()),
            no_modifiers(),
        )
        .expect("key input");
        let rendered = format!(
            "{:?}",
            CdpInputPlan::try_from(&key_input).expect("key plan")
        );
        for secret in ["€", "8364", "sensitive-code", "sensitive-text"] {
            assert!(!rendered.contains(secret));
        }
        assert!(rendered.contains("key_utf16_units"));
        assert!(rendered.contains("text_utf16_units"));

        let insert_input = BrowserInput::insert_text("inserted-sensitive-text");
        let rendered = format!(
            "{:?}",
            CdpInputPlan::try_from(&insert_input).expect("insert plan")
        );
        assert!(!rendered.contains("inserted-sensitive-text"));
        assert!(rendered.contains("text_utf16_units"));
    }

    #[test]
    fn fixture_locks_source_identity_exact_table_and_unfinished_effect_boundary() {
        let fixture = serde_json::from_str::<serde_json::Value>(CDP_INPUT_PLAN_FIXTURE)
            .expect("fixture must be valid JSON");
        assert_eq!(fixture["schema"], "openbot-cdp-input-plan-v1");
        assert_eq!(
            fixture["upstream"]["commit"],
            "891df72f1827454d8b353d108fe5dd2313b7e30d"
        );
        assert_eq!(
            fixture["upstream"]["gitBlob"],
            "9bc27c11fc1b4cd296f7fc9df412aea0bedbbb22"
        );
        assert_eq!(fixture["upstream"]["bytes"], 6_906);
        assert_eq!(
            fixture["upstream"]["sha256"],
            "be79bde5007f03f37e3b99a1ef1388ba672d684ba32ec2b9090c417f9f47f566"
        );

        let expected = NAMED_VIRTUAL_KEY_CODES
            .iter()
            .map(|(key, code)| serde_json::json!([key, code]))
            .collect::<Vec<_>>();
        assert_eq!(
            fixture["namedVirtualKeyCodes"],
            serde_json::Value::Array(expected)
        );
        assert_eq!(fixture["keyRules"]["unknownMultiUtf16Units"], 0);
        assert_eq!(fixture["evidenceBoundary"]["closedPurePlan"], true);
        assert_eq!(
            fixture["evidenceBoundary"]["ordinaryPlanAcceptsSecretInsert"],
            false
        );
        for unfinished in ["productEngineWire", "liveCdpEffect", "screenHub"] {
            assert_eq!(fixture["evidenceBoundary"][unfinished], false);
        }
    }
}
