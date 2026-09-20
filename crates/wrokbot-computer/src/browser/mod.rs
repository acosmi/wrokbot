//! Closed browser-engine protocol and authority-owned residency decisions. No free CDP method or
//! host path crosses this boundary.

pub mod cdp_input;
pub mod eviction;
pub mod protocol;

pub use cdp_input::{
    CdpInputPlan, CdpInputPlanError, CdpKeyEventType, CdpKeyPlan, CdpMouseEventType, CdpMousePlan,
};
pub use protocol::{
    BrowserInput, BrowserInputKind, BrowserOperation, BrowserOperationKind, ElementTarget,
    InputProtocolError, KeyInput, ModifierMask, MouseButton, NavigateOperation, PointerInput,
    ProfileOperation, ScreencastOperation, ScrollOperation, SecretInsert, TextInput,
};
