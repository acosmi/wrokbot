//! Computer-surface business projections.

pub mod placeholder;

pub use placeholder::ComputerPlaceholder;

pub(crate) mod admin;
pub(crate) mod workspace;

pub(crate) mod frame;

mod latest_frame;

pub(crate) mod viewer;
