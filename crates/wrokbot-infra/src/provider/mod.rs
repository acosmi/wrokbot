//! Provider adapters；vendor wire types 不穿 application boundary。

pub mod anthropic;
pub mod context;
pub mod credential;
pub mod custom;
pub mod google;
pub mod openai;

mod common;
pub(crate) mod sse;
