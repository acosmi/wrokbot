//! Trunk pre-build materialization for ignored UI assets.

use std::path::Path;

use anyhow::{Result, anyhow};

#[path = "../../../openbot-ui/build_support/assets.rs"]
mod assets;

pub(crate) fn run(root: &Path) -> Result<()> {
    let manifest = root.join("crates/openbot-ui");
    assets::materialize_token_css(&manifest).map_err(|error| anyhow!(error.to_string()))?;
    println!(
        "ui-assets: generated {} from design/tokens.toml",
        manifest.join("design/tokens.css").display()
    );
    Ok(())
}
