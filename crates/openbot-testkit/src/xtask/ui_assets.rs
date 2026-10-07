//! Trunk pre-build materialization for ignored UI assets.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};

use super::tools;

#[path = "../../../wrokbot-ui/build_support/assets.rs"]
mod assets;

pub(crate) fn run(root: &Path) -> Result<()> {
    let manifest = root.join("crates/wrokbot-ui");
    assets::materialize_token_css(&manifest).map_err(|error| anyhow!(error.to_string()))?;
    println!(
        "ui-assets: generated {} from design/tokens.toml",
        manifest.join("design/tokens.css").display()
    );

    let tailwind = tools::verified_tailwindcss(root)?;
    fs::create_dir_all(manifest.join("design/generated"))?;
    let mut command = Command::new(&tailwind);
    command.current_dir(&manifest).stdin(Stdio::null()).args([
        "--input",
        "design/app.css",
        "--output",
        "design/generated/app.css",
    ]);
    if std::env::var("TRUNK_PROFILE").is_ok_and(|profile| profile == "release") {
        command.arg("--minify");
    }
    let status = command
        .status()
        .with_context(|| format!("run {} for UI CSS", tailwind.display()))?;
    if !status.success() {
        bail!("pinned Tailwind CSS compilation failed: {status}");
    }
    println!("ui-assets: compiled design/generated/app.css with pinned Tailwind");
    Ok(())
}
