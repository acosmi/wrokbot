use std::error::Error;
use std::path::PathBuf;

use leptos_i18n_build::{Config, ParseOptions, TranslationsInfos};

#[path = "build_support/assets.rs"]
mod assets;

fn main() -> Result<(), Box<dyn Error>> {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let output = PathBuf::from(std::env::var("OUT_DIR")?);
    for tracked in [
        "build_support/assets.rs",
        "design/tokens.toml",
        "design/icons.toml",
        "assets/fonts/InterVariable.woff2",
        "assets/fonts/InterVariable-Italic.woff2",
        "locales/en.json",
        "locales/zh-CN.json",
    ] {
        println!("cargo:rerun-if-changed={tracked}");
    }

    assets::generate_build_assets(&manifest, &output)?;

    let mut config = Config::new("en")?.add_locale("zh-CN")?;
    config.options = ParseOptions::new().interpolate_display(true);
    let translations = TranslationsInfos::parse_at_dir(&manifest, config)?;
    translations.emit_diagnostics();
    translations.rerun_if_locales_changed();
    translations.generate_i18n_module(output.join("i18n"))?;
    Ok(())
}
