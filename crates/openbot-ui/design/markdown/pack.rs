//! Syntax pack definition and builder for OpenBot Markdown code block highlighting.
//!
//! Enforces the 24 required programming languages specified in GUI Design Specification §6.4:
//! bash, sh, powershell, rust, toml, json, yaml, sql, ts, tsx, js, jsx, html, css, md, py, go,
//! java, kotlin, swift, c, cpp, diff, dockerfile.

use std::fs;
use std::path::Path;
use syntect::dumps::dump_to_uncompressed_file;
use syntect::parsing::{SyntaxDefinition, SyntaxSet};

/// The 24 target languages and their canonical extensions / tokens.
pub const TARGET_LANGUAGES: [(&str, &str); 24] = [
    ("bash", "sh"),
    ("sh", "sh"),
    ("powershell", "ps1"),
    ("rust", "rs"),
    ("toml", "toml"),
    ("json", "json"),
    ("yaml", "yaml"),
    ("sql", "sql"),
    ("ts", "ts"),
    ("tsx", "tsx"),
    ("js", "js"),
    ("jsx", "jsx"),
    ("html", "html"),
    ("css", "css"),
    ("md", "md"),
    ("py", "py"),
    ("go", "go"),
    ("java", "java"),
    ("kotlin", "kt"),
    ("swift", "swift"),
    ("c", "c"),
    ("cpp", "cpp"),
    ("diff", "diff"),
    ("dockerfile", "Dockerfile"),
];

/// Builds a complete `SyntaxSet` incorporating syntect's defaults and the 8 extra syntax definitions.
pub fn build_openbot_syntax_set(syntax_dir: &Path) -> Result<SyntaxSet, String> {
    let mut builder = SyntaxSet::load_defaults_newlines().into_builder();
    let entries = [
        "dockerfile.sublime-syntax",
        "kotlin.sublime-syntax",
        "powershell.sublime-syntax",
        "toml.sublime-syntax",
        "swift.sublime-syntax",
        "typescript.sublime-syntax",
        "tsx.sublime-syntax",
        "jsx.sublime-syntax",
    ];
    for entry in entries {
        let path = syntax_dir.join(entry);
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        let syntax = SyntaxDefinition::load_from_str(&content, true, None)
            .map_err(|e| format!("failed to parse {}: {:?}", path.display(), e))?;
        builder.add(syntax);
    }

    Ok(builder.build())
}

/// Dumps the full 24-language syntax set to the given packdump path.
pub fn dump_openbot_syntax_pack(syntax_dir: &Path, out_path: &Path) -> Result<(), String> {
    let set = build_openbot_syntax_set(syntax_dir)?;
    dump_to_uncompressed_file(&set, out_path).map_err(|e| format!("failed to write packdump: {e}"))
}
