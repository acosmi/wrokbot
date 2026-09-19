//! Rebuild the pinned, offline syntax pack after reviewing asset provenance.
#[path = "../design/markdown/pack.rs"]
mod pack;
fn main() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("design/markdown");
    let set = pack::build_openbot_syntax_set(&root.join("syntaxes"))
        .expect("reviewed syntax definitions");
    for (_, token) in pack::TARGET_LANGUAGES {
        assert!(
            set.find_syntax_by_token(token)
                .or_else(|| set.find_syntax_by_extension(token))
                .is_some(),
            "missing token {token}"
        );
    }
    pack::dump_openbot_syntax_pack(
        &root.join("syntaxes"),
        &root.join("openbot_syntaxes.packdump"),
    )
    .expect("syntax pack");
}
