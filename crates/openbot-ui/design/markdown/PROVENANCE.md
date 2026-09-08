# Wrok Bot Markdown syntax provenance

Verified on 2026-09-05 against public repository metadata and pinned source bytes. The inherited candidate contained incorrect commit references and license names; it is replaced by this record. No floating branch is used by the build.

The UI exposes 24 language tokens (bash/sh share a grammar), with Plain Text for unknown tokens. The pack also keeps syntect default dependency grammars required by cross-syntax references; it is not claimed to contain exactly 24 definitions.

| Local asset | Verified repository / commit | Exact upstream path | License / review |
| --- | --- | --- | --- |
| syntaxes/dockerfile.sublime-syntax | keith-hall/Containerfile-sublime-syntax `1459a3b954608b50894789c4130fae80db22011d` | `Containerfile.sublime-syntax` | MIT; GitHub tree blob f91f8fd26690df0aa93827ca639d45e0e00240a0 equals local git blob; filename only renamed. |
| syntaxes/kotlin.sublime-syntax | guille/sublime-kotlin `9b8b4a1f651ff651741fab031fbb6d6a4fce3ac3` | `Kotlin.sublime-syntax` | Unlicense; Downloaded bytes match. |
| syntaxes/powershell.sublime-syntax | SublimeText/PowerShell `2938700b586aeaa9c1d2dc0c04a1cc569ff3c24e` | `PowerShell.sublime-syntax` | MIT; Downloaded bytes match. |
| syntaxes/toml.sublime-syntax | sublimehq/Packages `ee7e91ce623d570dd8fee5a5ba8562cb7ef2e720` | `TOML/TOML.sublime-syntax` | LicenseRef-Sublime-Packages; Downloaded bytes match; preserve actual permissive LICENSE text, not MIT relabeling. |
| syntaxes/swift.sublime-syntax | sharkdp/bat `7323a7514f7601737640e7172be115127d6db08c` | `assets/syntaxes/02_Extra/Swift.sublime-syntax` | MIT OR Apache-2.0; Downloaded bytes match; retain bat NOTICE and licenses. |
| syntaxes/typescript.sublime-syntax | sharkdp/bat `7323a7514f7601737640e7172be115127d6db08c` | `assets/syntaxes/02_Extra/TypeScript.sublime-syntax` | MIT OR Apache-2.0; Downloaded bytes match; also retain original Microsoft TypeScript-Sublime Apache-2.0 license. |
| syntaxes/tsx.sublime-syntax | sharkdp/bat `a02713dc15818dd2d82d5a38b45d2cc33a4de95c` | `assets/syntaxes/02_Extra/TypsecriptReact.sublime-syntax` | MIT OR Apache-2.0; Replaced untraceable 200576-byte candidate with verified 153556-byte upstream file. Typsecript spelling is the actual historical path; retain Microsoft original license. |
| syntaxes/jsx.sublime-syntax | sharkdp/bat `7323a7514f7601737640e7172be115127d6db08c` | `assets/syntaxes/02_Extra/JavaScript (Babel).sublime-syntax` | MIT; Base SHA256 8072942a98bf6d87331f3bc9245919a2642e91d332e2c331e6964e7ca9675434; exact documented fancy-regex compatibility patch; retain Babel MIT license. |

`MANIFEST.json` records byte lengths and SHA-256 values. Original notices are shipped through `assets/notices/markdown/`; the custom Sublime Packages permission text is preserved verbatim. The JSX adaptation is recorded in `jsx-fancy-compat.patch`, and the TSX file was replaced because the inherited asset could not be matched to the claimed source.

Rebuild with `cargo run -p openbot-ui --example pack_markdown --locked --offline`; then rerun UI tests, release WASM build, syntax token checks and bundle budget. The source `.sublime-syntax` files are build inputs, not downloaded at runtime. Clipboard operations require an explicit user click; unknown languages and large code blocks keep plain text.
