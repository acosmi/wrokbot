#!/usr/bin/env bash
# G6 / Batch 15: exact Leptos GUI license, build-script and unmaintained-macro guard.
set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
  printf 'UI dependency guard: FAIL: %s\n' "$1" >&2
  exit 1
}

cargo_cache_root="${CARGO_HOME:-$HOME/.cargo}"
registry_root="$cargo_cache_root/registry/src"
shopt -s nullglob

crate_root() {
  local package_spec="$1"
  local candidates=("$registry_root"/*/"$package_spec")
  [[ ${#candidates[@]} -eq 1 && -d "${candidates[0]}" ]] \
    || fail "registry source for $package_spec is missing or ambiguous"
  printf '%s' "${candidates[0]}"
}

check_hash() {
  local package_spec="$1"
  local relative_path="$2"
  local expected_hash="$3"
  local source_file
  source_file="$(crate_root "$package_spec")/$relative_path"
  [[ -f "$source_file" ]] || fail "$package_spec/$relative_path is missing"
  local actual_hash
  actual_hash="$(shasum -a 256 "$source_file" | awk '{print $1}')"
  [[ "$actual_hash" == "$expected_hash" ]] \
    || fail "$package_spec/$relative_path hash changed: $actual_hash"
}

# GUI first-source exact direct selections. A version/feature change is a new dependency audit.
grep -qxF 'leptos = { version = "=0.8.19", features = ["csr"] }' Cargo.toml \
  || fail 'Leptos pin/features drifted'
grep -qxF 'leptos_router = "=0.8.13"' Cargo.toml || fail 'leptos_router pin drifted'
grep -qxF 'leptos_meta = "=0.8.6"' Cargo.toml || fail 'leptos_meta pin drifted'
grep -qxF 'leptos_i18n = { version = "=0.6.2", features = ["csr", "plurals", "format_datetime", "format_nums", "icu_compiled_data"] }' Cargo.toml \
  || fail 'leptos_i18n pin/features drifted'
grep -qxF 'leptos_i18n_build = "=0.6.2"' Cargo.toml \
  || fail 'leptos_i18n_build pin drifted'
grep -qxF 'gloo-net = { version = "=0.6.0", default-features = false, features = ["http", "json", "websocket"] }' Cargo.toml \
  || fail 'gloo-net pin/WebSocket feature boundary drifted'
grep -qxF 'image = { version = "=0.25.10", default-features = false, features = ["png"] }' Cargo.toml \
  || fail 'golden image pin/PNG-only feature boundary drifted'
grep -qxF 'image = { workspace = true, optional = true }' crates/openbot-testkit/Cargo.toml \
  || fail 'golden image edge is not optional and testkit-owned'
[[ "$(grep -cF '"dep:image"' crates/openbot-testkit/Cargo.toml)" == 1 ]] \
  || fail 'golden image must be enabled exactly once by the xtask feature'
for product_manifest in crates/openbot-{contracts,domain,application,infra,agent,computer,server,ui,desktop}/Cargo.toml; do
  ! grep -qE '^image[[:space:]]*=' "$product_manifest" \
    || fail "golden image escaped into product manifest $product_manifest"
done
golden_image_tree="$(cargo tree -p openbot-testkit --features xtask -i image --locked --offline)"
[[ "$golden_image_tree" == $'image v0.25.10\n└── openbot-testkit v0.0.0 ('* ]] \
  || fail "golden image dependency path drifted: $golden_image_tree"
for package_spec in image-0.25.10 moxcms-0.8.1 pxfm-0.1.30 byteorder-lite-0.1.0; do
  package_root="$(crate_root "$package_spec")"
  [[ ! -e "$package_root/build.rs" ]] || fail "$package_spec gained a build script"
done
grep -qxF 'license = "MIT OR Apache-2.0"' "$(crate_root image-0.25.10)/Cargo.toml" \
  || fail 'image license changed'
grep -qxF 'license = "BSD-3-Clause OR Apache-2.0"' "$(crate_root moxcms-0.8.1)/Cargo.toml" \
  || fail 'moxcms license changed'
grep -qxF 'license = "BSD-3-Clause OR Apache-2.0"' "$(crate_root pxfm-0.1.30)/Cargo.toml" \
  || fail 'pxfm license changed'
grep -qxF 'license = "Unlicense OR MIT"' "$(crate_root byteorder-lite-0.1.0)/Cargo.toml" \
  || fail 'byteorder-lite license changed'
grep -qF '85ab80394333c02fe689eaf900ab500fbd0c2213da414687ebf995a65d5a6104' Cargo.lock \
  || fail 'image Cargo.lock checksum changed'
grep -qF 'Cargo.lock checksum = 85ab80394333c02fe689eaf900ab500fbd0c2213da414687ebf995a65d5a6104' provenance/sources.spdx.json \
  || fail 'image SPDX lock identity is stale'
grep -qxF 'futures-util.workspace = true' crates/openbot-ui/Cargo.toml \
  || fail 'UI WebSocket StreamExt dependency boundary drifted'
gloo_net_root="$(crate_root gloo-net-0.6.0)"
[[ ! -e "$gloo_net_root/build.rs" ]] || fail 'gloo-net gained a build script'
grep -qF 'pub fn open_with_protocol(url: &str, protocol: &str)' \
  "$gloo_net_root/src/websocket/futures.rs" \
  || fail 'gloo-net typed WebSocket protocol constructor drifted'

# Every build script that Batch 15 added. Hash equality is intentionally stronger than a keyword
# scan: any new side effect, even without a familiar network/process spelling, requires re-review.
check_hash camino-1.2.5 build.rs 5bc29910c9644c320a7cceed121474915f7e832f484f1bf694dec80a45182aa0
check_hash cookie-0.18.2 build.rs 75c45e6b8566ca721dd5759b6ef16e365d5cb201660eee5ec04e278f9d1eefe2
check_hash crossbeam-deque-0.8.7 build.rs e40cf96d7d7b1650f9f53a3f578633a178324dbea1d905b3f71a75b45d3982a1
check_hash erased-serde-0.4.10 build.rs cc81259cd7861fc7c4b054656fc50bc381b5e96f22501e1c77f045ca93d41f77
check_hash icu_calendar_data-2.2.0 build.rs c2d446772e3d766a804963dbf36e51729f910920f91f4b68c0c199fe6ca0853e
check_hash icu_datetime_data-2.2.0 build.rs c2d446772e3d766a804963dbf36e51729f910920f91f4b68c0c199fe6ca0853e
check_hash icu_decimal_data-2.2.0 build.rs c2d446772e3d766a804963dbf36e51729f910920f91f4b68c0c199fe6ca0853e
check_hash icu_locale_data-2.2.0 build.rs c2d446772e3d766a804963dbf36e51729f910920f91f4b68c0c199fe6ca0853e
check_hash icu_plurals_data-2.2.0 build.rs c2d446772e3d766a804963dbf36e51729f910920f91f4b68c0c199fe6ca0853e
check_hash icu_time_data-2.2.1 build.rs c2d446772e3d766a804963dbf36e51729f910920f91f4b68c0c199fe6ca0853e
check_hash leptos-0.8.19 build.rs e212d639297796bd51e905411d3d9c77bf99de7e187769e420118df5d01f7cd4
check_hash leptos-use-0.18.3 build.rs bcec3171f169950ffc50fbcc6c7de59f3636e61299f3c7958cde27202263b26d
check_hash leptos_macro-0.8.17 build.rs 11ccc42a6266f3bb42677ff796dd8f456a72460f0a20a83cce22bb29dfec534e
check_hash leptos_router-0.8.13 build.rs 11ccc42a6266f3bb42677ff796dd8f456a72460f0a20a83cce22bb29dfec534e
check_hash matrixmultiply-0.3.11 build.rs 70108cb12936fdbe2123b2018c42899a531c7cb0007b3e402a8fdea7411e88a7
check_hash mime_guess-2.0.5 build.rs bc413487e376b343b65089a9a897f4bb3c9d5fbaa5a6833e87db1d3c18c462d8
check_hash paste-1.0.15 build.rs dba46ae4291317fb644ba2143f44eaf54a8ab946ba1367a33d055d694715f68a
check_hash proc-macro2-diagnostics-0.10.1 build.rs 66fcc487972086f42011c84a1949861799dc7cfde1e56201d22cf8e71b59b8b1
check_hash rayon-core-1.13.0 build.rs fa31cb198b772600d100a7c403ddedccef637d2e6b2da431fa7f02ca41307fc6
check_hash reactive_graph-0.2.14 build.rs 11ccc42a6266f3bb42677ff796dd8f456a72460f0a20a83cce22bb29dfec534e
check_hash rustix-1.1.4 build.rs 74cb32e64aa6fe99c2496a425b016e22f4e43c438a8237966b8acae04a98eaf9
check_hash server_fn-0.8.13 build.rs 11ccc42a6266f3bb42677ff796dd8f456a72460f0a20a83cce22bb29dfec534e
check_hash server_fn_macro-0.8.10 build.rs 11ccc42a6266f3bb42677ff796dd8f456a72460f0a20a83cce22bb29dfec534e
check_hash slotmap-1.1.1 build.rs fa4b3bd978b8f9c9a619b6fd61b4471a9b0a386335dd3b1fc8997daa8a16c4ff
check_hash tachys-0.2.18 build.rs 11ccc42a6266f3bb42677ff796dd8f456a72460f0a20a83cce22bb29dfec534e
check_hash typeid-1.0.3 build.rs 688afbcaa398ea159c3481b26d74fde6ce3a675d48364d772557c8e91100de46
check_hash wasmparser-0.239.0 build.rs ba7ab1735d3642c53562d1223a6eb54c2392e619ade3005e0deee3fc4229feea
check_hash windows_x86_64_gnu-0.52.6 build.rs 6d40bd2c0ed4cbea5126dfcd89d72f229c7d986540cbf0dc34acc1017f1de20f
check_hash windows_x86_64_msvc-0.52.6 build.rs 6d40bd2c0ed4cbea5126dfcd89d72f229c7d986540cbf0dc34acc1017f1de20f
check_hash zip-2.4.2 src/build.rs 8a048f0daacc5e4067f432b107cafe331426f6aecd4f76759a8be42d5556027e

# New license families and the two packaged Windows import archives are exact bytes.
check_hash base16-0.2.1 LICENSE-CC0 a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499
check_hash xxhash-rust-0.8.18 LICENSE c9bff75738922193e67fa726fa225535870d2aa1059f91452c411736284ad566
check_hash windows_x86_64_gnu-0.52.6 lib/libwindows.0.52.0.a 33f0f658b3d2108a4b7ba7809e2dcb5ad0431d9c474be5adc5efa2944f24f665
check_hash windows_x86_64_msvc-0.52.6 lib/windows.0.52.0.lib 24d8cbc445955b0d48041948a3c71ce2cddb948c089b25ec7106fadd9f3efde0
check_hash cookie-0.18.2 scripts/test.sh a76191d56d96c32efcb6883e0983e86beb4c6842e6e5c5a8bfded4c8183ff6f6
check_hash leptos-use-0.18.3 template/createfn.sh b5cc498eca3f1bc4d9cf75e6ce30b37c59788e9030fb030c72184178097c820b

grep -qxF '    "CC0-1.0",' deny.toml || fail 'CC0-1.0 license decision missing'
grep -qxF '    "BSL-1.0",' deny.toml || fail 'BSL-1.0 license decision missing'

# The two new RustSec records are informational-only and have no patched release. Paste itself is
# a proc macro; every direct proc-macro-error2 consumer is also a proc macro. Any reachability or
# patched-status change invalidates the narrow temporary waiver.
paste_root="$(cargo tree -i paste -e normal,build --prefix depth --charset ascii --locked --offline | head -n 1)"
[[ "$paste_root" == '0paste v1.0.15 (proc-macro)' ]] || fail "paste boundary changed: $paste_root"

macro_error_consumers="$(cargo tree -i proc-macro-error2 -e normal,build --prefix depth --charset ascii --locked --offline \
  | awk '/^1/ {print substr($0, 2)}' | sort -u)"
expected_macro_error_consumers='leptos_macro v0.8.17 (proc-macro)
leptos_router_macro v0.8.6 (proc-macro)
reactive_stores_macro v0.4.3 (proc-macro)
syn_derive v0.2.0 (proc-macro)'
[[ "$macro_error_consumers" == "$expected_macro_error_consumers" ]] \
  || fail "proc-macro-error2 consumers changed: $macro_error_consumers"

for advisory_id in RUSTSEC-2024-0436 RUSTSEC-2026-0173; do
  advisory_candidates=("$cargo_cache_root"/advisory-db/crates/*/"$advisory_id.md")
  [[ ${#advisory_candidates[@]} -eq 1 ]] || fail "$advisory_id record missing or ambiguous"
  grep -qxF 'informational = "unmaintained"' "${advisory_candidates[0]}" \
    || fail "$advisory_id is no longer informational-only"
  grep -qxF 'patched = []' "${advisory_candidates[0]}" \
    || fail "$advisory_id now has a patched release; remove the waiver and upgrade"
done

grep -qxF 'ignore = ["RUSTSEC-2023-0071", "RUSTSEC-2024-0436", "RUSTSEC-2026-0173"]' deny.toml \
  || fail 'deny.toml RustSec waiver set drifted'
grep -qF 'cargo audit --deny warnings --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2024-0436 --ignore RUSTSEC-2026-0173' .github/workflows/ci.yml \
  || fail 'manual CI cargo-audit waiver set drifted'

printf '%s\n' 'UI dependency guard: ok (30 build scripts; gloo-net WebSocket exact/no-build.rs; golden image 0.25.10 PNG-only/testkit-only + 4 zero-build.rs packages; 6 license identities; 2 compile-time unmaintained advisories; 2 Windows archives; 2 unreachable maintainer scripts)'
