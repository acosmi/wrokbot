#!/usr/bin/env bash
# Run cargo-deny against each real release target without cargo-deny's multi-target cross-product.
set -euo pipefail

cd "$(dirname "$0")/.."

checks=("$@")
if [[ ${#checks[@]} -eq 0 ]]; then
  # Licenses/advisories are intentionally not defaulted while Batch 16 policy decisions remain red.
  checks=(bans sources)
fi

has_bans=false
other_checks=()
for check in "${checks[@]}"; do
  if [[ "$check" == "bans" ]]; then
    has_bans=true
  else
    other_checks+=("$check")
  fi
done

targets=(
  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-gnu
  x86_64-apple-darwin
  aarch64-apple-darwin
  x86_64-pc-windows-msvc
  wasm32-unknown-unknown
)

if $has_bans; then
  # The configured multi-target union is still authoritative for workspace-dependency/wildcard/
  # duplicate policy. Only build-script-not-allowed is suppressed here because cargo-deny can join
  # a macOS parent edge to a Linux-only GTK child in the union. The individual runs below restore
  # that lint on each actually buildable target.
  cargo deny --log-level error --all-features --locked --offline check \
    --allow build-script-not-allowed bans
fi

for target in "${targets[@]}"; do
  printf 'cargo-deny target: %s\n' "$target"
  if $has_bans; then
    # A target-filtered graph calls macOS/Windows-only workspace dependencies "unused" on
    # Linux/WASM. The union run above checks the real workspace-wide unused invariant; do not mask
    # build-script, executable, archive or any other target-specific lint here.
    cargo deny --log-level error --target "$target" --all-features --locked --offline check \
      --allow unused-workspace-dependency bans
  fi
  if [[ ${#other_checks[@]} -gt 0 ]]; then
    cargo deny --log-level error --target "$target" --all-features --locked --offline \
      check "${other_checks[@]}"
  fi
done

printf '%s\n' 'cargo-deny release-target guard: ok'
