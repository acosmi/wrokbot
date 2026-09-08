#!/usr/bin/env bash
# Offline integrity/provenance guard for v4 §24 G4 provider recorded traces.
set -euo pipefail

fail() {
  printf 'provider recorded trace guard: FAIL: %s\n' "$1" >&2
  exit 1
}

shopt -s nullglob
provenance_files=(fixtures/provider/*.provenance.json)
(( ${#provenance_files[@]} > 0 )) || fail 'no provenance files found'

for provenance in "${provenance_files[@]}"; do
  jq -e '
    .schema == "openbot-provider-recorded-trace-v1" and
    (.provider == "openai" or .provider == "anthropic" or .provider == "google") and
    (.protocol.api | type == "string" and length > 0) and
    (.protocol.transport | type == "string" and length > 0) and
    (.protocol.endpoint | type == "string" and startswith("https://")) and
    (.protocol.method == "POST") and
    (.provenance.kind == "vendor_capture_published_by_vendor" or
     .provenance.kind == "controlled_live_vendor_capture") and
    (.provenance.source_commit | test("^[0-9a-f]{40}$")) and
    (.provenance.source_record_git_blob_sha1 | test("^[0-9a-f]{40}$")) and
    (.provenance.source_record_sha256 | test("^[0-9a-f]{64}$")) and
    (.provenance.source_record_bytes | type == "number" and . > 0) and
    (.provenance.source_record_url | type == "string" and startswith("https://")) and
    (.provenance.retrieved_at_utc | type == "string" and endswith("Z")) and
    (.payload.path | type == "string" and startswith("fixtures/provider/") and endswith(".sse")) and
    (.payload.fixture_bytes | type == "number" and . > 0 and . <= 1048576) and
    (.payload.fixture_sha256 | test("^[0-9a-f]{64}$")) and
    (.payload.raw_response_body_bytes == .payload.fixture_bytes) and
    (.payload.raw_response_body_sha256 == .payload.fixture_sha256) and
    (.redaction.request_prompt_stored == false) and
    (.redaction.authorization_or_api_key_stored == false) and
    (.redaction.customer_data_stored == false) and
    (.redaction.verifiable_secret_hash_stored == false) and
    (.license.spdx | type == "string" and length > 0) and
    (.license.copyright | type == "string" and length > 0) and
    (all(.response_headers.preserved | keys[];
      . == "content-type" or . == "openai-version" or . == "anthropic-version"))
  ' "$provenance" >/dev/null || fail "$provenance violates the closed provenance schema"

  provider="$(jq -er '.provider' "$provenance")"
  source_url="$(jq -er '.provenance.source_record_url' "$provenance")"
  case "$provider:$source_url" in
    openai:https://github.com/openai/*) ;;
    anthropic:https://github.com/anthropics/*) ;;
    google:https://github.com/googleapis/*|google:https://github.com/google-gemini/*) ;;
    *) fail "$provenance source is not on the provider's official GitHub organization" ;;
  esac

  fixture="$(jq -er '.payload.path' "$provenance")"
  [[ -f "$fixture" && ! -L "$fixture" ]] || fail "$fixture is missing, non-regular, or a symlink"
  expected_bytes="$(jq -er '.payload.fixture_bytes' "$provenance")"
  actual_bytes="$(wc -c < "$fixture" | tr -d '[:space:]')"
  [[ "$actual_bytes" == "$expected_bytes" ]] \
    || fail "$fixture byte count differs from provenance"
  expected_sha="$(jq -er '.payload.fixture_sha256' "$provenance")"
  actual_sha="$(shasum -a 256 "$fixture" | awk '{print $1}')"
  [[ "$actual_sha" == "$expected_sha" ]] \
    || fail "$fixture SHA-256 differs from provenance"
done

orphan_diff="$({
  find fixtures/provider -maxdepth 1 -type f -name '*.sse' -print | LC_ALL=C sort
  printf '%s\n' '--REFERENCED--'
  for provenance in "${provenance_files[@]}"; do
    jq -er '.payload.path' "$provenance"
  done | LC_ALL=C sort
} | awk '
  $0 == "--REFERENCED--" { referenced = 1; next }
  !referenced { files[$0]++ ; next }
  { references[$0]++ }
  END {
    for (path in files) if (files[path] != 1 || references[path] != 1) print path
    for (path in references) if (files[path] != 1 || references[path] != 1) print path
  }
' | LC_ALL=C sort -u)"
[[ -z "$orphan_diff" ]] || fail "orphan or multiply referenced SSE fixture: $orphan_diff"

if rg -n 'sk-[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{20,}|Bearer[[:space:]]+[A-Za-z0-9._~+/-]{16,}' \
  fixtures/provider --glob '*.sse'; then
  fail 'a recorded trace contains a credential-shaped value'
fi

providers="$(for provenance in "${provenance_files[@]}"; do jq -er '.provider' "$provenance"; done \
  | LC_ALL=C sort -u | tr '\n' ',' | sed 's/,$//')"
printf 'provider recorded trace guard: ok (traces=%s; providers=%s)\n' \
  "${#provenance_files[@]}" "$providers"
