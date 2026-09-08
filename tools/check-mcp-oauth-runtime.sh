#!/usr/bin/env bash
# G4 Batch 12/102/103: MCP OAuth must stay on per-server SafeDialer authority, exact
# issuer/resource, local-first revocation and retained admin-removal compensation.
set -euo pipefail

fail() {
  printf 'MCP OAuth runtime guard: FAIL: %s\n' "$1" >&2
  exit 1
}

files=(
  crates/openbot-infra/src/mcp_oauth.rs
  crates/openbot-infra/src/mcp_connections.rs
  crates/openbot-infra/src/mcp_credentials.rs
)

if rg -n 'reqwest|hyper::|TcpStream|lookup_host|Command::new|std::process' "${files[@]}"; then
  fail 'OAuth/credential code bypasses the unique SafeDialer or starts a process'
fi
grep -qF 'SafeHttpRequest::mcp(' crates/openbot-infra/src/mcp_oauth.rs \
  || fail '401 protected-resource probe no longer uses bounded SafeDialer MCP request'
grep -qF 'bearer_parameter(challenge, "resource_metadata")' crates/openbot-infra/src/mcp_oauth.rs \
  || fail 'WWW-Authenticate resource_metadata priority disappeared'
grep -qF 'serializer.append_pair("resource", resource);' crates/openbot-infra/src/mcp_oauth.rs \
  || fail 'authorization/code token resource binding disappeared'
grep -qF 'serializer.append_pair("resource", discovery.resource());' crates/openbot-infra/src/mcp_oauth.rs \
  || fail 'refresh token resource binding disappeared'
grep -qF 'code_challenge_method", "S256"' crates/openbot-infra/src/mcp_oauth.rs \
  || fail 'PKCE S256 authorization binding disappeared'
grep -qF 'metadata.issuer != client.issuer' crates/openbot-infra/src/mcp_oauth.rs \
  || fail 'authorization-server exact issuer validation disappeared'
grep -qF 'dialer: self.dialer.with_egress_policy(EgressPolicy::new(allowlist))' \
  crates/openbot-infra/src/mcp_oauth.rs \
  || fail 'MCP OAuth no longer clones the shared dialer with exact per-server egress authority'
[[ $(grep -c '\.with_egress_allowlist' crates/openbot-infra/src/mcp_connections.rs) -eq 4 ]] \
  || fail 'register/begin/code/revoke do not all consume per-server OAuth egress authority'
grep -qF 'self.with_egress_allowlist(request.egress_allowlist().clone())' \
  crates/openbot-infra/src/mcp_oauth.rs \
  || fail 'runtime refresh rotation lost its selected server egress authority'
grep -qF 'coalesce(s.egress_allow_cidrs,ARRAY[]::text[]) AS egress_allow_cidrs' \
  crates/openbot-infra/src/store/plugin_user_credential.rs \
  || fail 'runtime credential selection no longer carries current server egress authority'
grep -qF "coalesce(s.transport,'mcp') AS server_transport" \
  crates/openbot-infra/src/store/plugin_user_credential.rs \
  || fail 'runtime credential selection no longer binds the closed vendor transport'
grep -qF 'FOR SHARE OF s,d' crates/openbot-infra/src/store/plugin_user_credential.rs \
  || fail 'post-token refresh rotation no longer locks current server/client authority'
grep -qF 'if request.transport() != "mcp"' crates/openbot-infra/src/mcp_oauth.rs \
  || fail 'generic MCP refresh accepted another vendor transport'
grep -qF '|| request.transport() != "google_drive_rest"' \
  crates/openbot-infra/src/google_drive_oauth.rs \
  || fail 'curated Drive refresh accepted another vendor transport'
grep -qF '|| !request.egress_allowlist().is_empty()' \
  crates/openbot-infra/src/google_drive_oauth.rs \
  || fail 'curated Google Drive OAuth accepted an MCP private-egress override'

grep -qF 'openbot-mcp-oauth-state-v1' crates/openbot-infra/src/mcp_connections.rs \
  || fail 'OAuth state HMAC purpose separation disappeared'
grep -qF 'openbot-mcp-oauth-attempt-aead-v1' crates/openbot-infra/src/mcp_connections.rs \
  || fail 'OAuth attempt AEAD purpose separation disappeared'
grep -qF 'DELETE FROM public.verifications WHERE identifier=$1' crates/openbot-infra/src/mcp_connections.rs \
  || fail 'callback no longer burns state before validation/network'
grep -qF "FOR UPDATE SKIP LOCKED" crates/openbot-infra/src/mcp_connections.rs \
  || fail 'pending vendor revocation is no longer multi-replica claimed'
grep -qF "'revocation_status','pending'" crates/openbot-infra/src/mcp_connections.rs \
  || fail 'local-first disconnect tombstone disappeared'
grep -qF 'const ATTEMPT_VERSION: u8 = 3;' crates/openbot-infra/src/mcp_connections.rs \
  || fail 'sealed OAuth attempt no longer binds the v3 egress authority shape'
grep -qF 'material.egress_allow_cidrs != attempt.egress_allow_cidrs' \
  crates/openbot-infra/src/mcp_connections.rs \
  || fail 'OAuth callback no longer rejects egress authority drift before token exchange'
grep -qF 'validate_stored_client' crates/openbot-infra/src/mcp_oauth.rs \
  || fail 'admin removal no longer validates retained OAuth client material without network'
grep -qF 'struct RemovedServerRevocationContext' crates/openbot-infra/src/mcp_connections.rs \
  || fail 'versioned admin-removal revocation context disappeared'
grep -qF 'removed_server_client_material' crates/openbot-infra/src/mcp_connections.rs \
  || fail 'admin removal no longer reloads its exact retained client/context'
grep -qF 'match self.removed_server_client_material(&claim).await' \
  crates/openbot-infra/src/mcp_connections.rs \
  || fail 'removed-server claim no longer routes through its retained context'
if grep -qF 'let material = if removed_server' crates/openbot-infra/src/mcp_connections.rs; then
  fail 'removed-server tombstones can fall back to a re-added same-id server'
fi
grep -qF "'revocation_status','operator_required'" crates/openbot-infra/src/mcp_connections.rs \
  || fail 'irrecoverable retained revocation material no longer exits the retry loop'
grep -qF "metadata=metadata-'server_removal_revocation'" \
  crates/openbot-infra/src/mcp_connections.rs \
  || fail 'successful user-token revoke no longer scrubs retained network context'
grep -qF "split_part(g.ref,'/',1)=\$1" crates/openbot-infra/src/mcp_connections.rs \
  || fail 'admin removal no longer deletes stale/orphan grants by exact server prefix'
test -f repository contract \
  || fail 'admin-removal vendor compensation runbook disappeared'

grep -qF 'ADD COLUMN credential_generation bigint' crates/openbot-infra/sql/native_0018.sql \
  || fail 'credential generation migration disappeared'
grep -qF 'g.credential_generation=coalesce(s.credential_generation,0)' crates/openbot-infra/src/mcp_catalog.rs \
  || fail 'grant visibility no longer binds deployment credential generation'
grep -qF 'outcome == Err(McpClientError::AuthRequired)' crates/openbot-infra/src/agent_tools.rs \
  || fail 'controlled OAuth 401 refresh/retry branch disappeared'

authorization_slice=$(sed -n '/pub async fn authorization_plan/,/pub async fn exchange_authorization_code/p' crates/openbot-infra/src/mcp_oauth.rs)
if rg -n 'append_pair\("(access_token|refresh_token|client_secret)"' <<< "$authorization_slice"; then
  fail 'a credential was added to an authorization URL query'
fi
grep -qF '.field("client_secret", &"[redacted]")' crates/openbot-contracts/src/mcp.rs \
  || fail 'admin OAuth client Debug redaction disappeared'

printf 'MCP OAuth runtime guard: ok (per-server egress + rotation CAS; SafeDialer PRM/issuer/resource; HMAC+AEAD state v3; credential generation; local-first + admin-removal compensation)\n'
