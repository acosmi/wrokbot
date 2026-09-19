//! Bounded, same-origin framing for the existing typed Plugins application surface.

#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use openbot_contracts::mcp::{
    McpAdminPage, McpCustomServerRegistration, McpOAuthClientRegistration, McpServerMutation,
    PluginGrantKind, PluginGrantMutation,
};
use serde_json::{Value, json};

use super::{ApiError, encode_url_component, validate_mcp_server_id};

pub(crate) fn plugin_href(id: &str) -> Result<String, ApiError> {
    validate_mcp_server_id(id)?;
    Ok(format!("/admin/plugins/{}", encode_url_component(id)))
}

pub(crate) fn account_href(id: &str) -> Result<String, ApiError> {
    validate_mcp_server_id(id)?;
    Ok(format!(
        "/settings/connected-accounts/{}",
        encode_url_component(id)
    ))
}

pub(crate) fn tool_href(server: &str, name: &str) -> Result<String, ApiError> {
    if !bounded(name, 256) || name.contains('/') {
        return Err(ApiError::InvalidResponse);
    }
    Ok(format!(
        "{}/tools/{}",
        plugin_href(server)?,
        encode_url_component(name)
    ))
}

pub(crate) fn validate_page(page: &McpAdminPage) -> Result<(), ApiError> {
    if page.bots_may_call_back || page.servers.len() > 512 || page.catalogue.len() > 64 {
        return Err(ApiError::InvalidResponse);
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut total_tools = 0_usize;
    for server in &page.servers {
        validate_mcp_server_id(&server.id)?;
        if !ids.insert(&server.id)
            || !bounded(&server.title, 256)
            || server.summary.len() > 4096
            || !valid_https(&server.url)
            || (!server.docs_url.is_empty() && !valid_https(&server.docs_url))
            || server.egress_allow_cidrs.len() > 64
            || server
                .last_error
                .as_deref()
                .is_some_and(|code| code != "mcp_catalog_unavailable")
        {
            return Err(ApiError::InvalidResponse);
        }
        let mut names = std::collections::BTreeSet::new();
        total_tools = total_tools.saturating_add(server.tools.len());
        for tool in &server.tools {
            if tool.server_id != server.id
                || tool_href(&server.id, &tool.name).is_err()
                || !names.insert(&tool.name)
                || tool.reference != format!("{}/{}", server.id, tool.name)
                || tool.description.len() > 32 * 1024
                || tool.granted_to.len() > 4096
                || serde_json::to_vec(&tool.input_schema)
                    .map_or(true, |bytes| bytes.len() > 256 * 1024)
            {
                return Err(ApiError::InvalidResponse);
            }
            let grants = tool
                .granted_to
                .iter()
                .collect::<std::collections::BTreeSet<_>>();
            if grants.len() != tool.granted_to.len() || grants.iter().any(|id| !bounded(id, 512)) {
                return Err(ApiError::InvalidResponse);
            }
        }
    }
    if total_tools > 4096 {
        return Err(ApiError::InvalidResponse);
    }
    ids.clear();
    for entry in &page.catalogue {
        validate_mcp_server_id(&entry.key)?;
        if !ids.insert(&entry.key)
            || !bounded(&entry.title, 256)
            || entry.summary.len() > 4096
            || !valid_https(&entry.docs_url)
        {
            return Err(ApiError::InvalidResponse);
        }
    }
    if page
        .redirect_uri
        .as_ref()
        .is_some_and(|uri| uri.len() > 8192 || uri.chars().any(char::is_control))
    {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

pub(crate) fn valid_https(value: &str) -> bool {
    if value.len() > 8192 || value.chars().any(char::is_control) {
        return false;
    }
    url::Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    })
}

fn bounded(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

pub(crate) async fn load_page() -> Result<McpAdminPage, ApiError> {
    let value = request("GET", "/api/plugins", None).await?;
    let mut page: McpAdminPage =
        serde_json::from_value(value).map_err(|_| ApiError::InvalidResponse)?;
    // Personal/deployment skill instructions are not a consumer of these admin plugin routes.
    page.skills.clear();
    validate_page(&page)?;
    Ok(page)
}

pub(crate) async fn add_curated(id: &str) -> Result<(), ApiError> {
    validate_mcp_server_id(id)?;
    server_receipt(
        request("POST", "/api/plugins/servers", Some(json!({"key": id}))).await?,
        id,
    )
}

pub(crate) async fn add_custom(registration: &McpCustomServerRegistration) -> Result<(), ApiError> {
    validate_mcp_server_id(&registration.id)?;
    if !valid_https(&registration.url) || !bounded(&registration.title, 256) {
        return Err(ApiError::InvalidResponse);
    }
    server_receipt(
        request(
            "POST",
            "/api/plugins/servers/custom",
            Some(serde_json::to_value(registration).map_err(|_| ApiError::InvalidResponse)?),
        )
        .await?,
        &registration.id,
    )
}

pub(crate) async fn refresh(id: &str) -> Result<(), ApiError> {
    let path = server_path(id)?;
    server_receipt(request("POST", &format!("{path}/refresh"), None).await?, id)
}

pub(crate) async fn remove(id: &str) -> Result<(), ApiError> {
    acknowledged(request("DELETE", &server_path(id)?, None).await?)
}

pub(crate) async fn register_client(
    id: &str,
    registration: McpOAuthClientRegistration,
) -> Result<(), ApiError> {
    let path = format!("{}/oauth-client", server_path(id)?);
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;
        use web_sys::{RequestCache, RequestCredentials, RequestRedirect};
        let outgoing = super::secret_json(
            Request::post(&path)
                .cache(RequestCache::NoStore)
                .credentials(RequestCredentials::SameOrigin)
                .redirect(RequestRedirect::Error),
            &registration,
        )?;
        drop(registration);
        let response = outgoing.send().await.map_err(|_| ApiError::Network)?;
        if response.status() != 200 {
            return Err(super::status_error(response.status()));
        }
        let body = response
            .text()
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        if body.len() > 1024 {
            return Err(ApiError::InvalidResponse);
        }
        acknowledged(serde_json::from_str(&body).map_err(|_| ApiError::InvalidResponse)?)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (path, registration);
        Err(ApiError::Unavailable)
    }
}

pub(crate) async fn begin_connection(id: &str) -> Result<String, ApiError> {
    let value = request(
        "POST",
        &format!("{}/connect?returnTo=admin", server_path(id)?),
        None,
    )
    .await?;
    let authorization: openbot_contracts::mcp::McpOAuthAuthorization =
        serde_json::from_value(value).map_err(|_| ApiError::InvalidResponse)?;
    #[cfg(any(target_arch = "wasm32", test))]
    super::validate_authorization_target(&authorization.authorization_url)?;
    Ok(authorization.authorization_url)
}

pub(crate) async fn set_grant(reference: &str, agent: &str, enabled: bool) -> Result<(), ApiError> {
    if !bounded(reference, 512) || !bounded(agent, 512) {
        return Err(ApiError::InvalidResponse);
    }
    let value = if enabled {
        request(
            "POST",
            "/api/plugins/grants",
            Some(
                serde_json::to_value(PluginGrantMutation {
                    kind: PluginGrantKind::Mcp,
                    reference: reference.to_owned(),
                    agent_id: agent.to_owned(),
                })
                .map_err(|_| ApiError::InvalidResponse)?,
            ),
        )
        .await?
    } else {
        request(
            "DELETE",
            &format!(
                "/api/plugins/grants?kind=mcp&ref={}&agentId={}",
                encode_url_component(reference),
                encode_url_component(agent)
            ),
            None,
        )
        .await?
    };
    acknowledged(value)
}

fn server_path(id: &str) -> Result<String, ApiError> {
    validate_mcp_server_id(id)?;
    Ok(format!("/api/plugins/servers/{}", encode_url_component(id)))
}

fn server_receipt(value: Value, id: &str) -> Result<(), ApiError> {
    let receipt: McpServerMutation =
        serde_json::from_value(value).map_err(|_| ApiError::InvalidResponse)?;
    if receipt.server_id == id && receipt.catalog_generation > 0 {
        Ok(())
    } else {
        Err(ApiError::InvalidResponse)
    }
}

fn acknowledged(value: Value) -> Result<(), ApiError> {
    if value == json!({"ok":true}) {
        Ok(())
    } else {
        Err(ApiError::InvalidResponse)
    }
}

pub(crate) async fn request(
    method: &'static str,
    path: &str,
    body: Option<Value>,
) -> Result<Value, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;
        use web_sys::{RequestCache, RequestCredentials, RequestRedirect};
        let request = match method {
            "GET" => Request::get(path),
            "POST" => Request::post(path),
            "DELETE" => Request::delete(path),
            _ => return Err(ApiError::InvalidResponse),
        }
        .cache(RequestCache::NoStore)
        .credentials(RequestCredentials::SameOrigin)
        .redirect(RequestRedirect::Error);
        let response = if let Some(body) = body {
            request
                .json(&body)
                .map_err(|_| ApiError::InvalidResponse)?
                .send()
                .await
        } else {
            request.send().await
        }
        .map_err(|_| ApiError::Network)?;
        // 202 is an unknown commit, never a success receipt. The UI always refetches after writes.
        if response.status() != 200 {
            return Err(super::status_error(response.status()));
        }
        let text = response
            .text()
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        if text.len() > 8 * 1024 * 1024 {
            return Err(ApiError::InvalidResponse);
        }
        serde_json::from_str(&text).map_err(|_| ApiError::InvalidResponse)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (method, path, body);
        Err(ApiError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page() -> McpAdminPage {
        serde_json::from_value(json!({
            "catalogue": [], "botsMayCallBack": false, "skills": [], "redirectUri": null,
            "servers": [{"id":"notes", "title":"Notes", "vendor":"notes.example.test",
                "url":"https://notes.example.test/mcp", "summary":"", "docsUrl":"",
                "provenance":"custom", "authentication":"none", "hasCredential":false,
                "toolsRefreshedAt":null, "lastError":null, "addedBy":null, "egressAllowCidrs":[],
                "tools":[{"serverId":"notes", "name":"search", "description":"Search notes",
                    "inputSchema":{"type":"object"}, "ref":"notes/search", "effect":"read",
                    "grantedTo":["agent-a"]}]}]
        }))
        .expect("typed response fixture")
    }

    #[test]
    fn projections_reject_cross_server_refs_and_duplicate_grants() {
        let valid = page();
        assert!(validate_page(&valid).is_ok());
        let mut forged = valid.clone();
        forged.servers[0].tools[0].reference = "other/search".to_owned();
        assert!(validate_page(&forged).is_err());
        forged = valid.clone();
        forged.servers[0].tools[0].server_id = "other".to_owned();
        assert!(validate_page(&forged).is_err());
        forged = valid;
        forged.servers[0].tools[0]
            .granted_to
            .push("agent-a".to_owned());
        assert!(validate_page(&forged).is_err());
    }

    #[test]
    fn projections_reject_legacy_callback_unknown_error_and_oversized_schema() {
        let mut forged = page();
        forged.bots_may_call_back = true;
        assert!(validate_page(&forged).is_err());
        forged = page();
        forged.servers[0].last_error = Some("raw vendor response".to_owned());
        assert!(validate_page(&forged).is_err());
        forged = page();
        forged.servers[0].tools[0].input_schema = json!({"description":"x".repeat(256 * 1024)});
        assert!(validate_page(&forged).is_err());
    }

    #[test]
    fn endpoint_and_route_framing_do_not_accept_credentials_or_injected_segments() {
        assert!(valid_https("https://notes.example.test/mcp"));
        for invalid in [
            "http://example.test",
            "https://user:secret@example.test",
            "javascript:alert(1)",
            "https://example.test/#fragment",
        ] {
            assert!(!valid_https(invalid));
        }
        assert!(plugin_href("../settings").is_err());
        assert!(tool_href("notes", "other/search").is_err());
        assert_eq!(
            tool_href("notes", "query?x&y").unwrap(),
            "/admin/plugins/notes/tools/query%3Fx%26y"
        );
    }

    #[test]
    fn receipts_require_exact_success_and_matching_server() {
        assert!(acknowledged(json!({"ok":true})).is_ok());
        for value in [
            json!({"ok":false}),
            json!({"ok":true,"pending":true}),
            json!({"status":"unknown"}),
        ] {
            assert!(acknowledged(value).is_err());
        }
        let receipt =
            json!({"serverId":"notes", "catalogGeneration":1, "toolCount":2, "suspendedGrants":0});
        assert!(server_receipt(receipt.clone(), "notes").is_ok());
        assert!(server_receipt(receipt, "other").is_err());
        assert!(server_receipt(json!({"serverId":"notes", "catalogGeneration":0,"toolCount":0,"suspendedGrants":0}), "notes").is_err());
    }
}
