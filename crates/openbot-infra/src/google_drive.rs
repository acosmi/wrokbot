//! Google Drive v3 GA REST adapter for the first-source §9.5 read-only connector.
//!
//! This is deliberately not MCP. It exposes the four static tool names that the fixed upstream
//! preserves, while every request still uses the repository's unique [`SafeDialer`]. No response
//! body is cached or written to PostgreSQL; bounded text exists only for one tool call.

use std::time::Duration;

use http::StatusCode;
use http::header::WWW_AUTHENTICATE;
use openbot_domain::tool::metadata::Effect;
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;
use zeroize::Zeroizing;

use crate::mcp::{MAX_MCP_RESULT_CHARS, McpBearerToken, McpCallOutcome, McpListedTool};
use crate::net::safe_http::{
    AuthorizationValue, SafeDialer, SafeHttpBudget, SafeHttpRequest, SchemePolicy,
};

/// Curated server id used by grants and model-visible tool names.
pub const GOOGLE_DRIVE_SERVER_ID: &str = "google-drive";
/// Curated display title.
pub const GOOGLE_DRIVE_TITLE: &str = "Google Drive";
/// Curated accountable vendor.
pub const GOOGLE_DRIVE_VENDOR: &str = "Google";
/// Provenance stored with the reviewed catalogue row.
pub const GOOGLE_DRIVE_PROVENANCE: &str = "first-party";
/// Closed transport value stored by native 0019.
pub const GOOGLE_DRIVE_TRANSPORT: &str = "google_drive_rest";
/// Reviewed GA REST endpoint; the Developer Preview MCP endpoint is intentionally absent.
pub const GOOGLE_DRIVE_API_BASE: &str = "https://www.googleapis.com/drive/v3";
/// The only scope this read-only adapter requests.
pub const GOOGLE_DRIVE_READONLY_SCOPE: &str = "https://www.googleapis.com/auth/drive.readonly";
/// Curated OAuth authorization endpoint.
pub const GOOGLE_DRIVE_AUTHORIZATION_ENDPOINT: &str =
    "https://accounts.google.com/o/oauth2/v2/auth";
/// Curated OAuth token endpoint.
pub const GOOGLE_DRIVE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
/// Curated OAuth revocation endpoint.
pub const GOOGLE_DRIVE_REVOCATION_ENDPOINT: &str = "https://oauth2.googleapis.com/revoke";
/// Google issuer accepted for this curated OAuth client.
pub const GOOGLE_DRIVE_ISSUER: &str = "https://accounts.google.com";
/// Belt-and-braces write classification if a future catalog ever advertises these names.
pub const GOOGLE_DRIVE_NAMED_WRITES: &[&str] = &["create_file", "copy_file"];

/// Credential ownership for the single reviewed Drive catalogue entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GoogleDriveCatalogueAuthentication {
    /// The person asking must connect their own Google account.
    UserOAuth,
}

/// Compile-time reviewed Drive catalogue identity. It contains no caller-controlled field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoogleDriveCatalogueEntry {
    /// Stable key.
    pub key: &'static str,
    /// Display title.
    pub title: &'static str,
    /// Accountable vendor.
    pub vendor: &'static str,
    /// Exact GA REST resource.
    pub api_base: &'static str,
    /// Closed native-0019 transport.
    pub transport: &'static str,
    /// Credential principal mode.
    pub authentication: GoogleDriveCatalogueAuthentication,
    /// Exact requested OAuth scope.
    pub scope: &'static str,
}

/// The only reviewed Drive catalogue entry in this build.
pub const GOOGLE_DRIVE_CATALOGUE_ENTRY: GoogleDriveCatalogueEntry = GoogleDriveCatalogueEntry {
    key: GOOGLE_DRIVE_SERVER_ID,
    title: GOOGLE_DRIVE_TITLE,
    vendor: GOOGLE_DRIVE_VENDOR,
    api_base: GOOGLE_DRIVE_API_BASE,
    transport: GOOGLE_DRIVE_TRANSPORT,
    authentication: GoogleDriveCatalogueAuthentication::UserOAuth,
    scope: GOOGLE_DRIVE_READONLY_SCOPE,
};

/// Resolve the compile-time entry by key. Unknown vendors and instance hosts have no fallback.
#[must_use]
pub fn google_drive_catalogue_entry(key: &str) -> Option<&'static GoogleDriveCatalogueEntry> {
    (key == GOOGLE_DRIVE_SERVER_ID).then_some(&GOOGLE_DRIVE_CATALOGUE_ENTRY)
}

/// Upstream parity timeout for one Drive request.
pub const GOOGLE_DRIVE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Upstream parity list size.
pub const GOOGLE_DRIVE_PAGE_SIZE: usize = 25;
/// Added hardening: do not read an unbounded file/error/list body before model projection.
pub const MAX_GOOGLE_DRIVE_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

const FILE_FIELDS: &str = "id,name,mimeType,modifiedTime,webViewLink,size,owners(emailAddress)";
const MAX_DRIVE_FILES: usize = GOOGLE_DRIVE_PAGE_SIZE;
const MAX_DRIVE_STRING_BYTES: usize = 64 * 1024;

/// Stable Drive adapter failure. URLs, tokens and remote response bodies never cross this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GoogleDriveError {
    /// SafeDialer/DNS/TLS/HTTP unavailable.
    #[error("google_drive_transport_unavailable")]
    Transport,
    /// Request wall-clock deadline elapsed.
    #[error("google_drive_timeout")]
    Timeout,
    /// Resource server rejected/expired the access token.
    #[error("google_drive_auth_required")]
    AuthRequired,
    /// OAuth challenge explicitly requires a wider interactive scope.
    #[error("google_drive_insufficient_scope")]
    InsufficientScope,
    /// JSON/text/file metadata violates the bounded adapter contract.
    #[error("google_drive_invalid_response")]
    InvalidResponse,
    /// Static catalog and dispatcher drifted.
    #[error("google_drive_tool_missing")]
    ToolMissing,
}

/// SafeDialer-backed Drive REST transport.
#[derive(Clone)]
pub struct GoogleDriveRestTransport {
    dialer: SafeDialer,
    base: Url,
    scheme_policy: SchemePolicy,
}

impl GoogleDriveRestTransport {
    /// Construct the production adapter at Google's reviewed GA endpoint.
    pub fn new(dialer: SafeDialer) -> Result<Self, GoogleDriveError> {
        Self::new_with_endpoint(
            dialer,
            Url::parse(GOOGLE_DRIVE_API_BASE).map_err(|_| GoogleDriveError::InvalidResponse)?,
            SchemePolicy::HttpsOnly,
        )
    }

    /// Construct with an explicit reviewed endpoint/network policy. Production uses [`Self::new`];
    /// `HttpOrHttps` exists for CIDR-allowlisted local wire conformance.
    pub fn new_with_endpoint(
        dialer: SafeDialer,
        base: Url,
        scheme_policy: SchemePolicy,
    ) -> Result<Self, GoogleDriveError> {
        validate_base(&base, scheme_policy)?;
        Ok(Self {
            dialer,
            base,
            scheme_policy,
        })
    }

    /// Static tool list; discovering it never needs a person's credential or a remote request.
    #[must_use]
    pub fn list_tools(&self) -> Vec<McpListedTool> {
        google_drive_tools()
    }

    /// Call exactly one of the four read-only Drive tools.
    pub async fn call_tool(
        &self,
        bearer: &McpBearerToken,
        tool_name: &str,
        arguments: &Value,
    ) -> Result<McpCallOutcome, GoogleDriveError> {
        let object = arguments
            .as_object()
            .ok_or(GoogleDriveError::InvalidResponse)?;
        match tool_name {
            "search_files" => {
                let Some(query) = string_argument(object, "query") else {
                    return Ok(normalize_drive_result(
                        "A search needs something to search for.".to_owned(),
                        true,
                    ));
                };
                let response = self
                    .request(
                        bearer,
                        &["files"],
                        &[
                            ("pageSize", GOOGLE_DRIVE_PAGE_SIZE.to_string()),
                            ("fields", format!("files({FILE_FIELDS})")),
                            ("q", drive_query(query)),
                        ],
                    )
                    .await?;
                match response {
                    DriveHttpResponse::Success(body) => list_outcome(body),
                    DriveHttpResponse::Refused(outcome) => Ok(outcome),
                }
            }
            "list_recent_files" => {
                if !object.is_empty() {
                    return Err(GoogleDriveError::InvalidResponse);
                }
                let response = self
                    .request(
                        bearer,
                        &["files"],
                        &[
                            ("pageSize", GOOGLE_DRIVE_PAGE_SIZE.to_string()),
                            ("fields", format!("files({FILE_FIELDS})")),
                            ("orderBy", "modifiedTime desc".to_owned()),
                        ],
                    )
                    .await?;
                match response {
                    DriveHttpResponse::Success(body) => list_outcome(body),
                    DriveHttpResponse::Refused(outcome) => Ok(outcome),
                }
            }
            "get_file_metadata" => {
                let Some(file_id) = string_argument(object, "fileId") else {
                    return Ok(normalize_drive_result(
                        "A file id is needed to look a file up.".to_owned(),
                        true,
                    ));
                };
                let response = self
                    .request(
                        bearer,
                        &["files", file_id],
                        &[("fields", FILE_FIELDS.to_owned())],
                    )
                    .await?;
                let response = match response {
                    DriveHttpResponse::Success(body) => body,
                    DriveHttpResponse::Refused(outcome) => return Ok(outcome),
                };
                let file: DriveFile = serde_json::from_slice(&response)
                    .map_err(|_| GoogleDriveError::InvalidResponse)?;
                validate_file(&file)?;
                let mut lines = vec![file_line(&file)];
                if let Some(size) = &file.size {
                    lines.push(format!("size: {size} bytes"));
                }
                if let Some(owner) = file
                    .owners
                    .as_ref()
                    .and_then(|owners| owners.first())
                    .and_then(|owner| owner.email_address.as_deref())
                {
                    lines.push(format!("owner: {owner}"));
                }
                Ok(normalize_drive_result(lines.join("\n"), false))
            }
            "read_file_content" => {
                let Some(file_id) = string_argument(object, "fileId") else {
                    return Ok(normalize_drive_result(
                        "A file id is needed to read a file.".to_owned(),
                        true,
                    ));
                };
                let metadata = self
                    .request(
                        bearer,
                        &["files", file_id],
                        &[("fields", "id,name,mimeType,webViewLink".to_owned())],
                    )
                    .await?;
                let metadata = match metadata {
                    DriveHttpResponse::Success(body) => body,
                    DriveHttpResponse::Refused(outcome) => return Ok(outcome),
                };
                let file: DriveFile = serde_json::from_slice(&metadata)
                    .map_err(|_| GoogleDriveError::InvalidResponse)?;
                validate_file(&file)?;
                let export_as = file.mime_type.as_deref().and_then(export_mime);
                if export_as.is_none() && !is_textual(file.mime_type.as_deref()) {
                    let name = file.name.as_deref().unwrap_or(file_id);
                    let mime = file.mime_type.as_deref().unwrap_or("binary");
                    let link = file
                        .web_view_link
                        .as_deref()
                        .and_then(safe_vendor_link)
                        .map_or_else(String::new, |link| format!(" Open it at {link}."));
                    return Ok(normalize_drive_result(
                        format!(
                            "{name} is a {mime} file, which this connector cannot read as text. Its metadata and link are available, and somebody can open it themselves.{link}"
                        ),
                        true,
                    ));
                }
                let response = match export_as {
                    Some(mime) => {
                        self.request(
                            bearer,
                            &["files", file_id, "export"],
                            &[("mimeType", mime.to_owned())],
                        )
                        .await?
                    }
                    None => {
                        self.request(bearer, &["files", file_id], &[("alt", "media".to_owned())])
                            .await?
                    }
                };
                let body = match response {
                    DriveHttpResponse::Success(body) => body,
                    DriveHttpResponse::Refused(outcome) => return Ok(outcome),
                };
                let text =
                    String::from_utf8(body).map_err(|_| GoogleDriveError::InvalidResponse)?;
                let name = file.name.as_deref().unwrap_or(file_id);
                let heading = file
                    .web_view_link
                    .as_deref()
                    .and_then(safe_vendor_link)
                    .map_or_else(
                        || escape_markdown_text(name),
                        |link| format!("[{}]({link})", escape_markdown_text(name)),
                    );
                Ok(normalize_drive_result(
                    format!("{heading}\n\n{text}"),
                    false,
                ))
            }
            _ => Err(GoogleDriveError::ToolMissing),
        }
    }

    async fn request(
        &self,
        bearer: &McpBearerToken,
        segments: &[&str],
        query: &[(&str, String)],
    ) -> Result<DriveHttpResponse, GoogleDriveError> {
        let mut url = self.base.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| GoogleDriveError::InvalidResponse)?;
            path.pop_if_empty();
            for segment in segments {
                path.push(segment);
            }
        }
        {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in query {
                pairs.append_pair(key, value);
            }
        }
        let token = bearer
            .expose_for_vendor()
            .map_err(|_| GoogleDriveError::InvalidResponse)?;
        let mut authorization = Zeroizing::new(String::with_capacity(token.len() + 7));
        authorization.push_str("Bearer ");
        authorization.push_str(token);
        let authorization = AuthorizationValue::parse(&authorization)
            .map_err(|_| GoogleDriveError::InvalidResponse)?;
        let budget = SafeHttpBudget::new(
            MAX_GOOGLE_DRIVE_RESPONSE_BYTES,
            GOOGLE_DRIVE_REQUEST_TIMEOUT,
        )
        .map_err(|_| GoogleDriveError::InvalidResponse)?;
        let request = SafeHttpRequest::get(url, self.scheme_policy, budget)
            .map_err(|_| GoogleDriveError::InvalidResponse)?
            .with_authorization(authorization);
        let response = self.dialer.execute(request).await.map_err(|error| {
            if error == crate::net::safe_http::SafeHttpError::DeadlineExceeded {
                GoogleDriveError::Timeout
            } else {
                GoogleDriveError::Transport
            }
        })?;
        let status = response.status();
        if status == StatusCode::UNAUTHORIZED {
            return Err(GoogleDriveError::AuthRequired);
        }
        if status == StatusCode::FORBIDDEN
            && response
                .header(&WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.to_ascii_lowercase().contains("insufficient_scope"))
        {
            return Err(GoogleDriveError::InsufficientScope);
        }
        let (_, _, body) = response.into_parts();
        if status.is_success() {
            return Ok(DriveHttpResponse::Success(body));
        }
        let detail = google_error_detail(&body).unwrap_or_default();
        let text = if detail.is_empty() {
            format!("Google Drive refused this request ({status}).")
        } else {
            format!("Google Drive refused this request ({status}): {detail}")
        };
        Ok(DriveHttpResponse::Refused(normalize_drive_result(
            text, true,
        )))
    }
}

impl core::fmt::Debug for GoogleDriveRestTransport {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("GoogleDriveRestTransport")
            .field("endpoint", &"[reviewed]")
            .field("scheme_policy", &self.scheme_policy)
            .finish_non_exhaustive()
    }
}

enum DriveHttpResponse {
    Success(Vec<u8>),
    Refused(McpCallOutcome),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DriveFileList {
    #[serde(default)]
    files: Vec<DriveFile>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DriveFile {
    id: Option<String>,
    name: Option<String>,
    mime_type: Option<String>,
    modified_time: Option<String>,
    web_view_link: Option<String>,
    size: Option<String>,
    owners: Option<Vec<DriveOwner>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DriveOwner {
    email_address: Option<String>,
}

/// Exact four-tool static catalog. All effects are classified read by first-party code.
#[must_use]
pub fn google_drive_tools() -> Vec<McpListedTool> {
    vec![
        McpListedTool {
            name: "search_files".to_owned(),
            description: "Search the files in your Google Drive by name and full text. Returns matching files with their names, types, last modified times and links.".to_owned(),
            input_schema: json!({
                "type":"object",
                "properties":{"query":{"type":"string","description":"What to look for, in file names and file contents."}},
                "required":["query"]
            }),
        },
        McpListedTool {
            name: "list_recent_files".to_owned(),
            description: "List the files in your Google Drive that changed most recently, newest first.".to_owned(),
            input_schema: json!({"type":"object","properties":{}}),
        },
        McpListedTool {
            name: "get_file_metadata".to_owned(),
            description: "Get the name, type, size, owner, last modified time and link for one file, by its id.".to_owned(),
            input_schema: json!({
                "type":"object",
                "properties":{"fileId":{"type":"string","description":"The file's Drive id."}},
                "required":["fileId"]
            }),
        },
        McpListedTool {
            name: "read_file_content".to_owned(),
            description: "Read the text of one file in your Google Drive, by its id. Google Docs, Sheets and Slides are exported as text.".to_owned(),
            input_schema: json!({
                "type":"object",
                "properties":{"fileId":{"type":"string","description":"The file's Drive id."}},
                "required":["fileId"]
            }),
        },
    ]
}

/// First-party effect classification. Only an advertised, non-write Drive tool is read; an
/// unknown/unadvertised name stays write even though the current dispatcher will also reject it.
#[must_use]
pub fn google_drive_effect(tool_name: &str, advertised: bool) -> Effect {
    if advertised && !GOOGLE_DRIVE_NAMED_WRITES.contains(&tool_name) {
        Effect::Read
    } else {
        Effect::Write
    }
}

fn list_outcome(body: Vec<u8>) -> Result<McpCallOutcome, GoogleDriveError> {
    let list: DriveFileList =
        serde_json::from_slice(&body).map_err(|_| GoogleDriveError::InvalidResponse)?;
    if list.files.len() > MAX_DRIVE_FILES {
        return Err(GoogleDriveError::InvalidResponse);
    }
    let mut lines = Vec::with_capacity(list.files.len());
    for file in list.files {
        validate_file(&file)?;
        lines.push(file_line(&file));
    }
    Ok(normalize_drive_result(lines.join("\n"), false))
}

fn validate_file(file: &DriveFile) -> Result<(), GoogleDriveError> {
    for value in [
        file.id.as_deref(),
        file.name.as_deref(),
        file.mime_type.as_deref(),
        file.modified_time.as_deref(),
        file.web_view_link.as_deref(),
        file.size.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if value.len() > MAX_DRIVE_STRING_BYTES || value.as_bytes().contains(&0) {
            return Err(GoogleDriveError::InvalidResponse);
        }
    }
    if file.owners.as_ref().is_some_and(|owners| {
        owners.len() > 64
            || owners.iter().any(|owner| {
                owner.email_address.as_ref().is_some_and(|email| {
                    email.len() > MAX_DRIVE_STRING_BYTES || email.as_bytes().contains(&0)
                })
            })
    }) {
        return Err(GoogleDriveError::InvalidResponse);
    }
    Ok(())
}

fn file_line(file: &DriveFile) -> String {
    let name = file.name.as_deref().unwrap_or("(untitled)");
    let display = file
        .web_view_link
        .as_deref()
        .and_then(safe_vendor_link)
        .map_or_else(
            || escape_markdown_text(name),
            |link| format!("[{}]({link})", escape_markdown_text(name)),
        );
    let mut parts = vec![display];
    if let Some(mime) = &file.mime_type {
        parts.push(mime.clone());
    }
    if let Some(modified) = &file.modified_time {
        parts.push(format!("modified {modified}"));
    }
    if let Some(id) = &file.id {
        parts.push(format!("id: {id}"));
    }
    format!("- {}", parts.join(" · "))
}

fn safe_vendor_link(value: &str) -> Option<&str> {
    let url = Url::parse(value).ok()?;
    (url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none())
    .then_some(value)
}

fn escape_markdown_text(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            '\\' | '[' | ']' => vec!['\\', character],
            _ => vec![character],
        })
        .collect()
}

fn drive_query(query: &str) -> String {
    let escaped = query.replace('\\', "\\\\").replace('\'', "\\'");
    format!("name contains '{escaped}' or fullText contains '{escaped}'")
}

fn string_argument<'a>(object: &'a serde_json::Map<String, Value>, key: &str) -> Option<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty() && value.len() <= 256 * 1024)
}

fn export_mime(mime: &str) -> Option<&'static str> {
    match mime {
        "application/vnd.google-apps.document" => Some("text/plain"),
        "application/vnd.google-apps.spreadsheet" => Some("text/csv"),
        "application/vnd.google-apps.presentation" => Some("text/plain"),
        _ => None,
    }
}

fn is_textual(mime: Option<&str>) -> bool {
    let Some(mime) = mime else {
        return false;
    };
    let essence = mime
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    essence.starts_with("text/")
        || matches!(
            essence.as_str(),
            "application/json"
                | "application/xml"
                | "application/xhtml+xml"
                | "application/javascript"
                | "application/x-ndjson"
                | "application/yaml"
                | "application/x-yaml"
                | "application/sql"
                | "application/toml"
        )
}

fn normalize_drive_result(text: String, is_error: bool) -> McpCallOutcome {
    let joined = text.trim().to_owned();
    let body = if joined.is_empty() {
        "The tool returned no content. Nothing was found, so there is nothing here to answer from."
            .to_owned()
    } else {
        joined
    };
    let body_count = body.chars().count();
    let annotated = format!("[Source: Google Drive REST · first-party]\n{body}");
    let count = annotated.chars().count();
    if count <= MAX_MCP_RESULT_CHARS {
        return McpCallOutcome {
            text: annotated,
            is_error,
            truncated: false,
        };
    }
    let prefix = annotated
        .chars()
        .take(MAX_MCP_RESULT_CHARS)
        .collect::<String>();
    McpCallOutcome {
        text: format!("{prefix}\n\n[truncated: the tool returned {body_count} characters]"),
        is_error,
        truncated: true,
    }
}

fn google_error_detail(body: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct Envelope {
        error: Option<GoogleError>,
    }
    #[derive(Deserialize)]
    struct GoogleError {
        message: Option<String>,
    }
    let detail = serde_json::from_slice::<Envelope>(body)
        .ok()?
        .error?
        .message?;
    let sanitized = detail
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .take(4 * 1024)
        .collect::<String>();
    (!sanitized.is_empty()).then_some(sanitized)
}

fn validate_base(base: &Url, scheme_policy: SchemePolicy) -> Result<(), GoogleDriveError> {
    if base.cannot_be_a_base()
        || !scheme_policy.accepts(base.scheme())
        || base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        return Err(GoogleDriveError::InvalidResponse);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_tools_and_query_escape_are_closed() {
        let tools = google_drive_tools();
        assert_eq!(
            tools
                .iter()
                .map(|tool| tool.name.as_str())
                .collect::<Vec<_>>(),
            [
                "search_files",
                "list_recent_files",
                "get_file_metadata",
                "read_file_content"
            ]
        );
        assert_eq!(
            drive_query("don't \\ ship"),
            "name contains 'don\\'t \\\\ ship' or fullText contains 'don\\'t \\\\ ship'"
        );
        assert_eq!(
            export_mime("application/vnd.google-apps.document"),
            Some("text/plain")
        );
        assert!(is_textual(Some("application/json; charset=utf-8")));
        assert!(!is_textual(Some("application/pdf")));
        assert!(
            tools
                .iter()
                .all(|tool| google_drive_effect(&tool.name, true) == Effect::Read)
        );
        assert_eq!(google_drive_effect("copy_file", true), Effect::Write);
        assert_eq!(google_drive_effect("unknown", false), Effect::Write);
    }

    #[test]
    fn result_projection_is_bounded_and_links_are_https_only() {
        let empty = normalize_drive_result(String::new(), false);
        assert!(!empty.is_error);
        assert!(empty.text.contains("Nothing was found"));
        let long = normalize_drive_result("🦀".repeat(MAX_MCP_RESULT_CHARS + 1), false);
        assert!(long.truncated);
        assert!(long.text.contains("20001 characters"));
        let unsafe_file = DriveFile {
            id: Some("id".to_owned()),
            name: Some("[name]".to_owned()),
            mime_type: None,
            modified_time: None,
            web_view_link: Some("javascript:alert(1)".to_owned()),
            size: None,
            owners: None,
        };
        assert!(!file_line(&unsafe_file).contains("javascript:"));
        assert!(file_line(&unsafe_file).contains("\\[name\\]"));
    }
}
