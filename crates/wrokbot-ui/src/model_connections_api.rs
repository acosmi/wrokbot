//! Personal model inventory framing. Secrets only cross the transient write boundary.
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use super::ApiError;
use wrokbot_contracts::model_connections::*;

const ROOT: &str = "/api/me/model-connections";
const MAX_DIRECTORY_ROWS: usize = 1_000;
const MAX_DIRECTORY_PAGES: usize = 11;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WriteError {
    InvalidInput,
    Rejected(ApiError),
    Unknown,
}

fn path(id: &str) -> Result<String, ApiError> {
    uuid::Uuid::parse_str(id).map_err(|_| ApiError::InvalidResponse)?;
    Ok(format!("{ROOT}/{}", super::encode_url_component(id)))
}

pub(crate) fn valid_metadata(name: &str, endpoint: &str, model: &str) -> bool {
    let text = |s: &str, max| {
        !s.is_empty() && s.len() <= max && s.trim() == s && !s.chars().any(char::is_control)
    };
    if !text(name, MAX_MODEL_CONNECTION_NAME_BYTES)
        || !text(model, MAX_MODEL_CONNECTION_MODEL_BYTES)
        || !text(endpoint, MAX_MODEL_CONNECTION_ENDPOINT_BYTES)
    {
        return false;
    }
    let Ok(url) = url::Url::parse(endpoint) else {
        return false;
    };
    let authority = endpoint
        .split_once("://")
        .map(|(_, s)| s.split(['/', '?', '#']).next().unwrap_or(""))
        .unwrap_or("");
    url.scheme() == "https"
        && url.host_str().is_some()
        && !authority.contains('@')
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

fn validate_row(row: &ModelConnection) -> Result<(), ApiError> {
    path(&row.id)?;
    if row.revision <= 0 || !valid_metadata(&row.name, &row.endpoint, &row.model) {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

fn validate_page(page: &ModelConnectionPage, cursor: Option<&str>) -> Result<(), ApiError> {
    if page.connections.len() > MODEL_CONNECTION_PAGE_SIZE {
        return Err(ApiError::InvalidResponse);
    }
    let mut seen = std::collections::BTreeSet::new();
    for row in &page.connections {
        validate_row(row)?;
        if !seen.insert(&row.id) {
            return Err(ApiError::InvalidResponse);
        }
    }
    if let Some(next) = &page.next_cursor {
        path(next)?;
        if Some(next.as_str()) == cursor {
            return Err(ApiError::InvalidResponse);
        }
    }
    Ok(())
}

pub(crate) async fn list(cursor: Option<&str>) -> Result<ModelConnectionPage, ApiError> {
    let route = if let Some(cursor) = cursor {
        path(cursor)?;
        format!("{ROOT}?cursor={}", super::encode_url_component(cursor))
    } else {
        ROOT.to_owned()
    };
    let page: ModelConnectionPage = read(&route).await?;
    validate_page(&page, cursor)?;
    Ok(page)
}

#[derive(Default)]
struct DirectoryAccumulator {
    rows: Vec<ModelConnection>,
    row_ids: std::collections::BTreeSet<String>,
    cursors: std::collections::BTreeSet<String>,
    pages: usize,
}

impl DirectoryAccumulator {
    fn push(
        &mut self,
        page: ModelConnectionPage,
        cursor: Option<&str>,
    ) -> Result<Option<String>, ApiError> {
        self.pages = self.pages.saturating_add(1);
        if self.pages > MAX_DIRECTORY_PAGES {
            return Err(ApiError::InvalidResponse);
        }
        validate_page(&page, cursor)?;
        for row in page.connections {
            if self.rows.len() >= MAX_DIRECTORY_ROWS || !self.row_ids.insert(row.id.clone()) {
                return Err(ApiError::InvalidResponse);
            }
            self.rows.push(row);
        }
        if let Some(next) = &page.next_cursor
            && !self.cursors.insert(next.clone())
        {
            return Err(ApiError::InvalidResponse);
        }
        Ok(page.next_cursor)
    }
}

/// Read the complete bounded v1 inventory without accepting cursor loops or duplicate rows.
pub(crate) async fn list_all() -> Result<Vec<ModelConnection>, ApiError> {
    let mut directory = DirectoryAccumulator::default();
    let mut cursor = None::<String>;
    loop {
        let page = list(cursor.as_deref()).await?;
        let Some(next) = directory.push(page, cursor.as_deref())? else {
            return Ok(directory.rows);
        };
        cursor = Some(next);
    }
}

pub(crate) async fn get(id: &str) -> Result<ModelConnection, ApiError> {
    let row: ModelConnection = read(&path(id)?).await?;
    validate_row(&row)?;
    if row.id != id {
        return Err(ApiError::InvalidResponse);
    }
    Ok(row)
}

/// No input payload is retained by the caller after this operation is dispatched.
pub(crate) enum Write {
    Create(CreateModelConnection),
    Update(String, UpdateModelConnection),
    Delete(String, DeleteModelConnection),
}

pub(crate) async fn write(input: Write) -> Result<(), WriteError> {
    #[cfg(target_arch = "wasm32")]
    {
        // Deliberately retain only non-secret receipt checks. Endpoint normalization is Server-owned.
        let (route, method, status, expected, prior) = match &input {
            Write::Create(v) => (
                ROOT.to_owned(),
                "POST",
                201,
                Some((v.name.clone(), v.protocol, v.model.clone(), v.enabled)),
                None,
            ),
            Write::Update(id, v) => (
                path(id).map_err(|_| WriteError::InvalidInput)?,
                "PUT",
                200,
                Some((v.name.clone(), v.protocol, v.model.clone(), v.enabled)),
                Some((id.clone(), v.expected_revision)),
            ),
            Write::Delete(id, v) => (
                path(id).map_err(|_| WriteError::InvalidInput)?,
                "DELETE",
                200,
                None,
                Some((id.clone(), v.expected_revision)),
            ),
        };
        let builder = builder(&route, method);
        let outgoing = match &input {
            Write::Create(v) => super::secret_json(builder, v),
            Write::Update(_, v) => super::secret_json(builder, v),
            Write::Delete(_, v) => super::secret_json(builder, v),
        }
        .map_err(|_| WriteError::InvalidInput)?;
        drop(input);
        let response = outgoing.send().await.map_err(|_| WriteError::Unknown)?;
        if response.status() != status {
            return Err(write_failure(response.status()));
        }
        if let Some((name, protocol, model, enabled)) = expected {
            let row: ModelConnection = decode(response).await.map_err(|_| WriteError::Unknown)?;
            validate_row(&row).map_err(|_| WriteError::Unknown)?;
            if row.name != name
                || row.protocol != protocol
                || row.model != model
                || row.enabled != enabled
                || !row.has_credential
                || prior.is_some_and(|(id, revision)| row.id != id || row.revision <= revision)
            {
                return Err(WriteError::Unknown);
            }
        } else {
            let receipt: ModelConnectionDeleted =
                decode(response).await.map_err(|_| WriteError::Unknown)?;
            if prior.is_none_or(|(id, revision)| receipt.id != id || receipt.revision <= revision) {
                return Err(WriteError::Unknown);
            }
        }
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = input;
        Err(WriteError::Rejected(ApiError::Unavailable))
    }
}

fn write_failure(status: u16) -> WriteError {
    match status {
        400 | 422 => WriteError::InvalidInput,
        401 => WriteError::Rejected(ApiError::Unauthorized),
        403 => WriteError::Rejected(ApiError::Forbidden),
        404 => WriteError::Rejected(ApiError::NotFound),
        409 | 410 | 412 => WriteError::Rejected(ApiError::Conflict),
        // Includes accepted/unknown, lost acknowledgement, server failures and malformed success.
        _ => WriteError::Unknown,
    }
}

async fn read<T: serde::de::DeserializeOwned>(route: &str) -> Result<T, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        let response = builder(route, "GET")
            .send()
            .await
            .map_err(|_| ApiError::Network)?;
        if response.status() != 200 {
            return Err(super::status_error(response.status()));
        }
        decode(response).await
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = route;
        Err(ApiError::Unavailable)
    }
}

#[cfg(target_arch = "wasm32")]
fn builder(route: &str, method: &str) -> gloo_net::http::RequestBuilder {
    use crate::api::request::Request;
    use web_sys::{RequestCache, RequestCredentials, RequestRedirect};
    match method {
        "POST" => Request::post(route),
        "PUT" => Request::put(route),
        "DELETE" => Request::delete(route),
        _ => Request::get(route),
    }
    .cache(RequestCache::NoStore)
    .credentials(RequestCredentials::SameOrigin)
    .redirect(RequestRedirect::Error)
}

#[cfg(target_arch = "wasm32")]
async fn decode<T: serde::de::DeserializeOwned>(
    response: gloo_net::http::Response,
) -> Result<T, ApiError> {
    let text = response
        .text()
        .await
        .map_err(|_| ApiError::InvalidResponse)?;
    if text.len() > 512 * 1024 {
        return Err(ApiError::InvalidResponse);
    }
    serde_json::from_str(&text).map_err(|_| ApiError::InvalidResponse)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(index: usize) -> ModelConnection {
        ModelConnection {
            id: format!("01991389-7380-7000-8000-{index:012x}"),
            source: ModelConnectionSource::Custom,
            name: format!("Test {index}"),
            protocol: CustomModelProtocol::OpenaiResponses,
            endpoint: "https://example.test/v1/responses".into(),
            model: format!("model-{index}"),
            enabled: true,
            revision: 1,
            has_credential: true,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn sensitive_endpoint_framing_rejects_hidden_credentials_and_unicode_overflow() {
        for endpoint in [
            "http://example.test",
            "https://@example.test",
            "https://user:pass@example.test",
            "https://example.test?key=secret",
            "https://example.test#secret",
            " https://example.test",
            "https://exam\tple.test",
        ] {
            assert!(!valid_metadata("name", endpoint, "model"), "{endpoint}");
        }
        assert!(valid_metadata(
            &"名".repeat(33),
            "https://example.test/v2",
            "model"
        ));
        assert!(!valid_metadata(
            &"名".repeat(34),
            "https://example.test/v2",
            "model"
        ));
        assert!(path("../../another-owner").is_err());
    }
    #[test]
    fn uncertain_writes_never_turn_into_retryable_rejections() {
        for status in [200, 201, 202, 204, 301, 408, 429, 500, 502, 503] {
            assert_eq!(write_failure(status), WriteError::Unknown);
        }
        assert_eq!(write_failure(409), WriteError::Rejected(ApiError::Conflict));
        assert_eq!(write_failure(400), WriteError::InvalidInput);
    }
    #[test]
    fn page_rejects_duplicate_identity_and_cursor_loops() {
        let row = row(1);
        let mut page = ModelConnectionPage {
            connections: vec![row.clone()],
            next_cursor: Some(row.id.clone()),
        };
        assert!(validate_page(&page, None).is_ok());
        assert!(validate_page(&page, Some(&row.id)).is_err());
        page.connections.push(row);
        assert!(validate_page(&page, None).is_err());
    }

    #[test]
    fn page_size_boundary_is_exact() {
        let mut page = ModelConnectionPage {
            connections: (0..MODEL_CONNECTION_PAGE_SIZE).map(row).collect(),
            next_cursor: None,
        };
        assert!(validate_page(&page, None).is_ok());
        page.connections.push(row(MODEL_CONNECTION_PAGE_SIZE));
        assert_eq!(validate_page(&page, None), Err(ApiError::InvalidResponse));
    }

    #[test]
    fn complete_directory_rejects_cross_page_duplicates_and_cursor_cycles() {
        let mut duplicate = DirectoryAccumulator::default();
        assert_eq!(
            duplicate
                .push(
                    ModelConnectionPage {
                        connections: vec![row(1)],
                        next_cursor: Some(row(1).id),
                    },
                    None,
                )
                .unwrap(),
            Some(row(1).id)
        );
        assert_eq!(
            duplicate.push(
                ModelConnectionPage {
                    connections: vec![row(1)],
                    next_cursor: None,
                },
                Some(&row(1).id),
            ),
            Err(ApiError::InvalidResponse)
        );

        let mut cycle = DirectoryAccumulator::default();
        let first = row(10).id;
        let second = row(11).id;
        cycle
            .push(
                ModelConnectionPage {
                    connections: vec![],
                    next_cursor: Some(first.clone()),
                },
                None,
            )
            .unwrap();
        cycle
            .push(
                ModelConnectionPage {
                    connections: vec![],
                    next_cursor: Some(second.clone()),
                },
                Some(&first),
            )
            .unwrap();
        assert_eq!(
            cycle.push(
                ModelConnectionPage {
                    connections: vec![],
                    next_cursor: Some(first),
                },
                Some(&second),
            ),
            Err(ApiError::InvalidResponse)
        );
    }

    #[test]
    fn complete_directory_rejects_rows_beyond_the_global_bound() {
        let mut directory = DirectoryAccumulator::default();
        for page in 0..10 {
            let start = page * MODEL_CONNECTION_PAGE_SIZE;
            let next = row(start + MODEL_CONNECTION_PAGE_SIZE - 1).id;
            directory
                .push(
                    ModelConnectionPage {
                        connections: (start..start + MODEL_CONNECTION_PAGE_SIZE)
                            .map(row)
                            .collect(),
                        next_cursor: Some(next.clone()),
                    },
                    (page > 0).then(|| row(start - 1).id).as_deref(),
                )
                .unwrap();
        }
        assert_eq!(directory.rows.len(), MAX_DIRECTORY_ROWS);
        assert_eq!(
            directory.push(
                ModelConnectionPage {
                    connections: vec![row(MAX_DIRECTORY_ROWS)],
                    next_cursor: None,
                },
                Some(&row(MAX_DIRECTORY_ROWS - 1).id),
            ),
            Err(ApiError::InvalidResponse)
        );
    }

    #[test]
    fn complete_directory_rejects_a_twelfth_page() {
        let mut directory = DirectoryAccumulator::default();
        for page in 0..MAX_DIRECTORY_PAGES {
            let current = (page > 0).then(|| row(page - 1).id);
            let next = row(page).id;
            assert_eq!(
                directory.push(
                    ModelConnectionPage {
                        connections: vec![],
                        next_cursor: Some(next.clone()),
                    },
                    current.as_deref(),
                ),
                Ok(Some(next))
            );
        }
        assert_eq!(
            directory.push(
                ModelConnectionPage {
                    connections: vec![],
                    next_cursor: None,
                },
                Some(&row(MAX_DIRECTORY_PAGES - 1).id),
            ),
            Err(ApiError::InvalidResponse)
        );
    }
}
