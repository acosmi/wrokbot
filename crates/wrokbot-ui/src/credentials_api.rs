//! Bounded same-origin credential framing. Secret writes move directly to a zeroizing serializer;
//! neither the inventory nor mutation receipt can contain existing plaintext/ciphertext.

#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use super::ApiError;
use openbot_contracts::credential_admin::{
    CREDENTIAL_PAGE_SIZE, CredentialExternalRevocation, CredentialPage, CredentialStatus,
    CredentialWrite,
};
#[cfg(target_arch = "wasm32")]
use openbot_contracts::credential_admin::{CredentialRevocationReceipt, CredentialWritten};

pub(crate) async fn load(cursor: Option<&str>) -> Result<CredentialPage, ApiError> {
    let path = match cursor {
        Some(cursor) if !cursor.is_empty() && cursor.len() <= 512 => format!(
            "/api/admin/credentials?cursor={}",
            super::encode_url_component(cursor)
        ),
        Some(_) => return Err(ApiError::InvalidResponse),
        None => "/api/admin/credentials".to_owned(),
    };
    #[cfg(target_arch = "wasm32")]
    {
        let response = builder(&path, false)
            .send()
            .await
            .map_err(|_| ApiError::Network)?;
        if response.status() != 200 {
            return Err(super::status_error(response.status()));
        }
        let page: CredentialPage = bounded_response(response).await?;
        validate_page(&page)?;
        if page
            .next_cursor
            .as_deref()
            .is_some_and(|next| Some(next) == cursor)
        {
            return Err(ApiError::InvalidResponse);
        }
        Ok(page)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = path;
        Err(ApiError::Unavailable)
    }
}

pub(crate) async fn save(
    previous: Option<&str>,
    input: CredentialWrite,
) -> Result<CredentialStatus, ApiError> {
    let path = match previous {
        Some(id) => format!("{}/rotate", credential_path(id)?),
        None => "/api/admin/credentials".to_owned(),
    };
    #[cfg(target_arch = "wasm32")]
    {
        let expected = (
            input.kind(),
            input.provider().to_owned(),
            input.key_id().to_owned(),
            input.metadata().clone(),
        );
        let outgoing = super::secret_json(builder(&path, true), &input)?;
        drop(input);
        let response = outgoing.send().await.map_err(|_| ApiError::Network)?;
        if response.status() != if previous.is_some() { 200 } else { 201 } {
            return Err(super::status_error(response.status()));
        }
        let result: CredentialWritten = bounded_response(response).await?;
        let row = result.credential;
        validate_row(&row)?;
        if row.kind.manual() != Some(expected.0)
            || row.provider != expected.1
            || row.key_id != expected.2
            || row.metadata != expected.3
            || row.revoked_at.is_some()
            || row.external_revocation != CredentialExternalRevocation::NotRequested
            || previous.is_some_and(|id| id == row.id)
        {
            return Err(ApiError::InvalidResponse);
        }
        Ok(row)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (path, input);
        Err(ApiError::Unavailable)
    }
}

pub(crate) async fn revoke(id: &str) -> Result<(), ApiError> {
    let path = format!("{}/revoke", credential_path(id)?);
    #[cfg(target_arch = "wasm32")]
    {
        let response = builder(&path, true)
            .send()
            .await
            .map_err(|_| ApiError::Network)?;
        if response.status() != 200 {
            return Err(super::status_error(response.status()));
        }
        let receipt: CredentialRevocationReceipt = bounded_response(response).await?;
        if receipt.credential.id != id
            || receipt.credential.external_revocation == CredentialExternalRevocation::NotRequested
        {
            return Err(ApiError::InvalidResponse);
        }
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = path;
        Err(ApiError::Unavailable)
    }
}

fn credential_path(id: &str) -> Result<String, ApiError> {
    uuid::Uuid::parse_str(id).map_err(|_| ApiError::InvalidResponse)?;
    Ok(format!(
        "/api/admin/credentials/{}",
        super::encode_url_component(id)
    ))
}

pub(crate) fn validate_row(row: &CredentialStatus) -> Result<(), ApiError> {
    credential_path(&row.id)?;
    if row.provider.is_empty()
        || row.provider.len() > 256
        || row.key_id.is_empty()
        || row.key_id.len() > 1024
        || row.provider.chars().any(char::is_control)
        || row.key_id.chars().any(char::is_control)
        || !row.metadata.is_object()
        || serde_json::to_vec(&row.metadata).map_or(true, |v| v.len() > 64 * 1024)
        || row.revoked_at.is_none()
            != (row.external_revocation == CredentialExternalRevocation::NotRequested)
    {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

pub(crate) fn validate_page(page: &CredentialPage) -> Result<(), ApiError> {
    if page.credentials.len() > CREDENTIAL_PAGE_SIZE
        || page
            .next_cursor
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > 512)
    {
        return Err(ApiError::InvalidResponse);
    }
    let mut ids = std::collections::BTreeSet::new();
    for row in &page.credentials {
        validate_row(row)?;
        if !ids.insert(&row.id) {
            return Err(ApiError::InvalidResponse);
        }
    }
    if let Some(hint) = &page.model_reference
        && (hint.provider.is_empty()
            || hint.provider.len() > 256
            || hint.key_id.is_empty()
            || hint.key_id.len() > 1024
            || hint.provider.chars().any(char::is_control)
            || hint.key_id.chars().any(char::is_control))
    {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn builder(path: &str, post: bool) -> gloo_net::http::RequestBuilder {
    use crate::api::request::Request;
    use web_sys::{RequestCache, RequestCredentials, RequestRedirect};
    (if post {
        Request::post(path)
    } else {
        Request::get(path)
    })
    .cache(RequestCache::NoStore)
    .credentials(RequestCredentials::SameOrigin)
    .redirect(RequestRedirect::Error)
}

#[cfg(target_arch = "wasm32")]
async fn bounded_response<T: serde::de::DeserializeOwned>(
    response: gloo_net::http::Response,
) -> Result<T, ApiError> {
    let text = response
        .text()
        .await
        .map_err(|_| ApiError::InvalidResponse)?;
    if text.len() > 8 * 1024 * 1024 {
        return Err(ApiError::InvalidResponse);
    }
    serde_json::from_str(&text).map_err(|_| ApiError::InvalidResponse)
}
