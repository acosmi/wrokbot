//! Personal custom-model HTTP framing; all scope and persistence authority stays in application.

use crate::{
    auth::{Authenticated, FreshOriginAuthenticated},
    error::HttpError,
    http::ServerState,
};
use axum::{
    Json,
    extract::{
        Path, Query, RawQuery, State,
        rejection::{JsonRejection, QueryRejection},
    },
};
use http::{
    HeaderMap, StatusCode,
    header::{CACHE_CONTROL, HeaderValue},
};
use openbot_contracts::{
    command::{AppCommand, AppReply},
    error::AppError,
    model_connections::*,
};

#[cfg(test)]
#[path = "model_connections_tests.rs"]
mod tests;

/// `GET /api/me/model-connections`.
pub async fn list(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    query: Result<Query<ModelConnectionPageRequest>, QueryRejection>,
) -> Result<(HeaderMap, Json<ModelConnectionPage>), HttpError> {
    let Query(query) = query.map_err(|_| AppError::MalformedPayload { field: "query" })?;
    match state
        .application()
        .execute(auth, AppCommand::ListModelConnections(query))
        .await?
    {
        AppReply::ModelConnections(page) => Ok((headers(), Json(page))),
        _ => Err(contract_error()),
    }
}

/// `GET /api/me/model-connections/{id}`.
pub async fn get(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    RawQuery(query): RawQuery,
    Path(connection_id): Path<String>,
) -> Result<(HeaderMap, Json<ModelConnection>), HttpError> {
    reject_query(query)?;
    let row = connection_reply(
        state
            .application()
            .execute(auth, AppCommand::GetModelConnection { connection_id })
            .await?,
    )?;
    Ok((headers(), Json(row)))
}

/// Fresh Origin/authentication are checked before secret-bearing JSON is parsed.
pub async fn create(
    State(state): State<ServerState>,
    FreshOriginAuthenticated(auth): FreshOriginAuthenticated,
    RawQuery(query): RawQuery,
    body: Result<Json<CreateModelConnection>, JsonRejection>,
) -> Result<(StatusCode, HeaderMap, Json<ModelConnection>), HttpError> {
    reject_query(query)?;
    let Json(input) = body.map_err(|_| AppError::MalformedPayload { field: "body" })?;
    let row = connection_reply(
        state
            .application()
            .execute(auth, AppCommand::CreateModelConnection(input))
            .await?,
    )?;
    Ok((StatusCode::CREATED, headers(), Json(row)))
}

/// `PUT /api/me/model-connections/{id}`; stale metadata is never silently merged.
pub async fn update(
    State(state): State<ServerState>,
    FreshOriginAuthenticated(auth): FreshOriginAuthenticated,
    RawQuery(query): RawQuery,
    Path(connection_id): Path<String>,
    body: Result<Json<UpdateModelConnection>, JsonRejection>,
) -> Result<(HeaderMap, Json<ModelConnection>), HttpError> {
    reject_query(query)?;
    let Json(input) = body.map_err(|_| AppError::MalformedPayload { field: "body" })?;
    let row = connection_reply(
        state
            .application()
            .execute(
                auth,
                AppCommand::UpdateModelConnection {
                    connection_id,
                    input,
                },
            )
            .await?,
    )?;
    Ok((headers(), Json(row)))
}

/// `DELETE /api/me/model-connections/{id}` with a closed expectedRevision body.
pub async fn delete(
    State(state): State<ServerState>,
    FreshOriginAuthenticated(auth): FreshOriginAuthenticated,
    RawQuery(query): RawQuery,
    Path(connection_id): Path<String>,
    body: Result<Json<DeleteModelConnection>, JsonRejection>,
) -> Result<(HeaderMap, Json<ModelConnectionDeleted>), HttpError> {
    reject_query(query)?;
    let Json(input) = body.map_err(|_| AppError::MalformedPayload { field: "body" })?;
    match state
        .application()
        .execute(
            auth,
            AppCommand::DeleteModelConnection {
                connection_id,
                input,
            },
        )
        .await?
    {
        AppReply::ModelConnectionDeleted(row) => Ok((headers(), Json(row))),
        _ => Err(contract_error()),
    }
}

fn connection_reply(reply: AppReply) -> Result<ModelConnection, HttpError> {
    match reply {
        AppReply::ModelConnection(row) => Ok(row),
        _ => Err(contract_error()),
    }
}
fn contract_error() -> HttpError {
    AppError::DependencyUnavailable {
        dependency: "application",
    }
    .into()
}
fn headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers
}

fn reject_query(query: Option<String>) -> Result<(), HttpError> {
    if query.is_some() {
        Err(AppError::MalformedPayload { field: "query" }.into())
    } else {
        Ok(())
    }
}
