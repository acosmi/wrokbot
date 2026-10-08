//! Explicit synthetic ModelPicker data for the testkit-only UI fixture binary.
//! These safe DTOs do not establish a credential, connectivity, provider or run capability.

#[cfg(not(feature = "testkit"))]
compile_error!("Synthetic ModelPicker assembly requires the testkit feature");

use std::ffi::OsStr;
use std::io;

use async_trait::async_trait;
use openbot_application::model_connections::{
    ModelConnectionAdministration, ModelConnectionError,
};
use openbot_contracts::{
    auth::{AuthContext, Role},
    ids::{ActorId, DeploymentId, TenantId},
    model_connections::{
        CreateModelConnection, CustomModelProtocol, DeleteModelConnection, ModelConnection,
        ModelConnectionDeleted, ModelConnectionPage, ModelConnectionPageRequest,
        ModelConnectionSource, UpdateModelConnection,
    },
};
use time::OffsetDateTime;

pub(super) const ENV: &str = "OPENBOT_UI_MODEL_PICKER_FIXTURE";

pub(super) fn enabled(value: Option<&OsStr>) -> Result<bool, io::Error> {
    match value {
        None => Ok(false),
        Some(value) if value == OsStr::new("1") => Ok(true),
        Some(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "OPENBOT_UI_MODEL_PICKER_FIXTURE must be exactly 1 when present",
        )),
    }
}

pub(super) fn validate_mode(
    enabled: bool,
    approval_mode: &str,
    auth_mode: &str,
    auth_journey: bool,
) -> Result<(), io::Error> {
    if enabled && (approval_mode != "memory" || auth_mode != "fixed" || auth_journey) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Synthetic ModelPicker requires Memory/fixed mode without the auth journey",
        ));
    }
    Ok(())
}

pub(super) struct FixtureModelConnections {
    deployment: DeploymentId,
    tenant: TenantId,
    actor: ActorId,
    connections: [ModelConnection; 3],
}

impl FixtureModelConnections {
    pub(super) fn new() -> Self {
        // 2026-10-02T00:00:00Z, matching the existing strict p2 synthetic DTO.
        let now = OffsetDateTime::from_unix_timestamp(1_790_899_200)
            .expect("fixed synthetic date is representable");
        let connection = |id: &str, enabled, has_credential| ModelConnection {
            id: id.to_owned(),
            source: ModelConnectionSource::Custom,
            name: "Synthetic Custom".to_owned(),
            protocol: CustomModelProtocol::OpenaiChatCompletions,
            endpoint: "https://model.example.test/v1/chat/completions".to_owned(),
            model: "fixture-model".to_owned(),
            enabled,
            revision: 1,
            has_credential,
            created_at: now,
            updated_at: now,
        };
        Self {
            deployment: DeploymentId::new(super::FIXTURE_DEPLOYMENT),
            tenant: TenantId::new(super::FIXTURE_TENANT),
            actor: ActorId::new(super::FIXTURE_ACTOR),
            connections: [
                connection("01991389-7380-7000-8000-000000000001", true, true),
                connection("01991389-7380-7000-8000-000000000002", false, true),
                connection("01991389-7380-7000-8000-000000000003", true, false),
            ],
        }
    }

    fn ensure_actor(&self, auth: &AuthContext) -> Result<(), ModelConnectionError> {
        if auth.deployment() == &self.deployment
            && auth.tenant() == &self.tenant
            && auth.actor() == &self.actor
            && (auth.has_role(Role::User) || auth.has_role(Role::Admin))
        {
            Ok(())
        } else {
            Err(ModelConnectionError::NotVisible)
        }
    }
}

#[async_trait]
impl ModelConnectionAdministration for FixtureModelConnections {
    async fn list(
        &self,
        auth: &AuthContext,
        request: &ModelConnectionPageRequest,
    ) -> Result<ModelConnectionPage, ModelConnectionError> {
        self.ensure_actor(auth)?;
        if request.cursor.is_some() {
            return Err(ModelConnectionError::InvalidInput { field: "cursor" });
        }
        Ok(ModelConnectionPage {
            connections: self.connections.to_vec(),
            next_cursor: None,
        })
    }

    async fn get(
        &self,
        auth: &AuthContext,
        id: &str,
    ) -> Result<ModelConnection, ModelConnectionError> {
        self.ensure_actor(auth)?;
        self.connections
            .iter()
            .find(|connection| connection.id == id)
            .cloned()
            .ok_or(ModelConnectionError::NotVisible)
    }

    async fn create(
        &self,
        auth: &AuthContext,
        _input: &CreateModelConnection,
    ) -> Result<ModelConnection, ModelConnectionError> {
        self.ensure_actor(auth)?;
        Err(ModelConnectionError::Unavailable)
    }

    async fn update(
        &self,
        auth: &AuthContext,
        _id: &str,
        _input: &UpdateModelConnection,
    ) -> Result<ModelConnection, ModelConnectionError> {
        self.ensure_actor(auth)?;
        Err(ModelConnectionError::Unavailable)
    }

    async fn delete(
        &self,
        auth: &AuthContext,
        _id: &str,
        _input: &DeleteModelConnection,
    ) -> Result<ModelConnectionDeleted, ModelConnectionError> {
        self.ensure_actor(auth)?;
        Err(ModelConnectionError::Unavailable)
    }
}
