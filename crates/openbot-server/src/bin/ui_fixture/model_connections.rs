//! Explicit synthetic ModelPicker data for the testkit-only UI fixture binary.
//! These safe DTOs do not establish a credential, connectivity, provider or run capability.

#[cfg(not(feature = "testkit"))]
compile_error!("Synthetic ModelPicker assembly requires the testkit feature");

use std::ffi::OsStr;
use std::io;

use async_trait::async_trait;
use openbot_application::model_connections::{ModelConnectionAdministration, ModelConnectionError};
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

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_application::{ApplicationService, OpenBotApplication};
    use openbot_contracts::{
        auth::AuthGeneration, command::AppCommand, error::AppError, model_connections::ModelApiKey,
    };
    use zeroize::Zeroizing;

    const IDS: [&str; 3] = [
        "01991389-7380-7000-8000-000000000001",
        "01991389-7380-7000-8000-000000000002",
        "01991389-7380-7000-8000-000000000003",
    ];

    fn context(
        deployment: &str,
        tenant: &str,
        actor: &str,
        roles: &[Role],
        single_user: bool,
    ) -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new(deployment),
            TenantId::new(tenant),
            ActorId::new(actor),
            roles.iter().copied(),
            AuthGeneration::new(1),
            single_user,
        )
    }

    fn owner(role: Role) -> AuthContext {
        context(
            super::super::FIXTURE_DEPLOYMENT,
            super::super::FIXTURE_TENANT,
            super::super::FIXTURE_ACTOR,
            &[role],
            false,
        )
    }

    fn synthetic_key() -> ModelApiKey {
        ModelApiKey::new(Zeroizing::new(
            "FIXTURE_TEST_ONLY_NOT_A_PROVIDER_KEY".to_owned(),
        ))
        .unwrap()
    }

    fn create_input(malformed_metadata: bool) -> CreateModelConnection {
        CreateModelConnection {
            name: if malformed_metadata {
                String::new()
            } else {
                "Test-only replacement".to_owned()
            },
            protocol: CustomModelProtocol::OpenaiChatCompletions,
            endpoint: if malformed_metadata {
                "not a URL".to_owned()
            } else {
                "https://fixture-write.example.test/v1/chat/completions".to_owned()
            },
            model: if malformed_metadata {
                String::new()
            } else {
                "test-only-model".to_owned()
            },
            enabled: true,
            api_key: synthetic_key(),
        }
    }

    fn update_input(expected_revision: i64, replace_key: bool) -> UpdateModelConnection {
        UpdateModelConnection {
            expected_revision,
            name: "Test-only replacement".to_owned(),
            protocol: CustomModelProtocol::OpenaiChatCompletions,
            endpoint: "https://fixture-write.example.test/v1/chat/completions".to_owned(),
            model: "test-only-model".to_owned(),
            enabled: true,
            api_key: replace_key.then(synthetic_key),
        }
    }

    #[test]
    fn model_picker_fixture_opt_in_is_absent_or_exact_os_one() {
        assert!(!enabled(None).unwrap());
        assert!(enabled(Some(OsStr::new("1"))).unwrap());
        for value in ["", "0", "true", " 1", "1 ", "1\n", "１", "test-only-canary"] {
            let error = enabled(Some(OsStr::new(value))).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(
                error.to_string(),
                "OPENBOT_UI_MODEL_PICKER_FIXTURE must be exactly 1 when present"
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;

            let error = enabled(Some(OsStr::from_bytes(b"\xff1"))).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(
                error.to_string(),
                "OPENBOT_UI_MODEL_PICKER_FIXTURE must be exactly 1 when present"
            );
        }
    }

    #[test]
    fn model_picker_fixture_opt_in_requires_memory_fixed_without_auth_journey() {
        assert!(validate_mode(true, "memory", "fixed", false).is_ok());
        for (approval, auth, journey) in [
            ("postgres", "fixed", false),
            ("memory", "session", false),
            ("memory", "fixed", true),
            ("postgres", "session", true),
            ("test-only-mode", "test-only-auth", false),
        ] {
            let error = validate_mode(true, approval, auth, journey).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(
                error.to_string(),
                "Synthetic ModelPicker requires Memory/fixed mode without the auth journey"
            );
            // No opt-in adds no restriction to the existing fixture-mode validation.
            assert!(validate_mode(false, approval, auth, journey).is_ok());
        }
    }

    #[tokio::test]
    async fn default_application_keeps_model_connections_missing_without_opt_in() {
        assert!(!enabled(None).unwrap());
        let application = OpenBotApplication::new(super::super::FixtureChannels::new(
            OffsetDateTime::UNIX_EPOCH,
        ));
        for role in [Role::User, Role::Admin] {
            for command in [
                AppCommand::ListModelConnections(ModelConnectionPageRequest::default()),
                AppCommand::GetModelConnection {
                    connection_id: IDS[0].to_owned(),
                },
            ] {
                assert!(matches!(
                    application.execute(owner(role), command).await,
                    Err(AppError::DependencyUnavailable {
                        dependency: "model_connections"
                    })
                ));
            }
        }
    }

    #[tokio::test]
    async fn model_picker_fixture_fences_all_five_methods_before_input_handling() {
        let fixture = FixtureModelConnections::new();
        let mut rejected = Vec::new();
        for role in [Role::User, Role::Admin] {
            rejected.extend([
                context(
                    "different-deployment",
                    super::super::FIXTURE_TENANT,
                    super::super::FIXTURE_ACTOR,
                    &[role],
                    false,
                ),
                context(
                    super::super::FIXTURE_DEPLOYMENT,
                    "different-tenant",
                    super::super::FIXTURE_ACTOR,
                    &[role],
                    false,
                ),
                context(
                    super::super::FIXTURE_DEPLOYMENT,
                    super::super::FIXTURE_TENANT,
                    "different-actor",
                    &[role],
                    false,
                ),
            ]);
        }
        for single_user in [false, true] {
            rejected.push(context(
                super::super::FIXTURE_DEPLOYMENT,
                super::super::FIXTURE_TENANT,
                super::super::FIXTURE_ACTOR,
                &[],
                single_user,
            ));
        }
        let cursor = ModelConnectionPageRequest {
            cursor: Some("test-only-invalid-cursor".to_owned()),
        };
        let create = create_input(true);
        let mut update = update_input(0, true);
        update.name.clear();
        update.endpoint = "not a URL".to_owned();
        let delete = DeleteModelConnection {
            expected_revision: 0,
        };
        for auth in rejected {
            assert_eq!(
                fixture.list(&auth, &cursor).await,
                Err(ModelConnectionError::NotVisible)
            );
            assert_eq!(
                fixture.get(&auth, IDS[0]).await,
                Err(ModelConnectionError::NotVisible)
            );
            assert_eq!(
                fixture.create(&auth, &create).await,
                Err(ModelConnectionError::NotVisible)
            );
            assert_eq!(
                fixture.update(&auth, IDS[0], &update).await,
                Err(ModelConnectionError::NotVisible)
            );
            assert_eq!(
                fixture.delete(&auth, IDS[0], &delete).await,
                Err(ModelConnectionError::NotVisible)
            );
        }
    }

    #[tokio::test]
    async fn model_picker_fixture_reads_only_three_ordered_safe_custom_dtos() {
        let fixture = FixtureModelConnections::new();
        for role in [Role::User, Role::Admin] {
            let auth = owner(role);
            let page = fixture
                .list(&auth, &ModelConnectionPageRequest::default())
                .await
                .unwrap();
            assert!(page.next_cursor.is_none());
            assert_eq!(
                page.connections
                    .iter()
                    .map(|row| (row.id.as_str(), row.enabled, row.has_credential))
                    .collect::<Vec<_>>(),
                vec![
                    (IDS[0], true, true),
                    (IDS[1], false, true),
                    (IDS[2], true, false)
                ]
            );
            for row in &page.connections {
                assert_eq!(row.source, ModelConnectionSource::Custom);
                assert_eq!(row.protocol, CustomModelProtocol::OpenaiChatCompletions);
                assert_eq!(row.revision, 1);
                assert_eq!(fixture.get(&auth, &row.id).await.unwrap(), *row);
            }
            for cursor in ["", IDS[0], "test-only-invalid-cursor"] {
                assert_eq!(
                    fixture
                        .list(
                            &auth,
                            &ModelConnectionPageRequest {
                                cursor: Some(cursor.to_owned())
                            }
                        )
                        .await,
                    Err(ModelConnectionError::InvalidInput { field: "cursor" })
                );
            }
            for id in [
                "",
                "01991389-7380-7000-8000-000000000004",
                "01991389-7380-7000-8000-000000000001/extra",
            ] {
                assert_eq!(
                    fixture.get(&auth, id).await,
                    Err(ModelConnectionError::NotVisible)
                );
            }
        }
    }

    #[tokio::test]
    async fn model_picker_fixture_writes_stay_unavailable_without_changing_public_rows() {
        let fixture = FixtureModelConnections::new();
        for role in [Role::User, Role::Admin] {
            let auth = owner(role);
            let before = fixture
                .list(&auth, &ModelConnectionPageRequest::default())
                .await
                .unwrap();
            for malformed_metadata in [false, true] {
                let error = fixture
                    .create(&auth, &create_input(malformed_metadata))
                    .await
                    .unwrap_err();
                assert_eq!(error, ModelConnectionError::Unavailable);
                assert_eq!(error.to_string(), "model_connection_unavailable");
            }
            for id in [IDS[0], "01991389-7380-7000-8000-000000000004"] {
                for expected_revision in [1, 0, -1] {
                    for replace_key in [false, true] {
                        assert_eq!(
                            fixture
                                .update(&auth, id, &update_input(expected_revision, replace_key))
                                .await,
                            Err(ModelConnectionError::Unavailable)
                        );
                    }
                    assert_eq!(
                        fixture
                            .delete(&auth, id, &DeleteModelConnection { expected_revision })
                            .await,
                        Err(ModelConnectionError::Unavailable)
                    );
                }
            }
            let after = fixture
                .list(&auth, &ModelConnectionPageRequest::default())
                .await
                .unwrap();
            assert_eq!(after, before);
        }
    }
}
