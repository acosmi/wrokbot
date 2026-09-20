use super::*;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17 and owned TLS; explicit include-ignored only"]
async fn enrollment_binds_current_actor_vault_identity_and_ready_catalogue() {
    let tls = TlsFixture::new(vec![
        json_plan(metadata_body()),
        json_plan(profile_body(ACCOUNT_ID, "")),
        json_plan(catalogue()),
    ])
    .await;
    let admin = harness::admin_config("gateway_authority_enroll_ready");
    harness::with_temp_database(&admin, "sdkgwready", |config| async move {
        let fixture = DatabaseFixture::new(config, &tls).await;
        let initial = tokens(&tls.endpoint(), false, 1);
        let receipt = enroll(&fixture, &tls, &initial).await;

        let client = fixture
            .pool
            .get()
            .await
            .map_err(|error| error.to_string())?;
        let row = client
            .query_one(
                "SELECT c.state,c.revision,c.credential_generation,c.auth_generation,
                        c.issuer,c.client_id,c.account_id,c.organization_id,c.current_secret_id,
                        s.encrypted_value,s.retired_at IS NULL
                   FROM public.sdk_gateway_connections c
                   JOIN public.sdk_gateway_secrets s ON s.id=c.current_secret_id
                  WHERE c.id=$1",
                &[&receipt.id()],
            )
            .await
            .map_err(|error| error.to_string())?;
        assert_eq!(row.get::<_, String>(0), "ready");
        assert_eq!(row.get::<_, i64>(1), 1);
        assert_eq!(row.get::<_, i64>(2), 1);
        assert_eq!(row.get::<_, i64>(3), 7);
        assert_eq!(row.get::<_, String>(4), tls.endpoint());
        assert_eq!(row.get::<_, String>(5), CLIENT_ID);
        assert_eq!(row.get::<_, String>(6), ACCOUNT_ID);
        assert_eq!(row.get::<_, Option<String>>(7), None);
        let secret_id: Uuid = row.get(8);
        let encrypted: String = row.get(9);
        assert!(row.get::<_, bool>(10));
        for marker in ["QA_ACCESS_1", "QA_REFRESH_1", ACCOUNT_ID, CLIENT_ID] {
            assert!(!encrypted.contains(marker));
        }
        let opened = fixture
            .vault
            .open(
                &secret_id,
                SecretKind::Model,
                SecretPrincipal::Actor(ActorId::new(ACTOR)),
                SecretPrincipal::Service(ServiceId::new(receipt.id().to_string())),
                &encrypted,
            )
            .unwrap();
        assert!(!opened.needs_migration());
        let stored: Value = serde_json::from_slice(opened.into_secret().expose()).unwrap();
        assert_eq!(stored["connectionId"], receipt.id().to_string());
        assert_eq!(stored["credentialGeneration"], 1);
        assert_eq!(stored["authGeneration"], 7);
        assert_eq!(stored["issuer"], tls.endpoint());
        assert_eq!(stored["accountId"], ACCOUNT_ID);
        assert_eq!(stored["clientId"], CLIENT_ID);
        assert_eq!(stored["tokens"]["access_token"], "QA_ACCESS_1");
        assert!(
            fixture
                .vault
                .open(
                    &secret_id,
                    SecretKind::Model,
                    SecretPrincipal::Actor(ActorId::new("bob")),
                    SecretPrincipal::Service(ServiceId::new(receipt.id().to_string())),
                    &encrypted,
                )
                .is_err()
        );
        assert!(
            fixture
                .vault
                .open(
                    &secret_id,
                    SecretKind::Model,
                    SecretPrincipal::Actor(ActorId::new(ACTOR)),
                    SecretPrincipal::Service(ServiceId::new(Uuid::nil().to_string())),
                    &encrypted,
                )
                .is_err()
        );
        let audit: String = client
            .query_one(
                "SELECT string_agg(event_type||':'||payload::text,' ' ORDER BY created_at)
                   FROM public.audit_events WHERE target_id=$1",
                &[&receipt.id().to_string()],
            )
            .await
            .map_err(|error| error.to_string())?
            .get(0);
        assert!(audit.contains("configuration.changed"));
        assert!(!audit.contains("QA_ACCESS"));
        assert!(!audit.contains("QA_REFRESH"));
        drop(client);

        assert_eq!(
            fixture
                .accounts
                .operation(
                    auth("bob", 3, Role::Admin),
                    receipt.id(),
                    1,
                    CancellationToken::new(),
                    Instant::now() + Duration::from_secs(10),
                    Arc::new(Outcomes::default()),
                )
                .await
                .unwrap_err(),
            GatewayAuthorityError::NotVisible
        );
        for (context, expected_revision, expected) in [
            (
                auth("charlie", 1, Role::User),
                1,
                GatewayAuthorityError::NotVisible,
            ),
            (owner(), 2, GatewayAuthorityError::Conflict),
        ] {
            assert_eq!(
                fixture
                    .accounts
                    .operation(
                        context,
                        receipt.id(),
                        expected_revision,
                        CancellationToken::new(),
                        Instant::now() + Duration::from_secs(10),
                        Arc::new(Outcomes::default()),
                    )
                    .await
                    .expect_err("negative currentness case must fail"),
                expected
            );
        }
        let wrong_scope = AuthContextBuilder::from_verified_session(
            DeploymentId::new("other-deployment"),
            TenantId::new(TENANT),
            ActorId::new(ACTOR),
            AuthGeneration::new(7),
            false,
        )
        .with_roles([Role::User])
        .build();
        assert_eq!(
            fixture
                .accounts
                .operation(
                    wrong_scope,
                    receipt.id(),
                    1,
                    CancellationToken::new(),
                    Instant::now() + Duration::from_secs(10),
                    Arc::new(Outcomes::default()),
                )
                .await
                .expect_err("cross deployment must fail"),
            GatewayAuthorityError::NotVisible
        );
        let outcomes = Arc::new(Outcomes::default());
        let sdk = operation_client(
            &fixture,
            &tls.endpoint(),
            receipt.id(),
            1,
            CancellationToken::new(),
            outcomes.clone(),
        )
        .await
        .unwrap();
        let models = sdk.list_models(None, false).await.unwrap();
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].id, "qa-model");
        assert_eq!(tls.count(), 3);
        assert_eq!(
            tls.captures.lock().unwrap()[2].path,
            "/api/v4/managed-models"
        );
        assert!(
            outcomes
                .snapshots()
                .iter()
                .all(|item| item.permit_released())
        );
        fixture.pool.close();
        tls.stop().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17 and owned TLS; explicit include-ignored only"]
async fn enrollment_rechecks_scope_role_and_auth_generation_before_any_socket() {
    let tls = TlsFixture::new(Vec::new()).await;
    let admin = harness::admin_config("gateway_authority_enroll_currentness");
    harness::with_temp_database(&admin, "sdkgwenrollcurrent", |config| async move {
        let fixture = DatabaseFixture::new(config, &tls).await;
        let wrong_scope = AuthContextBuilder::from_verified_session(
            DeploymentId::new("wrong-deployment"),
            TenantId::new(TENANT),
            ActorId::new(ACTOR),
            AuthGeneration::new(7),
            false,
        )
        .with_roles([Role::User])
        .build();
        assert_eq!(
            fixture
                .accounts
                .prepare_enrollment(wrong_scope, "Wrong scope", CLIENT_ID)
                .expect_err("scope mismatch must fail"),
            GatewayAuthorityError::NotVisible
        );
        let stale = fixture
            .accounts
            .prepare_enrollment(auth(ACTOR, 6, Role::User), "Stale actor", CLIENT_ID)
            .unwrap();
        assert_eq!(
            fixture
                .accounts
                .enroll(
                    &stale,
                    &tokens(&tls.endpoint(), false, 1),
                    CancellationToken::new(),
                    Arc::new(Outcomes::default()),
                )
                .await
                .expect_err("stale generation must fail before metadata"),
            GatewayAuthorityError::AccountProtocol
        );
        let no_role = fixture
            .accounts
            .prepare_enrollment(auth("charlie", 1, Role::User), "No role", CLIENT_ID)
            .unwrap();
        assert_eq!(
            fixture
                .accounts
                .enroll(
                    &no_role,
                    &tokens(&tls.endpoint(), false, 1),
                    CancellationToken::new(),
                    Arc::new(Outcomes::default()),
                )
                .await
                .expect_err("database role mismatch must fail before metadata"),
            GatewayAuthorityError::AccountProtocol
        );
        assert_eq!(tls.count(), 0);
        fixture.pool.close();
        tls.stop().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17 and owned TLS; explicit include-ignored only"]
async fn malformed_token_sets_are_rejected_before_fence_socket_or_pg_rows() {
    let tls = TlsFixture::new(Vec::new()).await;
    let admin = harness::admin_config("gateway_authority_enroll_token_shape");
    harness::with_temp_database(&admin, "sdkgwtokenshape", |config| async move {
        let fixture = DatabaseFixture::new(config, &tls).await;
        let origin = tls.endpoint();
        let mut invalid = Vec::new();

        let mut empty_refresh = tokens(&origin, false, 1);
        empty_refresh.refresh_token.clear();
        invalid.push(empty_refresh);

        let mut bad_expiry = tokens(&origin, false, 1);
        bad_expiry.expires_at = "not-rfc3339".to_owned();
        invalid.push(bad_expiry);

        let mut bad_scope = tokens(&origin, false, 1);
        bad_scope.scope = "ai".to_owned();
        invalid.push(bad_scope);

        let mut bad_server = tokens(&origin, false, 1);
        bad_server.server_url = "https://other.example.test".to_owned();
        invalid.push(bad_server);

        let mut bad_client = tokens(&origin, false, 1);
        bad_client.client_id = "different-client".to_owned();
        invalid.push(bad_client);

        let mut huge_access = tokens(&origin, false, 1);
        huge_access.access_token = "A".repeat(16_378);
        invalid.push(huge_access);

        let outcomes = Arc::new(Outcomes::default());
        for (index, token_set) in invalid.iter().enumerate() {
            let intent = fixture
                .accounts
                .prepare_enrollment(owner(), &format!("Invalid token {index}"), CLIENT_ID)
                .unwrap();
            assert_eq!(
                fixture
                    .accounts
                    .enroll(
                        &intent,
                        token_set,
                        CancellationToken::new(),
                        outcomes.clone(),
                    )
                    .await
                    .expect_err("malformed TokenSet must fail"),
                GatewayAuthorityError::InvalidInput
            );
        }
        assert_eq!(tls.count(), 0);
        assert!(
            outcomes.snapshots().is_empty(),
            "TokenSet shape must be checked before transport/fence construction"
        );
        let client = fixture
            .pool
            .get()
            .await
            .map_err(|error| error.to_string())?;
        for table in [
            "sdk_gateway_connections",
            "sdk_gateway_secrets",
            "sdk_gateway_operations",
        ] {
            let count: i64 = client
                .query_one(&format!("SELECT count(*) FROM public.{table}"), &[])
                .await
                .map_err(|error| error.to_string())?
                .get(0);
            assert_eq!(count, 0, "invalid TokenSet wrote {table}");
        }
        drop(client);
        fixture.pool.close();
        tls.stop().await;
        Ok(())
    })
    .await;
}
