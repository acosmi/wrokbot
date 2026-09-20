use super::*;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17 and owned TLS; explicit include-ignored only"]
async fn two_authorities_serialize_one_refresh_advance_generation_and_retire_old_secret() {
    let tls = TlsFixture::new(vec![
        json_plan(metadata_body()),
        json_plan(profile_body(ACCOUNT_ID, "organization-one")),
        json_plan(metadata_body()),
        json_plan(refresh_response(2)),
        json_plan(metadata_body()),
        json_plan(profile_body(ACCOUNT_ID, "organization-one")),
        json_plan(catalogue()),
        json_plan(catalogue()),
    ])
    .await;
    let admin = harness::admin_config("gateway_authority_rotation");
    harness::with_temp_database(&admin, "sdkgwrotate", |config| async move {
        let fixture = DatabaseFixture::new(config, &tls).await;
        let receipt = enroll(&fixture, &tls, &tokens(&tls.endpoint(), true, 1)).await;
        let old_secret: Uuid = fixture
            .pool
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT current_secret_id FROM public.sdk_gateway_connections WHERE id=$1",
                &[&receipt.id()],
            )
            .await
            .unwrap()
            .get(0);

        let outcomes_a = Arc::new(Outcomes::default());
        let outcomes_b = Arc::new(Outcomes::default());
        let client_a = operation_client(
            &fixture,
            &tls.endpoint(),
            receipt.id(),
            receipt.revision(),
            CancellationToken::new(),
            outcomes_a.clone(),
        )
        .await
        .unwrap();
        let client_b = operation_client(
            &fixture,
            &tls.endpoint(),
            receipt.id(),
            receipt.revision(),
            CancellationToken::new(),
            outcomes_b.clone(),
        )
        .await
        .unwrap();
        let (left, right) = tokio::join!(
            client_a.list_models(None, false),
            client_b.list_models(None, false)
        );
        assert_eq!(left.unwrap().len(), 1);
        assert_eq!(right.unwrap().len(), 1);

        let captures = tls.captures.lock().unwrap().clone();
        assert_eq!(captures.len(), 8);
        assert_eq!(
            captures
                .iter()
                .filter(|capture| capture.path == "/oauth/desktop/token")
                .count(),
            1,
            "two independent authority instances must not spend one refresh token twice"
        );
        let token_request = captures
            .iter()
            .find(|capture| capture.path == "/oauth/desktop/token")
            .unwrap();
        assert_eq!(token_request.method, "POST");
        assert!(String::from_utf8_lossy(&token_request.body).contains("grant_type=refresh_token"));
        assert_eq!(
            captures
                .iter()
                .filter(|capture| capture.path == "/api/oauth/profile")
                .count(),
            2,
            "enrollment and rotated token each require an authenticated profile read"
        );
        drop(captures);

        let client = fixture
            .pool
            .get()
            .await
            .map_err(|error| error.to_string())?;
        let row = client
            .query_one(
                "SELECT state,credential_generation,current_secret_id,pending_operation_id
                   FROM public.sdk_gateway_connections WHERE id=$1",
                &[&receipt.id()],
            )
            .await
            .map_err(|error| error.to_string())?;
        assert_eq!(row.get::<_, String>(0), "ready");
        assert_eq!(row.get::<_, i64>(1), 2);
        let new_secret: Uuid = row.get(2);
        assert_ne!(new_secret, old_secret);
        assert_eq!(row.get::<_, Option<Uuid>>(3), None);
        let old_retired: bool = client
            .query_one(
                "SELECT retired_at IS NOT NULL FROM public.sdk_gateway_secrets WHERE id=$1",
                &[&old_secret],
            )
            .await
            .map_err(|error| error.to_string())?
            .get(0);
        assert!(old_retired);
        let new_row = client
            .query_one(
                "SELECT encrypted_value,retired_at IS NULL FROM public.sdk_gateway_secrets
                  WHERE id=$1 AND credential_generation=2",
                &[&new_secret],
            )
            .await
            .map_err(|error| error.to_string())?;
        let encrypted: String = new_row.get(0);
        assert!(new_row.get::<_, bool>(1));
        let opened = fixture
            .vault
            .open(
                &new_secret,
                SecretKind::Model,
                SecretPrincipal::Actor(ActorId::new(ACTOR)),
                SecretPrincipal::Service(ServiceId::new(receipt.id().to_string())),
                &encrypted,
            )
            .unwrap();
        let stored: Value = serde_json::from_slice(opened.into_secret().expose()).unwrap();
        assert_eq!(stored["credentialGeneration"], 2);
        assert_eq!(stored["tokens"]["access_token"], "QA_ACCESS_2");
        assert_eq!(stored["tokens"]["refresh_token"], "QA_REFRESH_2");
        assert_eq!(stored["tokens"]["scope"], "ai account");
        assert_eq!(stored["tokens"]["client_id"], CLIENT_ID);
        assert_eq!(stored["tokens"]["server_url"], tls.endpoint());
        let audit: String = client
            .query_one(
                "SELECT string_agg(payload::text,' ' ORDER BY created_at)
                   FROM public.audit_events WHERE target_id=$1",
                &[&receipt.id().to_string()],
            )
            .await
            .map_err(|error| error.to_string())?
            .get(0);
        for event in [
            "gateway_rotation_begun",
            "gateway_rotation_send_admitted",
            "gateway_rotation_staged",
            "gateway_rotation_committed",
        ] {
            assert!(audit.contains(event), "missing audit fact {event}");
        }
        assert!(!audit.contains("QA_ACCESS"));
        assert!(!audit.contains("QA_REFRESH"));
        drop(client);
        assert!(
            outcomes_a
                .snapshots()
                .iter()
                .all(|item| item.permit_released())
        );
        assert!(
            outcomes_b
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
async fn sdk_logout_clears_locally_without_claiming_vendor_revocation() {
    let tls = TlsFixture::new(vec![
        json_plan(metadata_body()),
        json_plan(profile_body(ACCOUNT_ID, "")),
        json_plan(metadata_body()),
    ])
    .await;
    let admin = harness::admin_config("gateway_authority_clear");
    harness::with_temp_database(&admin, "sdkgwclear", |config| async move {
        let fixture = DatabaseFixture::new(config, &tls).await;
        let receipt = enroll(&fixture, &tls, &tokens(&tls.endpoint(), false, 1)).await;
        let sdk = operation_client(
            &fixture,
            &tls.endpoint(),
            receipt.id(),
            receipt.revision(),
            CancellationToken::new(),
            Arc::new(Outcomes::default()),
        )
        .await
        .unwrap();
        sdk.logout(None).await.unwrap();
        assert!(
            tls.captures
                .lock()
                .unwrap()
                .iter()
                .all(|capture| capture.path != "/oauth/desktop/revoke"),
            "local clear must not report or send a vendor revocation"
        );
        let client = fixture
            .pool
            .get()
            .await
            .map_err(|error| error.to_string())?;
        let row = client
            .query_one(
                "SELECT state,credential_generation,current_secret_id,pending_operation_id,revision
                   FROM public.sdk_gateway_connections WHERE id=$1",
                &[&receipt.id()],
            )
            .await
            .map_err(|error| error.to_string())?;
        assert_eq!(row.get::<_, String>(0), "missing");
        assert_eq!(row.get::<_, i64>(1), 2);
        assert_eq!(row.get::<_, Option<Uuid>>(2), None);
        assert_eq!(row.get::<_, Option<Uuid>>(3), None);
        assert_eq!(
            row.get::<_, i64>(4),
            1,
            "credential clear is not config edit"
        );
        let active: i64 = client
            .query_one(
                "SELECT count(*) FROM public.sdk_gateway_secrets
                  WHERE connection_id=$1 AND retired_at IS NULL",
                &[&receipt.id()],
            )
            .await
            .map_err(|error| error.to_string())?
            .get(0);
        assert_eq!(active, 0);
        drop(client);
        let requests_before = tls.count();
        let outcomes = Arc::new(Outcomes::default());
        let operation = fixture
            .accounts
            .operation(
                owner(),
                receipt.id(),
                1,
                CancellationToken::new(),
                Instant::now() + Duration::from_secs(10),
                outcomes.clone(),
            )
            .await
            .unwrap();
        let unauthenticated = Client::create_with_authority(
            sdk_config(&tls.endpoint()),
            operation.transport(),
            operation.authority(),
            None,
        )
        .await
        .expect("Missing constructs an explicitly unauthenticated SDK client");
        assert!(unauthenticated.token_set().is_none());
        let error = unauthenticated
            .ensure_token(None)
            .await
            .expect_err("Missing must refuse token use");
        assert!(error.to_string().contains("token_authority_missing"));
        assert_eq!(tls.count(), requests_before);
        assert!(
            outcomes.snapshots().is_empty(),
            "Missing authority must refuse before transport attempt"
        );
        fixture.pool.close();
        tls.stop().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17 and owned TLS; explicit include-ignored only"]
async fn people_generation_advance_makes_old_and_new_contexts_auth_required() {
    let tls = TlsFixture::new(vec![
        json_plan(metadata_body()),
        json_plan(profile_body(ACCOUNT_ID, "")),
    ])
    .await;
    let admin = harness::admin_config("gateway_authority_people_advance");
    harness::with_temp_database(&admin, "sdkgwpeople", |config| async move {
        let fixture = DatabaseFixture::new(config, &tls).await;
        let receipt = enroll(&fixture, &tls, &tokens(&tls.endpoint(), false, 1)).await;
        let people = PostgresPeopleAdministration::new(
            fixture.pool.clone(),
            None,
            b"people-gateway-audit-key-32-bytes".to_vec(),
        )
        .unwrap();
        people
            .change_role(&ActorId::new("bob"), &ActorId::new(ACTOR), Role::Admin)
            .await
            .unwrap();
        let client = fixture
            .pool
            .get()
            .await
            .map_err(|error| error.to_string())?;
        let row = client
            .query_one(
                "SELECT state,credential_generation,auth_generation,current_secret_id,
                        pending_operation_id
                   FROM public.sdk_gateway_connections WHERE id=$1",
                &[&receipt.id()],
            )
            .await
            .map_err(|error| error.to_string())?;
        assert_eq!(row.get::<_, String>(0), "auth_required");
        assert_eq!(row.get::<_, i64>(1), 2);
        assert_eq!(
            row.get::<_, i64>(2),
            7,
            "old binding remains for explicit reconfirm"
        );
        assert_eq!(row.get::<_, Option<Uuid>>(3), None);
        assert_eq!(row.get::<_, Option<Uuid>>(4), None);
        let active: i64 = client
            .query_one(
                "SELECT count(*) FROM public.sdk_gateway_secrets
                  WHERE connection_id=$1 AND retired_at IS NULL",
                &[&receipt.id()],
            )
            .await
            .map_err(|error| error.to_string())?
            .get(0);
        assert_eq!(active, 0);
        drop(client);

        assert_eq!(
            fixture
                .accounts
                .operation(
                    owner(),
                    receipt.id(),
                    1,
                    CancellationToken::new(),
                    Instant::now() + Duration::from_secs(10),
                    Arc::new(Outcomes::default()),
                )
                .await
                .expect_err("old auth generation must fail"),
            GatewayAuthorityError::NotVisible
        );
        assert_eq!(
            fixture
                .accounts
                .operation(
                    auth(ACTOR, 8, Role::Admin),
                    receipt.id(),
                    1,
                    CancellationToken::new(),
                    Instant::now() + Duration::from_secs(10),
                    Arc::new(Outcomes::default()),
                )
                .await
                .expect_err("new generation still requires explicit reconfirmation"),
            GatewayAuthorityError::Conflict
        );
        assert_eq!(tls.count(), 2);
        fixture.pool.close();
        tls.stop().await;
        Ok(())
    })
    .await;
}
