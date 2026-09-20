use super::*;

async fn assert_pending_without_second_post(
    fixture: &DatabaseFixture,
    tls: &TlsFixture,
    id: Uuid,
    expected_requests: usize,
) -> Result<(), String> {
    let client = fixture
        .pool
        .get()
        .await
        .map_err(|error| error.to_string())?;
    let row = client
        .query_one(
            "SELECT state,pending_operation_id,current_secret_id,credential_generation
               FROM public.sdk_gateway_connections WHERE id=$1",
            &[&id],
        )
        .await
        .map_err(|error| error.to_string())?;
    assert_eq!(row.get::<_, String>(0), "rotation_pending");
    assert!(row.get::<_, Option<Uuid>>(1).is_some());
    assert!(row.get::<_, Option<Uuid>>(2).is_some());
    assert_eq!(row.get::<_, i64>(3), 1);
    drop(client);

    // A fresh operation owns a distinct AuthorityInner. Reaching RotationPending through its
    // advisory-lock-backed load proves that the prior physical session released the lock; a leaked
    // session would time out as Unavailable instead.
    let operation = fixture
        .accounts
        .operation(
            owner(),
            id,
            1,
            CancellationToken::new(),
            Instant::now() + Duration::from_secs(10),
            Arc::new(Outcomes::default()),
        )
        .await
        .unwrap();
    let error = Client::create_with_authority(
        sdk_config(&tls.endpoint()),
        operation.transport(),
        operation.authority(),
        None,
    )
    .await
    .err()
    .expect("a new SDK client must preserve durable pending");
    assert!(error.to_string().contains("rotation_pending"));
    assert_eq!(tls.count(), expected_requests);
    assert_eq!(
        tls.captures
            .lock()
            .unwrap()
            .iter()
            .filter(|capture| capture.path == "/oauth/desktop/token")
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17 and owned TLS; explicit include-ignored only"]
async fn cancelled_token_response_closes_exact_session_and_restart_keeps_pending_without_repost() {
    let token_gate = Arc::new(Semaphore::new(0));
    let mut blocked_token = json_plan(refresh_response(2));
    blocked_token.body_gate = Some(token_gate);
    let tls = TlsFixture::new(vec![
        json_plan(metadata_body()),
        json_plan(profile_body(ACCOUNT_ID, "")),
        json_plan(metadata_body()),
        blocked_token,
    ])
    .await;
    let admin = harness::admin_config("gateway_authority_cancel_pending");
    harness::with_temp_database(&admin, "sdkgwcancel", |config| async move {
        let fixture = DatabaseFixture::new(config, &tls).await;
        let receipt = enroll(&fixture, &tls, &tokens(&tls.endpoint(), true, 1)).await;
        let cancel = CancellationToken::new();
        let sdk = operation_client(
            &fixture,
            &tls.endpoint(),
            receipt.id(),
            receipt.revision(),
            cancel.clone(),
            Arc::new(Outcomes::default()),
        )
        .await
        .unwrap();
        let call_cancel = cancel.clone();
        let task = tokio::spawn(async move { sdk.list_models(Some(call_cancel), false).await });
        tls.wait_count(4).await;
        cancel.cancel();
        assert!(task.await.unwrap().is_err());
        tokio::time::timeout(Duration::from_secs(2), async {
            while tls.closed.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancellation must close the exact TLS session");
        assert_pending_without_second_post(&fixture, &tls, receipt.id(), 4).await?;

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let client = fixture
                .pool
                .get()
                .await
                .map_err(|error| error.to_string())?;
            let idle: i64 = client
                .query_one(
                    "SELECT count(*) FROM pg_stat_activity
                      WHERE datname=current_database() AND state LIKE 'idle in transaction%'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .get(0);
            drop(client);
            if idle == 0 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "cancelled authority session leaked"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        fixture.pool.close();
        tls.stop().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17 and owned TLS; explicit include-ignored only"]
async fn token_response_loss_keeps_pending_and_a_new_client_does_zero_network() {
    let mut lost_token = json_plan(refresh_response(2));
    lost_token.body_gate = Some(Arc::new(Semaphore::new(0)));
    let tls = TlsFixture::new(vec![
        json_plan(metadata_body()),
        json_plan(profile_body(ACCOUNT_ID, "")),
        json_plan(metadata_body()),
        lost_token,
    ])
    .await;
    let origin = tls.endpoint();
    let captures = tls.captures.clone();
    let admin = harness::admin_config("gateway_authority_response_loss");
    harness::with_temp_database(&admin, "sdkgwloss", |config| async move {
        let fixture = DatabaseFixture::new(config, &tls).await;
        let receipt = enroll(&fixture, &tls, &tokens(&origin, true, 1)).await;
        let sdk = operation_client(
            &fixture,
            &origin,
            receipt.id(),
            1,
            CancellationToken::new(),
            Arc::new(Outcomes::default()),
        )
        .await
        .unwrap();
        let task = tokio::spawn(async move { sdk.list_models(None, false).await });
        tls.wait_count(4).await;
        tls.stop().await;
        assert!(task.await.unwrap().is_err());

        let client = fixture
            .pool
            .get()
            .await
            .map_err(|error| error.to_string())?;
        let state: String = client
            .query_one(
                "SELECT state FROM public.sdk_gateway_connections WHERE id=$1",
                &[&receipt.id()],
            )
            .await
            .map_err(|error| error.to_string())?
            .get(0);
        assert_eq!(state, "rotation_pending");
        drop(client);
        let operation = fixture
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
            .unwrap();
        assert!(
            Client::create_with_authority(
                sdk_config(&origin),
                operation.transport(),
                operation.authority(),
                None,
            )
            .await
            .is_err()
        );
        assert_eq!(captures.lock().unwrap().len(), 4);
        assert_eq!(
            captures
                .lock()
                .unwrap()
                .iter()
                .filter(|capture| capture.path == "/oauth/desktop/token")
                .count(),
            1
        );
        fixture.pool.close();
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17 and owned TLS; explicit include-ignored only"]
async fn rotated_profile_subject_mismatch_preserves_pending_and_never_spends_refresh_again() {
    let tls = TlsFixture::new(vec![
        json_plan(metadata_body()),
        json_plan(profile_body(ACCOUNT_ID, "")),
        json_plan(metadata_body()),
        json_plan(refresh_response(2)),
        json_plan(metadata_body()),
        json_plan(profile_body("different-account", "")),
    ])
    .await;
    let admin = harness::admin_config("gateway_authority_subject_pending");
    harness::with_temp_database(&admin, "sdkgwsubject", |config| async move {
        let fixture = DatabaseFixture::new(config, &tls).await;
        let receipt = enroll(&fixture, &tls, &tokens(&tls.endpoint(), true, 1)).await;
        let sdk = operation_client(
            &fixture,
            &tls.endpoint(),
            receipt.id(),
            1,
            CancellationToken::new(),
            Arc::new(Outcomes::default()),
        )
        .await
        .unwrap();
        assert!(sdk.list_models(None, false).await.is_err());
        assert_pending_without_second_post(&fixture, &tls, receipt.id(), 6).await?;
        let client = fixture
            .pool
            .get()
            .await
            .map_err(|error| error.to_string())?;
        let staged: i64 = client
            .query_one(
                "SELECT count(*) FROM public.sdk_gateway_operations
                  WHERE connection_id=$1 AND state='staged'",
                &[&receipt.id()],
            )
            .await
            .map_err(|error| error.to_string())?
            .get(0);
        assert_eq!(staged, 0, "wrong subject must not stage a candidate secret");
        drop(client);
        fixture.pool.close();
        tls.stop().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17 and owned TLS; explicit include-ignored only"]
async fn audit_failure_rolls_back_enrollment_after_real_identity_reads() {
    let tls = TlsFixture::new(vec![
        json_plan(metadata_body()),
        json_plan(profile_body(ACCOUNT_ID, "")),
    ])
    .await;
    let admin = harness::admin_config("gateway_authority_audit_failure");
    harness::with_temp_database(&admin, "sdkgwauditfail", |config| async move {
        let fixture = DatabaseFixture::new(config, &tls).await;
        let client = fixture.pool.get().await.map_err(|error| error.to_string())?;
        client
            .batch_execute(
                "CREATE FUNCTION public.reject_gateway_audit() RETURNS trigger LANGUAGE plpgsql AS $$
                   BEGIN
                     RAISE EXCEPTION 'forced gateway audit failure';
                   END $$;
                 CREATE TRIGGER reject_gateway_audit BEFORE INSERT ON public.audit_events
                   FOR EACH ROW EXECUTE FUNCTION public.reject_gateway_audit();",
            )
            .await
            .map_err(|error| error.to_string())?;
        drop(client);
        let intent = fixture
            .accounts
            .prepare_enrollment(owner(), "Audit failure", CLIENT_ID)
            .unwrap();
        let error = fixture
            .accounts
            .enroll(
                &intent,
                &tokens(&tls.endpoint(), false, 1),
                CancellationToken::new(),
                Arc::new(Outcomes::default()),
            )
            .await
            .err()
            .expect("audit failure cannot produce enrollment success");
        assert!(matches!(
            error,
            GatewayAuthorityError::Unavailable
                | GatewayAuthorityError::CommitUnknown
                | GatewayAuthorityError::ReconciliationRequired
        ));
        assert_eq!(tls.count(), 2);
        let client = fixture.pool.get().await.map_err(|error| error.to_string())?;
        for table in ["sdk_gateway_connections", "sdk_gateway_secrets"] {
            let count: i64 = client
                .query_one(&format!("SELECT count(*) FROM public.{table}"), &[])
                .await
                .map_err(|error| error.to_string())?
                .get(0);
            assert_eq!(count, 0, "audit failure left rows in {table}");
        }
        drop(client);
        fixture.pool.close();
        tls.stop().await;
        Ok(())
    })
    .await;
}

async fn install_rotation_audit_failure(
    pool: &deadpool_postgres::Pool,
    audit_fact: &str,
) -> Result<(), String> {
    assert!(matches!(
        audit_fact,
        "gateway_rotation_staged" | "gateway_rotation_committed"
    ));
    let client = pool.get().await.map_err(|error| error.to_string())?;
    client
        .batch_execute(&format!(
            "CREATE FUNCTION public.reject_selected_gateway_audit() RETURNS trigger LANGUAGE plpgsql AS $$
               BEGIN
                 IF position('{audit_fact}' in NEW.payload::text)>0 THEN
                   RAISE EXCEPTION 'forced selected gateway audit failure';
                 END IF;
                 RETURN NEW;
               END $$;
             CREATE TRIGGER reject_selected_gateway_audit BEFORE INSERT ON public.audit_events
               FOR EACH ROW EXECUTE FUNCTION public.reject_selected_gateway_audit();"
        ))
        .await
        .map_err(|error| error.to_string())
}

async fn rotation_audit_failure_case(fail_fact: &'static str) {
    let tls = TlsFixture::new(vec![
        json_plan(metadata_body()),
        json_plan(profile_body(ACCOUNT_ID, "")),
        json_plan(metadata_body()),
        json_plan(refresh_response(2)),
        json_plan(metadata_body()),
        json_plan(profile_body(ACCOUNT_ID, "")),
    ])
    .await;
    let admin = harness::admin_config(fail_fact);
    harness::with_temp_database(&admin, fail_fact, |config| async move {
        let fixture = DatabaseFixture::new(config, &tls).await;
        let receipt = enroll(&fixture, &tls, &tokens(&tls.endpoint(), true, 1)).await;
        let client = fixture
            .pool
            .get()
            .await
            .map_err(|error| error.to_string())?;
        let old_secret: Uuid = client
            .query_one(
                "SELECT current_secret_id FROM public.sdk_gateway_connections WHERE id=$1",
                &[&receipt.id()],
            )
            .await
            .map_err(|error| error.to_string())?
            .get(0);
        drop(client);
        install_rotation_audit_failure(&fixture.pool, fail_fact).await?;

        let sdk = operation_client(
            &fixture,
            &tls.endpoint(),
            receipt.id(),
            1,
            CancellationToken::new(),
            Arc::new(Outcomes::default()),
        )
        .await
        .unwrap();
        assert!(sdk.list_models(None, false).await.is_err());
        assert_pending_without_second_post(&fixture, &tls, receipt.id(), 6).await?;

        let client = fixture
            .pool
            .get()
            .await
            .map_err(|error| error.to_string())?;
        let connection = client
            .query_one(
                "SELECT state,current_secret_id,pending_operation_id,credential_generation
                   FROM public.sdk_gateway_connections WHERE id=$1",
                &[&receipt.id()],
            )
            .await
            .map_err(|error| error.to_string())?;
        assert_eq!(connection.get::<_, String>(0), "rotation_pending");
        assert_eq!(connection.get::<_, Option<Uuid>>(1), Some(old_secret));
        let operation_id = connection
            .get::<_, Option<Uuid>>(2)
            .expect("pending operation retained");
        assert_eq!(connection.get::<_, i64>(3), 1);
        let operation = client
            .query_one(
                "SELECT state,candidate_secret_id,token_admitted_at IS NOT NULL
                   FROM public.sdk_gateway_operations WHERE id=$1",
                &[&operation_id],
            )
            .await
            .map_err(|error| error.to_string())?;
        assert!(
            operation.get::<_, bool>(2),
            "token admission must remain durable"
        );
        let candidate: Option<Uuid> = operation.get(1);
        let old_active: bool = client
            .query_one(
                "SELECT retired_at IS NULL FROM public.sdk_gateway_secrets WHERE id=$1",
                &[&old_secret],
            )
            .await
            .map_err(|error| error.to_string())?
            .get(0);
        assert!(
            old_active,
            "failed finalization cannot retire old current secret"
        );
        let generation_two: i64 = client
            .query_one(
                "SELECT count(*) FROM public.sdk_gateway_secrets
                  WHERE connection_id=$1 AND credential_generation=2",
                &[&receipt.id()],
            )
            .await
            .map_err(|error| error.to_string())?
            .get(0);
        if fail_fact == "gateway_rotation_staged" {
            assert_eq!(operation.get::<_, String>(0), "pending");
            assert_eq!(candidate, None);
            assert_eq!(
                generation_two, 0,
                "candidate insert must roll back with staged audit"
            );
        } else {
            assert_eq!(operation.get::<_, String>(0), "staged");
            assert!(
                candidate.is_some(),
                "staged candidate must remain for reconciliation"
            );
            assert_eq!(generation_two, 1);
        }
        drop(client);
        fixture.pool.close();
        tls.stop().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17 and owned TLS; explicit include-ignored only"]
async fn staged_audit_failure_rolls_back_candidate_and_restart_does_zero_repost() {
    rotation_audit_failure_case("gateway_rotation_staged").await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17 and owned TLS; explicit include-ignored only"]
async fn committed_audit_failure_preserves_staged_candidate_and_old_current() {
    rotation_audit_failure_case("gateway_rotation_committed").await;
}
