//! New endpoint-only committed faults and raw-wire identities through the actual PG provider.
use super::*;
use openbot_application::{ProviderMessage, ProviderMessageRole};

#[path = "../support/provider_target_fixture.rs"]
mod provider_target_fixture;
use provider_target_fixture::{Counts, OwnedWire, Reply};

fn certificate() -> [&'static str; 3] {
    [
        TEST_CA_DER_BASE64,
        TEST_LEAF_DER_BASE64,
        TEST_KEY_DER_BASE64,
    ]
}

fn protocols() -> [CustomModelProtocol; 3] {
    [
        CustomModelProtocol::OpenaiChatCompletions,
        CustomModelProtocol::OpenaiResponses,
        CustomModelProtocol::AnthropicMessages,
    ]
}

fn suffix(protocol: CustomModelProtocol) -> &'static str {
    match protocol {
        CustomModelProtocol::OpenaiChatCompletions => "/chat/completions",
        CustomModelProtocol::OpenaiResponses => "/responses",
        CustomModelProtocol::AnthropicMessages => "/messages",
    }
}

async fn observe(
    client: &deadpool_postgres::Client,
    connection: Uuid,
    run: &str,
) -> (Value, bool, i32) {
    let row = client
        .query_one(
            "SELECT jsonb_build_object(
            'connection',to_jsonb(c),'snapshot',to_jsonb(s),'user',to_jsonb(u),
            'run',to_jsonb(r),'lease',to_jsonb(l),'input',to_jsonb(m),'secret',to_jsonb(k),
            'audit_events',coalesce((SELECT jsonb_agg(to_jsonb(a) ORDER BY a.created_at,a.id)
                                    FROM public.audit_events a),'[]'::jsonb),
            'audit_checkpoints',coalesce((SELECT jsonb_agg(to_jsonb(p) ORDER BY p.sequence)
                                         FROM public.audit_checkpoints p),'[]'::jsonb)),
            r.status='running' AND l.expires_at>clock_timestamp(),pg_backend_pid()
         FROM public.model_connections c
         JOIN public.run_model_selections s ON s.connection_id=c.id AND s.run_id=$2
         JOIN public.users u ON u.id=s.owner_user_id
         JOIN public.runs r ON r.run_id=s.run_id
         JOIN public.thread_leases l ON l.thread_id=r.thread_id AND l.fencing_token=r.fencing_token
         JOIN public.messages m ON m.message_id=r.run_id||':input'
         JOIN public.model_connection_secrets k ON k.id=s.secret_id
         WHERE c.id=$1",
            &[&connection, &run],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1), row.get(2))
}

fn without_endpoint(mut value: Value, current: bool) -> Value {
    value[if current { "connection" } else { "snapshot" }]
        .as_object_mut()
        .unwrap()
        .remove("endpoint");
    value
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and owned TLS; root directed include-ignored only"]
async fn custom_current_and_snapshot_endpoint_only_commits_reject_before_dns() {
    let admin = harness::admin_config("custom_endpoint_only_commits");
    harness::with_temp_database(&admin, "customendpointonly", |config| async move {
        let fixture = Fixture::new(config).await;
        for (index, protocol) in protocols().into_iter().enumerate() {
            let wire = OwnedWire::new(vec![], certificate()).await;
            let base = format!("{}/owned-route/v1", wire.origin());
            let (model, begin, request) = fixture.begin(900 + index as u64, protocol, &base, false).await;
            let expected = format!("{}{}", base, suffix(protocol));
            let connection = Uuid::parse_str(&model.id).unwrap();
            let run = begin.command.run_id.as_str();
            let mut writer = fixture.pool.get().await.unwrap();
            // A different physical PG session observes the writer's COMMIT and provider effects.
            let observer = fixture.pool.get().await.unwrap();
            let writer_pid: i32 = writer.query_one("SELECT pg_backend_pid()", &[]).await.unwrap().get(0);
            let adapter = fixture.adapter(wire.dialer(), Duration::from_secs(3));
            let mut evidence = Vec::new();
            for current in [true, false] {
                for prefix in [true, false] {
                    let bad = if prefix {
                        expected.replace("/owned-route/", "/shadow-route/")
                    } else {
                        format!("{}/owned-route/v1/child{}", wire.origin(), suffix(protocol))
                    };
                    let canonical = openbot_application::model_connections::normalize_model_endpoint(protocol, &bad);
                    let before = observe(&observer, connection, run).await;
                    let tx = writer.transaction().await.unwrap();
                    let affected = if current {
                        tx.execute("UPDATE public.model_connections SET endpoint=$1 WHERE id=$2", &[&bad, &connection]).await.unwrap()
                    } else {
                        tx.execute("UPDATE public.run_model_selections SET endpoint=$1 WHERE run_id=$2", &[&bad, &run]).await.unwrap()
                    };
                    tx.commit().await.unwrap();
                    let committed = observe(&observer, connection, run).await;
                    let counts_before = wire.counts();
                    let outcome = match adapter.start(request.clone()).await {
                        Err(ProviderPortError::InvalidRequest { field }) => Some(field),
                        Err(_) => Some("different_error"),
                        Ok(session) => { drop(session); None },
                    };
                    let after_start = observe(&observer, connection, run).await;
                    let counts_after = wire.counts();
                    let tx = writer.transaction().await.unwrap();
                    if current {
                        tx.execute("UPDATE public.model_connections SET endpoint=$1 WHERE id=$2", &[&expected, &connection]).await.unwrap();
                    } else {
                        tx.execute("UPDATE public.run_model_selections SET endpoint=$1 WHERE run_id=$2", &[&expected, &run]).await.unwrap();
                    }
                    tx.commit().await.unwrap();
                    let restored = observe(&observer, connection, run).await;
                    evidence.push((current, prefix, bad, canonical, affected, before, committed, after_start, restored, counts_before, counts_after, outcome));
                }
            }
            drop(observer);
            drop(writer);
            let record = wire.finish().await;
            assert_eq!(record.joined, record.counts.tcp);
            assert_eq!(record.failed, 0);
            assert_eq!(record.counts, Counts { dns: 0, tcp: 0, http: 0 });
            assert!(record.requests.is_empty());
            assert_eq!(model.endpoint, expected, "independently selected canonical A");
            let ProviderRoute::CustomModel(binding) = &request.route else { panic!("actual PG context selected custom route"); };
            assert_eq!(binding.endpoint(), expected);
            assert_eq!(evidence.len(), 4);
            for (current, prefix, bad, canonical, affected, before, committed, after_start, restored, counts_before, counts_after, outcome) in evidence {
                assert_eq!(canonical.unwrap(), bad, "B is a valid existing protocol endpoint, no query relaxation");
                assert_eq!(affected, 1);
                assert_ne!(before.2, writer_pid, "observer uses independent physical PG session");
                assert_eq!(before.2, committed.2);
                assert!(before.1 && committed.1 && after_start.1 && restored.1, "lease still active; not an expiry false positive");
                assert!(!before.0["audit_events"].as_array().unwrap().is_empty(), "actual CRUD/context baseline has durable audit events");
                assert_eq!(before.0["connection"]["endpoint"], expected);
                assert_eq!(before.0["snapshot"]["endpoint"], expected);
                assert_eq!(committed.0[if current { "connection" } else { "snapshot" }]["endpoint"], bad);
                assert_eq!(without_endpoint(before.0.clone(), current), without_endpoint(committed.0.clone(), current), "only one committed endpoint changed: revision/model/protocol/secret/authgen, seven source rows and all owned-database audit events/checkpoints preserved");
                assert_eq!(after_start.0, committed.0, "rejected actual provider did not mutate observed source or audit rows");
                assert_eq!(restored.0, before.0, "exact fault restoration");
                // This field originates in the current-authority check before Vault open;
                // zero DNS/TCP/HTTP is separately observed, not inferred from the error alone.
                assert_eq!(outcome, Some("custom_model_authority"));
                assert_eq!(counts_before, Counts { dns: 0, tcp: 0, http: 0 });
                assert_eq!(counts_after, counts_before);
                println!("Custom protocol={protocol:?} current={current} prefix={prefix}: one-field COMMIT observed by separate PG session; authority refusal; DNS/TCP/HTTP delta0; tasks joined");
            }
        }
        fixture.pool.close();
        Ok(())
    }).await;
}

fn message(role: ProviderMessageRole, content: &str) -> ProviderMessage {
    ProviderMessage {
        role,
        content: content.to_owned(),
        tool_call_id: None,
        tool_name: None,
        tool_calls: vec![],
    }
}

fn expected_body(protocol: CustomModelProtocol) -> Vec<u8> {
    let system = "TARGET_IDENTITY_SYSTEM_CANARY";
    let user = "TARGET_IDENTITY_USER_CANARY";
    let body = match protocol {
        CustomModelProtocol::OpenaiChatCompletions => {
            json!({"model":"exact-chosen-model","messages":[{"role":"system","content":system},{"role":"user","content":user}],"stream":true,"stream_options":{"include_usage":true},"max_tokens":32})
        }
        CustomModelProtocol::OpenaiResponses => {
            json!({"model":"exact-chosen-model","input":[{"role":"system","content":system},{"role":"user","content":user}],"stream":true,"max_output_tokens":32})
        }
        CustomModelProtocol::AnthropicMessages => {
            json!({"model":"exact-chosen-model","system":system,"messages":[{"role":"user","content":[{"type":"text","text":user}]}],"stream":true,"max_tokens":32})
        }
    };
    serde_json::to_vec(&body).unwrap()
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and owned TLS; root directed include-ignored only"]
async fn custom_three_protocol_full_target_and_body_identity() {
    let admin = harness::admin_config("custom_full_target_body");
    harness::with_temp_database(&admin, "customtargetbody", |config| async move {
        let fixture = Fixture::new(config).await;
        for (index, protocol) in protocols().into_iter().enumerate() {
            let response = match protocol {
                CustomModelProtocol::OpenaiChatCompletions => chat_text(),
                CustomModelProtocol::OpenaiResponses => responses_text(),
                CustomModelProtocol::AnthropicMessages => anthropic_text(),
            };
            let wire = OwnedWire::new(vec![Reply { content_type: "text/event-stream", body: response }], certificate()).await;
            let origin = wire.origin();
            let base = format!("{origin}/owned-prefix/v1");
            let (model, begin, mut request) = fixture.begin(950 + index as u64, protocol, &base, false).await;
            let had_tools = !request.tools.is_empty();
            // The route is produced by actual PG context; only bounded business messages are
            // controlled so all three protocol bodies have an independent exact byte oracle.
            request.messages = vec![message(ProviderMessageRole::System, "TARGET_IDENTITY_SYSTEM_CANARY"), message(ProviderMessageRole::User, "TARGET_IDENTITY_USER_CANARY")];
            let observer = fixture.pool.get().await.unwrap();
            let before = observe(&observer, Uuid::parse_str(&model.id).unwrap(), begin.command.run_id.as_str()).await;
            let session = fixture.adapter(wire.dialer(), Duration::from_secs(3)).start(request).await;
            let output = match session { Ok(session) => Some(events(session).await), Err(_) => None };
            let after = observe(&observer, Uuid::parse_str(&model.id).unwrap(), begin.command.run_id.as_str()).await;
            drop(observer);
            let record = wire.finish().await;
            assert_eq!(record.joined, record.counts.tcp);
            assert_eq!(record.failed, 0);
            assert_eq!(record.counts, Counts { dns: 1, tcp: 1, http: 1 });
            assert!(!had_tools, "fixture grants no tools and this test creates none");
            assert!(before.1 && after.1);
            assert!(!before.0["audit_events"].as_array().unwrap().is_empty());
            assert_eq!(before.0, after.0, "provider sampling preserves seven source rows and all owned-database audit events/checkpoints");
            let expected_target = format!("/owned-prefix/v1{}", suffix(protocol));
            assert_eq!(model.endpoint, format!("{origin}{expected_target}"));
            let actual = &record.requests[0];
            assert_eq!(actual.method, "POST");
            assert_eq!(actual.target, expected_target, "independently selected full request target");
            assert_eq!(actual.headers["host"], origin.trim_start_matches("https://"));
            assert_eq!(actual.header_counts["host"], 1);
            assert_eq!(actual.headers["content-type"], "application/json");
            // Custom uses SafeMethod::PostJson; its fixed SafeDialer STREAM_ACCEPT
            // includes bounded JSON errors as well as SSE. SDK's closed gateway
            // EventStream framing has a separate, narrower header contract.
            assert_eq!(actual.headers["accept"], "text/event-stream, application/json");
            assert_eq!(actual.header_counts["accept"], 1);
            assert_eq!(actual.body, expected_body(protocol), "raw bytes, not Value.to_string from old capture");
            match protocol {
                CustomModelProtocol::AnthropicMessages => {
                    assert_eq!(actual.header_counts["x-api-key"], 1);
                    assert_eq!(actual.headers["x-api-key"], KEY);
                    assert_eq!(actual.headers["anthropic-version"], "2023-06-01");
                }
                _ => {
                    assert_eq!(actual.header_counts["authorization"], 1);
                    assert_eq!(actual.headers["authorization"], format!("Bearer {KEY}"));
                }
            }
            let output = output.expect("actual provider start succeeds");
            assert!(output.iter().any(|e| matches!(e, ProviderEvent::TextDelta { delta, .. } if delta == "hello custom")));
            assert_eq!(output.last(), Some(&ProviderEvent::Completed));
            println!("Custom protocol={protocol:?}: actual CRUD/context/Vault/provider/TLS; prefixed full target/method/raw body and independent PG rows; joined1");
        }
        fixture.pool.close();
        Ok(())
    }).await;
}
