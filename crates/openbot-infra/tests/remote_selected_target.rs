//! Delivered Remote target/body composition evidence with real provider, transport, and TCP.
//! Runtime authority/context/coordinator/journal ports below are controlled fixtures, not PG.

#![cfg(feature = "server-runtime")]

#[path = "support/remote_selected_target_fixture.rs"]
mod fixture;

use std::sync::Arc;
use std::time::Duration;

use fixture::*;
use openbot_agent::RemoteAguiProvider;
use openbot_application::{
    ProviderAdapter, ProviderEvent, ProviderRoute, RunFailureCode, RunSemanticChannel, RunTerminal,
};

#[tokio::test]
async fn actual_remote_provider_preserves_prefixed_target_and_typed_resume_body() {
    let server = OwnedServer::start(false).await;
    let port = server.address.port();
    let endpoint = server.endpoint(A_TARGET);
    let resolver = Arc::new(OwnedResolver::default());
    let transport = Arc::new(ForwardingTransport::new(resolver.clone()));
    let provider = RemoteAguiProvider::new(transport.clone());
    let mut input = request(&endpoint);
    let ProviderRoute::RemoteAgUi(route) = input.route else {
        unreachable!("fixture route")
    };
    input.route = ProviderRoute::RemoteAgUi(route.with_resume(resume()).expect("typed lineage"));
    let result = tokio::time::timeout(Duration::from_secs(4), async {
        let mut session = provider.start(input).await?;
        let mut events = Vec::new();
        while let Some(event) = session.next_event().await? {
            events.push(event);
        }
        Ok::<_, openbot_application::ProviderPortError>(events)
    })
    .await;
    let wire = server.state.requests.lock().expect("wire lock").clone();
    let tcp = server.state.tcp.load(std::sync::atomic::Ordering::SeqCst);
    let stopped = server.stop().await;
    // All actors are joined before the assertions, including unexpected provider failures.
    assert!(stopped.is_ok(), "owned listener joined: {stopped:?}");
    let events = result
        .expect("finite provider session")
        .expect("real Remote provider");
    assert!(events.iter().any(
        |event| matches!(event, ProviderEvent::ResponseStarted { response_id }
        if response_id == &format!("remote-agui:{RESUMED_RUN}"))
    ));
    assert!(events.iter().any(
        |event| matches!(event, ProviderEvent::TextDelta { delta, .. }
        if delta == "resumed answer")
    ));
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, ProviderEvent::Completed))
            .count(),
        1
    );
    assert!(!events.iter().any(|event| matches!(
        event,
        ProviderEvent::Failed(_) | ProviderEvent::Interrupted(_)
    )));
    assert_eq!(tcp, 1);
    assert_eq!(wire.len(), 1);
    let observations = transport.observations.lock().expect("transport lock");
    assert_eq!(observations.len(), 1);
    assert_wire(&wire[0], &observations[0], &endpoint, port, true);
    assert_eq!(
        *resolver.calls.lock().expect("resolver lock"),
        vec![("remote.test".to_owned(), port)]
    );
    println!(
        "remote selected direct: actual provider/SafeDialer/TCP=1, exact prefix/query/body and typed resume; owned listener joined=true; PostgreSQL=false"
    );
}

#[tokio::test]
async fn actual_runtime_same_target_resume_sends_new_protocol_lineage_on_real_wire() {
    let evidence = runtime_evidence(false).await;
    assert_baseline(&evidence);
    assert_eq!(
        evidence.after,
        EffectCounts {
            provider: 2,
            transport: 2,
            resolver: 2,
            tcp: 2,
            http: 2,
            b_http: 0
        }
    );
    assert_eq!(evidence.endpoint_a, evidence.endpoint_b);
    assert_eq!(evidence.wire.len(), 2);
    assert_eq!(evidence.transport.len(), 2);
    assert_eq!(evidence.starts.len(), 2);
    assert_wire(
        &evidence.wire[1],
        &evidence.transport[1],
        &evidence.endpoint_a,
        evidence.port,
        true,
    );
    assert_eq!(
        evidence.starts[1],
        RouteObservation {
            endpoint: evidence.endpoint_a.clone(),
            thread: THREAD.to_owned(),
            local_run: LOCAL_RUN.to_owned(),
            protocol_run: RESUMED_RUN.to_owned(),
            bot: BOT.to_owned(),
            parent: Some(LOCAL_RUN.to_owned())
        }
    );
    assert_eq!(
        evidence.dns,
        vec![("remote.test".to_owned(), evidence.port); 2]
    );
    assert_eq!(
        evidence.runtime,
        vec![
            RuntimeCall::Chunk(1, RunSemanticChannel::Text, "resumed answer".to_owned()),
            RuntimeCall::Finish(2, RunTerminal::Completed)
        ]
    );
    println!(
        "remote runtime same A: first actual interrupt A=1; after release provider/transport/DNS/TCP/HTTP=2; exact new protocol/parent/resume; actual Runtime Completed; owned listener joined=true; synthetic authority/journal/coordinator, PostgreSQL=false"
    );
}

#[tokio::test]
async fn actual_runtime_endpoint_only_resume_drift_is_rejected_before_second_effect() {
    let evidence = runtime_evidence(true).await;
    assert_baseline(&evidence);
    assert_ne!(evidence.endpoint_a, evidence.endpoint_b);
    assert_eq!(
        evidence.after, evidence.before,
        "second provider/DNS/TCP/HTTP effect delta must be zero"
    );
    assert_eq!(evidence.wire.len(), 1);
    assert_eq!(evidence.transport.len(), 1);
    assert_eq!(evidence.starts.len(), 1);
    assert_eq!(
        evidence.dns,
        vec![("remote.test".to_owned(), evidence.port)]
    );
    assert_eq!(
        evidence.runtime,
        vec![RuntimeCall::Finish(
            1,
            RunTerminal::Failed(RunFailureCode::ProviderInvalidResponse)
        )]
    );
    println!(
        "remote runtime endpoint-only A -> same-origin prefixed B: first actual interrupt A=1; after release provider/transport/DNS/TCP/HTTP delta=0, B HTTP=0; actual Runtime Failed ProviderInvalidResponse; owned listener joined=true; synthetic authority/journal/coordinator, PostgreSQL=false"
    );
}
