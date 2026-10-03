//! R426 closed wire and borrowed carrier tests. Synthetic guards below prove only
//! Contracts semantics; they are not PostgreSQL, native Local or host authority.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_contracts::request_binding::{
    HostRequestBindingError, HostRequestBindingGuard, HostRequestBindingKind,
    MAX_SERVER_SESSION_EPOCH_LOOKUP_BYTES, RequestBindingIssuer, RequestBindingOwnerLease,
    ServerSessionBindingIdentity,
};
use openbot_contracts::runtime_capabilities::{
    MAX_RUNTIME_CAPABILITY_REVISION_BYTES, ORDERED_RUNTIME_CAPABILITY_IDS,
    RUNTIME_CAPABILITY_COUNT, RUNTIME_CAPABILITY_SCHEMA_VERSION, RuntimeCapabilitiesResponse,
    RuntimeCapabilitiesWireError, RuntimeCapabilityEntry, RuntimeCapabilityHostMode as Host,
    RuntimeCapabilityId as Id, RuntimeCapabilityReasonCode as Reason,
    RuntimeCapabilityState as State,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use time::OffsetDateTime;

// Independent normative literals and classes, not generated from product getters.
const IDS: [(Id, &str); 13] = [
    (Id::Workspace, "workspace"),
    (Id::AgentTools, "agent_tools"),
    (Id::ModelCustomV1, "model_custom_v1"),
    (Id::ModelSelectionV2, "model_selection_v2"),
    (Id::ModelSdkGateway, "model_sdk_gateway"),
    (Id::ModelAccountBridge, "model_account_bridge"),
    (Id::BrowserControl, "browser_control"),
    (Id::NativeControl, "native_control"),
    (Id::PixelEgress, "pixel_egress"),
    (Id::LocalConfirmation, "local_confirmation"),
    (Id::BackupRestore, "backup_restore"),
    (Id::DynamicSso, "dynamic_sso"),
    (Id::DevicePairing, "device_pairing"),
];
const STATES: [(State, &str); 5] = [
    (State::Unsupported, "unsupported"),
    (State::Unconfigured, "unconfigured"),
    (State::PermissionRequired, "permission_required"),
    (State::Ready, "ready"),
    (State::Unavailable, "unavailable"),
];
const HOSTS: [(Host, &str); 4] = [
    (Host::DesktopLocal, "desktop_local"),
    (Host::DesktopRemote, "desktop_remote"),
    (Host::Server, "server"),
    (Host::MobileRemote, "mobile_remote"),
];
const REASONS: [(Reason, &str, State); 40] = [
    (
        Reason::CurrentChecksAvailable,
        "current_checks_available",
        State::Ready,
    ),
    (
        Reason::PlatformUnimplemented,
        "platform_unimplemented",
        State::Unsupported,
    ),
    (
        Reason::IndependentApiMissing,
        "independent_api_missing",
        State::Unsupported,
    ),
    (
        Reason::SupportUnproven,
        "support_unproven",
        State::Unavailable,
    ),
    (
        Reason::ReleaseDependencyMissing,
        "release_dependency_missing",
        State::Unavailable,
    ),
    (
        Reason::ReleaseDependencyUnproven,
        "release_dependency_unproven",
        State::Unavailable,
    ),
    (
        Reason::PolicyUnconfigured,
        "policy_unconfigured",
        State::Unconfigured,
    ),
    (Reason::PolicyEmpty, "policy_empty", State::Unconfigured),
    (Reason::PolicyInvalid, "policy_invalid", State::Unconfigured),
    (
        Reason::PolicyUnproven,
        "policy_unproven",
        State::Unavailable,
    ),
    (
        Reason::ModelKeyMissing,
        "model_key_missing",
        State::Unconfigured,
    ),
    (
        Reason::ModelKeyUnproven,
        "model_key_unproven",
        State::Unavailable,
    ),
    (
        Reason::ConfigurationMissing,
        "configuration_missing",
        State::Unconfigured,
    ),
    (
        Reason::ConfigurationInvalid,
        "configuration_invalid",
        State::Unconfigured,
    ),
    (
        Reason::ConfigurationUnproven,
        "configuration_unproven",
        State::Unavailable,
    ),
    (
        Reason::AccountBridgeSourceBlocked,
        "account_bridge_source_blocked",
        State::Unconfigured,
    ),
    (
        Reason::AccountBridgeSourceUnproven,
        "account_bridge_source_unproven",
        State::Unavailable,
    ),
    (
        Reason::ProductPermissionRequired,
        "product_permission_required",
        State::PermissionRequired,
    ),
    (
        Reason::ProductPermissionUnproven,
        "product_permission_unproven",
        State::Unavailable,
    ),
    (
        Reason::OsPermissionCaptureRequired,
        "os_permission_capture_required",
        State::PermissionRequired,
    ),
    (
        Reason::OsPermissionAccessibilityRequired,
        "os_permission_accessibility_required",
        State::PermissionRequired,
    ),
    (
        Reason::OsPermissionInputRequired,
        "os_permission_input_required",
        State::PermissionRequired,
    ),
    (
        Reason::OsPermissionUnproven,
        "os_permission_unproven",
        State::Unavailable,
    ),
    (
        Reason::OsPermissionExpired,
        "os_permission_expired",
        State::Unavailable,
    ),
    (
        Reason::LocalConfirmationRequired,
        "local_confirmation_required",
        State::PermissionRequired,
    ),
    (
        Reason::LocalConfirmationPending,
        "local_confirmation_pending",
        State::PermissionRequired,
    ),
    (
        Reason::LocalConfirmationUnavailable,
        "local_confirmation_unavailable",
        State::Unavailable,
    ),
    (
        Reason::LocalConfirmationUnproven,
        "local_confirmation_unproven",
        State::Unavailable,
    ),
    (
        Reason::LocalConfirmationExpired,
        "local_confirmation_expired",
        State::Unavailable,
    ),
    (
        Reason::PixelConsentRequired,
        "pixel_consent_required",
        State::PermissionRequired,
    ),
    (
        Reason::PixelConsentUnproven,
        "pixel_consent_unproven",
        State::Unavailable,
    ),
    (
        Reason::PixelConsentExpired,
        "pixel_consent_expired",
        State::Unavailable,
    ),
    (
        Reason::ComputerSourceMissing,
        "computer_source_missing",
        State::Unavailable,
    ),
    (
        Reason::NativeSourceMissing,
        "native_source_missing",
        State::Unavailable,
    ),
    (
        Reason::ScreenSourceMissing,
        "screen_source_missing",
        State::Unavailable,
    ),
    (
        Reason::SourceUnproven,
        "source_unproven",
        State::Unavailable,
    ),
    (Reason::SourceExpired, "source_expired", State::Unavailable),
    (
        Reason::ProviderDisconnected,
        "provider_disconnected",
        State::Unavailable,
    ),
    (
        Reason::ProviderUnproven,
        "provider_unproven",
        State::Unavailable,
    ),
    (
        Reason::ProviderExpired,
        "provider_expired",
        State::Unavailable,
    ),
];

fn entries(state: State, reason: Reason) -> [RuntimeCapabilityEntry; 13] {
    IDS.map(|(id, _)| RuntimeCapabilityEntry::try_new(id, state, reason).unwrap())
}
fn response() -> RuntimeCapabilitiesResponse {
    RuntimeCapabilitiesResponse::try_new(
        Host::Server,
        "r426.1".to_owned(),
        entries(State::Ready, Reason::CurrentChecksAvailable),
    )
    .unwrap()
}
fn wire() -> Value {
    serde_json::to_value(response()).unwrap()
}
fn rejects(value: Value) {
    assert!(serde_json::from_value::<RuntimeCapabilitiesResponse>(value).is_err());
}
fn closed_enum<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug + Copy>(
    values: &[(T, &str)],
) {
    let mut unique = HashSet::new();
    for &(variant, literal) in values {
        assert!(unique.insert(literal));
        assert_eq!(serde_json::to_value(variant).unwrap(), json!(literal));
        assert_eq!(
            serde_json::from_value::<T>(json!(literal)).unwrap(),
            variant
        );
        assert!(serde_json::from_value::<T>(json!(literal.to_uppercase())).is_err());
        assert!(serde_json::from_value::<T>(json!(format!("{literal} "))).is_err());
    }
    for malformed in [
        json!("future_value"),
        json!(""),
        json!(null),
        json!(0),
        json!({}),
        json!([]),
    ] {
        assert!(serde_json::from_value::<T>(malformed).is_err());
    }
}

#[test]
fn exact_thirteen_ids_five_states_four_modes_and_forty_reasons_are_closed() {
    assert_eq!(RUNTIME_CAPABILITY_SCHEMA_VERSION, 1);
    assert_eq!(RUNTIME_CAPABILITY_COUNT, 13);
    assert_eq!(MAX_RUNTIME_CAPABILITY_REVISION_BYTES, 64);
    assert_eq!(ORDERED_RUNTIME_CAPABILITY_IDS, IDS.map(|(id, _)| id));
    closed_enum(&IDS);
    closed_enum(&STATES);
    closed_enum(&HOSTS);
    closed_enum(&REASONS.map(|(reason, literal, _)| (reason, literal)));
    for (id, literal) in IDS {
        assert_eq!(id.as_str(), literal);
    }
    for (state, literal) in STATES {
        assert_eq!(state.as_str(), literal);
    }
    for (host, literal) in HOSTS {
        assert_eq!(host.as_str(), literal);
    }
    for (reason, literal, state) in REASONS {
        assert_eq!(reason.as_str(), literal);
        assert_eq!(reason.state(), state);
    }
}

#[test]
fn every_reason_has_one_legal_state_and_the_other_four_fail_closed() {
    for (reason, literal, legal_state) in REASONS {
        for (state, state_literal) in STATES {
            let actual = RuntimeCapabilityEntry::try_new(Id::Workspace, state, reason);
            let deserialized = serde_json::from_value::<RuntimeCapabilityEntry>(json!({
                "id":"workspace", "state":state_literal, "reasonCode":literal
            }));
            if state == legal_state {
                let entry = actual.unwrap();
                assert_eq!(entry.id(), Id::Workspace);
                assert_eq!(entry.state(), legal_state);
                assert_eq!(entry.reason_code(), reason);
                assert_eq!(deserialized.unwrap(), entry);
            } else {
                assert_eq!(actual, Err(RuntimeCapabilitiesWireError::StateReason));
                assert!(
                    deserialized.is_err(),
                    "illegal pair {state_literal}/{literal}"
                );
            }
        }
    }
}

#[test]
fn public_response_contains_only_four_fields_and_each_entry_only_three() {
    let value = wire();
    let mut keys: Vec<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["capabilities", "hostMode", "revision", "schemaVersion"]
    );
    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["hostMode"], "server");
    assert_eq!(value["revision"], "r426.1");
    for (entry, (_, literal)) in value["capabilities"].as_array().unwrap().iter().zip(IDS) {
        let mut keys: Vec<_> = entry
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["id", "reasonCode", "state"]);
        assert_eq!(entry["id"], literal);
    }
    let decoded: RuntimeCapabilitiesResponse = serde_json::from_value(value).unwrap();
    assert_eq!(decoded, response());
    assert_eq!(decoded.schema_version(), 1);
    assert_eq!(decoded.host_mode(), Host::Server);
    assert_eq!(decoded.revision(), "r426.1");
    assert_eq!(decoded.capabilities().len(), 13);
}

#[test]
fn response_unknown_missing_null_and_wrong_primitive_fields_are_rejected() {
    for field in [
        "actorId",
        "authGeneration",
        "window",
        "connectionId",
        "mode",
        "detail",
        "kind",
    ] {
        let mut value = wire();
        value[field] = json!("untrusted");
        rejects(value);
    }
    for field in ["schemaVersion", "hostMode", "revision", "capabilities"] {
        let mut value = wire();
        value.as_object_mut().unwrap().remove(field);
        rejects(value);
        let mut value = wire();
        value[field] = Value::Null;
        rejects(value);
    }
    for (field, invalid) in [
        ("schemaVersion", json!("1")),
        ("hostMode", json!(1)),
        ("revision", json!(64)),
        ("capabilities", json!({})),
    ] {
        let mut value = wire();
        value[field] = invalid;
        rejects(value);
    }
}

#[test]
fn entry_unknown_missing_duplicate_and_nonstring_fields_are_rejected() {
    for field in [
        "detail",
        "reason",
        "source",
        "actorId",
        "current",
        "supported",
        "reason_code",
    ] {
        let mut value = wire();
        value["capabilities"][0][field] = json!("untrusted");
        rejects(value);
    }
    for field in ["id", "state", "reasonCode"] {
        let mut value = wire();
        value["capabilities"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        rejects(value);
        for invalid in [Value::Null, json!(1), json!(true), json!([]), json!({})] {
            let mut value = wire();
            value["capabilities"][0][field] = invalid;
            rejects(value);
        }
    }
    let duplicate = r#"{"id":"workspace","id":"workspace","state":"ready","reasonCode":"current_checks_available"}"#;
    assert!(serde_json::from_str::<RuntimeCapabilityEntry>(duplicate).is_err());
    for field in ["state", "reasonCode"] {
        let entry = serde_json::to_string(&response().capabilities()[0]).unwrap();
        let literal = if field == "state" {
            "ready"
        } else {
            "current_checks_available"
        };
        let duplicated = entry.replacen('{', &format!("{{\"{field}\":\"{literal}\","), 1);
        assert!(serde_json::from_str::<RuntimeCapabilityEntry>(&duplicated).is_err());
    }
}

#[test]
fn duplicate_response_keys_fail_even_when_both_values_match() {
    let encoded = serde_json::to_string(&response()).unwrap();
    for fragment in [
        r#""schemaVersion":1,"#,
        r#""hostMode":"server","#,
        r#""revision":"r426.1","#,
    ] {
        let duplicate = encoded.replacen('{', &format!("{{{fragment}"), 1);
        assert!(serde_json::from_str::<RuntimeCapabilitiesResponse>(&duplicate).is_err());
    }
    let capabilities = serde_json::to_string(&response().capabilities()).unwrap();
    let duplicate = encoded.replacen('{', &format!("{{\"capabilities\":{capabilities},"), 1);
    assert!(serde_json::from_str::<RuntimeCapabilitiesResponse>(&duplicate).is_err());
}

#[test]
fn count_order_uniqueness_and_schema_are_checked_on_ingress_and_construction() {
    for count in [0, 1, 12, 14] {
        let mut value = wire();
        let list = value["capabilities"].as_array_mut().unwrap();
        while list.len() > count {
            list.pop();
        }
        while list.len() < count {
            list.push(
                json!({"id":"workspace","state":"ready","reasonCode":"current_checks_available"}),
            );
        }
        rejects(value);
    }
    for index in 1..13 {
        let mut value = wire();
        value["capabilities"].as_array_mut().unwrap().swap(0, index);
        rejects(value);
        let mut values = entries(State::Ready, Reason::CurrentChecksAvailable);
        values.swap(0, index);
        assert_eq!(
            RuntimeCapabilitiesResponse::try_new(Host::Server, "ok".into(), values),
            Err(RuntimeCapabilitiesWireError::Order)
        );
        let mut value = wire();
        value["capabilities"][index] = value["capabilities"][0].clone();
        rejects(value);
    }
    for schema in [
        json!(0),
        json!(2),
        json!(255),
        json!(256),
        json!(-1),
        json!(1.0),
    ] {
        let mut value = wire();
        value["schemaVersion"] = schema;
        rejects(value);
    }
}

#[test]
fn revision_accepts_exact_ascii_bounds_and_rejects_multibyte_controls_and_paths() {
    for revision in ["x".to_owned(), "AazZ09._-".into(), "A".repeat(64)] {
        let result = RuntimeCapabilitiesResponse::try_new(
            Host::Server,
            revision.clone(),
            entries(State::Ready, Reason::CurrentChecksAvailable),
        )
        .unwrap();
        assert_eq!(
            serde_json::from_value::<RuntimeCapabilitiesResponse>(
                serde_json::to_value(&result).unwrap()
            )
            .unwrap(),
            result
        );
    }
    for revision in [
        "".to_owned(),
        "A".repeat(65),
        "文".repeat(21),
        "é".into(),
        "a b".into(),
        "a\nb".into(),
        "a\0b".into(),
        "a/b".into(),
        "a\\b".into(),
        "a:b".into(),
        "a@b".into(),
        "a?b".into(),
    ] {
        assert_eq!(
            RuntimeCapabilitiesResponse::try_new(
                Host::Server,
                revision.clone(),
                entries(State::Ready, Reason::CurrentChecksAvailable)
            ),
            Err(RuntimeCapabilitiesWireError::Revision)
        );
        let mut value = wire();
        value["revision"] = json!(revision);
        rejects(value);
    }
}

#[test]
fn largest_legal_closed_compact_payload_stays_within_derived_1526_bytes() {
    let maximum = RuntimeCapabilitiesResponse::try_new(
        Host::DesktopRemote,
        "R".repeat(64),
        entries(
            State::PermissionRequired,
            Reason::OsPermissionAccessibilityRequired,
        ),
    )
    .unwrap();
    let encoded = serde_json::to_vec(&maximum).unwrap();
    assert_eq!(encoded.len(), 1526);
    assert_eq!(
        serde_json::from_slice::<RuntimeCapabilitiesResponse>(&encoded).unwrap(),
        maximum
    );
    for (reason, _, state) in REASONS {
        for (host, _) in HOSTS {
            let value =
                RuntimeCapabilitiesResponse::try_new(host, "R".repeat(64), entries(state, reason))
                    .unwrap();
            assert!(serde_json::to_vec(&value).unwrap().len() <= 1526);
        }
    }
}

#[test]
fn command_is_unit_input_and_internal_reply_retains_its_kind_envelope() {
    assert_eq!(
        serde_json::to_value(AppCommand::GetRuntimeCapabilities).unwrap(),
        json!({"kind":"get_runtime_capabilities"})
    );
    for field in [
        "actorId",
        "hostMode",
        "window",
        "connectionId",
        "input",
        "revision",
    ] {
        let mut value = json!({"kind":"get_runtime_capabilities"});
        value[field] = json!("untrusted");
        assert!(serde_json::from_value::<AppCommand>(value).is_err());
    }
    let reply = AppReply::RuntimeCapabilities(response());
    let mut expected = wire();
    expected["kind"] = json!("runtime_capabilities");
    assert_eq!(serde_json::to_value(&reply).unwrap(), expected);
    assert_eq!(serde_json::from_value::<AppReply>(expected).unwrap(), reply);
}

fn auth() -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new("synthetic-deployment"),
        TenantId::new("synthetic-tenant"),
        ActorId::new("synthetic-actor"),
        AuthGeneration::new(7),
        false,
    )
    .with_role(Role::User)
    .build()
}
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("synthetic guard unexpectedly awaited"),
    }
}
struct LegacyOnly(Arc<AtomicUsize>);
impl HostRequestBindingGuard for LegacyOnly {
    fn verify_current<'a>(
        &'a self,
        _: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
}
fn bound(issuer: &RequestBindingIssuer, id: &str, calls: Arc<AtomicUsize>) -> AuthContext {
    let unbound = auth();
    let key = ServerSessionBindingIdentity::from_verified_row(
        id.to_owned(),
        unbound.actor().clone(),
        "synthetic-private-hmac".to_owned(),
        OffsetDateTime::UNIX_EPOCH,
        unbound.auth_generation(),
    );
    let binding = issuer
        .bind_server_session(&unbound, key, Arc::new(LegacyOnly(calls)))
        .unwrap();
    unbound.with_verified_request_binding(binding).unwrap()
}

#[test]
fn deadline_default_is_unavailable_and_never_falls_back_to_legacy_guard() {
    let (_lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let calls = Arc::new(AtomicUsize::new(0));
    let auth = bound(&issuer, "legacy-row", Arc::clone(&calls));
    let binding = auth.request_binding().unwrap();
    assert_eq!(
        ready(binding.verify_current_before(&auth, Instant::now() + Duration::from_secs(5))),
        Err(HostRequestBindingError::Unavailable)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(ready(binding.verify_current(&auth)), Ok(()));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn expired_budget_never_calls_old_guard_and_does_not_change_metadata_semantics() {
    let (_lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let calls = Arc::new(AtomicUsize::new(0));
    let auth = bound(&issuer, "expired-row", Arc::clone(&calls));
    assert_eq!(
        ready(
            auth.request_binding()
                .unwrap()
                .verify_current_before(&auth, Instant::now())
        ),
        Err(HostRequestBindingError::Unavailable)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        ready(auth.request_binding().unwrap().verify_current(&auth)),
        Ok(())
    );
}

#[test]
fn borrowed_epoch_is_original_exact_tuple_and_not_current_authorization() {
    let (lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let auth = bound(&issuer, "private-row", Arc::new(AtomicUsize::new(0)));
    let identity = auth.request_binding().unwrap().identity();
    let epoch = issuer.borrow_server_session_epoch(identity).unwrap();
    assert_eq!(epoch.lookup_id(), "private-row");
    assert!(epoch.matches_raw_row(
        "private-row",
        "synthetic-actor",
        "synthetic-private-hmac",
        OffsetDateTime::UNIX_EPOCH,
        7
    ));
    for (id, user, token, created, issued) in [
        (
            "different",
            "synthetic-actor",
            "synthetic-private-hmac",
            OffsetDateTime::UNIX_EPOCH,
            7,
        ),
        (
            "private-row",
            "foreign",
            "synthetic-private-hmac",
            OffsetDateTime::UNIX_EPOCH,
            7,
        ),
        (
            "private-row",
            "synthetic-actor",
            "different",
            OffsetDateTime::UNIX_EPOCH,
            7,
        ),
        (
            "private-row",
            "synthetic-actor",
            "synthetic-private-hmac",
            OffsetDateTime::UNIX_EPOCH + time::Duration::nanoseconds(1),
            7,
        ),
        (
            "private-row",
            "synthetic-actor",
            "synthetic-private-hmac",
            OffsetDateTime::UNIX_EPOCH,
            8,
        ),
        (
            "private-row",
            "synthetic-actor",
            "synthetic-private-hmac",
            OffsetDateTime::UNIX_EPOCH,
            -1,
        ),
    ] {
        assert!(!epoch.matches_raw_row(id, user, token, created, issued));
    }
    lease.close();
    // A previously borrowed tuple still compares bytes; it must never imply permission.
    assert!(epoch.matches_raw_row(
        "private-row",
        "synthetic-actor",
        "synthetic-private-hmac",
        OffsetDateTime::UNIX_EPOCH,
        7
    ));
    assert!(matches!(
        issuer.borrow_server_session_epoch(identity),
        Err(HostRequestBindingError::NotCurrent)
    ));
}

#[test]
fn lookup_capacity_is_utf8_bytes_and_does_not_retroactively_reject_old_binding() {
    let (_lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    assert_eq!(MAX_SERVER_SESSION_EPOCH_LOOKUP_BYTES, 512);
    for id in [
        "x".to_owned(),
        "x".repeat(512),
        "é".repeat(256),
        "historical:non-uuid/row".into(),
    ] {
        let auth = bound(&issuer, &id, Arc::new(AtomicUsize::new(0)));
        assert_eq!(
            issuer
                .borrow_server_session_epoch(auth.request_binding().unwrap().identity())
                .unwrap()
                .lookup_id(),
            id
        );
    }
    for id in [
        "".to_owned(),
        "x".repeat(513),
        "é".repeat(257),
        "row\ncontrol".into(),
        "row\0control".into(),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let auth = bound(&issuer, &id, Arc::clone(&calls));
        assert!(matches!(
            issuer.borrow_server_session_epoch(auth.request_binding().unwrap().identity()),
            Err(HostRequestBindingError::Unavailable)
        ));
        assert_eq!(
            ready(auth.request_binding().unwrap().verify_current(&auth)),
            Ok(())
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn foreign_closed_and_wrong_kind_issuers_cannot_borrow_an_epoch() {
    let (_lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let auth = bound(&issuer, "original", Arc::new(AtomicUsize::new(0)));
    let (foreign_lease, foreign) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    assert!(matches!(
        foreign.borrow_server_session_epoch(auth.request_binding().unwrap().identity()),
        Err(HostRequestBindingError::NotCurrent)
    ));
    foreign_lease.close();
    let (_single_lease, single) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSingleUserOwner);
    let single_auth = AuthContextBuilder::from_verified_session(
        auth.deployment().clone(),
        auth.tenant().clone(),
        auth.actor().clone(),
        auth.auth_generation(),
        true,
    )
    .with_role(Role::User)
    .build();
    let single_binding = single
        .bind_single_user_owner(
            &single_auth,
            Arc::new(LegacyOnly(Arc::new(AtomicUsize::new(0)))),
        )
        .unwrap();
    assert!(matches!(
        single.borrow_server_session_epoch(single_binding.identity()),
        Err(HostRequestBindingError::Missing)
    ));
}

#[test]
fn window_epoch_matching_requires_original_owner_label_id_and_running_lease() {
    let (lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::DesktopWindow);
    let binding = issuer
        .bind_desktop_window(
            &auth(),
            "main".into(),
            1,
            Arc::new(LegacyOnly(Arc::new(AtomicUsize::new(0)))),
        )
        .unwrap();
    assert!(issuer.matches_desktop_window_epoch(binding.identity(), "main", 1));
    assert!(!issuer.matches_desktop_window_epoch(binding.identity(), "other", 1));
    assert!(!issuer.matches_desktop_window_epoch(binding.identity(), "main", 2));
    let (_other_lease, other) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::DesktopWindow);
    let other_binding = other
        .bind_desktop_window(
            &auth(),
            "main".into(),
            1,
            Arc::new(LegacyOnly(Arc::new(AtomicUsize::new(0)))),
        )
        .unwrap();
    assert!(!issuer.matches_desktop_window_epoch(other_binding.identity(), "main", 1));
    lease.close();
    assert!(!issuer.matches_desktop_window_epoch(binding.identity(), "main", 1));
}
