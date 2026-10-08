//! Pure DTO/key tests; synthetic allocation/cancel ports do not prove Host or database authority.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::auth::{AuthContext, AuthGeneration, Role};
use crate::ids::{ActorId, DeploymentId, TenantId};
use crate::request_binding::{
    CustomModelCatalogHostObservation, CustomModelCatalogHostTailFactory,
    CustomModelCatalogHostTailWitness, CustomModelCatalogHostTarget,
    CustomModelCatalogSessionFacts, HostRequestBindingError, HostRequestBindingGuard,
    HostRequestBindingKind, RequestBindingOwnerLease,
};

use super::*;

fn entry(index: usize) -> CustomModelCatalogEntry {
    let id = format!("00000000-0000-0000-0000-{index:012x}");
    CustomModelCatalogEntry {
        source: ModelConnectionSource::Custom,
        model_id: format!("custom:{id}"),
        connection_id: id,
        connection_revision: 3,
        catalog_revision: 11,
        name: "Private model".into(),
        protocol: CustomModelProtocol::OpenaiResponses,
        model: "provider-model".into(),
        enabled: false,
    }
}

fn page(count: usize) -> CustomModelCatalogPage {
    CustomModelCatalogPage {
        models: (0..count).map(entry).collect(),
        next_cursor: None,
    }
}

#[test]
fn custom_catalog_dto_exposes_only_nine_entry_and_two_page_keys() {
    let value = serde_json::to_value(page(1)).unwrap();
    let object = value.as_object().unwrap();
    assert_eq!(object.len(), 2);
    assert!(object.contains_key("models"));
    assert_eq!(object["nextCursor"], serde_json::Value::Null);
    let row = object["models"][0].as_object().unwrap();
    let mut keys: Vec<_> = row.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "catalogRevision",
            "connectionId",
            "connectionRevision",
            "enabled",
            "model",
            "modelId",
            "name",
            "protocol",
            "source",
        ]
    );
    assert_eq!(row["source"], "custom");
    assert_eq!(row["enabled"], false);
    assert_eq!(row["connectionRevision"], 3);
    assert_eq!(row["catalogRevision"], 11);
}

#[test]
fn custom_catalog_rejects_noncanonical_uuid_and_keeps_revisions_independent() {
    let original = entry(10);
    assert!(original.is_valid());
    for id in [
        original.connection_id.to_uppercase(),
        format!("{} ", original.connection_id),
        "00000000000000000000000000000000000a".into(),
    ] {
        let mut bad = original.clone();
        bad.connection_id = id;
        bad.model_id = format!("custom:{}", bad.connection_id);
        assert!(!bad.is_valid());
        assert!(
            serde_json::from_value::<CustomModelCatalogEntry>(serde_json::to_value(bad).unwrap())
                .is_err()
        );
    }
    for (connection, catalog) in [(0, 1), (1, 0), (-1, 9), (8, -2)] {
        let mut bad = original.clone();
        bad.connection_revision = connection;
        bad.catalog_revision = catalog;
        assert!(!bad.is_valid());
    }
    let mut maximal = original;
    maximal.connection_revision = i64::MAX;
    maximal.catalog_revision = 1;
    assert!(maximal.is_valid());
    maximal.model_id.push('x');
    assert!(!maximal.is_valid());
}

#[test]
fn custom_catalog_checks_utf8_bytes_trim_controls_and_closed_protocol() {
    let original = entry(1);
    for name in [
        "".into(),
        " leading".into(),
        "trailing ".into(),
        "a\u{7f}".into(),
        "界".repeat(34),
    ] {
        let mut bad = original.clone();
        bad.name = name;
        assert!(!bad.is_valid());
    }
    let mut valid = original.clone();
    valid.name = "界".repeat(33);
    valid.model = "m".repeat(512);
    assert!(valid.is_valid());
    valid.model = "界".repeat(171);
    assert!(!valid.is_valid());
    for (key, value) in [("protocol", "unsupported"), ("source", "gateway")] {
        let mut wire = serde_json::to_value(&original).unwrap();
        wire[key] = value.into();
        assert!(serde_json::from_value::<CustomModelCatalogEntry>(wire).is_err());
    }
}

#[test]
fn custom_catalog_page_checks_100_order_unique_and_last_cursor() {
    assert!(page(0).is_valid());
    assert!(page(100).is_valid());
    assert!(!page(101).is_valid());
    let mut full = page(100);
    full.next_cursor = Some(full.models[99].connection_id.clone());
    assert!(full.is_valid());
    full.next_cursor = Some(full.models[98].connection_id.clone());
    assert!(!full.is_valid());
    let mut short = page(1);
    short.next_cursor = Some(short.models[0].connection_id.clone());
    assert!(!short.is_valid());
    let mut duplicate = page(2);
    duplicate.models[1] = duplicate.models[0].clone();
    assert!(!duplicate.is_valid());
    let mut reversed = page(2);
    reversed.models.reverse();
    assert!(!reversed.is_valid());
}

#[test]
fn custom_catalog_deserialize_rejects_unknown_proof_and_bad_cursor_fields() {
    for wire in [
        serde_json::json!({"models": []}),
        serde_json::json!({"models": [], "nextCursor": false}),
        serde_json::json!({"models": [], "nextCursor": {"proof":"forged"}}),
    ] {
        assert!(serde_json::from_value::<CustomModelCatalogReply>(wire).is_err());
    }
    for extra in ["proof", "endpoint", "owner", "ready", "key"] {
        let mut wire = serde_json::to_value(page(1)).unwrap();
        wire[extra] = "forged".into();
        assert!(serde_json::from_value::<CustomModelCatalogReply>(wire).is_err());
        let mut row = serde_json::to_value(entry(1)).unwrap();
        row[extra] = "forged".into();
        assert!(serde_json::from_value::<CustomModelCatalogEntry>(row).is_err());
    }
    for cursor in ["", "CURSOR", "00000000-0000-0000-0000-00000000000A"] {
        assert!(
            serde_json::from_value::<CustomModelCatalogPageRequest>(
                serde_json::json!({"cursor":cursor})
            )
            .is_err()
        );
    }
    assert!(
        serde_json::from_value::<CustomModelCatalogPageRequest>(
            serde_json::json!({"cursor":null,"owner":"another"})
        )
        .is_err()
    );
    assert!(CustomModelCatalogPageRequest { cursor: None }.is_valid());
    assert!(
        CustomModelCatalogPageRequest {
            cursor: Some(entry(1).connection_id)
        }
        .is_valid()
    );
}

struct Allocation(CustomModelCatalogPage);

impl CustomModelCatalogReplyAllocation for Allocation {
    fn page(&self) -> &CustomModelCatalogPage {
        &self.0
    }
}

struct Cancel(Arc<AtomicUsize>);

impl CustomModelCatalogReplyCancel for Cancel {
    fn cancel(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn custom_catalog_pair_identity_rejects_fresh_pair_on_same_allocation() {
    let allocation = Arc::new(Allocation(page(1)));
    let calls = Arc::new(AtomicUsize::new(0));
    let (first, registration) = CustomModelCatalogReply::issue_for_delivery(
        allocation.clone(),
        Box::new(Cancel(calls.clone())),
    );
    let (second, other) =
        CustomModelCatalogReply::issue_for_delivery(allocation, Box::new(Cancel(calls.clone())));
    assert!(registration.matches_reply(&first));
    assert!(!registration.matches_reply(&second));
    assert!(!other.matches_reply(&first));
    assert_ne!(first, second);
    drop(registration);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    drop(first);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    drop(second);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn custom_catalog_serde_roundtrip_has_no_key_and_no_cancel_authority() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (reply, registration) = CustomModelCatalogReply::issue_for_delivery(
        Arc::new(Allocation(page(1))),
        Box::new(Cancel(calls.clone())),
    );
    let wire = serde_json::to_value(&reply).unwrap();
    assert_eq!(wire, serde_json::to_value(page(1)).unwrap());
    let rebuilt: CustomModelCatalogReply = serde_json::from_value(wire).unwrap();
    assert_eq!(rebuilt.page(), reply.page());
    assert_ne!(rebuilt, reply);
    assert!(!registration.matches_reply(&rebuilt));
    assert_eq!(format!("{reply:?}"), "CustomModelCatalogReply(<redacted>)");
    drop(rebuilt);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(registration.matches_reply(&reply));
    drop(reply);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

struct Guard;

impl HostRequestBindingGuard for Guard {
    fn verify_current<'a>(
        &'a self,
        _auth: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

struct Target;

impl CustomModelCatalogHostTarget for Target {
    fn matches_authority(&self, _authority: &Arc<()>) -> bool {
        true
    }
    fn matches_auth(&self, _auth: &AuthContext) -> bool {
        true
    }
}

struct Tail;

impl CustomModelCatalogHostTailWitness for Tail {
    fn verify_current(
        &self,
        _auth: &AuthContext,
        _deadline: Instant,
    ) -> Result<(), HostRequestBindingError> {
        Ok(())
    }
}

struct Factory(Arc<AtomicUsize>);

impl CustomModelCatalogHostTailFactory for Factory {
    fn witness(
        &self,
        _auth: &AuthContext,
        _session: Option<CustomModelCatalogSessionFacts>,
        _deadline: Instant,
    ) -> Result<Box<dyn CustomModelCatalogHostTailWitness>, HostRequestBindingError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Tail))
    }
}

#[test]
fn custom_catalog_host_default_is_closed_and_observation_keeps_original_kind() {
    let auth = AuthContext::for_test(
        DeploymentId::new("deployment"),
        TenantId::new("tenant"),
        ActorId::new("actor"),
        [Role::User],
        AuthGeneration::new(1),
        true,
    );
    let (_lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSingleUserOwner);
    let auth = auth
        .clone()
        .with_verified_request_binding(
            issuer
                .bind_single_user_owner(&auth, Arc::new(Guard))
                .unwrap(),
        )
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let binding = auth.request_binding().unwrap();
    assert!(matches!(
        binding.borrow_custom_model_catalog_host_before(&auth, &Target, deadline),
        Err(HostRequestBindingError::Unavailable)
    ));
    let calls = Arc::new(AtomicUsize::new(0));
    assert!(matches!(
        CustomModelCatalogHostObservation::from_trusted_host(
            HostRequestBindingKind::DesktopWindow,
            binding.identity().clone(),
            None,
            Box::new(Factory(calls.clone()))
        ),
        Err(HostRequestBindingError::NotCurrent)
    ));
    let observation = CustomModelCatalogHostObservation::from_trusted_host(
        HostRequestBindingKind::ServerSingleUserOwner,
        binding.identity().clone(),
        None,
        Box::new(Factory(calls.clone())),
    )
    .unwrap();
    let now = time::OffsetDateTime::now_utc();
    assert!(matches!(
        observation.witness(
            &auth,
            Some(CustomModelCatalogSessionFacts {
                created_at: now,
                updated_at: now,
                expires_at: now,
                observed_wall: now,
                observed_monotonic: Instant::now(),
            }),
            deadline,
        ),
        Err(HostRequestBindingError::NotCurrent)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let (kind, identity, epoch, factory) = observation.into_parts();
    assert_eq!(kind, HostRequestBindingKind::ServerSingleUserOwner);
    assert!(identity.same_binding(binding.identity()));
    assert!(epoch.is_none());
    factory.witness(&auth, None, deadline).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
