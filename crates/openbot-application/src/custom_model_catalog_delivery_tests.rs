//! Pure Core ownership tests with synthetic Inventory/Host/tail ports, not PG/Server/Local proof.

use std::future::{Future, pending};
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use async_trait::async_trait;
use openbot_contracts::auth::{AuthGeneration, Role};
use openbot_contracts::command::AppCommand;
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_contracts::request_binding::{
    HostRequestBindingError, HostRequestBindingGuard, HostRequestBindingKind,
    RequestBindingOwnerLease, RequestBindingOwnerObservation,
};

use crate::custom_model_catalog::{CurrentCustomModelCatalogPage, NoCustomModelCatalogInventory};
use crate::{ApplicationService, OpenBotApplication};

use super::*;

struct Guard;

impl HostRequestBindingGuard for Guard {
    fn verify_current<'a>(
        &'a self,
        _auth: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

struct Host {
    auth: AuthContext,
    lease: RequestBindingOwnerLease,
    owner: RequestBindingOwnerObservation,
}

fn host() -> Host {
    let auth = unbound_auth();
    let (lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSingleUserOwner);
    let owner = issuer.observation();
    let binding = issuer
        .bind_single_user_owner(&auth, Arc::new(Guard))
        .unwrap();
    Host {
        auth: auth.with_verified_request_binding(binding).unwrap(),
        lease,
        owner,
    }
}

fn unbound_auth() -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new("deployment"),
        TenantId::new("tenant"),
        ActorId::new("actor"),
        [Role::User],
        AuthGeneration::new(7),
        true,
    )
}

fn request() -> CustomModelCatalogPageRequest {
    CustomModelCatalogPageRequest { cursor: None }
}

fn empty_page() -> CustomModelCatalogPage {
    CustomModelCatalogPage {
        models: Vec::new(),
        next_cursor: None,
    }
}

struct Inventory {
    owner: RequestBindingOwnerObservation,
    calls: AtomicUsize,
    current: Arc<AtomicBool>,
    deadline: Mutex<Option<Instant>>,
    return_auth: Option<AuthContext>,
    extend_deadline: bool,
    drop_observer: Option<(Weak<RegistryInner>, Arc<AtomicUsize>)>,
}

impl Inventory {
    fn new(host: &Host) -> Self {
        Self {
            owner: host.owner.clone(),
            calls: AtomicUsize::new(0),
            current: Arc::new(AtomicBool::new(true)),
            deadline: Mutex::new(None),
            return_auth: None,
            extend_deadline: false,
            drop_observer: None,
        }
    }
}

struct Tail {
    owner: RequestBindingOwnerObservation,
    expected: AuthContext,
    deadline: Instant,
    current: Arc<AtomicBool>,
    drop_observer: Option<(Weak<RegistryInner>, Arc<AtomicUsize>)>,
}

impl CustomModelCatalogHostTailWitness for Tail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: Instant,
    ) -> Result<(), HostRequestBindingError> {
        if !self.owner.is_current()
            || !self.current.load(Ordering::SeqCst)
            || !same_original_auth(&self.expected, auth)
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        if deadline != self.deadline || Instant::now() >= deadline {
            return Err(HostRequestBindingError::Unavailable);
        }
        Ok(())
    }
}

impl Drop for Tail {
    fn drop(&mut self) {
        let Some((registry, locked_drops)) = &self.drop_observer else {
            return;
        };
        let Some(registry) = registry.upgrade() else {
            return;
        };
        if registry.pending.try_lock().is_err() {
            locked_drops.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[async_trait]
impl CustomModelCatalogInventory for Inventory {
    async fn list_current(
        &self,
        auth: &AuthContext,
        _request: &CustomModelCatalogPageRequest,
        deadline: Instant,
    ) -> Result<CurrentCustomModelCatalogPage, CustomModelCatalogError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.deadline.lock().unwrap() = Some(deadline);
        let original = self.return_auth.as_ref().unwrap_or(auth).clone();
        let observed_deadline = if self.extend_deadline {
            deadline + Duration::from_secs(1)
        } else {
            deadline
        };
        CurrentCustomModelCatalogPage::from_rollback_acknowledged_observation(
            empty_page(),
            original.clone(),
            observed_deadline,
            Box::new(Tail {
                owner: self.owner.clone(),
                expected: original,
                deadline: observed_deadline,
                current: self.current.clone(),
                drop_observer: self.drop_observer.clone(),
            }),
        )
    }
}

async fn issue(
    registry: &CustomModelCatalogRegistry,
    inventory: &dyn CustomModelCatalogInventory,
    auth: &AuthContext,
) -> AppReply {
    AppReply::CustomModelCatalog(
        registry
            .list_current(inventory, auth, request())
            .await
            .unwrap(),
    )
}

fn charged(registry: &CustomModelCatalogRegistry) -> usize {
    registry.inner.admission.global.load(Ordering::SeqCst)
}

fn assert_busy<T: fmt::Debug>(result: Result<T, AppError>) {
    assert!(matches!(
        result,
        Err(AppError::RequestConflict {
            resource: "custom_model_catalog"
        })
    ));
}

#[tokio::test]
async fn custom_catalog_default_closed_and_invalid_typed_input_never_calls_port() {
    let host = host();
    let registry = CustomModelCatalogRegistry::new();
    let inventory = Inventory::new(&host);
    assert!(matches!(
        registry
            .list_current(&inventory, &unbound_auth(), request())
            .await,
        Err(AppError::NotVisible)
    ));
    assert!(matches!(
        registry
            .list_current(
                &inventory,
                &host.auth,
                CustomModelCatalogPageRequest {
                    cursor: Some("%2f".into())
                }
            )
            .await,
        Err(AppError::MalformedPayload { field: "cursor" })
    ));
    assert_eq!(inventory.calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        registry
            .list_current(&NoCustomModelCatalogInventory, &host.auth, request())
            .await,
        Err(AppError::DependencyUnavailable {
            dependency: "custom_model_catalog"
        })
    ));
    assert_eq!(charged(&registry), 0);
}

#[tokio::test]
async fn custom_catalog_identical_pending_pages_and_serde_cannot_cross_consume() {
    let host = host();
    let inventory = Inventory::new(&host);
    let registry = CustomModelCatalogRegistry::new();
    let (first, second) = tokio::join!(
        issue(&registry, &inventory, &host.auth),
        issue(&registry, &inventory, &host.auth)
    );
    assert_eq!(
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(&second).unwrap()
    );
    assert_ne!(first, second);
    let rebuilt: AppReply = serde_json::from_value(serde_json::to_value(&first).unwrap()).unwrap();
    assert!(matches!(
        registry.take(host.auth.clone(), rebuilt),
        Err(AppError::NotVisible)
    ));
    assert_eq!(registry.inner.pending.lock().unwrap().len(), 2);
    assert_eq!(charged(&registry), 2);
    let mut left = registry.take(host.auth.clone(), first).unwrap();
    let mut right = registry.take(host.auth.clone(), second).unwrap();
    assert_eq!(left.page(), right.page());
    left.verify_current_tail_once(&host.auth).unwrap();
    right.verify_current_tail_once(&host.auth).unwrap();
    assert!(matches!(
        left.verify_current_tail_once(&host.auth),
        Err(AppError::NotVisible)
    ));
    assert_eq!(charged(&registry), 2);
    drop(left);
    assert_eq!(charged(&registry), 1);
    drop(right);
    assert_eq!(charged(&registry), 0);
}

struct PlainPage(CustomModelCatalogPage);

impl CustomModelCatalogReplyAllocation for PlainPage {
    fn page(&self) -> &CustomModelCatalogPage {
        &self.0
    }
}

struct NoCancel;

impl CustomModelCatalogReplyCancel for NoCancel {
    fn cancel(&self) {}
}

#[tokio::test]
async fn custom_catalog_unregistered_fresh_pair_cannot_steal_equal_live_page() {
    let host = host();
    let inventory = Inventory::new(&host);
    let registry = CustomModelCatalogRegistry::new();
    let live = issue(&registry, &inventory, &host.auth).await;
    let (forged, _registration) = CustomModelCatalogReply::issue_for_delivery(
        Arc::new(PlainPage(empty_page())),
        Box::new(NoCancel),
    );
    assert!(matches!(
        registry.take(host.auth.clone(), AppReply::CustomModelCatalog(forged)),
        Err(AppError::NotVisible)
    ));
    assert_eq!(registry.inner.pending.lock().unwrap().len(), 1);
    let mut delivery = registry.take(host.auth.clone(), live).unwrap();
    delivery.verify_current_tail_once(&host.auth).unwrap();
}

#[tokio::test]
async fn custom_catalog_wrong_binding_retires_only_its_owned_key() {
    let first_host = host();
    let rebound_host = host();
    assert_eq!(first_host.auth, rebound_host.auth);
    assert!(!same_original_auth(&first_host.auth, &rebound_host.auth));
    let inventory = Inventory::new(&first_host);
    let registry = CustomModelCatalogRegistry::new();
    let first = issue(&registry, &inventory, &first_host.auth).await;
    let second = issue(&registry, &inventory, &first_host.auth).await;
    assert!(matches!(
        registry.take(rebound_host.auth.clone(), first),
        Err(AppError::NotVisible)
    ));
    assert_eq!(charged(&registry), 1);
    let mut remaining = registry.take(first_host.auth.clone(), second).unwrap();
    remaining
        .verify_current_tail_once(&first_host.auth)
        .unwrap();
}

#[test]
fn custom_catalog_window_epoch_change_is_not_equal_original_binding() {
    let auth = unbound_auth();
    let (_lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::DesktopWindow);
    let first = auth
        .clone()
        .with_verified_request_binding(
            issuer
                .bind_desktop_window(&auth, "main".into(), 1, Arc::new(Guard))
                .unwrap(),
        )
        .unwrap();
    let rebound = auth
        .clone()
        .with_verified_request_binding(
            issuer
                .bind_desktop_window(&auth, "main".into(), 2, Arc::new(Guard))
                .unwrap(),
        )
        .unwrap();
    assert_eq!(first, rebound);
    assert!(!same_original_auth(&first, &rebound));
}

#[tokio::test]
async fn custom_catalog_original_key_drop_removes_only_original_pending_entry() {
    let host = host();
    let inventory = Inventory::new(&host);
    let registry = CustomModelCatalogRegistry::new();
    let first = issue(&registry, &inventory, &host.auth).await;
    let second = issue(&registry, &inventory, &host.auth).await;
    drop(first);
    assert_eq!(registry.inner.pending.lock().unwrap().len(), 1);
    assert_eq!(charged(&registry), 1);
    drop(second);
    assert!(registry.inner.pending.lock().unwrap().is_empty());
    assert_eq!(charged(&registry), 0);
}

#[tokio::test]
async fn custom_catalog_key_drop_under_contention_defers_own_reap_without_reentry() {
    let host = host();
    let inventory = Inventory::new(&host);
    let registry = CustomModelCatalogRegistry::new();
    let reply = issue(&registry, &inventory, &host.auth).await;
    let pending = registry.inner.pending.lock().unwrap();
    drop(reply);
    assert_eq!(pending[0].state.load(Ordering::SeqCst), CANCELLED);
    assert_eq!(charged(&registry), 1);
    drop(pending);
    registry.inner.reap().unwrap();
    assert_eq!(charged(&registry), 0);
}

#[tokio::test]
async fn custom_catalog_host_eight_and_global_64_include_selected_and_handed_off() {
    let registry = CustomModelCatalogRegistry::new();
    let hosts: Vec<_> = (0..9).map(|_| host()).collect();
    let mut held = Vec::new();
    for host in hosts.iter().take(8) {
        let inventory = Inventory::new(host);
        for index in 0..8 {
            let reply = issue(&registry, &inventory, &host.auth).await;
            let mut delivery = registry.take(host.auth.clone(), reply).unwrap();
            if index % 2 == 0 {
                delivery.verify_current_tail_once(&host.auth).unwrap();
            }
            held.push(delivery);
        }
        assert_busy(
            registry
                .list_current(&inventory, &host.auth, request())
                .await,
        );
    }
    assert_eq!(charged(&registry), 64);
    let ninth = Inventory::new(&hosts[8]);
    assert_busy(
        registry
            .list_current(&ninth, &hosts[8].auth, request())
            .await,
    );
    assert_eq!(ninth.calls.load(Ordering::SeqCst), 0);
    drop(held.pop());
    let reply = issue(&registry, &ninth, &hosts[8].auth).await;
    assert_eq!(charged(&registry), 64);
    drop(reply);
    drop(held);
    assert_eq!(charged(&registry), 0);
}

struct PendingInventory;

#[async_trait]
impl CustomModelCatalogInventory for PendingInventory {
    async fn list_current(
        &self,
        _auth: &AuthContext,
        _request: &CustomModelCatalogPageRequest,
        _deadline: Instant,
    ) -> Result<CurrentCustomModelCatalogPage, CustomModelCatalogError> {
        pending().await
    }
}

#[tokio::test]
async fn custom_catalog_inflight_capacity_and_future_drop_release_memory_permit() {
    let host = host();
    let registry = CustomModelCatalogRegistry::new();
    let inventory = PendingInventory;
    let mut inflight = Vec::new();
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..8 {
        let mut future = Box::pin(registry.list_current(&inventory, &host.auth, request()));
        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
        inflight.push(future);
    }
    assert_eq!(charged(&registry), 8);
    assert_busy(
        registry
            .list_current(&inventory, &host.auth, request())
            .await,
    );
    drop(inflight.pop());
    assert_eq!(charged(&registry), 7);
    drop(inflight);
    assert_eq!(charged(&registry), 0);
    // This proves Core memory cancellation only, not any PG/driver closure ACK.
}

#[tokio::test]
async fn custom_catalog_expired_external_replies_remain_charged_until_real_drop() {
    let host = host();
    let inventory = Inventory::new(&host);
    let registry = CustomModelCatalogRegistry::new();
    let mut held = Vec::new();
    for _ in 0..8 {
        held.push(issue(&registry, &inventory, &host.auth).await);
    }
    tokio::time::sleep(BUDGET + Duration::from_millis(20)).await;
    assert_busy(
        registry
            .list_current(&inventory, &host.auth, request())
            .await,
    );
    assert!(registry.inner.pending.lock().unwrap().is_empty());
    assert_eq!(charged(&registry), 8);
    drop(held.pop());
    let replacement = issue(&registry, &inventory, &host.auth).await;
    assert_eq!(charged(&registry), 8);
    drop(replacement);
    drop(held);
    assert_eq!(charged(&registry), 0);
}

#[tokio::test]
async fn custom_catalog_last_allocation_drop_not_tail_success_returns_quota() {
    let host = host();
    let inventory = Inventory::new(&host);
    let registry = CustomModelCatalogRegistry::new();
    let reply = issue(&registry, &inventory, &host.auth).await;
    let mut delivery = registry.take(host.auth.clone(), reply).unwrap();
    let allocation = delivery.entry._allocation.clone();
    delivery.verify_current_tail_once(&host.auth).unwrap();
    drop(delivery);
    assert_eq!(charged(&registry), 1);
    drop(allocation);
    assert_eq!(charged(&registry), 0);
}

#[tokio::test]
async fn custom_catalog_registry_owner_drop_closes_selected_without_strong_cycle() {
    let host = host();
    let inventory = Inventory::new(&host);
    let registry = CustomModelCatalogRegistry::new();
    let reply = issue(&registry, &inventory, &host.auth).await;
    let pending = issue(&registry, &inventory, &host.auth).await;
    let mut delivery = registry.take(host.auth.clone(), reply).unwrap();
    let inner = Arc::downgrade(&registry.inner);
    let book = registry.inner.admission.clone();
    drop(registry);
    assert!(inner.upgrade().is_none());
    assert!(book.closed.load(Ordering::SeqCst));
    assert!(matches!(
        delivery.verify_current_tail_once(&host.auth),
        Err(AppError::DependencyUnavailable {
            dependency: "custom_model_catalog"
        })
    ));
    assert_eq!(book.global.load(Ordering::SeqCst), 2);
    drop(delivery);
    assert_eq!(book.global.load(Ordering::SeqCst), 1);
    drop(pending);
    assert_eq!(book.global.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn custom_catalog_rejects_port_deadline_extension_and_changed_original_auth() {
    let host = host();
    let registry = CustomModelCatalogRegistry::new();
    let mut extended = Inventory::new(&host);
    extended.extend_deadline = true;
    assert!(matches!(
        registry
            .list_current(&extended, &host.auth, request())
            .await,
        Err(AppError::DependencyUnavailable {
            dependency: "custom_model_catalog"
        })
    ));
    assert_eq!(charged(&registry), 0);
    let rebound = super::tests::host();
    let mut wrong = Inventory::new(&host);
    wrong.return_auth = Some(rebound.auth.clone());
    assert!(matches!(
        registry.list_current(&wrong, &host.auth, request()).await,
        Err(AppError::NotVisible)
    ));
    assert_eq!(charged(&registry), 0);
    let start = Instant::now();
    let inventory = Inventory::new(&host);
    let reply = issue(&registry, &inventory, &host.auth).await;
    let observed = inventory.deadline.lock().unwrap().unwrap();
    assert!(observed >= start);
    assert!(observed <= Instant::now() + BUDGET);
    drop(reply);
}

#[tokio::test]
async fn custom_catalog_known_revoke_does_not_poison_new_valid_host_request() {
    let old_host = host();
    let old = Inventory::new(&old_host);
    let registry = CustomModelCatalogRegistry::new();
    let reply = issue(&registry, &old, &old_host.auth).await;
    let mut delivery = registry.take(old_host.auth.clone(), reply).unwrap();
    old_host.lease.close();
    assert!(matches!(
        delivery.verify_current_tail_once(&old_host.auth),
        Err(AppError::NotVisible)
    ));
    assert!(!registry.inner.closed.load(Ordering::SeqCst));
    let new_host = host();
    let new = Inventory::new(&new_host);
    let reply = issue(&registry, &new, &new_host.auth).await;
    let mut next = registry.take(new_host.auth.clone(), reply).unwrap();
    next.verify_current_tail_once(&new_host.auth).unwrap();
}

#[tokio::test]
async fn custom_catalog_removed_tail_drops_outside_registry_lock() {
    let host = host();
    let registry = CustomModelCatalogRegistry::new();
    let locked = Arc::new(AtomicUsize::new(0));
    let mut inventory = Inventory::new(&host);
    inventory.drop_observer = Some((Arc::downgrade(&registry.inner), locked.clone()));
    let reply = issue(&registry, &inventory, &host.auth).await;
    drop(reply);
    assert_eq!(locked.load(Ordering::SeqCst), 0);
    let reply = issue(&registry, &inventory, &host.auth).await;
    drop(registry);
    assert_eq!(locked.load(Ordering::SeqCst), 0);
    drop(reply);
}

#[tokio::test]
async fn custom_catalog_pending_mutex_poison_closes_without_drop_panic() {
    let host = host();
    let inventory = Inventory::new(&host);
    let registry = CustomModelCatalogRegistry::new();
    let reply = issue(&registry, &inventory, &host.auth).await;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = registry.inner.pending.lock().unwrap();
        panic!("synthetic Core poison");
    }));
    assert!(result.is_err());
    assert!(matches!(
        registry
            .list_current(&inventory, &host.auth, request())
            .await,
        Err(AppError::DependencyUnavailable {
            dependency: "custom_model_catalog"
        })
    ));
    drop(registry);
    drop(reply);
}

#[tokio::test]
async fn custom_catalog_seven_builders_preserve_original_registry_and_inventory() {
    let host = host();
    let inventory = Arc::new(Inventory::new(&host));
    let app = OpenBotApplication::new(crate::fakes::FakeChannelReader::empty())
        .with_custom_model_catalog_inventory(inventory.clone());
    let reply = app
        .execute(
            host.auth.clone(),
            AppCommand::ListCustomModelCatalog(request()),
        )
        .await
        .unwrap();
    let app = app
        .with_people(crate::ports::NoPeopleAdministration)
        .with_audit(crate::ports::NoAuditReader)
        .with_policy(crate::ports::NoPolicyAdministration)
        .with_tools(crate::tool::NoToolControlPlane, crate::tool::NoToolJournal)
        .with_threads(crate::ports::NoThreadDirectory)
        .with_memory(crate::ports::NoMemoryAdministration)
        .with_agent_callback_tokens(crate::agent_admin::NoAgentCallbackTokenAdministration);
    let mut delivery = app
        .take_custom_model_catalog_delivery(host.auth.clone(), reply)
        .unwrap();
    delivery.verify_current_tail_once(&host.auth).unwrap();
    let second = app
        .execute(
            host.auth.clone(),
            AppCommand::ListCustomModelCatalog(request()),
        )
        .await
        .unwrap();
    app.take_custom_model_catalog_delivery(host.auth.clone(), second)
        .unwrap();
    assert_eq!(inventory.calls.load(Ordering::SeqCst), 2);
}
