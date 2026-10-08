//! 原请求目录应答的一次交付、同步取消与 allocation 配额。

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError, Weak};
use std::time::{Duration, Instant};

use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::AppReply;
use openbot_contracts::custom_model_catalog::{
    CustomModelCatalogPage, CustomModelCatalogPageRequest, CustomModelCatalogReply,
    CustomModelCatalogReplyAllocation, CustomModelCatalogReplyCancel,
    CustomModelCatalogReplyRegistration,
};
use openbot_contracts::error::AppError;
use openbot_contracts::request_binding::{
    CustomModelCatalogHostTailWitness, HostRequestBindingIdentity,
};

use crate::custom_model_catalog::{
    CustomModelCatalogError, CustomModelCatalogInventory, host_error, require_actor,
    same_original_auth, unavailable,
};

const GLOBAL_CAPACITY: usize = 64;
const HOST_CAPACITY: usize = 8;
const BUDGET: Duration = Duration::from_secs(5);
const PENDING: u8 = 0;
const SELECTED: u8 = 1;
const HANDED_OFF: u8 = 2;
const CANCELLED: u8 = 3;

pub(crate) struct CustomModelCatalogRegistry {
    inner: Arc<RegistryInner>,
}

struct RegistryInner {
    closed: Arc<AtomicBool>,
    pending: Mutex<Vec<Arc<PrivateCustomModelCatalogDeliveryEntry>>>,
    admission: Arc<AdmissionBook>,
}

struct AdmissionBook {
    closed: Arc<AtomicBool>,
    global: AtomicUsize,
    hosts: Mutex<Vec<Arc<HostCounter>>>,
}

struct HostCounter {
    identity: HostRequestBindingIdentity,
    held: AtomicUsize,
}

struct AdmissionPermit {
    book: Arc<AdmissionBook>,
    host: Arc<HostCounter>,
}

// Declaration order is material: page allocations disappear before the quota is returned.
struct PageAllocation {
    page: CustomModelCatalogPage,
    _permit: AdmissionPermit,
}

impl CustomModelCatalogReplyAllocation for PageAllocation {
    fn page(&self) -> &CustomModelCatalogPage {
        &self.page
    }
}

struct PrivateCustomModelCatalogDeliveryEntry {
    registration: CustomModelCatalogReplyRegistration,
    original: AuthContext,
    host: HostRequestBindingIdentity,
    deadline: Instant,
    tail: Box<dyn CustomModelCatalogHostTailWitness>,
    _allocation: Arc<PageAllocation>,
    state: AtomicU8,
    closed: Arc<AtomicBool>,
}

struct CancelOriginalEntry {
    entry: Weak<PrivateCustomModelCatalogDeliveryEntry>,
    registry: Weak<RegistryInner>,
}

impl AdmissionBook {
    fn reserve(
        self: &Arc<Self>,
        identity: &HostRequestBindingIdentity,
        deadline: Instant,
    ) -> Result<AdmissionPermit, AppError> {
        if self.closed.load(Ordering::SeqCst) || Instant::now() >= deadline {
            return Err(unavailable());
        }
        let mut retired = Vec::new();
        let mut hosts = match self.hosts.try_lock() {
            Ok(hosts) => hosts,
            Err(TryLockError::WouldBlock) => return Err(unavailable()),
            Err(TryLockError::Poisoned(_)) => {
                self.closed.store(true, Ordering::SeqCst);
                return Err(unavailable());
            }
        };
        let result = (|| {
            let mut index = 0;
            while index < hosts.len() {
                if hosts[index].held.load(Ordering::SeqCst) == 0 {
                    retired.push(hosts.swap_remove(index));
                } else {
                    index += 1;
                }
            }
            if self.closed.load(Ordering::SeqCst) || Instant::now() >= deadline {
                return Err(unavailable());
            }
            if self.global.load(Ordering::SeqCst) >= GLOBAL_CAPACITY {
                return Err(CustomModelCatalogError::Busy.into_app_error());
            }
            let host = if let Some(host) = hosts
                .iter()
                .find(|host| host.identity.same_binding(identity))
            {
                host.clone()
            } else {
                if hosts.len() >= GLOBAL_CAPACITY {
                    return Err(CustomModelCatalogError::Busy.into_app_error());
                }
                let host = Arc::new(HostCounter {
                    identity: identity.clone(),
                    held: AtomicUsize::new(0),
                });
                hosts.push(host.clone());
                host
            };
            if host.held.load(Ordering::SeqCst) >= HOST_CAPACITY {
                return Err(CustomModelCatalogError::Busy.into_app_error());
            }
            // Reservations are serialized by this bounded host map. Drop only decrements.
            host.held.fetch_add(1, Ordering::SeqCst);
            self.global.fetch_add(1, Ordering::SeqCst);
            Ok(AdmissionPermit {
                book: self.clone(),
                host,
            })
        })();
        drop(hosts);
        drop(retired);
        result
    }
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        // No lock, callback, task or allocation in this final-memory release path.
        let host = self
            .host
            .held
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_sub(1)
            });
        let global = self
            .book
            .global
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_sub(1)
            });
        if host.is_err() || global.is_err() {
            self.book.closed.store(true, Ordering::SeqCst);
        }
    }
}

impl RegistryInner {
    fn pending(
        &self,
    ) -> Result<MutexGuard<'_, Vec<Arc<PrivateCustomModelCatalogDeliveryEntry>>>, AppError> {
        match self.pending.try_lock() {
            Ok(pending) => Ok(pending),
            Err(TryLockError::WouldBlock) => Err(unavailable()),
            Err(TryLockError::Poisoned(_)) => {
                self.closed.store(true, Ordering::SeqCst);
                Err(unavailable())
            }
        }
    }

    fn reap(&self) -> Result<(), AppError> {
        let mut retired = Vec::new();
        let mut pending = self.pending()?;
        let now = Instant::now();
        let mut index = 0;
        while index < pending.len() {
            let entry = &pending[index];
            if entry.state.load(Ordering::SeqCst) != PENDING || now >= entry.deadline {
                entry.cancel();
                retired.push(pending.swap_remove(index));
            } else {
                index += 1;
            }
        }
        drop(pending);
        drop(retired);
        Ok(())
    }
}

impl CustomModelCatalogRegistry {
    pub(crate) fn new() -> Self {
        let closed = Arc::new(AtomicBool::new(false));
        Self {
            inner: Arc::new(RegistryInner {
                closed: closed.clone(),
                pending: Mutex::new(Vec::new()),
                admission: Arc::new(AdmissionBook {
                    closed,
                    global: AtomicUsize::new(0),
                    hosts: Mutex::new(Vec::new()),
                }),
            }),
        }
    }

    pub(crate) async fn list_current(
        &self,
        inventory: &dyn CustomModelCatalogInventory,
        auth: &AuthContext,
        request: CustomModelCatalogPageRequest,
    ) -> Result<CustomModelCatalogReply, AppError> {
        // This one absolute budget begins before reap, admission and any adapter checkout.
        let deadline = Instant::now().checked_add(BUDGET).ok_or_else(unavailable)?;
        require_actor(auth).map_err(CustomModelCatalogError::into_app_error)?;
        if !request.is_valid() {
            return Err(CustomModelCatalogError::InvalidCursor.into_app_error());
        }
        let host = auth
            .request_binding()
            .ok_or(AppError::NotVisible)?
            .identity()
            .clone();
        self.inner.reap()?;
        let permit = self.inner.admission.reserve(&host, deadline)?;
        let current = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            inventory.list_current(auth, &request, deadline),
        )
        .await
        .map_err(|_| unavailable())?
        .map_err(CustomModelCatalogError::into_app_error)?;
        let (page, original, observed_deadline, tail) = current.into_parts();
        if !same_original_auth(auth, &original) {
            return Err(AppError::NotVisible);
        }
        if observed_deadline != deadline
            || !page.is_valid()
            || Instant::now() >= deadline
            || self.inner.closed.load(Ordering::SeqCst)
        {
            return Err(unavailable());
        }
        tail.verify_current(auth, deadline)
            .map_err(host_error)
            .map_err(CustomModelCatalogError::into_app_error)?;
        let allocation = Arc::new(PageAllocation {
            page,
            _permit: permit,
        });
        let mut issued_reply = None;
        let entry = Arc::new_cyclic(|weak| {
            let (reply, registration) = CustomModelCatalogReply::issue_for_delivery(
                allocation.clone(),
                Box::new(CancelOriginalEntry {
                    entry: weak.clone(),
                    registry: Arc::downgrade(&self.inner),
                }),
            );
            issued_reply = Some(reply);
            PrivateCustomModelCatalogDeliveryEntry {
                registration,
                original,
                host,
                deadline,
                tail,
                _allocation: allocation.clone(),
                state: AtomicU8::new(PENDING),
                closed: self.inner.closed.clone(),
            }
        });
        let reply = issued_reply.ok_or_else(unavailable)?;
        self.insert(entry)?;
        Ok(reply)
    }

    fn insert(&self, entry: Arc<PrivateCustomModelCatalogDeliveryEntry>) -> Result<(), AppError> {
        let mut pending = self.inner.pending()?;
        let result = if self.inner.closed.load(Ordering::SeqCst) || Instant::now() >= entry.deadline
        {
            Err(unavailable())
        } else if pending.len() >= GLOBAL_CAPACITY {
            Err(CustomModelCatalogError::Busy.into_app_error())
        } else {
            pending.push(entry.clone());
            Ok(())
        };
        drop(pending);
        result
    }

    pub(crate) fn take(
        &self,
        auth: AuthContext,
        reply: AppReply,
    ) -> Result<PublicCustomModelCatalogDelivery, AppError> {
        let AppReply::CustomModelCatalog(reply) = reply else {
            return Err(unavailable());
        };
        self.inner.reap()?;
        let mut pending = self.inner.pending()?;
        let selected = pending
            .iter()
            .position(|entry| entry.registration.matches_reply(&reply))
            .map(|index| pending.swap_remove(index));
        if let Some(entry) = selected.as_ref() {
            let _ =
                entry
                    .state
                    .compare_exchange(PENDING, SELECTED, Ordering::SeqCst, Ordering::SeqCst);
        }
        drop(pending);
        let entry = selected.ok_or(AppError::NotVisible)?;
        if let Err(error) = entry.verify_selected(&auth) {
            entry.cancel();
            return Err(error);
        }
        Ok(PublicCustomModelCatalogDelivery { reply, entry })
    }
}

impl Drop for CustomModelCatalogRegistry {
    fn drop(&mut self) {
        self.inner.closed.store(true, Ordering::SeqCst);
        // Only this owner is retained by the Application. Permits retain a separate book.
        let retired = {
            let mut pending = match self.inner.pending.lock() {
                Ok(pending) => pending,
                Err(poisoned) => poisoned.into_inner(),
            };
            for entry in pending.iter() {
                entry.cancel();
            }
            std::mem::take(&mut *pending)
        };
        drop(retired);
    }
}

impl PrivateCustomModelCatalogDeliveryEntry {
    fn cancel(&self) {
        let _ = self
            .state
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |state| match state {
                PENDING | SELECTED => Some(CANCELLED),
                _ => None,
            });
    }

    fn verify_selected(&self, auth: &AuthContext) -> Result<(), AppError> {
        if self.state.load(Ordering::SeqCst) != SELECTED
            || !same_original_auth(&self.original, auth)
            || !auth
                .request_binding()
                .is_some_and(|binding| binding.identity().same_binding(&self.host))
        {
            return Err(AppError::NotVisible);
        }
        if self.closed.load(Ordering::SeqCst) || Instant::now() >= self.deadline {
            return Err(unavailable());
        }
        self.tail
            .verify_current(auth, self.deadline)
            .map_err(host_error)
            .map_err(CustomModelCatalogError::into_app_error)?;
        if self.state.load(Ordering::SeqCst) != SELECTED {
            return Err(AppError::NotVisible);
        }
        if self.closed.load(Ordering::SeqCst) || Instant::now() >= self.deadline {
            return Err(unavailable());
        }
        Ok(())
    }
}

impl CustomModelCatalogReplyCancel for CancelOriginalEntry {
    fn cancel(&self) {
        let Some(entry) = self.entry.upgrade() else {
            return;
        };
        entry.cancel();
        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        // Cancellation cannot be skipped due to contention: the state was set first.
        // A contended pending-table removal is completed by the next bounded reap.
        let removed = match registry.pending() {
            Ok(mut pending) => pending
                .iter()
                .position(|candidate| Arc::ptr_eq(candidate, &entry))
                .map(|index| pending.swap_remove(index)),
            Err(_) => None,
        };
        drop(removed);
    }
}

/// 一次实际交付的原应答与尾见证；不导出 Contracts 私有 key。
pub struct PublicCustomModelCatalogDelivery {
    // Original key Drop runs while the exact Entry is still alive.
    reply: CustomModelCatalogReply,
    entry: Arc<PrivateCustomModelCatalogDeliveryEntry>,
}

impl PublicCustomModelCatalogDelivery {
    /// 借用原不可变页；真实 transport 仍须在最终边界消费尾见证。
    #[must_use]
    pub fn page(&self) -> &CustomModelCatalogPage {
        self.reply.page()
    }

    /// 仅一次最终检查；失败取消原项，成功进入 HandedOff 终态。
    pub fn verify_current_tail_once(&mut self, auth: &AuthContext) -> Result<(), AppError> {
        if let Err(error) = self.entry.verify_selected(auth) {
            self.entry.cancel();
            return Err(error);
        }
        self.entry
            .state
            .compare_exchange(SELECTED, HANDED_OFF, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| AppError::NotVisible)?;
        Ok(())
    }
}

impl fmt::Debug for PublicCustomModelCatalogDelivery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicCustomModelCatalogDelivery(<redacted>)")
    }
}

#[cfg(test)]
#[path = "custom_model_catalog_delivery_tests.rs"]
mod tests;
