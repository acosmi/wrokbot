//! Authority-owned browser residency runtime.
//!
//! This manager makes the pure fixed-upstream LRU/idle decisions effective: it owns every live
//! driver handle, coalesces cold starts, retires selected handles before returning, and never keys
//! isolation by Bot ID alone. Product operations and policy/audit remain outside this crate.

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};

use openbot_contracts::ids::{ComputerGeneration, ComputerId};
use tokio::sync::{Mutex as AsyncMutex, MutexGuard, Notify};

use crate::browser::eviction::{
    DEFAULT_BROWSER_IDLE_TIMEOUT_MS, DEFAULT_MAX_LIVE_BROWSERS, choose_idle,
};
use crate::engine::{ComputerSecurityScope, EngineRole};

type ScopeKey = [u8; 32];

/// Boxed host-driver lifecycle future; the manager never exposes the driver response on a wire.
pub type BrowserDriverFuture<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;

/// Complete Rust-owned identity needed to launch or reuse one browser runtime.
#[derive(Clone, PartialEq, Eq)]
pub struct BrowserInstance {
    scope: ComputerSecurityScope,
    scope_key: ScopeKey,
    computer_id: ComputerId,
    generation: ComputerGeneration,
}

impl BrowserInstance {
    /// Bind the full isolation scope to one computer generation.
    #[must_use]
    pub fn new(
        scope: ComputerSecurityScope,
        computer_id: ComputerId,
        generation: ComputerGeneration,
    ) -> Self {
        let scope_key = EngineRole::BrowserComputer(scope.clone()).scope_digest();
        Self {
            scope,
            scope_key,
            computer_id,
            generation,
        }
    }

    /// Full authority-owned security scope. It is never reconstructed from renderer input.
    #[must_use]
    pub const fn scope(&self) -> &ComputerSecurityScope {
        &self.scope
    }

    /// Rust-owned computer ID.
    #[must_use]
    pub const fn computer_id(&self) -> &ComputerId {
        &self.computer_id
    }

    /// Current generation.
    #[must_use]
    pub const fn generation(&self) -> ComputerGeneration {
        self.generation
    }
}

impl core::fmt::Debug for BrowserInstance {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BrowserInstance")
            .field("scope", &"[digest]")
            .field("computer_id", &self.computer_id)
            .field("generation", &self.generation)
            .finish()
    }
}

/// Why the runtime owner is closing a browser process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrowserRetirementReason {
    /// A successful cold start needs the least-recently-used inactive slot.
    Capacity,
    /// The monotonic idle cutoff was reached.
    Idle,
    /// Authority advanced this exact scope to a newer generation.
    GenerationAdvanced,
    /// An explicit stop was requested.
    ExplicitStop,
    /// The whole runtime is shutting down.
    Shutdown,
    /// A later retirement failed, so the just-launched browser is rolled back.
    LaunchRollback,
}

/// Typed process-wide residency limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrowserRuntimeBudget {
    maximum_live: NonZeroUsize,
    idle_timeout_ms: Option<u64>,
}

impl BrowserRuntimeBudget {
    /// Construct a budget. `idle_timeout_ms=0` deliberately disables only the idle sweep.
    pub fn new(maximum_live: usize, idle_timeout_ms: u64) -> Result<Self, BrowserBudgetError> {
        let maximum_live =
            NonZeroUsize::new(maximum_live).ok_or(BrowserBudgetError::ZeroMaximum)?;
        Ok(Self {
            maximum_live,
            idle_timeout_ms: (idle_timeout_ms != 0).then_some(idle_timeout_ms),
        })
    }

    /// Maximum simultaneously resident browser handles.
    #[must_use]
    pub const fn maximum_live(self) -> NonZeroUsize {
        self.maximum_live
    }

    /// Monotonic idle timeout in milliseconds; absent means no idle sweep.
    #[must_use]
    pub const fn idle_timeout_ms(self) -> Option<u64> {
        self.idle_timeout_ms
    }
}

impl Default for BrowserRuntimeBudget {
    fn default() -> Self {
        Self {
            maximum_live: NonZeroUsize::new(DEFAULT_MAX_LIVE_BROWSERS)
                .expect("fixed maximum is positive"),
            idle_timeout_ms: Some(
                u64::try_from(DEFAULT_BROWSER_IDLE_TIMEOUT_MS)
                    .expect("fixed idle timeout is positive"),
            ),
        }
    }
}

/// Invalid typed browser budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BrowserBudgetError {
    /// Zero would close every newly started browser and is never a valid live-runtime cap.
    #[error("computer_browser_budget_zero")]
    ZeroMaximum,
}

/// Host-specific browser lifecycle operations.
///
/// `close` consumes the handle. Implementations must make `Drop` a fail-safe process termination,
/// so returning an error cannot leave an unowned browser process behind.
pub trait BrowserRuntimeDriver: Send + Sync + 'static {
    /// Opaque live browser/process handle.
    type Browser: Send + 'static;
    /// Stable or source-chained host failure. The manager never exposes its text as a product code.
    type Error: StdError + Send + Sync + 'static;

    /// Launch the exact authority-owned instance.
    fn launch<'a>(
        &'a self,
        instance: &'a BrowserInstance,
    ) -> BrowserDriverFuture<'a, Self::Browser, Self::Error>;

    /// Gracefully close one owned handle; dropping it remains the forced-cleanup fallback.
    fn close<'a>(
        &'a self,
        browser: Self::Browser,
        reason: BrowserRetirementReason,
    ) -> BrowserDriverFuture<'a, (), Self::Error>;
}

/// Stable manager failures. Driver prose is available only as an error source.
#[derive(thiserror::Error)]
pub enum BrowserRuntimeError<E: StdError + Send + Sync + 'static> {
    /// Runtime has begun shutdown and cannot mint new work.
    #[error("computer_runtime_closed")]
    Closed,
    /// A stale generation attempted to reuse or replace the current instance.
    #[error("computer_generation_stale")]
    StaleGeneration,
    /// The same full scope was presented with a different computer identity.
    #[error("computer_scope_identity_conflict")]
    ScopeIdentityConflict,
    /// Every resident slot is currently leased, so no safe LRU victim exists.
    #[error("computer_runtime_busy")]
    Busy,
    /// Driver launch failed before the instance became visible.
    #[error("computer_launch_failed")]
    Launch(#[source] E),
    /// Driver retirement failed; ownership was still consumed for forced Drop cleanup.
    #[error("computer_retirement_failed")]
    Retirement(#[source] E),
    /// Internal ownership/accounting invariant failed closed.
    #[error("computer_runtime_invariant")]
    Invariant,
}

impl<E: StdError + Send + Sync + 'static> core::fmt::Debug for BrowserRuntimeError<E> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, formatter)
    }
}

struct LiveBrowser<B> {
    instance: BrowserInstance,
    browser: Arc<AsyncMutex<B>>,
    last_used_ms: u64,
    touch_order: u64,
    leases: usize,
}

struct RuntimeState<B> {
    live: BTreeMap<ScopeKey, LiveBrowser<B>>,
    next_touch_order: u64,
    closed: bool,
}

impl<B> Default for RuntimeState<B> {
    fn default() -> Self {
        Self {
            live: BTreeMap::new(),
            next_touch_order: 0,
            closed: false,
        }
    }
}

struct RuntimeInner<D: BrowserRuntimeDriver> {
    driver: D,
    budget: BrowserRuntimeBudget,
    state: Mutex<RuntimeState<D::Browser>>,
    // Launch and retirement are globally serialized. Existing leased browsers remain concurrent.
    lifecycle: AsyncMutex<()>,
    lease_released: Notify,
}

/// Process-wide owner of live browser handles and the fixed LRU/idle budget.
pub struct BrowserRuntimeManager<D: BrowserRuntimeDriver> {
    inner: Arc<RuntimeInner<D>>,
}

impl<D: BrowserRuntimeDriver> Clone for BrowserRuntimeManager<D> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<D: BrowserRuntimeDriver> core::fmt::Debug for BrowserRuntimeManager<D> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let live = self
            .inner
            .state
            .lock()
            .map_or(usize::MAX, |state| state.live.len());
        formatter
            .debug_struct("BrowserRuntimeManager")
            .field("budget", &self.inner.budget)
            .field("live", &live)
            .finish_non_exhaustive()
    }
}

impl<D: BrowserRuntimeDriver> BrowserRuntimeManager<D> {
    /// Construct an empty runtime around one host driver.
    #[must_use]
    pub fn new(driver: D, budget: BrowserRuntimeBudget) -> Self {
        Self {
            inner: Arc::new(RuntimeInner {
                driver,
                budget,
                state: Mutex::new(RuntimeState::default()),
                lifecycle: AsyncMutex::new(()),
                lease_released: Notify::new(),
            }),
        }
    }

    /// Reuse or cold-start one exact instance and return an activity lease.
    ///
    /// `now_ms` must come from the Rust host's monotonic clock. The newest instance is made visible
    /// only after any selected inactive victim has actually been retired.
    pub async fn ensure(
        &self,
        instance: BrowserInstance,
        now_ms: u64,
    ) -> Result<BrowserLease<D>, BrowserRuntimeError<D::Error>> {
        if let Some(lease) = self.try_existing(&instance, now_ms)? {
            return Ok(lease);
        }

        let _lifecycle = self.inner.lifecycle.lock().await;
        if let Some(lease) = self.try_existing(&instance, now_ms)? {
            return Ok(lease);
        }

        let (victim, victim_reason) = {
            let mut state = self.lock_state()?;
            if state.closed {
                return Err(BrowserRuntimeError::Closed);
            }
            let victim = match state.live.get(&instance.scope_key) {
                Some(current) => {
                    if current.instance.computer_id != instance.computer_id {
                        return Err(BrowserRuntimeError::ScopeIdentityConflict);
                    }
                    if instance.generation <= current.instance.generation {
                        return Err(BrowserRuntimeError::StaleGeneration);
                    }
                    if current.leases != 0 {
                        return Err(BrowserRuntimeError::Busy);
                    }
                    state.live.remove(&instance.scope_key)
                }
                None if state.live.len() >= self.inner.budget.maximum_live.get() => {
                    let key = state
                        .live
                        .iter()
                        .filter(|(_, entry)| entry.leases == 0)
                        .min_by_key(|(_, entry)| entry.touch_order)
                        .map(|(key, _)| *key)
                        .ok_or(BrowserRuntimeError::Busy)?;
                    state.live.remove(&key)
                }
                None => None,
            };
            let reason = victim.as_ref().map(|entry| {
                if entry.instance.scope_key == instance.scope_key {
                    BrowserRetirementReason::GenerationAdvanced
                } else {
                    BrowserRetirementReason::Capacity
                }
            });
            (victim, reason)
        };

        let browser = match self.inner.driver.launch(&instance).await {
            Ok(browser) => browser,
            Err(error) => {
                if let Some(victim) = victim {
                    self.restore(victim)?;
                }
                return Err(BrowserRuntimeError::Launch(error));
            }
        };

        if let (Some(victim), Some(reason)) = (victim, victim_reason)
            && let Err(error) = self.retire(victim, reason).await
        {
            let _ = self
                .inner
                .driver
                .close(browser, BrowserRetirementReason::LaunchRollback)
                .await;
            return Err(error);
        }

        let browser = Arc::new(AsyncMutex::new(browser));
        let weak = Arc::downgrade(&self.inner);
        let rejected = {
            let mut state = self.lock_state()?;
            if state.closed || state.live.contains_key(&instance.scope_key) {
                true
            } else {
                let touch_order = next_touch(&mut state)?;
                state.live.insert(
                    instance.scope_key,
                    LiveBrowser {
                        instance: instance.clone(),
                        browser: browser.clone(),
                        last_used_ms: now_ms,
                        touch_order,
                        leases: 1,
                    },
                );
                false
            }
        };
        if rejected {
            let browser = Arc::try_unwrap(browser)
                .map_err(|_| BrowserRuntimeError::Invariant)?
                .into_inner();
            let _ = self
                .inner
                .driver
                .close(browser, BrowserRetirementReason::LaunchRollback)
                .await;
            return Err(BrowserRuntimeError::Invariant);
        }
        Ok(BrowserLease {
            inner: browser,
            runtime: weak,
            instance,
            released: false,
        })
    }

    /// Close inactive browsers at or before the idle cutoff.
    pub async fn sweep_idle(&self, now_ms: u64) -> Result<usize, BrowserRuntimeError<D::Error>> {
        let Some(timeout) = self.inner.budget.idle_timeout_ms else {
            return Ok(0);
        };
        let _lifecycle = self.inner.lifecycle.lock().await;
        let keys = {
            let state = self.lock_state()?;
            choose_idle(
                state
                    .live
                    .iter()
                    .filter(|(_, entry)| entry.leases == 0)
                    .map(|(key, entry)| (*key, i128::from(entry.last_used_ms))),
                i128::from(timeout),
                i128::from(now_ms),
            )
        };
        let victims = {
            let mut state = self.lock_state()?;
            keys.into_iter()
                .filter_map(|key| {
                    state
                        .live
                        .get(&key)
                        .is_some_and(|entry| entry.leases == 0)
                        .then(|| state.live.remove(&key))
                        .flatten()
                })
                .collect::<Vec<_>>()
        };
        let count = victims.len();
        self.retire_all(victims, BrowserRetirementReason::Idle)
            .await?;
        Ok(count)
    }

    /// Explicitly stop one exact inactive instance while preserving its profile.
    pub async fn stop(
        &self,
        instance: &BrowserInstance,
    ) -> Result<bool, BrowserRuntimeError<D::Error>> {
        let _lifecycle = self.inner.lifecycle.lock().await;
        let victim = {
            let mut state = self.lock_state()?;
            let Some(current) = state.live.get(&instance.scope_key) else {
                return Ok(false);
            };
            validate_identity(current, instance)?;
            if current.leases != 0 {
                return Err(BrowserRuntimeError::Busy);
            }
            state.live.remove(&instance.scope_key)
        };
        let Some(victim) = victim else {
            return Ok(false);
        };
        self.retire(victim, BrowserRetirementReason::ExplicitStop)
            .await?;
        Ok(true)
    }

    /// Stop accepting new leases and retire every inactive handle.
    ///
    /// If a caller still holds a lease, this returns `computer_runtime_busy`; dropping those leases
    /// and calling again completes shutdown without reviving the runtime.
    pub async fn close_all(&self) -> Result<usize, BrowserRuntimeError<D::Error>> {
        {
            let mut state = self.lock_state()?;
            state.closed = true;
        }
        let _lifecycle = self.inner.lifecycle.lock().await;
        let victims = {
            let mut state = self.lock_state()?;
            if state.live.values().any(|entry| entry.leases != 0) {
                return Err(BrowserRuntimeError::Busy);
            }
            core::mem::take(&mut state.live)
                .into_values()
                .collect::<Vec<_>>()
        };
        let count = victims.len();
        self.retire_all(victims, BrowserRetirementReason::Shutdown)
            .await?;
        Ok(count)
    }

    /// Borrow an already resident exact instance without implicitly starting or replacing it.
    pub fn acquire_existing(
        &self,
        instance: &BrowserInstance,
        now_ms: u64,
    ) -> Result<Option<BrowserLease<D>>, BrowserRuntimeError<D::Error>> {
        self.try_existing(instance, now_ms)
    }

    /// Authority-only identity snapshot. Process handles remain owned by this manager.
    pub fn resident_instances(
        &self,
    ) -> Result<Vec<BrowserInstance>, BrowserRuntimeError<D::Error>> {
        Ok(self
            .lock_state()?
            .live
            .values()
            .map(|entry| entry.instance.clone())
            .collect())
    }

    /// Wait for leases after the host has frozen the exact session's admission and requested
    /// cancellation. This does not itself cancel operations or claim an unknown effect was absent.
    pub async fn stop_after_drain(
        &self,
        instance: &BrowserInstance,
        bound: std::time::Duration,
    ) -> Result<bool, BrowserRuntimeError<D::Error>> {
        tokio::time::timeout(bound, async {
            loop {
                let released = self.inner.lease_released.notified();
                tokio::pin!(released);
                released.as_mut().enable();
                match self.stop(instance).await {
                    Err(BrowserRuntimeError::Busy) => released.await,
                    result => return result,
                }
            }
        })
        .await
        .unwrap_or(Err(BrowserRuntimeError::Busy))
    }

    /// Number of manager-owned resident handles, including currently leased ones.
    pub fn live_count(&self) -> Result<usize, BrowserRuntimeError<D::Error>> {
        Ok(self.lock_state()?.live.len())
    }

    /// Whether the exact identity/generation is currently resident.
    pub fn is_live(
        &self,
        instance: &BrowserInstance,
    ) -> Result<bool, BrowserRuntimeError<D::Error>> {
        Ok(self
            .lock_state()?
            .live
            .get(&instance.scope_key)
            .is_some_and(|entry| {
                entry.instance.computer_id == instance.computer_id
                    && entry.instance.generation == instance.generation
            }))
    }

    fn try_existing(
        &self,
        instance: &BrowserInstance,
        now_ms: u64,
    ) -> Result<Option<BrowserLease<D>>, BrowserRuntimeError<D::Error>> {
        let mut state = self.lock_state()?;
        if state.closed {
            return Err(BrowserRuntimeError::Closed);
        }
        let Some(current) = state.live.get(&instance.scope_key) else {
            return Ok(None);
        };
        validate_identity(current, instance)?;
        if current.instance.generation != instance.generation {
            return Ok(None);
        }
        let touch_order = next_touch(&mut state)?;
        let current = state
            .live
            .get_mut(&instance.scope_key)
            .ok_or(BrowserRuntimeError::Invariant)?;
        current.last_used_ms = current.last_used_ms.max(now_ms);
        current.touch_order = touch_order;
        current.leases = current
            .leases
            .checked_add(1)
            .ok_or(BrowserRuntimeError::Invariant)?;
        Ok(Some(BrowserLease {
            inner: current.browser.clone(),
            runtime: Arc::downgrade(&self.inner),
            instance: instance.clone(),
            released: false,
        }))
    }

    fn lock_state(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, RuntimeState<D::Browser>>, BrowserRuntimeError<D::Error>>
    {
        self.inner
            .state
            .lock()
            .map_err(|_| BrowserRuntimeError::Invariant)
    }

    fn restore(
        &self,
        victim: LiveBrowser<D::Browser>,
    ) -> Result<(), BrowserRuntimeError<D::Error>> {
        let mut state = self.lock_state()?;
        if state.live.contains_key(&victim.instance.scope_key) {
            return Err(BrowserRuntimeError::Invariant);
        }
        state.live.insert(victim.instance.scope_key, victim);
        Ok(())
    }

    async fn retire(
        &self,
        victim: LiveBrowser<D::Browser>,
        reason: BrowserRetirementReason,
    ) -> Result<(), BrowserRuntimeError<D::Error>> {
        if victim.leases != 0 {
            return Err(BrowserRuntimeError::Invariant);
        }
        let browser = Arc::try_unwrap(victim.browser)
            .map_err(|_| BrowserRuntimeError::Invariant)?
            .into_inner();
        self.inner
            .driver
            .close(browser, reason)
            .await
            .map_err(BrowserRuntimeError::Retirement)
    }

    async fn retire_all(
        &self,
        victims: Vec<LiveBrowser<D::Browser>>,
        reason: BrowserRetirementReason,
    ) -> Result<(), BrowserRuntimeError<D::Error>> {
        let mut first_error = None;
        for victim in victims {
            if let Err(error) = self.retire(victim, reason).await
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

fn validate_identity<B, E>(
    current: &LiveBrowser<B>,
    requested: &BrowserInstance,
) -> Result<(), BrowserRuntimeError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    if current.instance.computer_id != requested.computer_id {
        return Err(BrowserRuntimeError::ScopeIdentityConflict);
    }
    if requested.generation < current.instance.generation {
        return Err(BrowserRuntimeError::StaleGeneration);
    }
    Ok(())
}

fn next_touch<B, E>(state: &mut RuntimeState<B>) -> Result<u64, BrowserRuntimeError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    let next = state
        .next_touch_order
        .checked_add(1)
        .ok_or(BrowserRuntimeError::Invariant)?;
    state.next_touch_order = next;
    Ok(next)
}

/// Activity lease that prevents the selected browser from being evicted mid-operation.
pub struct BrowserLease<D: BrowserRuntimeDriver> {
    inner: Arc<AsyncMutex<D::Browser>>,
    runtime: Weak<RuntimeInner<D>>,
    instance: BrowserInstance,
    released: bool,
}

impl<D: BrowserRuntimeDriver> BrowserLease<D> {
    /// Exact instance represented by this lease.
    #[must_use]
    pub const fn instance(&self) -> &BrowserInstance {
        &self.instance
    }

    /// Lock the opaque driver handle for one operation while this activity lease remains held.
    pub async fn lock(&self) -> MutexGuard<'_, D::Browser> {
        self.inner.lock().await
    }
}

impl<D: BrowserRuntimeDriver> core::fmt::Debug for BrowserLease<D> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BrowserLease")
            .field("instance", &self.instance)
            .field("released", &self.released)
            .finish()
    }
}

impl<D: BrowserRuntimeDriver> Drop for BrowserLease<D> {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        let Some(runtime) = self.runtime.upgrade() else {
            return;
        };
        let Ok(mut state) = runtime.state.lock() else {
            return;
        };
        let Some(current) = state.live.get_mut(&self.instance.scope_key) else {
            return;
        };
        if current.instance.computer_id == self.instance.computer_id
            && current.instance.generation == self.instance.generation
        {
            current.leases = current.leases.saturating_sub(1);
            runtime.lease_released.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use openbot_contracts::ids::{
        BotId, ChannelId, ComputerGeneration, ComputerId, CredentialPrincipalId, TenantId,
    };
    use tokio::sync::Notify;

    use super::*;
    use crate::engine::WorkspaceScope;

    const BROWSER_RUNTIME_BUDGET_FIXTURE: &str =
        include_str!("../../../fixtures/computer/browser-runtime-budget.json");
    const BROWSER_RUNTIME_BUDGET_FIXTURE_BYTES: usize = 1_579;
    const BROWSER_RUNTIME_BUDGET_FIXTURE_SHA256: &str =
        "1dc491809ec8f7b84919349f492cfbff955ce034923ccc4b15858aea5c6e53ce";

    #[derive(Debug)]
    struct FakeBrowser {
        id: String,
    }

    #[derive(Clone, Default)]
    struct FakeDriver {
        launches: Arc<AtomicUsize>,
        closes: Arc<Mutex<Vec<(String, BrowserRetirementReason)>>>,
        fail_next_launch: Arc<AtomicBool>,
        block_next_launch: Arc<AtomicBool>,
        launch_started: Arc<Notify>,
        launch_release: Arc<Notify>,
    }

    impl BrowserRuntimeDriver for FakeDriver {
        type Browser = FakeBrowser;
        type Error = io::Error;

        fn launch<'a>(
            &'a self,
            instance: &'a BrowserInstance,
        ) -> BrowserDriverFuture<'a, Self::Browser, Self::Error> {
            Box::pin(async move {
                self.launches.fetch_add(1, Ordering::AcqRel);
                if self.block_next_launch.swap(false, Ordering::AcqRel) {
                    self.launch_started.notify_one();
                    self.launch_release.notified().await;
                }
                if self.fail_next_launch.swap(false, Ordering::AcqRel) {
                    return Err(io::Error::other("fixture launch failure"));
                }
                Ok(FakeBrowser {
                    id: instance.computer_id.as_str().to_owned(),
                })
            })
        }

        fn close<'a>(
            &'a self,
            browser: Self::Browser,
            reason: BrowserRetirementReason,
        ) -> BrowserDriverFuture<'a, (), Self::Error> {
            Box::pin(async move {
                self.closes.lock().unwrap().push((browser.id, reason));
                Ok(())
            })
        }
    }

    fn instance(tag: &str, generation: u64) -> BrowserInstance {
        BrowserInstance::new(
            ComputerSecurityScope::new(
                TenantId::new("tenant"),
                BotId::new(tag),
                CredentialPrincipalId::new(format!("principal-{tag}")),
                WorkspaceScope::Channel(ChannelId::new(format!("channel-{tag}"))),
            ),
            ComputerId::new(format!("computer-{tag}")),
            ComputerGeneration::new(generation),
        )
    }

    #[test]
    fn browser_runtime_budget_fixture_is_closed_and_does_not_overclaim_assembly() {
        use sha2::Digest as _;

        assert_eq!(
            BROWSER_RUNTIME_BUDGET_FIXTURE.len(),
            BROWSER_RUNTIME_BUDGET_FIXTURE_BYTES
        );
        assert_eq!(
            format!(
                "{:x}",
                sha2::Sha256::digest(BROWSER_RUNTIME_BUDGET_FIXTURE.as_bytes())
            ),
            BROWSER_RUNTIME_BUDGET_FIXTURE_SHA256
        );
        let fixture = serde_json::from_str::<serde_json::Value>(BROWSER_RUNTIME_BUDGET_FIXTURE)
            .expect("closed browser runtime fixture");
        assert_eq!(fixture["schema"], "openbot-browser-runtime-budget-v1");
        assert_eq!(
            fixture["upstream"]["commit"],
            "891df72f1827454d8b353d108fe5dd2313b7e30d"
        );
        assert_eq!(
            fixture["defaults"]["maximumLiveBrowsers"],
            DEFAULT_MAX_LIVE_BROWSERS
        );
        assert_eq!(
            fixture["defaults"]["browserIdleTimeoutMs"],
            DEFAULT_BROWSER_IDLE_TIMEOUT_MS
        );
        let mut cases = fixture["cases"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        cases.sort_unstable();
        assert_eq!(
            cases,
            [
                "allLeased",
                "capacity",
                "concurrentSameScope",
                "generation",
                "idleBoundary",
                "launchFailure",
                "shutdown",
            ]
        );
        assert_eq!(
            fixture["cases"]["allLeased"]["errorCode"],
            BrowserRuntimeError::<io::Error>::Busy.to_string()
        );
        assert_eq!(
            fixture["cases"]["generation"]["staleErrorCode"],
            BrowserRuntimeError::<io::Error>::StaleGeneration.to_string()
        );
        assert_eq!(
            fixture["cases"]["generation"]["identityConflictErrorCode"],
            BrowserRuntimeError::<io::Error>::ScopeIdentityConflict.to_string()
        );
        assert_eq!(
            fixture["cases"]["launchFailure"]["errorCode"],
            BrowserRuntimeError::Launch(io::Error::other("canary")).to_string()
        );
        assert_eq!(
            fixture["cases"]["shutdown"]["newLeaseErrorCode"],
            BrowserRuntimeError::<io::Error>::Closed.to_string()
        );
        assert_eq!(fixture["evidenceBoundary"]["pureSelector"], true);
        assert_eq!(
            fixture["evidenceBoundary"]["managerOwnsDriverHandles"],
            true
        );
        assert_eq!(
            fixture["evidenceBoundary"]["serverOrDesktopEngineAssembly"],
            false
        );
        assert_eq!(fixture["evidenceBoundary"]["cpuRssPidsDiskBudget"], false);
    }

    #[test]
    fn typed_budget_keeps_fixed_defaults_and_rejects_zero_capacity() {
        assert_eq!(
            BrowserRuntimeBudget::default(),
            BrowserRuntimeBudget::new(8, 1_800_000).unwrap()
        );
        assert_eq!(
            BrowserRuntimeBudget::new(0, 1).unwrap_err(),
            BrowserBudgetError::ZeroMaximum
        );
        assert_eq!(
            BrowserRuntimeBudget::new(1, 0).unwrap().idle_timeout_ms(),
            None
        );
    }

    #[test]
    fn runtime_errors_expose_only_stable_codes_in_display_and_debug() {
        let error = BrowserRuntimeError::Launch(io::Error::other("DRIVER_SECRET_CANARY"));
        assert_eq!(error.to_string(), "computer_launch_failed");
        assert_eq!(format!("{error:?}"), "computer_launch_failed");
        assert!(!error.to_string().contains("DRIVER_SECRET_CANARY"));
        assert!(!format!("{error:?}").contains("DRIVER_SECRET_CANARY"));
    }

    #[tokio::test]
    async fn concurrent_cold_requests_for_one_scope_launch_exactly_once() {
        let driver = FakeDriver::default();
        driver.block_next_launch.store(true, Ordering::Release);
        let manager = BrowserRuntimeManager::new(driver.clone(), BrowserRuntimeBudget::default());
        let wanted = instance("a", 1);
        let first = {
            let manager = manager.clone();
            let wanted = wanted.clone();
            tokio::spawn(async move { manager.ensure(wanted, 1).await })
        };
        driver.launch_started.notified().await;
        let second = {
            let manager = manager.clone();
            let wanted = wanted.clone();
            tokio::spawn(async move { manager.ensure(wanted, 2).await })
        };
        driver.launch_release.notify_one();
        let first = first.await.unwrap().unwrap();
        let second = second.await.unwrap().unwrap();
        assert_eq!(driver.launches.load(Ordering::Acquire), 1);
        assert_eq!(manager.live_count().unwrap(), 1);
        assert_eq!(first.lock().await.id, "computer-a");
        assert_eq!(second.lock().await.id, "computer-a");
    }

    #[tokio::test]
    async fn cap_retires_inactive_lru_and_never_the_new_browser() {
        let driver = FakeDriver::default();
        let manager = BrowserRuntimeManager::new(
            driver.clone(),
            BrowserRuntimeBudget::new(2, 1_000).unwrap(),
        );
        let a = instance("a", 1);
        let b = instance("b", 1);
        let c = instance("c", 1);
        drop(manager.ensure(a.clone(), 1).await.unwrap());
        drop(manager.ensure(b.clone(), 2).await.unwrap());
        drop(manager.ensure(a.clone(), 3).await.unwrap());
        drop(manager.ensure(c.clone(), 4).await.unwrap());
        assert!(manager.is_live(&a).unwrap());
        assert!(!manager.is_live(&b).unwrap());
        assert!(manager.is_live(&c).unwrap());
        assert_eq!(manager.live_count().unwrap(), 2);
        assert_eq!(
            driver.closes.lock().unwrap().as_slice(),
            [("computer-b".to_owned(), BrowserRetirementReason::Capacity)]
        );
    }

    #[tokio::test]
    async fn all_slots_leased_refuses_before_an_extra_launch() {
        let driver = FakeDriver::default();
        let manager = BrowserRuntimeManager::new(
            driver.clone(),
            BrowserRuntimeBudget::new(1, 1_000).unwrap(),
        );
        let held = manager.ensure(instance("a", 1), 1).await.unwrap();
        assert!(matches!(
            manager.ensure(instance("b", 1), 2).await,
            Err(BrowserRuntimeError::Busy)
        ));
        assert_eq!(driver.launches.load(Ordering::Acquire), 1);
        drop(held);
        drop(manager.ensure(instance("b", 1), 3).await.unwrap());
        assert_eq!(driver.launches.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn idle_sweep_uses_inclusive_boundary_and_skips_leased_handles() {
        let driver = FakeDriver::default();
        let manager =
            BrowserRuntimeManager::new(driver.clone(), BrowserRuntimeBudget::new(3, 10).unwrap());
        drop(manager.ensure(instance("a", 1), 0).await.unwrap());
        let held = manager.ensure(instance("b", 1), 0).await.unwrap();
        assert_eq!(manager.sweep_idle(10).await.unwrap(), 1);
        assert_eq!(manager.live_count().unwrap(), 1);
        drop(held);
        assert_eq!(manager.sweep_idle(10).await.unwrap(), 1);
        assert_eq!(manager.live_count().unwrap(), 0);
        assert!(
            driver
                .closes
                .lock()
                .unwrap()
                .iter()
                .all(|(_, reason)| *reason == BrowserRetirementReason::Idle)
        );
    }

    #[tokio::test]
    async fn generation_advance_retires_old_and_stale_or_colliding_identity_fails_closed() {
        let driver = FakeDriver::default();
        let manager = BrowserRuntimeManager::new(driver.clone(), BrowserRuntimeBudget::default());
        let first = instance("a", 1);
        drop(manager.ensure(first.clone(), 0).await.unwrap());
        let mut stale = first.clone();
        stale.generation = ComputerGeneration::new(0);
        assert!(matches!(
            manager.ensure(stale, 1).await,
            Err(BrowserRuntimeError::StaleGeneration)
        ));
        let mut collision = first.clone();
        collision.computer_id = ComputerId::new("other-computer");
        assert!(matches!(
            manager.ensure(collision, 1).await,
            Err(BrowserRuntimeError::ScopeIdentityConflict)
        ));
        let mut advanced = first.clone();
        advanced.generation = ComputerGeneration::new(2);
        drop(manager.ensure(advanced.clone(), 2).await.unwrap());
        assert!(manager.is_live(&advanced).unwrap());
        assert_eq!(
            driver.closes.lock().unwrap().as_slice(),
            [(
                "computer-a".to_owned(),
                BrowserRetirementReason::GenerationAdvanced
            )]
        );
    }

    #[tokio::test]
    async fn failed_launch_restores_the_reserved_lru_victim() {
        let driver = FakeDriver::default();
        let manager =
            BrowserRuntimeManager::new(driver.clone(), BrowserRuntimeBudget::new(1, 100).unwrap());
        let first = instance("a", 1);
        drop(manager.ensure(first.clone(), 0).await.unwrap());
        driver.fail_next_launch.store(true, Ordering::Release);
        assert!(matches!(
            manager.ensure(instance("b", 1), 1).await,
            Err(BrowserRuntimeError::Launch(_))
        ));
        assert!(manager.is_live(&first).unwrap());
        assert_eq!(manager.live_count().unwrap(), 1);
        assert!(driver.closes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn drain_waits_for_owned_lease_and_old_identity_cannot_stop_replacement() {
        let driver = FakeDriver::default();
        let manager = BrowserRuntimeManager::new(driver.clone(), BrowserRuntimeBudget::default());
        let first = instance("a", 1);
        let lease = manager.ensure(first.clone(), 0).await.unwrap();
        let drain = {
            let manager = manager.clone();
            let first = first.clone();
            tokio::spawn(async move {
                manager
                    .stop_after_drain(&first, std::time::Duration::from_secs(1))
                    .await
            })
        };
        tokio::task::yield_now().await;
        assert!(driver.closes.lock().unwrap().is_empty());
        drop(lease);
        assert!(drain.await.unwrap().unwrap());
        let replacement = instance("a", 2);
        drop(manager.ensure(replacement.clone(), 1).await.unwrap());
        assert!(matches!(
            manager.stop(&first).await,
            Err(BrowserRuntimeError::StaleGeneration)
        ));
        assert!(manager.is_live(&replacement).unwrap());
        assert_eq!(manager.resident_instances().unwrap(), vec![replacement]);
    }

    #[tokio::test]
    async fn bounded_drain_does_not_spin_or_report_an_active_instance_stopped() {
        let manager =
            BrowserRuntimeManager::new(FakeDriver::default(), BrowserRuntimeBudget::default());
        let first = instance("a", 1);
        let held = manager.ensure(first.clone(), 0).await.unwrap();
        assert!(matches!(
            manager
                .stop_after_drain(&first, std::time::Duration::from_millis(1))
                .await,
            Err(BrowserRuntimeError::Busy)
        ));
        assert!(manager.is_live(&first).unwrap());
        drop(held);
        assert!(
            manager
                .stop_after_drain(&first, std::time::Duration::from_secs(1))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn explicit_stop_and_shutdown_require_inactive_leases_and_close_exactly_once() {
        let driver = FakeDriver::default();
        let manager = BrowserRuntimeManager::new(driver.clone(), BrowserRuntimeBudget::default());
        let first = instance("a", 1);
        let held = manager.ensure(first.clone(), 0).await.unwrap();
        assert!(matches!(
            manager.stop(&first).await,
            Err(BrowserRuntimeError::Busy)
        ));
        assert!(matches!(
            manager.close_all().await,
            Err(BrowserRuntimeError::Busy)
        ));
        drop(held);
        assert_eq!(manager.close_all().await.unwrap(), 1);
        assert!(matches!(
            manager.ensure(instance("b", 1), 1).await,
            Err(BrowserRuntimeError::Closed)
        ));
        assert_eq!(
            driver.closes.lock().unwrap().as_slice(),
            [("computer-a".to_owned(), BrowserRetirementReason::Shutdown)]
        );
    }
}
