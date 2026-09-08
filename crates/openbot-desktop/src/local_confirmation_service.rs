//! Local-only orchestration. Window admission and receipt installation run as owned host jobs.
//! The host executes each job on its native main thread under the current windows-map read lock.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use openbot_contracts::auth::AuthContext;
use openbot_contracts::desktop::local_confirmation::{
    LOCAL_CONFIRMATION_WAIT_SECONDS, LocalConfirmationReceipt, LocalConfirmationStatus,
};
use openbot_contracts::error::AppError;
use openbot_contracts::ui::UiLocale;
use tokio::sync::{Semaphore, oneshot};

use crate::CancellationToken;
use crate::local_confirmation::{
    AttemptCancellation, ClockSample, ConfirmationAttempt, ConfirmationError, GrantHandle,
    LocalConfirmationCoordinator, NativeCompletionToken, NativeDisposition,
};
use crate::local_confirmation_authority::LocalConfirmationAuthority;

const POST_WAIT: Duration = Duration::from_secs(LOCAL_CONFIRMATION_WAIT_SECONDS as u64);

/// Rust-only owner/monitor health. These methods must not call OS preflight or acquire host
/// window locks. The independent native owner retains completion after request cancellation,
/// and alone acknowledges retirement, including a partially failed start.
pub(crate) trait LocalConfirmationNative: Send + Sync {
    fn is_available(&self) -> bool;
    fn start(
        &self,
        locale: UiLocale,
        completion: NativeCompletionToken,
    ) -> Result<oneshot::Receiver<NativeDisposition>, AppError>;
    fn stop(&self);
}

/// The implementation checks actual native foreground/runtime before acquiring its windows
/// read lock, then calls execute with the current binding while retaining that lock. It must
/// drop a returned attempt if delivery to the requesting future fails. No job can be cloned.
#[async_trait]
pub(crate) trait LocalConfirmationWindow: Send + Sync {
    async fn prepare(&self, job: PrepareLocalConfirmation)
    -> Result<ConfirmationAttempt, AppError>;

    async fn finish(
        &self,
        job: FinishLocalConfirmation,
    ) -> Result<LocalConfirmationReceipt, AppError>;
}

/// Shared whole-request deadline, starting at POST entry before PG/admission work. Sampling
/// under this private clock mutex avoids mistaking out-of-order callers for clock rollback.
#[derive(Clone)]
struct RequestBudget {
    clocks: Arc<Mutex<BudgetClocks>>,
    deadline: tokio::time::Instant,
    wait: Duration,
}

struct BudgetClocks {
    began_monotonic: Instant,
    began_wall: SystemTime,
    last_monotonic: Instant,
    last_wall: SystemTime,
}

impl RequestBudget {
    fn new(wait: Duration) -> Result<Self, AppError> {
        let monotonic = Instant::now();
        let wall = SystemTime::now();
        let deadline = monotonic.checked_add(wait).ok_or_else(unavailable)?;
        Ok(Self {
            clocks: Arc::new(Mutex::new(BudgetClocks {
                began_monotonic: monotonic,
                began_wall: wall,
                last_monotonic: monotonic,
                last_wall: wall,
            })),
            deadline: tokio::time::Instant::from_std(deadline),
            wait,
        })
    }

    fn sample(&self) -> Result<ClockSample, AppError> {
        let mut clocks = self.clocks.lock().map_err(|_| unavailable())?;
        let monotonic = Instant::now();
        let wall = SystemTime::now();
        if monotonic < clocks.last_monotonic || wall < clocks.last_wall {
            return Err(unavailable());
        }
        let elapsed_monotonic = monotonic
            .checked_duration_since(clocks.began_monotonic)
            .ok_or_else(unavailable)?;
        let elapsed_wall = wall
            .duration_since(clocks.began_wall)
            .map_err(|_| unavailable())?;
        if elapsed_monotonic >= self.wait || elapsed_wall >= self.wait {
            return Err(unavailable());
        }
        clocks.last_monotonic = monotonic;
        clocks.last_wall = wall;
        Ok(ClockSample::new(monotonic, wall))
    }

    fn sample_and_invalidate(
        &self,
        coordinator: &LocalConfirmationCoordinator,
    ) -> Result<ClockSample, AppError> {
        self.sample().inspect_err(|_| coordinator.invalidate_all())
    }
}

/// This state is distinct from native cancellation: a user-cancel callback legitimately
/// cancels the native token before its Cancelled disposition arrives.
struct RequestGuard {
    cancelled: Arc<Mutex<bool>>,
}

impl RequestGuard {
    fn new() -> Self {
        Self {
            cancelled: Arc::new(Mutex::new(false)),
        }
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        *self
            .cancelled
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
    }
}

/// Preserved by the service after moving the attempt into a queued finish job. Cancellation
/// and install use the same coordinator mutex, rather than racing a token check against CAS.
struct AttemptGuard(AttemptCancellation);

impl Drop for AttemptGuard {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

struct JobContext {
    coordinator: Arc<LocalConfirmationCoordinator>,
    original: GrantHandle,
    closed: CancellationToken,
    request_cancelled: Arc<Mutex<bool>>,
    budget: RequestBudget,
    native: Arc<dyn LocalConfirmationNative>,
}

impl JobContext {
    fn check_current<'a>(
        &'a self,
        current: &GrantHandle,
    ) -> Result<MutexGuard<'a, bool>, AppError> {
        // Additional fixed lock order: host windows -> request -> coordinator -> binding.
        // Budget sampling holds only its own short clock lock, never over a native call.
        let request = self.request_cancelled.lock().map_err(|_| unavailable())?;
        if *request || self.closed.is_cancelled() {
            return Err(AppError::Unauthenticated);
        }
        if !self.original.is_same_binding(current) {
            self.original.revoke();
            return Err(AppError::Unauthenticated);
        }
        if !self.native.is_available() {
            self.coordinator.set_available(false);
            return Err(unavailable());
        }
        Ok(request)
    }
}

/// Owned admission work; only the service can construct it. No renderer authority fields.
pub(crate) struct PrepareLocalConfirmation {
    context: JobContext,
    prechecked: AuthContext,
}

impl PrepareLocalConfirmation {
    /// Host calls only under its current native-window guard on the main thread.
    pub(crate) fn execute(self, current: &GrantHandle) -> Result<ConfirmationAttempt, AppError> {
        let _request = self.context.check_current(current)?;
        let now = self
            .context
            .budget
            .sample_and_invalidate(&self.context.coordinator)?;
        // Only an explicit new attempt restores availability, never a health/status read.
        self.context.coordinator.set_available(true);
        self.context
            .coordinator
            .begin(&self.context.original, &self.prechecked, now)
            .map_err(confirmation_error)
    }
}

enum FinishAction {
    Confirmed(AuthContext),
    Cancelled,
}

/// Owned final receipt work. The attempt cannot escape as a cloned handle for later worker CAS.
pub(crate) struct FinishLocalConfirmation {
    context: JobContext,
    attempt: ConfirmationAttempt,
    action: FinishAction,
}

impl FinishLocalConfirmation {
    /// Cancellation receipts need current binding/runtime, but not regained foreground.
    pub(crate) fn requires_foreground(&self) -> bool {
        matches!(self.action, FinishAction::Confirmed(_))
    }

    /// Host calls only under the same current windows-map guard as its binding check.
    pub(crate) fn execute(
        self,
        current: &GrantHandle,
    ) -> Result<LocalConfirmationReceipt, AppError> {
        let Self {
            context,
            attempt,
            action,
        } = self;
        let _request = context.check_current(current)?;
        let now = context.budget.sample_and_invalidate(&context.coordinator)?;
        match action {
            FinishAction::Confirmed(postchecked) => attempt.install(current, &postchecked, now),
            FinishAction::Cancelled => attempt.cancel(now),
        }
        .map_err(confirmation_error)
    }
}

pub(crate) struct LocalConfirmationService {
    coordinator: Arc<LocalConfirmationCoordinator>,
    authority: Arc<dyn LocalConfirmationAuthority>,
    native: Option<Arc<dyn LocalConfirmationNative>>,
    // Includes PG precheck: no unbounded precheck queue before native singleflight.
    admission: Semaphore,
    #[cfg(test)]
    test_wait: Duration,
}

pub(crate) fn sample_now() -> ClockSample {
    ClockSample::new(Instant::now(), SystemTime::now())
}

pub(crate) fn confirmation_error(error: ConfirmationError) -> AppError {
    match error {
        ConfirmationError::InvalidScope | ConfirmationError::NotCurrent => {
            AppError::Unauthenticated
        }
        ConfirmationError::Busy => AppError::RequestConflict {
            resource: "desktop_local_confirmation",
        },
        ConfirmationError::Unavailable
        | ConfirmationError::Expired
        | ConfirmationError::ClockRegression
        | ConfirmationError::StaleClockSample
        | ConfirmationError::InvalidState
        | ConfirmationError::Exhausted
        | ConfirmationError::Poisoned => unavailable(),
    }
}

fn unavailable() -> AppError {
    AppError::DependencyUnavailable {
        dependency: "desktop_local_confirmation",
    }
}

impl LocalConfirmationService {
    pub(crate) fn new(
        instance_id: &str,
        authority: Arc<dyn LocalConfirmationAuthority>,
        native: Option<Arc<dyn LocalConfirmationNative>>,
    ) -> Result<Self, AppError> {
        let available = native.as_ref().is_some_and(|native| native.is_available());
        Ok(Self {
            coordinator: Arc::new(
                LocalConfirmationCoordinator::new(instance_id, available)
                    .map_err(confirmation_error)?,
            ),
            authority,
            native,
            admission: Semaphore::new(1),
            #[cfg(test)]
            test_wait: POST_WAIT,
        })
    }

    fn budget(&self) -> Result<RequestBudget, AppError> {
        #[cfg(test)]
        let wait = self.test_wait;
        #[cfg(not(test))]
        let wait = POST_WAIT;
        RequestBudget::new(wait).inspect_err(|_| self.coordinator.invalidate_all())
    }

    pub(crate) fn register_binding(
        &self,
        binding_id: u64,
        auth: &AuthContext,
    ) -> Result<GrantHandle, AppError> {
        self.coordinator
            .register_binding(binding_id, auth)
            .map_err(confirmation_error)
    }

    /// Health is a pure owner/monitor fact, not successful LA canEvaluatePolicy. Recovery
    /// returns true without restoring the old epoch or automatically enabling a new grant.
    pub(crate) fn is_native_available(&self) -> bool {
        let available = self
            .native
            .as_ref()
            .is_some_and(|native| native.is_available());
        if !available {
            self.coordinator.set_available(false);
        }
        available
    }

    async fn verify(
        &self,
        expected: &AuthContext,
        closed: &CancellationToken,
        budget: &RequestBudget,
        native_cancelled: Option<&CancellationToken>,
    ) -> Result<AuthContext, AppError> {
        if closed.is_cancelled() {
            return Err(AppError::Unauthenticated);
        }
        budget.sample_and_invalidate(&self.coordinator)?;
        let result = tokio::select! {
            biased;
            () = closed.cancelled() => return Err(AppError::Unauthenticated),
            () = async {
                match native_cancelled {
                    Some(cancelled) => cancelled.cancelled().await,
                    None => std::future::pending::<()>().await,
                }
            } => return Err(unavailable()),
            () = tokio::time::sleep_until(budget.deadline) => {
                self.coordinator.invalidate_all();
                return Err(unavailable());
            },
            verified = self.authority.verify_current(expected) => verified,
        };
        let current = match result {
            Ok(current) if current == *expected => current,
            Ok(_) => {
                self.coordinator.invalidate_all();
                return Err(AppError::Unauthenticated);
            }
            Err(error) => {
                self.coordinator.invalidate_all();
                return Err(error);
            }
        };
        if closed.is_cancelled() {
            return Err(AppError::Unauthenticated);
        }
        // Includes PG returning successfully only after the wall/monotonic budget expired.
        budget.sample_and_invalidate(&self.coordinator)?;
        Ok(current)
    }

    pub(crate) async fn status(
        &self,
        grant: &GrantHandle,
        expected: &AuthContext,
        closed: &CancellationToken,
    ) -> Result<LocalConfirmationStatus, AppError> {
        let budget = self.budget()?;
        self.is_native_available();
        self.verify(expected, closed, &budget, None).await?;
        self.read_status(grant, closed, &budget)
    }

    fn read_status(
        &self,
        grant: &GrantHandle,
        closed: &CancellationToken,
        budget: &RequestBudget,
    ) -> Result<LocalConfirmationStatus, AppError> {
        if closed.is_cancelled() {
            return Err(AppError::Unauthenticated);
        }
        // Only repeat a pure read on a conservatively rejected concurrent clock sample.
        match grant.status(budget.sample_and_invalidate(&self.coordinator)?) {
            Err(ConfirmationError::StaleClockSample) => grant
                .status(budget.sample_and_invalidate(&self.coordinator)?)
                .map_err(confirmation_error),
            result => result.map_err(confirmation_error),
        }
    }

    pub(crate) async fn confirm(
        &self,
        grant: &GrantHandle,
        expected: &AuthContext,
        closed: &CancellationToken,
        locale: UiLocale,
        window: &dyn LocalConfirmationWindow,
    ) -> Result<LocalConfirmationReceipt, AppError> {
        let budget = self.budget()?;
        let request = RequestGuard::new();
        if closed.is_cancelled() {
            return Err(AppError::Unauthenticated);
        }
        let _admission = self
            .admission
            .try_acquire()
            .map_err(|_| AppError::RequestConflict {
                resource: "desktop_local_confirmation",
            })?;
        if !self.is_native_available() {
            return Err(unavailable());
        }
        let native = self.native.as_ref().cloned().ok_or_else(unavailable)?;
        let prechecked = self.verify(expected, closed, &budget, None).await?;
        let context = || JobContext {
            coordinator: Arc::clone(&self.coordinator),
            original: grant.clone(),
            closed: closed.clone(),
            request_cancelled: Arc::clone(&request.cancelled),
            budget: budget.clone(),
            native: Arc::clone(&native),
        };
        let prepare = PrepareLocalConfirmation {
            context: context(),
            prechecked,
        };
        let mut attempt = tokio::select! {
            biased;
            () = closed.cancelled() => return Err(AppError::Unauthenticated),
            () = tokio::time::sleep_until(budget.deadline) => {
                self.coordinator.invalidate_all();
                return Err(unavailable());
            },
            prepared = window.prepare(prepare) => prepared?,
        };
        let _attempt_guard = AttemptGuard(attempt.cancellation_handle());
        if closed.is_cancelled() {
            return Err(AppError::Unauthenticated);
        }
        if !self.is_native_available() {
            return Err(unavailable());
        }
        let completion = attempt
            .start_native(budget.sample_and_invalidate(&self.coordinator)?)
            .map_err(confirmation_error)?;
        let cancelled = completion.cancellation();
        // Synchronous dispatch only: this trait must never wait for a system dialog.
        let received = native.start(locale, completion)?;
        let disposition = tokio::select! {
            biased;
            () = closed.cancelled() => return Err(AppError::Unauthenticated),
            () = tokio::time::sleep_until(budget.deadline) => {
                self.coordinator.invalidate_all();
                return Err(unavailable());
            },
            result = received => result.map_err(|_| unavailable())?,
        };
        // A normal native Cancelled sets its cancellation token before sending this disposition.
        // Never race that token against outcome delivery here.
        let action = match disposition {
            NativeDisposition::Cancelled => FinishAction::Cancelled,
            NativeDisposition::Unavailable => {
                self.coordinator.set_available(false);
                return Err(unavailable());
            }
            NativeDisposition::Rejected => return Err(AppError::Unauthenticated),
            NativeDisposition::NeedsPostcheck => FinishAction::Confirmed(
                self.verify(expected, closed, &budget, Some(&cancelled))
                    .await?,
            ),
        };
        let finish = FinishLocalConfirmation {
            context: context(),
            attempt,
            action,
        };
        tokio::select! {
            biased;
            () = closed.cancelled() => Err(AppError::Unauthenticated),
            () = tokio::time::sleep_until(budget.deadline) => {
                self.coordinator.invalidate_all();
                Err(unavailable())
            },
            receipt = window.finish(finish) => receipt,
        }
    }

    pub(crate) fn invalidate_all(&self) {
        self.coordinator.invalidate_all();
    }

    pub(crate) fn clear_existing_grants(&self) {
        self.coordinator.clear_existing_grants();
    }

    pub(crate) fn shutdown(&self) {
        self.coordinator.shutdown();
        if let Some(native) = &self.native {
            native.stop();
        }
    }
}

impl Drop for LocalConfirmationService {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
#[path = "local_confirmation_service_tests.rs"]
mod tests;
