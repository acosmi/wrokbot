//! macOS integration of the narrow native owner with shared host confirmation state.
//! No Objective-C types, unsafe code, OS credentials or renderer input enter this module.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use openbot_contracts::error::AppError;
use openbot_contracts::ui::UiLocale;
use tokio::sync::oneshot;
use wrok_bot_macos_local_auth::{
    ConfirmationLocale, LocalAuthOutcome, MacLocalAuthOwner,
    session::{self, CleanupTicket, Invalidation, MonitorHandle},
};

use crate::local_confirmation::{
    ClockSample, NativeCompletionToken, NativeDisposition, NativeOutcome,
};
use crate::local_confirmation_authority::PostgresLocalConfirmationAuthority;
use crate::local_confirmation_host::LocalConfirmationForeground;
use crate::local_confirmation_host::{LocalConfirmationHost, TauriLocalConfirmationDispatcher};
use crate::local_confirmation_service::{
    LocalConfirmationNative, LocalConfirmationService, sample_now,
};
use crate::tauri_host::DesktopTauriProtocol;

pub(crate) struct MacLocalConfirmationNative {
    owner: Arc<MacLocalAuthOwner>,
    monitor: MonitorHandle,
    cleanup: CleanupTicket,
    stopping: AtomicBool,
}

pub(crate) struct PreparedMacLocalConfirmation {
    instance_id: String,
    authority: Arc<PostgresLocalConfirmationAuthority>,
}

impl PreparedMacLocalConfirmation {
    pub(crate) fn new(
        installation: &openbot_infra::auth::single_user::desktop_local::DesktopLocalAuthority,
        pool: openbot_infra::db::pool::DatabasePool,
    ) -> Self {
        Self {
            instance_id: installation.instance_id().to_owned(),
            authority: Arc::new(PostgresLocalConfirmationAuthority::new(
                installation.clone(),
                pool,
            )),
        }
    }

    pub(crate) fn install(
        self,
        app: tauri::AppHandle<tauri::Wry>,
        protocol: &Arc<DesktopTauriProtocol>,
    ) -> Result<(), AppError> {
        let native = Arc::new(MacLocalConfirmationNative::new(protocol)?);
        let result = (|| {
            let service = Arc::new(LocalConfirmationService::new(
                &self.instance_id,
                self.authority,
                Some(native.clone()),
            )?);
            let dispatcher = Arc::new(TauriLocalConfirmationDispatcher::new(
                app,
                protocol,
                native.clone(),
            ));
            protocol
                .install_local_confirmation(LocalConfirmationHost {
                    service,
                    dispatcher,
                })
                .map_err(|_| unavailable())
        })();
        if result.is_err() {
            // The caller is still on the native thread; construction failure must not leave
            // live notification callbacks after dropping the prospective host owner.
            let _ = native.cleanup_on_main_thread();
        }
        result
    }
}

fn unavailable() -> AppError {
    AppError::DependencyUnavailable {
        dependency: "desktop_local_confirmation_native",
    }
}

impl MacLocalConfirmationNative {
    /// Called only on the actual native main thread, before the first window is admitted.
    pub(crate) fn new(protocol: &Arc<DesktopTauriProtocol>) -> Result<Self, AppError> {
        let owner = Arc::new(MacLocalAuthOwner::new().map_err(|_| unavailable())?);
        let weak = Arc::downgrade(protocol);
        let monitor = session::start(move |event| {
            if let Some(protocol) = weak.upgrade() {
                match event.invalidation() {
                    Invalidation::ClearExistingGrant => {
                        // This path changes only the coordinator's grant epoch. The native
                        // callback does not acquire or wait for the windows registry.
                        let _ = protocol.clear_existing_confirmations();
                    }
                    Invalidation::InvalidateAll => protocol.invalidate_local_confirmations(),
                }
            }
        })
        .map_err(|_| unavailable())?;
        let cleanup = monitor.cleanup_ticket();
        Ok(Self {
            owner,
            monitor,
            cleanup,
            stopping: AtomicBool::new(false),
        })
    }
}

impl LocalConfirmationNative for MacLocalConfirmationNative {
    fn is_available(&self) -> bool {
        !self.stopping.load(Ordering::SeqCst) && self.owner.is_running() && self.monitor.is_live()
    }

    fn start(
        &self,
        locale: UiLocale,
        completion: NativeCompletionToken,
    ) -> Result<oneshot::Receiver<NativeDisposition>, AppError> {
        if !self.is_available() {
            let _ = completion.record_outcome(NativeOutcome::Unavailable, sample_now());
            completion.native_stopped(); // This request never reached the native owner.
            return Err(unavailable());
        }
        let locale = match locale {
            UiLocale::En => ConfirmationLocale::English,
            UiLocale::ZhCn => ConfirmationLocale::SimplifiedChinese,
        };
        let attempt = match self.owner.begin(locale) {
            Ok(attempt) => attempt,
            Err(_) => {
                let _ = completion.record_outcome(NativeOutcome::Unavailable, sample_now());
                completion.native_stopped(); // No native evaluation was created for this token.
                return Err(unavailable());
            }
        };
        let cancelled = completion.cancellation();
        let owner = Arc::clone(&self.owner);
        let (sender, receiver) = oneshot::channel();
        // This independent bounded owner survives the requesting HTTP future. The coordinator
        // retains its single native slot until this task observes real retirement; a timeout
        // cannot create an unbounded population of dialogs or background waiters.
        tauri::async_runtime::spawn(async move {
            let _owner = owner; // Preserve the native owner's weak-reference retirement checks.
            let mut sender = Some(sender);
            let mut cancellation_sent = false;
            loop {
                if cancelled.is_cancelled() && !cancellation_sent {
                    attempt.cancel();
                    cancellation_sent = true;
                }
                if let Some(outcome) = attempt.try_take_outcome() {
                    let outcome = match outcome {
                        LocalAuthOutcome::Confirmed(proof)
                            if proof.attempt_id() == attempt.id() =>
                        {
                            NativeOutcome::Succeeded {
                                at: ClockSample::new(
                                    proof.confirmed_at(),
                                    proof.confirmed_at_wall(),
                                ),
                            }
                        }
                        LocalAuthOutcome::Cancelled => NativeOutcome::Cancelled,
                        LocalAuthOutcome::Confirmed(_)
                        | LocalAuthOutcome::TimedOut
                        | LocalAuthOutcome::Stopped
                        | LocalAuthOutcome::Unavailable => NativeOutcome::Unavailable,
                    };
                    let disposition = completion
                        .record_outcome(outcome, sample_now())
                        .unwrap_or(NativeDisposition::Rejected);
                    if let Some(sender) = sender.take() {
                        let _ = sender.send(disposition);
                    }
                }
                if attempt.is_stopped() {
                    // A closed response is delivered separately from releasing this native slot.
                    // Native receipt means own references retired, not all framework/UI quiescence.
                    completion.native_stopped();
                    return;
                }
                if cancellation_sent {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                } else {
                    tokio::select! {
                        () = cancelled.cancelled() => {},
                        () = tokio::time::sleep(Duration::from_millis(25)) => {},
                    }
                }
            }
        });
        Ok(receiver)
    }

    fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        self.monitor.close_callbacks();
        self.owner.stop();
    }
}

impl LocalConfirmationForeground for MacLocalConfirmationNative {
    fn current_app_is_active(&self) -> Result<bool, AppError> {
        if !self.is_available() {
            return Err(unavailable());
        }
        session::current_app_is_active().map_err(|_| unavailable())
    }

    fn cleanup_on_main_thread(&self) -> Result<(), AppError> {
        self.stop();
        self.cleanup
            .cleanup_on_main_thread()
            .map(|_| ())
            .map_err(|_| unavailable())
    }

    fn is_native_stopped(&self) -> bool {
        self.owner.is_stopped()
    }
}

impl Drop for MacLocalConfirmationNative {
    fn drop(&mut self) {
        self.stop();
    }
}
