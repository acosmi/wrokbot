//! Native main-thread dispatch for Local confirmation. No renderer supplies this authority.

use std::sync::{Arc, Weak};

use async_trait::async_trait;
use openbot_contracts::desktop::local_confirmation::LocalConfirmationReceipt;
use openbot_contracts::error::AppError;
use tauri::{AppHandle, Manager, Runtime};
use tokio::sync::oneshot;

use crate::local_confirmation::ConfirmationAttempt;
use crate::local_confirmation_service::{
    FinishLocalConfirmation, LocalConfirmationService, LocalConfirmationWindow,
    PrepareLocalConfirmation,
};
use crate::tauri_host::DesktopTauriProtocol;

/// This getter must read the actual application on its native main thread. It must not activate
/// or focus the application, poll LocalAuthentication, or infer foreground from renderer state.
pub(crate) trait LocalConfirmationForeground: Send + Sync {
    fn current_app_is_active(&self) -> Result<bool, AppError>;
    fn cleanup_on_main_thread(&self) -> Result<(), AppError>;
    fn is_native_stopped(&self) -> bool;
}

#[async_trait]
pub(crate) trait LocalConfirmationDispatcher: Send + Sync {
    fn cleanup_on_main_thread(&self) -> Result<(), AppError>;
    fn is_native_stopped(&self) -> bool;

    async fn prepare(
        &self,
        label: &str,
        binding_id: u64,
        job: PrepareLocalConfirmation,
    ) -> Result<ConfirmationAttempt, AppError>;

    async fn finish(
        &self,
        label: &str,
        binding_id: u64,
        job: FinishLocalConfirmation,
    ) -> Result<LocalConfirmationReceipt, AppError>;
}

pub(crate) struct LocalConfirmationHost {
    pub(crate) service: Arc<LocalConfirmationService>,
    pub(crate) dispatcher: Arc<dyn LocalConfirmationDispatcher>,
}

pub(crate) struct BoundLocalConfirmationWindow<'a> {
    pub(crate) dispatcher: &'a dyn LocalConfirmationDispatcher,
    pub(crate) label: &'a str,
    pub(crate) binding_id: u64,
}

#[async_trait]
impl LocalConfirmationWindow for BoundLocalConfirmationWindow<'_> {
    async fn prepare(
        &self,
        job: PrepareLocalConfirmation,
    ) -> Result<ConfirmationAttempt, AppError> {
        self.dispatcher
            .prepare(self.label, self.binding_id, job)
            .await
    }

    async fn finish(
        &self,
        job: FinishLocalConfirmation,
    ) -> Result<LocalConfirmationReceipt, AppError> {
        self.dispatcher
            .finish(self.label, self.binding_id, job)
            .await
    }
}

/// The protocol owns this dispatcher, so the reverse reference is weak. Dropping a requesting
/// future does not make a queued main-thread closure current: each job owns explicit cancellation
/// and its original deadline, and checks them again while holding the current window guard.
pub(crate) struct TauriLocalConfirmationDispatcher<R: Runtime> {
    app: AppHandle<R>,
    protocol: Weak<DesktopTauriProtocol>,
    foreground: Arc<dyn LocalConfirmationForeground>,
}

impl<R: Runtime> TauriLocalConfirmationDispatcher<R> {
    pub(crate) fn new(
        app: AppHandle<R>,
        protocol: &Arc<DesktopTauriProtocol>,
        foreground: Arc<dyn LocalConfirmationForeground>,
    ) -> Self {
        Self {
            app,
            protocol: Arc::downgrade(protocol),
            foreground,
        }
    }
}

fn unavailable() -> AppError {
    AppError::DependencyUnavailable {
        dependency: "desktop_local_confirmation_window",
    }
}

/// Only call inside run_on_main_thread, before acquiring the protocol's window registry lock.
fn foreground_window<R: Runtime>(
    app: &AppHandle<R>,
    label: &str,
    foreground: &dyn LocalConfirmationForeground,
) -> Result<(), AppError> {
    let window = app
        .get_webview_window(label)
        .ok_or(AppError::Unauthenticated)?;
    if !window.is_focused().map_err(|_| unavailable())? || !foreground.current_app_is_active()? {
        return Err(unavailable());
    }
    Ok(())
}

#[async_trait]
impl<R: Runtime> LocalConfirmationDispatcher for TauriLocalConfirmationDispatcher<R> {
    fn cleanup_on_main_thread(&self) -> Result<(), AppError> {
        self.foreground.cleanup_on_main_thread()
    }

    fn is_native_stopped(&self) -> bool {
        self.foreground.is_native_stopped()
    }

    async fn prepare(
        &self,
        label: &str,
        binding_id: u64,
        job: PrepareLocalConfirmation,
    ) -> Result<ConfirmationAttempt, AppError> {
        let (sender, receiver) = oneshot::channel();
        let app = self.app.clone();
        let protocol = self.protocol.clone();
        let foreground = Arc::clone(&self.foreground);
        let label = label.to_owned();
        self.app
            .run_on_main_thread(move || {
                let result = (|| {
                    foreground_window(&app, &label, foreground.as_ref())?;
                    let protocol = protocol.upgrade().ok_or(AppError::Unauthenticated)?;
                    // The only operation under this guard is pure preparation. No OS getter,
                    // PostgreSQL read or wait occurs while the window registry is locked.
                    protocol.prepare_local_confirmation(&label, binding_id, job)
                })();
                // A discarded receiver drops a prepared attempt and cancels it; it cannot start OS.
                let _ = sender.send(result);
            })
            .map_err(|_| unavailable())?;
        receiver.await.map_err(|_| unavailable())?
    }

    async fn finish(
        &self,
        label: &str,
        binding_id: u64,
        job: FinishLocalConfirmation,
    ) -> Result<LocalConfirmationReceipt, AppError> {
        let (sender, receiver) = oneshot::channel();
        let app = self.app.clone();
        let protocol = self.protocol.clone();
        let foreground = Arc::clone(&self.foreground);
        let label = label.to_owned();
        let requires_foreground = job.requires_foreground();
        self.app
            .run_on_main_thread(move || {
                let result = (|| {
                    if requires_foreground {
                        foreground_window(&app, &label, foreground.as_ref())?;
                    } else if app.get_webview_window(&label).is_none() {
                        return Err(AppError::Unauthenticated);
                    }
                    let protocol = protocol.upgrade().ok_or(AppError::Unauthenticated)?;
                    // Current binding and grant CAS are one main-thread operation, mutually
                    // exclusive with unbind/replacement. Never return a clone for a later CAS.
                    protocol.finish_local_confirmation(&label, binding_id, job)
                })();
                let _ = sender.send(result);
            })
            .map_err(|_| unavailable())?;
        receiver.await.map_err(|_| unavailable())?
    }
}
