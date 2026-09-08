//! Fixed AppKit/Foundation boundary. Every ObjC owner stays on the real main thread.
use super::{MonitorError, ObserverOwner, SessionEvent, Shared, callback_boundary};
use block2::RcBlock;
use objc2::{
    MainThreadMarker,
    rc::{Retained, autoreleasepool},
    runtime::ProtocolObject,
};
use objc2_app_kit::{
    NSApplication, NSApplicationDidResignActiveNotification, NSWorkspace,
    NSWorkspaceDidWakeNotification, NSWorkspaceScreensDidSleepNotification,
    NSWorkspaceScreensDidWakeNotification, NSWorkspaceSessionDidBecomeActiveNotification,
    NSWorkspaceSessionDidResignActiveNotification, NSWorkspaceWillSleepNotification,
};
use objc2_foundation::{NSNotification, NSNotificationCenter, NSObjectProtocol};
use std::{ptr::NonNull, sync::Arc};

type Reply = RcBlock<dyn Fn(NonNull<NSNotification>)>;
struct Entry {
    center: Retained<NSNotificationCenter>,
    token: Retained<ProtocolObject<dyn NSObjectProtocol>>,
    _reply: Reply,
}
struct NativeObservers {
    entries: Vec<Entry>,
    app: Option<Retained<NSApplication>>,
    workspace: Option<Retained<NSWorkspace>>,
}

pub(super) fn main_thread() -> Result<MainThreadMarker, MonitorError> {
    MainThreadMarker::new().ok_or(MonitorError::WrongThread)
}

pub(super) fn current_app_is_active() -> Result<bool, MonitorError> {
    let main = main_thread()?;
    Ok(autoreleasepool(|_| {
        NSApplication::sharedApplication(main).isActive()
    }))
}

fn checked_reply<F>(callback: F) -> Reply
where
    F: Fn(NonNull<NSNotification>) + Send + Sync + 'static,
{
    // block2's erased DynBlock does not express Send/Sync; check captures before erasure.
    RcBlock::new(callback)
}

pub(super) fn register(main: MainThreadMarker, shared: Arc<Shared>) -> Box<dyn ObserverOwner> {
    autoreleasepool(|_| {
        let app = NSApplication::sharedApplication(main);
        let workspace = NSWorkspace::sharedWorkspace();
        let default_center = NSNotificationCenter::defaultCenter();
        let workspace_center = workspace.notificationCenter();
        let mut observers = NativeObservers {
            entries: Vec::with_capacity(7),
            app: Some(app),
            workspace: Some(workspace),
        };
        // SAFETY N8: Seven fixed public AppKit NSString globals from the linked supported SDK;
        // no renderer-supplied name/object/selector. Each name lives for this entire process.
        let names = unsafe {
            [
                (
                    NSApplicationDidResignActiveNotification,
                    SessionEvent::AppResignedActive,
                ),
                (
                    NSWorkspaceWillSleepNotification,
                    SessionEvent::SystemWillSleep,
                ),
                (NSWorkspaceDidWakeNotification, SessionEvent::SystemDidWake),
                (
                    NSWorkspaceScreensDidSleepNotification,
                    SessionEvent::ScreensDidSleep,
                ),
                (
                    NSWorkspaceScreensDidWakeNotification,
                    SessionEvent::ScreensDidWake,
                ),
                (
                    NSWorkspaceSessionDidResignActiveNotification,
                    SessionEvent::SessionResignedActive,
                ),
                (
                    NSWorkspaceSessionDidBecomeActiveNotification,
                    SessionEvent::SessionBecameActive,
                ),
            ]
        };
        for (name, event) in names {
            let state = Arc::clone(&shared);
            let reply = checked_reply(move |_notification| {
                // Do not dereference the payload or call ObjC. Boundary catches host Rust panic.
                callback_boundary(&state, event);
            });
            let (center, object) = if event == SessionEvent::AppResignedActive {
                (
                    &default_center,
                    observers
                        .app
                        .as_deref()
                        .map(|app| -> &objc2::runtime::AnyObject { app }),
                )
            } else {
                (&workspace_center, None)
            };
            // SAFETY N9: Correct center and fixed names; App filter is our retained NSApplication.
            // Workspace uses its own center without assuming an undocumented sender object.
            // queue=None delivers synchronously on posting thread; captures are Send+Sync and
            // ignore the notification pointer. The copied block is heap-owned and panic-contained.
            let token = unsafe {
                center.addObserverForName_object_queue_usingBlock(Some(name), object, None, &reply)
            };
            observers.entries.push(Entry {
                center: center.clone(),
                token,
                _reply: reply,
            });
        }
        Box::new(observers) as Box<dyn ObserverOwner>
    })
}

impl NativeObservers {
    fn remove_in_pool(&mut self) {
        for entry in self.entries.drain(..) {
            // SAFETY N10: Token is exactly the retained object returned by this same center's
            // registration. This set is created, removed and dropped only on the main thread.
            unsafe {
                entry
                    .center
                    .removeObserver(AsRef::<objc2::runtime::AnyObject>::as_ref(&*entry.token))
            };
            // Explicit drop here covers both retained token/center and RcBlock inside this pool.
            drop(entry);
        }
        drop(self.app.take());
        drop(self.workspace.take());
    }
}
impl ObserverOwner for NativeObservers {
    fn remove_all(&mut self) -> Result<(), MonitorError> {
        main_thread()?;
        autoreleasepool(|_| self.remove_in_pool());
        Ok(())
    }
}
impl Drop for NativeObservers {
    fn drop(&mut self) {
        // TLS is main-thread-only in production. Also covers an early registration return/unwind;
        // no automatic retained token/block field remains after this synchronous pool ends.
        autoreleasepool(|_| self.remove_in_pool());
    }
}
