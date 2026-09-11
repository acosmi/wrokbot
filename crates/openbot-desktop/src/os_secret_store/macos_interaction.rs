//! Serial, noninteractive use of the existing macOS generic-password APIs.
//!
//! Disabling optional UI is not a deadline or cancellation mechanism for SecurityServer IPC.

use std::sync::Mutex;

use security_framework::os::macos::keychain::{KeychainUserInteractionLock, SecKeychain};

use super::OsSecretStoreError;

// The framework's interaction guard is not a mutex and always enables UI on Drop. Every production
// constructor/read/write in this adapter uses this one gate; restoration happens before unlocking.
static KEYCHAIN_CALL_GATE: Mutex<()> = Mutex::new(());

trait InteractionControl {
    type Disabled;

    fn interaction_allowed(&self) -> Result<bool, OsSecretStoreError>;
    fn disable_interaction(&self) -> Result<Self::Disabled, OsSecretStoreError>;
}

struct SecurityInteraction;

impl InteractionControl for SecurityInteraction {
    type Disabled = KeychainUserInteractionLock;

    fn interaction_allowed(&self) -> Result<bool, OsSecretStoreError> {
        SecKeychain::user_interaction_allowed().map_err(|error| platform_error(error.code()))
    }

    fn disable_interaction(&self) -> Result<Self::Disabled, OsSecretStoreError> {
        SecKeychain::disable_user_interaction().map_err(|error| platform_error(error.code()))
    }
}

pub(super) fn non_interactive<T>(
    operation: impl FnOnce() -> Result<T, OsSecretStoreError>,
) -> Result<T, OsSecretStoreError> {
    with_interaction_gate(&KEYCHAIN_CALL_GATE, &SecurityInteraction, operation)
}

fn with_interaction_gate<I: InteractionControl, T>(
    gate: &Mutex<()>,
    interaction: &I,
    operation: impl FnOnce() -> Result<T, OsSecretStoreError>,
) -> Result<T, OsSecretStoreError> {
    let _permit = gate
        .lock()
        .map_err(|_| OsSecretStoreError::StoreUnavailable)?;
    let restore = if interaction.interaction_allowed()? {
        Some(interaction.disable_interaction()?)
    } else {
        // The external state was already noninteractive. Do not construct the upstream guard,
        // whose unconditional Drop would incorrectly turn interaction back on.
        None
    };
    let result = operation();
    drop(restore);
    result
}

pub(super) fn lookup<T>(result: Result<T, i32>) -> Result<Option<T>, OsSecretStoreError> {
    match result {
        Ok(item) => Ok(Some(item)),
        Err(security_framework_sys::base::errSecItemNotFound) => Ok(None),
        Err(code) => Err(platform_error(code)),
    }
}

pub(super) fn write_after_lookup<T>(
    find: impl FnOnce() -> Result<Option<T>, OsSecretStoreError>,
    update: impl FnOnce(T) -> Result<(), OsSecretStoreError>,
    add: impl FnOnce() -> Result<(), OsSecretStoreError>,
) -> Result<(), OsSecretStoreError> {
    match find()? {
        Some(item) => update(item),
        None => add(),
    }
}

pub(super) fn platform_error(platform_code: i32) -> OsSecretStoreError {
    let error = classify_platform_error(platform_code);
    tracing::warn!(category = %error, "macOS noninteractive Keychain operation failed");
    error
}

// Values are fixed by the locally installed Apple Security.framework SecBase.h. The
// security-framework-sys crate intentionally exports only a subset of these legacy Keychain
// statuses, so the narrow adapter owns the remaining reviewed mapping without exposing OSStatus.
fn classify_platform_error(platform_code: i32) -> OsSecretStoreError {
    match platform_code {
        // Permission/ACL/signing capability failures.
        -61 | -25292 | -25243 | -25244 | -25309 | -25317 | -34018 | -34020 => {
            OsSecretStoreError::AccessDenied
        }
        security_framework_sys::base::errSecAuthFailed => OsSecretStoreError::AuthFailed,
        // Both Security.framework spellings, plus dark wake where UI cannot be presented.
        -25308 | -25315 | -25320 => OsSecretStoreError::InteractionRequired,
        // No usable current-user Keychain/default/storage service.
        -25291 | -25294 | -25307 | -25312 | -67585 => OsSecretStoreError::StoreUnavailable,
        _ => OsSecretStoreError::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        sync::{Arc, mpsc},
        time::Duration,
    };

    use super::*;

    #[test]
    fn keychain_statuses_map_to_the_frozen_closed_error_set() {
        for (status, expected) in [
            (-34018, OsSecretStoreError::AccessDenied),
            (-34020, OsSecretStoreError::AccessDenied),
            (-25243, OsSecretStoreError::AccessDenied),
            (-25293, OsSecretStoreError::AuthFailed),
            (-25308, OsSecretStoreError::InteractionRequired),
            (-25315, OsSecretStoreError::InteractionRequired),
            (-25291, OsSecretStoreError::StoreUnavailable),
            (-25307, OsSecretStoreError::StoreUnavailable),
            (-50, OsSecretStoreError::Unknown),
            (-128, OsSecretStoreError::Unknown),
        ] {
            assert_eq!(classify_platform_error(status), expected);
        }
        assert_eq!(
            classify_platform_error(-25293),
            OsSecretStoreError::AuthFailed,
            "errSecAuthFailed must never be reported as a locked Keychain"
        );
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        Inspect,
        Disable,
        Operation(u8),
        Restore,
    }

    struct FakeState {
        allowed: bool,
        inspect_fails: bool,
        disable_fails: bool,
        events: Vec<Event>,
    }

    #[derive(Clone)]
    struct FakeInteraction {
        state: Arc<Mutex<FakeState>>,
        gate: Arc<Mutex<()>>,
    }

    impl FakeInteraction {
        fn new(allowed: bool) -> Self {
            Self {
                state: Arc::new(Mutex::new(FakeState {
                    allowed,
                    inspect_fails: false,
                    disable_fails: false,
                    events: Vec::new(),
                })),
                gate: Arc::new(Mutex::new(())),
            }
        }

        fn operation(&self, id: u8) {
            assert!(
                self.gate.try_lock().is_err(),
                "operation must own the serial gate"
            );
            let mut state = self.state.lock().unwrap();
            assert!(
                !state.allowed,
                "optional UI must be disabled during operation"
            );
            state.events.push(Event::Operation(id));
        }
    }

    struct FakeDisabled(FakeInteraction);

    impl Drop for FakeDisabled {
        fn drop(&mut self) {
            assert!(
                self.0.gate.try_lock().is_err(),
                "restore must happen before unlocking"
            );
            let mut state = self.0.state.lock().unwrap();
            state.allowed = true; // Models the upstream guard's unconditional re-enable.
            state.events.push(Event::Restore);
        }
    }

    impl InteractionControl for FakeInteraction {
        type Disabled = FakeDisabled;

        fn interaction_allowed(&self) -> Result<bool, OsSecretStoreError> {
            assert!(self.gate.try_lock().is_err());
            let mut state = self.state.lock().unwrap();
            state.events.push(Event::Inspect);
            if state.inspect_fails {
                Err(OsSecretStoreError::StoreUnavailable)
            } else {
                Ok(state.allowed)
            }
        }

        fn disable_interaction(&self) -> Result<Self::Disabled, OsSecretStoreError> {
            assert!(self.gate.try_lock().is_err());
            let mut state = self.state.lock().unwrap();
            state.events.push(Event::Disable);
            if state.disable_fails {
                Err(OsSecretStoreError::StoreUnavailable)
            } else {
                state.allowed = false;
                Ok(FakeDisabled(self.clone()))
            }
        }
    }

    #[test]
    fn original_interaction_state_is_preserved_and_restore_stays_inside_gate() {
        for allowed in [false, true] {
            let fake = FakeInteraction::new(allowed);
            let result = with_interaction_gate(&fake.gate, &fake, || {
                fake.operation(1);
                Ok(7)
            });
            assert_eq!(result, Ok(7));
            let state = fake.state.lock().unwrap();
            assert_eq!(state.allowed, allowed);
            assert_eq!(
                state.events,
                if allowed {
                    vec![
                        Event::Inspect,
                        Event::Disable,
                        Event::Operation(1),
                        Event::Restore,
                    ]
                } else {
                    vec![Event::Inspect, Event::Operation(1)]
                }
            );
            assert!(fake.gate.try_lock().is_ok());
        }
    }

    #[test]
    fn preparation_failure_does_not_enter_keychain_operation() {
        for inspect_fails in [true, false] {
            let fake = FakeInteraction::new(true);
            {
                let mut state = fake.state.lock().unwrap();
                state.inspect_fails = inspect_fails;
                state.disable_fails = !inspect_fails;
            }
            let result = with_interaction_gate(&fake.gate, &fake, || {
                panic!("failed UI control must not enter the OS operation")
            });
            assert_eq!(result, Err::<(), _>(OsSecretStoreError::StoreUnavailable));
            let state = fake.state.lock().unwrap();
            assert!(state.allowed);
            assert_eq!(
                state.events,
                if inspect_fails {
                    vec![Event::Inspect]
                } else {
                    vec![Event::Inspect, Event::Disable]
                }
            );
        }
    }

    #[test]
    fn operation_failure_restores_state_without_replaying_operation() {
        let fake = FakeInteraction::new(true);
        let result = with_interaction_gate(&fake.gate, &fake, || {
            fake.operation(1);
            Err::<(), _>(OsSecretStoreError::StoreUnavailable)
        });
        assert_eq!(result, Err(OsSecretStoreError::StoreUnavailable));
        let state = fake.state.lock().unwrap();
        assert!(state.allowed);
        assert_eq!(
            state.events,
            [
                Event::Inspect,
                Event::Disable,
                Event::Operation(1),
                Event::Restore
            ]
        );
        assert!(fake.gate.try_lock().is_ok());
    }

    #[test]
    fn concurrent_calls_cannot_reenable_ui_during_another_operation() {
        let fake = FakeInteraction::new(true);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let first = fake.clone();
        let task1 = std::thread::spawn(move || {
            with_interaction_gate(&first.gate, &first, || {
                first.operation(1);
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                assert!(!first.state.lock().unwrap().allowed);
                Ok(())
            })
        });
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let second = fake.clone();
        let (attempted_tx, attempted_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let task2 = std::thread::spawn(move || {
            attempted_tx.send(()).unwrap();
            let result = with_interaction_gate(&second.gate, &second, || {
                second.operation(2);
                Ok(())
            });
            finished_tx.send(()).unwrap();
            result
        });
        attempted_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            finished_rx.recv_timeout(Duration::from_millis(20)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        assert_eq!(
            fake.state.lock().unwrap().events,
            [Event::Inspect, Event::Disable, Event::Operation(1)]
        );
        release_tx.send(()).unwrap();
        task1.join().unwrap().unwrap();
        task2.join().unwrap().unwrap();
        assert_eq!(
            fake.state.lock().unwrap().events,
            [
                Event::Inspect,
                Event::Disable,
                Event::Operation(1),
                Event::Restore,
                Event::Inspect,
                Event::Disable,
                Event::Operation(2),
                Event::Restore
            ]
        );
        assert!(fake.state.lock().unwrap().allowed);
    }

    #[test]
    fn poisoned_gate_fails_before_interaction_state_or_operation_is_touched() {
        let fake = FakeInteraction::new(true);
        let gate = fake.gate.clone();
        assert!(
            std::thread::spawn(move || {
                let _guard = gate.lock().unwrap();
                panic!("test gate poison");
            })
            .join()
            .is_err()
        );
        let result = with_interaction_gate(&fake.gate, &fake, || panic!("poisoned gate"));
        assert_eq!(result, Err::<(), _>(OsSecretStoreError::StoreUnavailable));
        assert!(fake.state.lock().unwrap().events.is_empty());
    }

    struct FakePassword {
        lookup: Result<u8, i32>,
        update_fails: bool,
        add_fails: bool,
        operations: RefCell<Vec<&'static str>>,
    }

    impl FakePassword {
        fn write(&self) -> Result<(), OsSecretStoreError> {
            write_after_lookup(
                || {
                    self.operations.borrow_mut().push("find");
                    lookup(self.lookup)
                },
                |item| {
                    assert_eq!(item, 9);
                    self.operations.borrow_mut().push("update");
                    if self.update_fails {
                        Err(OsSecretStoreError::StoreUnavailable)
                    } else {
                        Ok(())
                    }
                },
                || {
                    self.operations.borrow_mut().push("add");
                    if self.add_fails {
                        Err(OsSecretStoreError::StoreUnavailable)
                    } else {
                        Ok(())
                    }
                },
            )
        }
    }

    #[test]
    fn only_item_not_found_permits_add_and_lookup_failures_never_write() {
        for code in [-25308, -25293, -128, -25291, -50] {
            let fake = FakePassword {
                lookup: Err(code),
                update_fails: false,
                add_fails: false,
                operations: RefCell::new(Vec::new()),
            };
            assert_eq!(fake.write(), Err(classify_platform_error(code)));
            assert_eq!(*fake.operations.borrow(), ["find"]);
        }
        for (result, expected) in [
            (Ok(9), "update"),
            (Err(security_framework_sys::base::errSecItemNotFound), "add"),
        ] {
            let fake = FakePassword {
                lookup: result,
                update_fails: false,
                add_fails: false,
                operations: RefCell::new(Vec::new()),
            };
            fake.write().unwrap();
            assert_eq!(*fake.operations.borrow(), ["find", expected]);
        }
    }

    #[test]
    fn mutation_errors_never_fallback_to_a_different_write_or_retry() {
        for (result, expected) in [
            (Ok(9), "update"),
            (Err(security_framework_sys::base::errSecItemNotFound), "add"),
        ] {
            let fake = FakePassword {
                lookup: result,
                update_fails: true,
                add_fails: true,
                operations: RefCell::new(Vec::new()),
            };
            assert_eq!(fake.write(), Err(OsSecretStoreError::StoreUnavailable));
            assert_eq!(*fake.operations.borrow(), ["find", expected]);
        }
    }
}
