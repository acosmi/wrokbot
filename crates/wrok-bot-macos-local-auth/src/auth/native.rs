//! The only unsafe boundary: fixed LocalAuthentication selectors on one owned worker thread.

use super::{
    Backend, Completion, ConfirmationLocale, Evaluation, LocalAuthStartError, NativeResult,
};
use block2::RcBlock;
use objc2::{
    rc::{Retained, autoreleasepool},
    runtime::Bool,
};
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAError, LAErrorDomain, LAPolicy};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, SystemTime};

static OWNER_HELD: AtomicBool = AtomicBool::new(false);

pub(super) struct NativeGate;

impl NativeGate {
    pub(super) fn acquire() -> Result<Self, LocalAuthStartError> {
        OWNER_HELD
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| Self)
            .map_err(|_| LocalAuthStartError::Busy)
    }
}

impl Drop for NativeGate {
    fn drop(&mut self) {
        OWNER_HELD.store(false, Ordering::SeqCst);
    }
}

pub(super) struct NativeBackend;

struct NativeEvaluation {
    context: Option<Retained<LAContext>>,
    _reply: Option<RcBlock<dyn Fn(Bool, *mut NSError)>>,
    invalidated: bool,
}

fn checked_reply<F>(callback: F) -> RcBlock<dyn Fn(Bool, *mut NSError)>
where
    F: Fn(Bool, *mut NSError) + Send + Sync + 'static,
{
    // block2 0.6.2 erases Send/Sync from DynBlock, so validate captures before erasure.
    RcBlock::new(callback)
}

fn classify_domain_code(is_local_auth: bool, code: isize) -> NativeResult {
    if is_local_auth
        && [
            LAError::UserCancel.0,
            LAError::UserFallback.0,
            LAError::SystemCancel.0,
            LAError::AppCancel.0,
        ]
        .contains(&code)
    {
        NativeResult::Cancelled
    } else {
        NativeResult::Unavailable
    }
}

fn classify_error(error: &NSError) -> NativeResult {
    // SAFETY N1: SDK-provided static NSString exists on supported macOS (10.11+).
    // This only compares the error domain; no error description/userInfo leaves this callback.
    let domain = unsafe { LAErrorDomain };
    let actual_domain = error.domain();
    let actual_domain: &NSString = &actual_domain;
    classify_domain_code(actual_domain == domain, error.code())
}

impl Backend for NativeBackend {
    fn start(
        &mut self,
        locale: ConfirmationLocale,
        completion: Completion,
    ) -> Result<Box<dyn Evaluation>, NativeResult> {
        // A pool surrounds this synchronous call only, never the pending worker wait.
        autoreleasepool(|_| self.start_in_pool(locale, completion))
    }
}

impl NativeBackend {
    fn start_in_pool(
        &mut self,
        locale: ConfirmationLocale,
        completion: Completion,
    ) -> Result<Box<dyn Evaluation>, NativeResult> {
        if !completion.is_live() {
            return Err(NativeResult::Cancelled);
        }
        let reason = NSString::from_str(match locale {
            ConfirmationLocale::English => "confirm sensitive changes in Wrok Bot",
            ConfirmationLocale::SimplifiedChinese => "确认 Wrok Bot 中的敏感更改",
        });
        // SAFETY N2: fixed LAContext class, supported platform, allocation and all first-party
        // handle accesses stay here. No claim about framework deallocation threads is made.
        // Context is never declared Send/Sync or exposed through safe API.
        let context = unsafe { LAContext::new() };
        let mut evaluation = NativeEvaluation {
            context: Some(context),
            _reply: None,
            invalidated: false,
        };
        let context = evaluation
            .context
            .as_ref()
            .ok_or(NativeResult::Unavailable)?;
        // SAFETY N3: context is live and owned here; 0.0 is a valid no-reuse duration (macOS10.12+).
        unsafe {
            context.setTouchIDAuthenticationAllowableReuseDuration(0.0);
        }
        // SAFETY N4: fixed system policy; never invoked inside its own reply callback. This
        // synchronous OS preflight is not claimed to be preemptible by the host's deadline.
        unsafe { context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication) }
            .map_err(|error| classify_error(&error))?;
        if !completion.is_live() {
            return Err(NativeResult::Cancelled);
        }
        let reply = checked_reply(move |success: Bool, error: *mut NSError| {
            // Capture both clocks at callback entry, never when the host later consumes proof.
            let monotonic = Instant::now();
            let wall = SystemTime::now();
            let result = autoreleasepool(|_| {
                if success.as_bool() && error.is_null() {
                    NativeResult::Confirmed
                } else if success.as_bool() || error.is_null() {
                    NativeResult::Unavailable
                } else {
                    // SAFETY N5: LocalAuthentication owns the optional NSError and guarantees its
                    // validity throughout this callback. Borrow only here inside a local pool;
                    // never retain/store the raw pointer/error. Only a closed Rust result exits.
                    classify_error(unsafe { &*error })
                }
            });
            completion.finish(result, monotonic, wall);
        });
        // SAFETY N6: reason is one of two fixed nonempty NSString values, fixed policy, live
        // retained context. Reply captures only Send+Sync+'static Rust state; no context, PG,
        // window, raw pointer, or main-thread wait. Retain our block beside the context through
        // normal evaluation. Forced closed cleanup can invalidate/drop our references earlier;
        // the framework owns its escaping invocation. No claim that callback stacks/UI are
        // quiescent is made. No first-party callback code panics/unwinds.
        unsafe {
            context.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthentication,
                &reason,
                &reply,
            );
        }
        evaluation._reply = Some(reply);
        Ok(Box::new(evaluation))
    }
}

impl Evaluation for NativeEvaluation {
    fn invalidate(&mut self) {
        autoreleasepool(|_| self.invalidate_in_pool());
    }
}

impl NativeEvaluation {
    fn invalidate_in_pool(&mut self) {
        if !self.invalidated {
            self.invalidated = true;
            // SAFETY N7: same thread and still-retained context. Invalidate is idempotent; once
            // called we never reuse the context. Its return is not used as callback/retirement ACK.
            if let Some(context) = &self.context {
                unsafe { context.invalidate() };
            }
        }
    }
}

impl Drop for NativeEvaluation {
    fn drop(&mut self) {
        autoreleasepool(|_| {
            self.invalidate_in_pool();
            // Explicit take keeps the actual Objective-C releases inside this synchronous pool.
            drop(self._reply.take());
            drop(self.context.take());
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_error_mapping_rejects_unknown_domains_and_codes() {
        assert!(matches!(
            classify_domain_code(true, -2),
            NativeResult::Cancelled
        ));
        assert!(matches!(
            classify_domain_code(true, -9),
            NativeResult::Cancelled
        ));
        for (domain, code) in [
            (false, -2),
            (true, -1),
            (true, -10),
            (true, -1004),
            (true, 999),
        ] {
            assert!(matches!(
                classify_domain_code(domain, code),
                NativeResult::Unavailable
            ));
        }
    }

    #[test]
    fn process_gate_allows_only_one_native_owner_without_calling_os() {
        let gate = NativeGate::acquire().unwrap();
        assert!(matches!(
            NativeGate::acquire(),
            Err(LocalAuthStartError::Busy)
        ));
        drop(gate);
        drop(NativeGate::acquire().unwrap());
    }
}
