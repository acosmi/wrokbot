//! Consume the existing R074/R075 read-only facts. This module has no mutation path.

use openbot_contracts::ids::{RunId, ThreadId};
#[cfg(target_arch = "wasm32")]
use openbot_contracts::reconciliation::MAX_RUN_RECONCILIATION_RESPONSE_BYTES;
#[cfg(any(target_arch = "wasm32", test))]
use openbot_contracts::reconciliation::{DEFAULT_RUN_RECONCILIATION_PAGE, valid_reconciliation_id};
use openbot_contracts::reconciliation::{
    RunEffectReceiptsSnapshot, RunReconciliationCursor, RunReconciliationSnapshot,
};

use super::ApiError;

/// Read one bounded attempt page for exactly the original thread and run.
pub(crate) async fn attempts(
    thread: &ThreadId,
    run: &RunId,
    after: Option<RunReconciliationCursor>,
) -> Result<RunReconciliationSnapshot, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        let path = read_path(thread, run, after, false)?;
        let page: RunReconciliationSnapshot = read_json(&path).await?;
        validate_attempts(&page, thread, run, after)?;
        Ok(page)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (thread, run, after);
        Err(ApiError::Unavailable)
    }
}

/// Read only remember's positive historical receipts; absence proves nothing about commitment.
pub(crate) async fn receipts(
    thread: &ThreadId,
    run: &RunId,
    after: Option<RunReconciliationCursor>,
) -> Result<RunEffectReceiptsSnapshot, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        let path = read_path(thread, run, after, true)?;
        let page: RunEffectReceiptsSnapshot = read_json(&path).await?;
        validate_receipts(&page, thread, run, after)?;
        Ok(page)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (thread, run, after);
        Err(ApiError::Unavailable)
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn read_path(
    thread: &ThreadId,
    run: &RunId,
    after: Option<RunReconciliationCursor>,
    receipts: bool,
) -> Result<String, ApiError> {
    if !valid_reconciliation_id(thread.as_str()) || !valid_reconciliation_id(run.as_str()) {
        return Err(ApiError::InvalidResponse);
    }
    openbot_contracts::reconciliation::validate_page(after, Some(DEFAULT_RUN_RECONCILIATION_PAGE))
        .map_err(|_| ApiError::InvalidResponse)?;
    let mut path = format!(
        "/api/threads/{}/runs/{}/reconciliation{}?limit={DEFAULT_RUN_RECONCILIATION_PAGE}",
        super::encode_url_component(thread.as_str()),
        super::encode_url_component(run.as_str()),
        if receipts { "/receipts" } else { "" },
    );
    if let Some(after) = after {
        use core::fmt::Write as _;
        write!(
            path,
            "&afterCallSequence={}&afterAttemptSequence={}",
            after.call_sequence, after.attempt_sequence,
        )
        .map_err(|_| ApiError::InvalidResponse)?;
    }
    Ok(path)
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_attempts(
    page: &RunReconciliationSnapshot,
    thread: &ThreadId,
    run: &RunId,
    after: Option<RunReconciliationCursor>,
) -> Result<(), ApiError> {
    if &page.thread_id != thread || &page.run_id != run {
        return Err(ApiError::InvalidResponse);
    }
    validate_rows(
        page.attempts.iter().map(|row| {
            (
                RunReconciliationCursor {
                    call_sequence: row.call_sequence,
                    attempt_sequence: row.attempt_sequence,
                },
                row.attempt_id.as_str(),
                row.tool_call_id.as_str(),
            )
        }),
        after,
        page.next,
    )
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_receipts(
    page: &RunEffectReceiptsSnapshot,
    thread: &ThreadId,
    run: &RunId,
    after: Option<RunReconciliationCursor>,
) -> Result<(), ApiError> {
    if &page.thread_id != thread || &page.run_id != run {
        return Err(ApiError::InvalidResponse);
    }
    if page
        .receipts
        .iter()
        .any(|row| !valid_reconciliation_id(&row.attempt_id))
    {
        return Err(ApiError::InvalidResponse);
    }
    validate_rows(
        page.receipts.iter().map(|row| {
            (
                RunReconciliationCursor {
                    call_sequence: row.call_sequence,
                    attempt_sequence: row.attempt_sequence,
                },
                row.receipt_id.as_str(),
                row.tool_call_id.as_str(),
            )
        }),
        after,
        page.next,
    )
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_rows<'a>(
    rows: impl Iterator<Item = (RunReconciliationCursor, &'a str, &'a str)>,
    after: Option<RunReconciliationCursor>,
    next: Option<RunReconciliationCursor>,
) -> Result<(), ApiError> {
    let mut previous = after;
    let mut last = None;
    let mut identities = std::collections::BTreeSet::new();
    for (index, (position, identity, call)) in rows.enumerate() {
        if index >= DEFAULT_RUN_RECONCILIATION_PAGE as usize
            || !position.is_valid()
            || !valid_reconciliation_id(identity)
            || !valid_reconciliation_id(call)
            || !identities.insert(identity)
            || previous.is_some_and(|previous| position <= previous)
        {
            return Err(ApiError::InvalidResponse);
        }
        previous = Some(position);
        last = Some(position);
    }
    if next.is_some() && next != last {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, ApiError> {
    use web_sys::{RequestCache, RequestCredentials, RequestRedirect};
    let response = super::request::Request::get(path)
        .cache(RequestCache::NoStore)
        .credentials(RequestCredentials::SameOrigin)
        .redirect(RequestRedirect::Error)
        .send()
        .await
        .map_err(|_| ApiError::Network)?;
    if response.status() != 200 {
        return Err(super::status_error(response.status()));
    }
    if response
        .headers()
        .get("Content-Length")
        .is_some_and(|value| {
            value
                .parse::<usize>()
                .map_or(true, |bytes| bytes > MAX_RUN_RECONCILIATION_RESPONSE_BYTES)
        })
    {
        return Err(ApiError::InvalidResponse);
    }
    // Stop reading at the contract's actual byte cap. A declared size is not an authority.
    let bytes = bounded_body(response).await?;
    serde_json::from_slice(&bytes).map_err(|_| ApiError::InvalidResponse)
}

#[cfg(target_arch = "wasm32")]
struct BodyReader(wasm_bindgen::JsValue);

#[cfg(target_arch = "wasm32")]
impl BodyReader {
    fn call(&self, method: &str) -> Result<wasm_bindgen::JsValue, ApiError> {
        use wasm_bindgen::JsCast as _;
        let function = js_sys::Reflect::get(&self.0, &method.into())
            .map_err(|_| ApiError::InvalidResponse)?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| ApiError::InvalidResponse)?;
        function.call0(&self.0).map_err(|_| ApiError::Network)
    }
}

#[cfg(target_arch = "wasm32")]
impl Drop for BodyReader {
    fn drop(&mut self) {
        // Also runs when the owning scoped future is cancelled during navigation/logout.
        use wasm_bindgen::JsCast as _;
        if let Ok(value) = self.call("cancel")
            && let Ok(promise) = value.dyn_into::<js_sys::Promise>()
        {
            leptos::task::spawn_local(async move {
                let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
            });
        }
        let _ = self.call("releaseLock");
    }
}

#[cfg(target_arch = "wasm32")]
async fn bounded_body(response: gloo_net::http::Response) -> Result<Vec<u8>, ApiError> {
    use wasm_bindgen::JsCast as _;
    let stream = response.body().ok_or(ApiError::InvalidResponse)?;
    let get_reader = js_sys::Reflect::get(stream.as_ref(), &"getReader".into())
        .map_err(|_| ApiError::InvalidResponse)?
        .dyn_into::<js_sys::Function>()
        .map_err(|_| ApiError::InvalidResponse)?;
    let reader = BodyReader(
        get_reader
            .call0(stream.as_ref())
            .map_err(|_| ApiError::Network)?,
    );
    let mut bytes = Vec::new();
    loop {
        let promise = reader
            .call("read")?
            .dyn_into::<js_sys::Promise>()
            .map_err(|_| ApiError::InvalidResponse)?;
        let part = wasm_bindgen_futures::JsFuture::from(promise)
            .await
            .map_err(|_| ApiError::Network)?;
        let done = js_sys::Reflect::get(&part, &"done".into())
            .map_err(|_| ApiError::InvalidResponse)?
            .as_bool()
            .ok_or(ApiError::InvalidResponse)?;
        if done {
            break;
        }
        let chunk = js_sys::Reflect::get(&part, &"value".into())
            .map_err(|_| ApiError::InvalidResponse)?
            .dyn_into::<js_sys::Uint8Array>()
            .map_err(|_| ApiError::InvalidResponse)?;
        let new_len = bytes
            .len()
            .checked_add(chunk.length() as usize)
            .filter(|length| *length <= MAX_RUN_RECONCILIATION_RESPONSE_BYTES)
            .ok_or(ApiError::InvalidResponse)?;
        let old_len = bytes.len();
        bytes.resize(new_len, 0);
        chunk.copy_to(&mut bytes[old_len..]);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::reconciliation::RunReconciliationStatus;

    #[test]
    fn exact_original_identity_and_complete_cursor_are_encoded_once() {
        let path = read_path(
            &ThreadId::new("t/one?x"),
            &RunId::new("r%two"),
            Some(RunReconciliationCursor {
                call_sequence: 2,
                attempt_sequence: 3,
            }),
            true,
        )
        .unwrap();
        assert_eq!(
            path,
            "/api/threads/t%2Fone%3Fx/runs/r%25two/reconciliation/receipts?limit=50&afterCallSequence=2&afterAttemptSequence=3"
        );
        assert!(read_path(&ThreadId::new("t"), &RunId::new("line\nbreak"), None, false).is_err());
        assert!(
            read_path(
                &ThreadId::new("t"),
                &RunId::new("r"),
                Some(RunReconciliationCursor {
                    call_sequence: -1,
                    attempt_sequence: 0
                }),
                false
            )
            .is_err()
        );
    }

    #[test]
    fn cursor_repetition_identity_duplication_and_fake_next_are_rejected() {
        let a = RunReconciliationCursor {
            call_sequence: 0,
            attempt_sequence: 0,
        };
        let b = RunReconciliationCursor {
            call_sequence: 0,
            attempt_sequence: 1,
        };
        assert!(
            validate_rows(
                [(a, "one", "call"), (b, "two", "call")].into_iter(),
                None,
                Some(b)
            )
            .is_ok()
        );
        assert!(validate_rows([(a, "one", "call")].into_iter(), Some(a), None).is_err());
        assert!(
            validate_rows(
                [(a, "one", "call"), (b, "one", "call")].into_iter(),
                None,
                None
            )
            .is_err()
        );
        assert!(validate_rows([(a, "one", "call")].into_iter(), None, Some(b)).is_err());
        assert!(validate_rows(std::iter::empty(), None, Some(a)).is_err());
    }

    #[test]
    fn empty_positive_receipts_and_original_unknown_do_not_grant_any_action() {
        let thread = ThreadId::new("t");
        let run = RunId::new("r");
        let page = RunEffectReceiptsSnapshot {
            thread_id: thread.clone(),
            run_id: run.clone(),
            status: RunReconciliationStatus::ReconciliationRequired,
            terminal_event_sequence: 7,
            observed_at: time::OffsetDateTime::UNIX_EPOCH,
            foreground_blocked: true,
            receipts: vec![],
            next: None,
            available_actions: [],
        };
        assert!(validate_receipts(&page, &thread, &run, None).is_ok());
        assert!(validate_receipts(&page, &thread, &RunId::new("other"), None).is_err());
        assert!(page.foreground_blocked);
        assert!(page.available_actions.is_empty());
        let attempts = RunReconciliationSnapshot {
            thread_id: thread.clone(),
            run_id: run.clone(),
            status: page.status,
            terminal_event_sequence: 7,
            observed_at: page.observed_at,
            foreground_blocked: true,
            attempts: vec![],
            next: None,
            available_actions: [],
        };
        assert!(validate_attempts(&attempts, &thread, &run, None).is_ok());
        assert!(validate_attempts(&attempts, &ThreadId::new("other"), &run, None).is_err());
    }
}
