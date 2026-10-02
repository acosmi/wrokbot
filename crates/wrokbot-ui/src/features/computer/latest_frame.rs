//! One active decode and one replaceable latest frame. An image load receipt is not a compositor
//! paint timestamp: received, decoding and displayed progress remain separate facts.
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

const PROGRESS_TIMEOUT_MS: f64 = 2_000.0;

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct ReceivedFrame {
    pub sequence: u64,
    pub at_ms: f64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct DisplayedFrame {
    pub received: ReceivedFrame,
    pub loaded_at_ms: f64,
}

pub(super) struct Frame<T> {
    pub received: ReceivedFrame,
    pub payload: T,
}

struct Decode {
    received: ReceivedFrame,
    started_at_ms: f64,
}

pub(super) struct Completed<T> {
    pub displayed: DisplayedFrame,
    pub next: Option<Frame<T>>,
}

pub(super) struct LatestFrame<T> {
    received: Option<ReceivedFrame>,
    displayed: Option<DisplayedFrame>,
    decoding: Option<Decode>,
    pending: Option<Frame<T>>,
    closed: bool,
}

impl<T> Default for LatestFrame<T> {
    fn default() -> Self {
        Self {
            received: None,
            displayed: None,
            decoding: None,
            pending: None,
            closed: false,
        }
    }
}

impl<T> LatestFrame<T> {
    pub fn received(&self) -> Option<ReceivedFrame> {
        self.received
    }

    /// Payload has already passed the wire's generation, sequence and byte-size checks.
    /// Replacing this single slot drops the older payload immediately.
    pub fn receive(
        &mut self,
        sequence: u64,
        at_ms: f64,
        payload: T,
    ) -> Result<Option<Frame<T>>, ()> {
        if self.closed
            || !at_ms.is_finite()
            || at_ms < 0.0
            || sequence == 0
            || self.received.is_some_and(|last| sequence <= last.sequence)
        {
            return Err(());
        }
        let received = ReceivedFrame { sequence, at_ms };
        self.received = Some(received);
        let frame = Frame { received, payload };
        if self.decoding.is_some() {
            self.pending = Some(frame);
            Ok(None)
        } else {
            self.start(&frame, at_ms);
            Ok(Some(frame))
        }
    }

    /// Only the exact active image can complete. The final pending image starts here even when
    /// the source never sends another frame (for example after a page becomes static).
    pub fn complete(&mut self, sequence: u64, at_ms: f64) -> Option<Completed<T>> {
        let active = self.decoding.as_ref()?;
        if self.closed
            || active.received.sequence != sequence
            || !at_ms.is_finite()
            || at_ms < active.started_at_ms
        {
            return None;
        }
        let displayed = DisplayedFrame {
            received: active.received,
            loaded_at_ms: at_ms,
        };
        self.displayed = Some(displayed);
        self.decoding = None;
        let next = self.pending.take();
        if let Some(frame) = &next {
            self.start(frame, at_ms);
        }
        Some(Completed { displayed, next })
    }

    fn start(&mut self, frame: &Frame<T>, at_ms: f64) {
        self.decoding = Some(Decode {
            received: frame.received,
            started_at_ms: at_ms,
        });
    }

    pub fn progress_timed_out(&self, connected_at_ms: f64, now_ms: f64) -> bool {
        if self.closed {
            return false;
        }
        let waiting_since = self
            .decoding
            .as_ref()
            .map(|decode| decode.started_at_ms)
            .or_else(|| self.received.is_none().then_some(connected_at_ms));
        waiting_since.is_some_and(|start| {
            !now_ms.is_finite() || now_ms < start || now_ms - start > PROGRESS_TIMEOUT_MS
        })
    }

    /// Closing is terminal for this connection. Late receives and image callbacks cannot revive it.
    pub fn close(&mut self) {
        self.closed = true;
        self.received = None;
        self.displayed = None;
        self.decoding = None;
        self.pending = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, rc::Rc};

    #[test]
    fn final_frame_is_started_without_another_network_message() {
        let mut frames = LatestFrame::default();
        assert_eq!(
            frames.receive(1, 10.0, "first").unwrap().unwrap().payload,
            "first"
        );
        assert!(frames.receive(2, 20.0, "last").unwrap().is_none());
        assert_eq!(frames.received().unwrap().sequence, 2);
        assert!(frames.displayed.is_none());
        let completed = frames.complete(1, 30.0).unwrap();
        assert_eq!(completed.displayed.received.sequence, 1);
        assert_eq!(completed.displayed.received.at_ms, 10.0);
        assert_eq!(completed.displayed.loaded_at_ms, 30.0);
        assert_eq!(completed.next.unwrap().payload, "last");
        let completed = frames.complete(2, 40.0).unwrap();
        assert_eq!(completed.displayed.received.sequence, 2);
        assert_eq!(completed.displayed.received.at_ms, 20.0);
        assert!(completed.next.is_none());
    }

    struct Counted(Rc<Cell<usize>>);
    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn bursts_keep_only_the_latest_pending_payload_and_release_replaced_bytes() {
        let dropped = Rc::new(Cell::new(0));
        let mut frames = LatestFrame::default();
        let first = frames
            .receive(1, 1.0, Counted(dropped.clone()))
            .unwrap()
            .unwrap();
        for sequence in 2..=100 {
            assert!(
                frames
                    .receive(sequence, sequence as f64, Counted(dropped.clone()))
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(dropped.get(), 98);
        let last = frames.complete(1, 101.0).unwrap().next.unwrap();
        assert_eq!(last.received.sequence, 100);
        drop(first);
        drop(last);
        assert_eq!(dropped.get(), 100);
    }

    #[test]
    fn stale_completion_cannot_confirm_or_displace_current_decode() {
        let mut frames = LatestFrame::default();
        frames.receive(1, 10.0, ()).unwrap();
        frames.receive(2, 20.0, ()).unwrap();
        assert!(frames.complete(2, 21.0).is_none());
        assert!(frames.displayed.is_none());
        assert_eq!(
            frames
                .complete(1, 30.0)
                .unwrap()
                .next
                .unwrap()
                .received
                .sequence,
            2
        );
        assert!(frames.complete(1, 31.0).is_none());
        assert_eq!(frames.displayed.unwrap().received.sequence, 1);
        assert_eq!(
            frames
                .complete(2, 32.0)
                .unwrap()
                .displayed
                .received
                .sequence,
            2
        );
    }

    #[test]
    fn close_drops_pending_and_rejects_all_late_events() {
        let dropped = Rc::new(Cell::new(0));
        let mut frames = LatestFrame::default();
        drop(frames.receive(1, 1.0, Counted(dropped.clone())).unwrap());
        frames.receive(2, 2.0, Counted(dropped.clone())).unwrap();
        frames.close();
        assert_eq!(dropped.get(), 2);
        assert!(frames.received().is_none());
        assert!(frames.complete(1, 3.0).is_none());
        assert!(frames.receive(3, 3.0, Counted(dropped.clone())).is_err());
        assert_eq!(dropped.get(), 3);
        assert!(!frames.progress_timed_out(0.0, 10_000.0));
    }

    #[test]
    fn progress_budget_tracks_first_frame_and_decode_not_static_source_silence() {
        let mut frames = LatestFrame::default();
        assert!(!frames.progress_timed_out(10.0, 2_010.0));
        assert!(frames.progress_timed_out(10.0, 2_011.0));
        frames.receive(1, 100.0, ()).unwrap();
        frames.receive(2, 2_000.0, ()).unwrap();
        assert!(frames.progress_timed_out(10.0, 2_101.0));
        frames.complete(1, 2_100.0).unwrap();
        assert!(!frames.progress_timed_out(10.0, 4_100.0));
        assert!(frames.progress_timed_out(10.0, 4_101.0));
        frames.complete(2, 4_100.0).unwrap();
        assert!(!frames.progress_timed_out(10.0, 1_000_000.0));
    }

    #[test]
    fn rejected_sequence_does_not_advance_receive_progress() {
        let mut frames = LatestFrame::default();
        frames.receive(3, 10.0, ()).unwrap();
        for sequence in [0, 1, 3] {
            assert!(frames.receive(sequence, 20.0, ()).is_err());
        }
        assert!(frames.receive(4, f64::NAN, ()).is_err());
        assert_eq!(
            frames.received(),
            Some(ReceivedFrame {
                sequence: 3,
                at_ms: 10.0
            })
        );
    }
}
