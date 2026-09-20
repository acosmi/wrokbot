//! Pure browser-residency eviction decisions.
//!
//! The production owner supplies authority-owned scope keys and clock values. This module decides
//! which already-running browsers must close; it never launches a browser, deletes a profile, or
//! accepts a Bot identifier from an engine/renderer.

/// Fixed-upstream default number of live browser contexts in one computer runtime.
pub const DEFAULT_MAX_LIVE_BROWSERS: usize = 8;

/// Fixed-upstream default idle timeout: thirty minutes.
pub const DEFAULT_BROWSER_IDLE_TIMEOUT_MS: i64 = 30 * 60_000;

/// Return the least-recently-used keys needed to bring `running` under `maximum`.
///
/// Equal timestamps retain input order. The runtime inserts a newly launched browser after existing
/// entries and calls this function only after insertion, so a positive cap never chooses that newest
/// browser ahead of an older equal-timestamp entry.
pub fn choose_evictions<K>(running: impl IntoIterator<Item = (K, i128)>, maximum: usize) -> Vec<K> {
    let mut entries = running.into_iter().collect::<Vec<_>>();
    let excess = entries.len().saturating_sub(maximum);
    if excess == 0 {
        return Vec::new();
    }
    entries.sort_by_key(|(_, used_at_ms)| *used_at_ms);
    entries
        .into_iter()
        .take(excess)
        .map(|(key, _)| key)
        .collect()
}

/// Return keys whose last use is at or before the idle cutoff.
///
/// A non-positive timeout disables idle eviction. Arithmetic is widened so hostile or erroneous
/// clock values cannot overflow into a fresh-looking or stale-looking timestamp.
pub fn choose_idle<K>(
    running: impl IntoIterator<Item = (K, i128)>,
    idle_timeout_ms: i128,
    now_ms: i128,
) -> Vec<K> {
    if idle_timeout_ms <= 0 {
        return Vec::new();
    }
    let Some(cutoff) = now_ms.checked_sub(idle_timeout_ms) else {
        return Vec::new();
    };
    running
        .into_iter()
        .filter(|(_, used_at_ms)| *used_at_ms <= cutoff)
        .map(|(key, _)| key)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_BROWSER_IDLE_TIMEOUT_MS, DEFAULT_MAX_LIVE_BROWSERS, choose_evictions, choose_idle,
    };

    fn running(used_at: &[i128]) -> Vec<(String, i128)> {
        used_at
            .iter()
            .enumerate()
            .map(|(index, value)| (format!("bot-{index}"), *value))
            .collect()
    }

    #[test]
    fn closes_nothing_while_there_is_room() {
        assert!(choose_evictions(running(&[1, 2, 3]), 8).is_empty());
    }

    #[test]
    fn closes_nothing_at_exactly_the_cap() {
        assert!(choose_evictions(running(&[1, 2, 3]), 3).is_empty());
    }

    #[test]
    fn closes_the_least_recently_used() {
        assert_eq!(choose_evictions(running(&[500, 100, 300]), 2), ["bot-1"]);
    }

    #[test]
    fn closes_as_many_as_it_takes_to_get_under_the_cap() {
        let mut chosen = choose_evictions(running(&[500, 100, 300, 200]), 2);
        chosen.sort();
        assert_eq!(chosen, ["bot-1", "bot-3"]);
    }

    #[test]
    fn the_one_that_just_asked_is_never_the_one_closed() {
        let now = 1_000_000;
        let chosen = choose_evictions(running(&[now - 10_000, now - 5_000, now]), 2);
        assert!(!chosen.iter().any(|key| key == "bot-2"));
    }

    #[test]
    fn a_cap_of_one_still_leaves_the_newest_running() {
        let now = 1_000_000;
        assert_eq!(choose_evictions(running(&[now - 1_000, now]), 1), ["bot-0"]);
    }

    #[test]
    fn closes_what_is_past_the_timeout() {
        let now = 1_000_000;
        assert_eq!(
            choose_idle(running(&[now - 60_000, now - 1_000]), 30_000, now),
            ["bot-0"]
        );
    }

    #[test]
    fn keeps_one_used_exactly_at_the_boundary_out_of_it() {
        let now = 1_000_000;
        assert_eq!(
            choose_idle(running(&[now - 30_000]), 30_000, now),
            ["bot-0"]
        );
        assert!(choose_idle(running(&[now - 29_999]), 30_000, now).is_empty());
    }

    #[test]
    fn a_timeout_of_zero_switches_it_off() {
        assert!(choose_idle(running(&[0]), 0, 1_000_000).is_empty());
        assert!(choose_idle(running(&[0]), -1, 1_000_000).is_empty());
    }

    #[test]
    fn closes_several_at_once() {
        let now = 1_000_000;
        let mut chosen = choose_idle(running(&[now - 60_000, now - 60_000, now]), 30_000, now);
        chosen.sort();
        assert_eq!(chosen, ["bot-0", "bot-1"]);
    }

    #[test]
    fn nothing_running_closes_nothing() {
        assert!(choose_idle(running(&[]), 30_000, 1_000_000).is_empty());
        assert!(choose_evictions(running(&[]), 8).is_empty());
    }

    #[test]
    fn a_cap_of_zero_closes_everything_which_is_why_empty_must() {
        assert_eq!(choose_evictions(running(&[1_000, 0]), 0).len(), 2);
    }

    #[test]
    fn the_default_keeps_several_browsers_which_is_what_an_unse() {
        assert_eq!(DEFAULT_MAX_LIVE_BROWSERS, 8);
        assert_eq!(DEFAULT_BROWSER_IDLE_TIMEOUT_MS, 1_800_000);
        assert!(choose_evictions(running(&[3, 2, 1]), 8).is_empty());
    }

    #[test]
    fn equal_timestamps_are_evicted_in_stable_insertion_order() {
        assert_eq!(
            choose_evictions(running(&[10, 10, 10]), 1),
            ["bot-0", "bot-1"]
        );
    }

    #[test]
    fn idle_cutoff_arithmetic_cannot_overflow() {
        assert!(choose_idle(running(&[i128::MAX]), 1, i128::MIN).is_empty());
        assert_eq!(
            choose_idle(running(&[i128::MIN]), i128::MAX, i128::MAX),
            ["bot-0"]
        );
    }
}
