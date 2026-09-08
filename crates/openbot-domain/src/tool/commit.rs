//! `commit_state` 的语义，以及"non-idempotent unknown commit 不自动重放"的判定
//! （§8.1 / §17.2 条 9 / repository contract §5 条 9）。
//!
//! # `unknown` 不是"失败"，也不是"成功"
//!
//! 三态里最重要的是第三态。工具执行完毕、结果却写不进库（连接断了、事务回滚、进程被杀），
//! 此时**远端的副作用已经发生与否是不可知的** —— 请求可能到了对面并成功，也可能在半路
//! 断掉。把它折成"失败"就会去重试（可能重复扣款）；折成"成功"就会漏掉真的没做成的情况。
//!
//! §15.3 因此规定 unknown commit 走 202/409 对应 reconciliation，**不伪装 500 或 success**；
//! `openbot_contracts::error::AppError::ReconciliationRequired` 是它在错误域里的落点。
//! 本模块管的是它在**重放决策**上的落点。
//!
//! # 判定表
//!
//! | commit_state | idempotency | 判定 | 理由 |
//! | --- | --- | --- | --- |
//! | `Committed` | 任意 | [`ReplayJudgement::NoReplayNeeded`] | 已经成了，重放只会做第二遍 |
//! | `NotCommitted` | 任意 | [`ReplayJudgement::SafeToReplay`] | **确知**没发生，重放不会产生第二次副作用 |
//! | `Unknown` | `Idempotent` | `SafeToReplay` | 做两次与做一次等价 |
//! | `Unknown` | `Keyed` + 有键 | `SafeToReplay` | 对端凭键去重 |
//! | `Unknown` | `Keyed` + **无键** | [`ReplayJudgement::MustNotReplay`] | 声明了要用键却没有键，去重不会发生 |
//! | `Unknown` | `NonIdempotent` | `MustNotReplay` | §17.2 条 9 |
//!
//! 中间那条（`Keyed` 但键缺席）是这张表里唯一需要论证的格子。声明成 `Keyed` 的工具，其
//! "重放安全"这件事**由键提供**，不是由工具本身提供；键没带上时它的实际行为与
//! `NonIdempotent` 完全一样。把它当安全处理，等于把一个"要满足前提才成立"的性质在前提
//! 不成立时照样采信 —— 这正是 fail-closed 要挡的那种推理。

use super::metadata::Idempotency;

/// 一次工具执行的提交状态。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CommitState {
    /// 确知已提交：副作用发生了，结果也记下来了。
    Committed,
    /// 确知未提交：副作用没有发生。
    NotCommitted,
    /// **不可知**：执行发生过，但结果写不进来。理由见模块文档。
    Unknown,
}

impl CommitState {
    /// 稳定字面量（进审计 payload 用）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::NotCommitted => "not_committed",
            Self::Unknown => "unknown",
        }
    }

    /// 这个状态是否需要进入 reconciliation 流程。
    #[must_use]
    pub const fn requires_reconciliation(self) -> bool {
        matches!(self, Self::Unknown)
    }
}

/// 幂等键。
///
/// 非空校验是它唯一的构造约束：空串在对端去重表里与"没带键"不可区分，而这两者在本模块的
/// 判定表里是不同的格子。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// 校验并构造。空串返回 `None`。
    #[must_use]
    pub fn new(value: impl Into<String>) -> Option<Self> {
        let value = value.into();
        if value.is_empty() {
            None
        } else {
            Some(Self(value))
        }
    }

    /// 借出底层字符串。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 一次重放判定的输入。
///
/// 做成结构体而不是三个散参数：三者必须**同时**看，任何"先看 commit_state 再决定要不要看
/// idempotency"的写法都会在某条分支上把其中一个忘掉。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayRequest {
    /// 上一次尝试的提交状态。
    pub commit_state: CommitState,
    /// 工具声明的幂等性档位。
    pub idempotency: Idempotency,
    /// 上一次尝试实际携带的幂等键。
    ///
    /// 是"实际携带的"而不是"能不能造一个"：一个此刻才生成的新键对上一次尝试的去重毫无用处。
    pub idempotency_key: Option<IdempotencyKey>,
}

/// 重放判定。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayJudgement {
    /// 不需要重放（已提交）。
    NoReplayNeeded,
    /// 可以自动重放。
    SafeToReplay,
    /// **不得自动重放**，必须走 reconciliation / 等人。
    MustNotReplay {
        /// 具体原因。
        reason: NoReplayReason,
    },
}

/// 不得自动重放的原因。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoReplayReason {
    /// 非幂等 + commit 未知（§17.2 条 9）。
    NonIdempotentUnknownCommit,
    /// 声明为 keyed 却没有携带幂等键，去重不会发生。
    KeyedWithoutIdempotencyKey,
}

impl NoReplayReason {
    /// 稳定字面量。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NonIdempotentUnknownCommit => "non_idempotent_unknown_commit",
            Self::KeyedWithoutIdempotencyKey => "keyed_without_idempotency_key",
        }
    }
}

/// 判定一次尝试能不能自动重放。判定表见模块文档。
#[must_use]
pub fn judge_replay(request: &ReplayRequest) -> ReplayJudgement {
    match request.commit_state {
        CommitState::Committed => ReplayJudgement::NoReplayNeeded,
        CommitState::NotCommitted => ReplayJudgement::SafeToReplay,
        CommitState::Unknown => match request.idempotency {
            Idempotency::Idempotent => ReplayJudgement::SafeToReplay,
            Idempotency::Keyed => {
                if request.idempotency_key.is_some() {
                    ReplayJudgement::SafeToReplay
                } else {
                    ReplayJudgement::MustNotReplay {
                        reason: NoReplayReason::KeyedWithoutIdempotencyKey,
                    }
                }
            }
            Idempotency::NonIdempotent => ReplayJudgement::MustNotReplay {
                reason: NoReplayReason::NonIdempotentUnknownCommit,
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(
        commit_state: CommitState,
        idempotency: Idempotency,
        key: Option<&str>,
    ) -> ReplayRequest {
        ReplayRequest {
            commit_state,
            idempotency,
            idempotency_key: key.and_then(IdempotencyKey::new),
        }
    }

    /// §17.2 条 9 的正面兑现：非幂等 + 未知 commit **绝不**自动重放。
    #[test]
    fn non_idempotent_unknown_commit_is_never_replayed() {
        assert_eq!(
            judge_replay(&request(
                CommitState::Unknown,
                Idempotency::NonIdempotent,
                None
            )),
            ReplayJudgement::MustNotReplay {
                reason: NoReplayReason::NonIdempotentUnknownCommit
            }
        );
        // 就算硬塞一个键也不行：工具声明的是非幂等，键对它没有意义。
        assert_eq!(
            judge_replay(&request(
                CommitState::Unknown,
                Idempotency::NonIdempotent,
                Some("k-1")
            )),
            ReplayJudgement::MustNotReplay {
                reason: NoReplayReason::NonIdempotentUnknownCommit
            }
        );
    }

    /// 正向对照：同一个判定器在幂等工具上确实会放行。
    ///
    /// 没有它，上一条在"judge_replay 永远返回 MustNotReplay"的世界里同样全绿。
    #[test]
    fn idempotent_tools_may_be_replayed_after_an_unknown_commit() {
        assert_eq!(
            judge_replay(&request(
                CommitState::Unknown,
                Idempotency::Idempotent,
                None
            )),
            ReplayJudgement::SafeToReplay
        );
    }

    /// `Keyed` 的安全性**来自键**：键缺席时按不安全处理。
    #[test]
    fn keyed_without_a_key_is_treated_as_unsafe() {
        assert_eq!(
            judge_replay(&request(
                CommitState::Unknown,
                Idempotency::Keyed,
                Some("k-1")
            )),
            ReplayJudgement::SafeToReplay
        );
        assert_eq!(
            judge_replay(&request(CommitState::Unknown, Idempotency::Keyed, None)),
            ReplayJudgement::MustNotReplay {
                reason: NoReplayReason::KeyedWithoutIdempotencyKey
            }
        );
        // 空串键 = 没带键：`IdempotencyKey::new("")` 返回 None。
        assert_eq!(
            judge_replay(&request(CommitState::Unknown, Idempotency::Keyed, Some(""))),
            ReplayJudgement::MustNotReplay {
                reason: NoReplayReason::KeyedWithoutIdempotencyKey
            }
        );
    }

    /// 确知未提交时，连非幂等工具都可以重放 —— 这条是"unknown 才是问题"的可执行证明。
    #[test]
    fn a_known_failure_is_safe_to_replay_even_when_non_idempotent() {
        for idempotency in [
            Idempotency::Idempotent,
            Idempotency::Keyed,
            Idempotency::NonIdempotent,
        ] {
            assert_eq!(
                judge_replay(&request(CommitState::NotCommitted, idempotency, None)),
                ReplayJudgement::SafeToReplay,
                "{} 在确知未提交时可以重放",
                idempotency.as_str()
            );
        }
    }

    #[test]
    fn a_committed_attempt_needs_no_replay() {
        for idempotency in [
            Idempotency::Idempotent,
            Idempotency::Keyed,
            Idempotency::NonIdempotent,
        ] {
            assert_eq!(
                judge_replay(&request(CommitState::Committed, idempotency, None)),
                ReplayJudgement::NoReplayNeeded
            );
        }
    }

    /// 判定表**全覆盖**：3 × 3 × 2（键有无）= 18 格，逐格都有确定答案且不为 panic。
    ///
    /// 顺带钉死"只有 unknown 会产出 MustNotReplay"这条整体性质。
    #[test]
    fn the_full_decision_table_is_total_and_only_unknown_can_refuse() {
        for commit_state in [
            CommitState::Committed,
            CommitState::NotCommitted,
            CommitState::Unknown,
        ] {
            for idempotency in [
                Idempotency::Idempotent,
                Idempotency::Keyed,
                Idempotency::NonIdempotent,
            ] {
                for key in [None, Some("k-1")] {
                    let judgement = judge_replay(&request(commit_state, idempotency, key));
                    if matches!(judgement, ReplayJudgement::MustNotReplay { .. }) {
                        assert_eq!(
                            commit_state,
                            CommitState::Unknown,
                            "只有 unknown commit 才可能拒绝重放"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn only_unknown_requires_reconciliation() {
        assert!(CommitState::Unknown.requires_reconciliation());
        assert!(!CommitState::Committed.requires_reconciliation());
        assert!(!CommitState::NotCommitted.requires_reconciliation());
    }

    #[test]
    fn empty_idempotency_keys_are_refused_at_construction() {
        assert!(IdempotencyKey::new("").is_none());
        assert_eq!(IdempotencyKey::new("k").unwrap().as_str(), "k");
    }
}
