//! hash chain：`row_hash = H(canonical(row) || prev_hash)`，以及**能指出断点位置**的校验。
//!
//! # 落地形态（v3 §8.6 / §28.1 R5）
//!
//! 链以**追加的两列 nullable 列**落在既有 `audit_events` 上：`prev_hash` / `row_hash`。
//! 三条约束决定了这个形态，缺一条都会变成另一种设计：
//!
//! 1. **不改分区表。** 把既有表改成分区表在 PostgreSQL 里等于建新表 + 搬行 + 换名，违反
//!    §14.3 兼容期禁令（禁止 drop / rename / 类型收紧 / 主键改写）。
//! 2. **必须 nullable。** 表里已经有行，而那些行从来没进过链。非空列意味着 backfill，
//!    而 backfill 一条历史审计行 = 给它补一个此刻才算出来的摘要 —— 那正是链要证明**没有**
//!    发生过的事。
//! 3. **首条 Rust 写入的行是 genesis**，它的 `prev_hash` 为 NULL；旧行两列都是 NULL。
//!    "链起点之前有 N 行未入链"这条事实由 genesis checkpoint 记下（[`super::checkpoint`]），
//!    于是"这段历史没有链保护"是**被写下来的**，不是靠读者自己发现的。
//!
//! # 这条链证明什么，不证明什么
//!
//! 证明：一段连续的行没有被**改写**或**抽走中间某行**而不留痕迹 —— 任一字节变化都会让
//! 该行的 `row_hash` 对不上，而后一行的 `prev_hash` 又钉住了它。
//!
//! 不证明：
//!
//! - **没有整段截断。** 一个能写库的攻击者可以把最后 K 行连同它们的 hash 一起删掉，剩下的
//!   链仍然自洽。对付截断的是周期 checkpoint（签名后另存，可选外部不可变 sink），不是链
//!   本身。这条限制必须说出来 —— 一条被误以为能防截断的链会让人不去部署真正能防截断的东西。
//! - **Desktop 上抵抗设备所有者。** §8.6 逐字：Desktop 同样 append-only，但只承诺可追溯，
//!   **不宣称**抵抗设备所有者 / root 篡改。链的签名密钥在同一台机器上，root 拿得到它就能
//!   重算整条链。
//!
//! # 为什么校验函数不能只回一个 bool
//!
//! "链断了"和"链在第 4173 行断了、那一行的 `row_hash` 对不上"是两条完全不同的信息，而后者
//! 是调查的起点。只回布尔的实现相当于在函数内部算出了断点位置，然后把它扔掉 —— 调用方要
//! 想知道就只能自己再实现一遍。所以 [`verify_chain`] 返回 [`ChainVerification`]，断裂时
//! 带上下标、事件 id 和断裂**种类**。

use openbot_contracts::ids::AuditEventId;

use super::event::AuditEvent;
use super::hash::{CanonicalWriter, Sha256Digest};

/// 审计行规范编码的域名标签。改它等于让全部既有 `row_hash` 失效，属于一次链重置。
pub const AUDIT_ROW_DOMAIN: &str = "openbot.audit.row.v1";

/// 上一行的摘要。
///
/// 独立枚举而不是直接用 `Option<Sha256Digest>`，是为了让 genesis 在**类型层面**有名字：
/// `None` 在调用点读起来像"这里还没填"，而 [`Self::Genesis`] 读起来是"这就是链的第一行"。
/// 两者在数据库里都是 NULL，但在代码里混淆它们会写出"忘了传 prev_hash 于是每行都成了
/// genesis"这种缺陷。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrevRowHash {
    /// 这是链的第一行。对应 `prev_hash` 列为 NULL。
    Genesis,
    /// 链上一行的 `row_hash`。
    Linked(Sha256Digest),
}

impl PrevRowHash {
    /// 投影成写库用的可空摘要。
    #[must_use]
    pub const fn as_option(&self) -> Option<Sha256Digest> {
        match self {
            Self::Genesis => None,
            Self::Linked(digest) => Some(*digest),
        }
    }

    /// 由读库得到的可空摘要还原。
    #[must_use]
    pub const fn from_option(value: Option<Sha256Digest>) -> Self {
        match value {
            None => Self::Genesis,
            Some(digest) => Self::Linked(digest),
        }
    }
}

impl AuditEvent {
    /// 计算该行在给定前驱下的 `row_hash`。
    ///
    /// 编码顺序：域名标签（由 [`CanonicalWriter::new`] 写入）→ 行的各列 → `prev_hash`。
    /// `prev_hash` 走 [`CanonicalWriter::option_digest`]，因此 genesis（`None`）与"前驱摘要
    /// 恰好是 32 个零字节"编出的字节不同 —— 链的起点无法伪造。
    #[must_use]
    pub fn row_hash(&self, prev: PrevRowHash) -> Sha256Digest {
        let mut writer = CanonicalWriter::new(AUDIT_ROW_DOMAIN);
        self.write_canonical(&mut writer);
        writer.option_digest(prev.as_option().as_ref());
        writer.digest_of_written()
    }
}

/// 一条**读回来的**审计行，连同它在数据库里的两个 hash 列。
///
/// 两列都是 `Option`，因为表里三种行都合法：
///
/// | `row_hash` | `prev_hash` | 含义 |
/// | --- | --- | --- |
/// | `None` | `None` | 链起点之前的旧行（未入链） |
/// | `Some` | `None` | genesis |
/// | `Some` | `Some` | 链上的普通行 |
///
/// 第四种组合（`row_hash` 为 NULL 而 `prev_hash` 非 NULL）在表里没有合法含义，
/// [`verify_chain`] 会把它判成 [`ChainBreakKind::PrevHashWithoutRowHash`]。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAuditRow {
    /// 行本身。
    pub event: AuditEvent,
    /// `prev_hash` 列。
    pub prev_hash: Option<Sha256Digest>,
    /// `row_hash` 列。
    pub row_hash: Option<Sha256Digest>,
}

impl StoredAuditRow {
    /// 由一条事件与前驱**现算**出一行 —— 写入路径用它。
    #[must_use]
    pub fn link(event: AuditEvent, prev: PrevRowHash) -> Self {
        let row_hash = event.row_hash(prev);
        Self {
            event,
            prev_hash: prev.as_option(),
            row_hash: Some(row_hash),
        }
    }

    /// 构造一条链起点之前的旧行（两列皆 NULL）。读侧还原历史数据时用。
    #[must_use]
    pub const fn unlinked(event: AuditEvent) -> Self {
        Self {
            event,
            prev_hash: None,
            row_hash: None,
        }
    }
}

/// 待校验区段相对于整条链的位置。
///
/// 没有这个入参，校验函数无法区分两件事：读到的第一条链上行**是** genesis，还是它只是
/// 某一页的第一行、它的前驱在上一页。把这个区分交给调用方是唯一诚实的做法 —— 只有调用方
/// 知道它查的是 `offset 0` 还是 `offset 4000`。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainAnchor {
    /// 区段从整条链的开头开始：第一条链上行必须是 genesis（`prev_hash` 为 NULL）。
    ///
    /// 区段**允许**以若干条未入链的旧行开头（链起点之前的历史）。
    ChainStart,
    /// 区段从链中间开始：第一条链上行的 `prev_hash` 必须等于给定摘要。
    ///
    /// 这种模式下未入链的旧行**不合法** —— 旧行只可能出现在 genesis 之前。
    ContinuingFrom(Sha256Digest),
}

/// 链校验结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainVerification {
    /// 区段自洽。
    Intact {
        /// 区段开头未入链的旧行条数（只可能出现在 [`ChainAnchor::ChainStart`] 模式下）。
        unlinked_prefix: usize,
        /// 已入链的行数。
        linked_rows: usize,
        /// 区段末尾的 `row_hash`；区段里一条链上行都没有时为 `None`。
        ///
        /// 它是下一段校验的 [`ChainAnchor::ContinuingFrom`] 入参 —— 分页校验一整张表时
        /// 靠它接力，而不必把全表读进内存。
        head: Option<Sha256Digest>,
    },
    /// 区段在某处断裂。
    Broken(ChainBreak),
}

/// 链断裂的具体位置与原因。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainBreak {
    /// 断裂行在传入切片中的下标。
    pub index: usize,
    /// 断裂行的事件 id —— 下标只在这次调用里有意义，id 才是能拿去查库的东西。
    pub event_id: AuditEventId,
    /// 断裂种类。
    pub kind: ChainBreakKind,
}

/// 链断裂的种类。四种，互斥且穷尽。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainBreakKind {
    /// 行内容与它自己记下的 `row_hash` 对不上 —— **这一行被改过**。
    RowHashMismatch {
        /// 数据库里记着的值。
        recorded: Sha256Digest,
        /// 按行内容重算出来的值。
        recomputed: Sha256Digest,
    },
    /// 行记下的 `prev_hash` 与前一行的 `row_hash` 对不上 —— **中间有行被抽走或被插入**。
    ///
    /// `expected` / `recorded` 为 `None` 表示 genesis 语义（`prev_hash` 列为 NULL）。
    PrevHashMismatch {
        /// 按前一行算出的应有值。
        expected: Option<Sha256Digest>,
        /// 数据库里记着的值。
        recorded: Option<Sha256Digest>,
    },
    /// 链已经开始之后又出现了一条未入链的行 —— 旧行只可能在 genesis 之前。
    UnlinkedRowAfterChainStart,
    /// `row_hash` 为空却有 `prev_hash`：这不是表里任何一种合法行。
    PrevHashWithoutRowHash,
}

/// 校验一段**连续**的审计行。
///
/// "连续"是前提，由调用方保证：行必须按 `(created_at, id)` 升序、无遗漏地读出来。传进来
/// 一段跳着读的行，本函数会诚实地报 [`ChainBreakKind::PrevHashMismatch`]——它无法区分
/// "有人抽走了行"和"你自己没读全"，也不该假装能区分。
///
/// 空切片返回 `Intact { unlinked_prefix: 0, linked_rows: 0, head: None }`：没有行就没有
/// 断裂，这不是"通过"，是"没有可判的东西"。调用方要区分的话看 `linked_rows`。
#[must_use]
pub fn verify_chain(rows: &[StoredAuditRow], anchor: ChainAnchor) -> ChainVerification {
    let mut expected_prev: Option<Sha256Digest> = match anchor {
        ChainAnchor::ChainStart => None,
        ChainAnchor::ContinuingFrom(head) => Some(head),
    };
    // 区段开头是否还允许出现未入链的旧行。`ContinuingFrom` 模式下一开始就不允许。
    let mut unlinked_still_allowed = matches!(anchor, ChainAnchor::ChainStart);
    let mut unlinked_prefix = 0usize;
    let mut linked_rows = 0usize;
    let mut head: Option<Sha256Digest> = None;

    for (index, row) in rows.iter().enumerate() {
        let break_at = |kind: ChainBreakKind| {
            ChainVerification::Broken(ChainBreak {
                index,
                event_id: row.event.id.clone(),
                kind,
            })
        };

        match (row.row_hash, row.prev_hash) {
            (None, None) => {
                if unlinked_still_allowed {
                    unlinked_prefix += 1;
                } else {
                    return break_at(ChainBreakKind::UnlinkedRowAfterChainStart);
                }
            }
            (None, Some(_)) => return break_at(ChainBreakKind::PrevHashWithoutRowHash),
            (Some(recorded), prev) => {
                // 第一条链上行落地之后，未入链的旧行就不再合法。
                unlinked_still_allowed = false;

                if prev != expected_prev {
                    return break_at(ChainBreakKind::PrevHashMismatch {
                        expected: expected_prev,
                        recorded: prev,
                    });
                }

                let recomputed = row.event.row_hash(PrevRowHash::from_option(prev));
                if recomputed != recorded {
                    return break_at(ChainBreakKind::RowHashMismatch {
                        recorded,
                        recomputed,
                    });
                }

                expected_prev = Some(recorded);
                head = Some(recorded);
                linked_rows += 1;
            }
        }
    }

    ChainVerification::Intact {
        unlinked_prefix,
        linked_rows,
        head,
    }
}

#[cfg(test)]
mod tests {
    use openbot_contracts::ids::ActorId;
    use time::OffsetDateTime;

    use super::*;
    use crate::audit::event::AuditEventType;
    use crate::audit::payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload};

    fn event(id: &str, seconds: i64) -> AuditEvent {
        AuditEvent {
            id: AuditEventId::new(id),
            actor: Some(ActorId::new("actor-1")),
            event_type: AuditEventType::COMPUTER_ACTION_ALLOWED,
            target_kind: AuditLabel::new("browser_tab"),
            target_id: Some(AuditIdentifier::new("tab-1").unwrap()),
            payload: AuditPayload::from_facts([AuditFact::DurationMs(12)]).unwrap(),
            created_at: OffsetDateTime::from_unix_timestamp(seconds).unwrap(),
        }
    }

    /// 从 genesis 起连续挂 `count` 行。
    fn linked_chain(count: usize) -> Vec<StoredAuditRow> {
        let mut prev = PrevRowHash::Genesis;
        let mut rows = Vec::new();
        for index in 0..count {
            let row = StoredAuditRow::link(
                event(&format!("ae-{index}"), 1_700_000_000 + index as i64),
                prev,
            );
            prev = PrevRowHash::Linked(row.row_hash.unwrap());
            rows.push(row);
        }
        rows
    }

    #[test]
    fn a_freshly_built_chain_verifies() {
        let rows = linked_chain(5);
        let result = verify_chain(&rows, ChainAnchor::ChainStart);
        assert_eq!(
            result,
            ChainVerification::Intact {
                unlinked_prefix: 0,
                linked_rows: 5,
                head: rows[4].row_hash,
            }
        );
    }

    /// 改动**任一列**都必须让链断在那一行。逐列覆盖，因为漏掉一列进编码就等于给篡改留门。
    #[test]
    fn every_column_is_covered_by_the_row_hash() {
        let baseline = linked_chain(3);

        // 类型别名而不是内联元组：clippy 的 type_complexity 在这里是对的 ——
        // “列名 + 一个变异函数”本来就是一个有名字的概念。
        type ColumnMutation = (&'static str, fn(&mut AuditEvent));
        let mutations: Vec<ColumnMutation> = vec![
            ("id", |e| e.id = AuditEventId::new("tampered")),
            ("actor_user_id", |e| e.actor = None),
            ("event_type", |e| {
                e.event_type = AuditEventType::COMPUTER_ACTION_REFUSED;
            }),
            ("target_type", |e| {
                e.target_kind = AuditLabel::new("mcp_server");
            }),
            ("target_id", |e| e.target_id = None),
            ("payload", |e| {
                e.payload = AuditPayload::from_facts([AuditFact::DurationMs(13)]).unwrap();
            }),
            ("created_at", |e| {
                e.created_at = OffsetDateTime::from_unix_timestamp(1).unwrap();
            }),
        ];

        for (column, mutate) in mutations {
            let mut rows = baseline.clone();
            mutate(&mut rows[1].event);
            match verify_chain(&rows, ChainAnchor::ChainStart) {
                ChainVerification::Broken(ChainBreak { index, kind, .. }) => {
                    assert_eq!(index, 1, "改 {column} 之后断点应在第 1 行");
                    assert!(
                        matches!(kind, ChainBreakKind::RowHashMismatch { .. }),
                        "改 {column} 之后应报 RowHashMismatch，实际是 {kind:?}"
                    );
                }
                other => panic!("改 {column} 之后链仍然自洽：{other:?}"),
            }
        }
    }

    /// 抽走中间一行：后一行的 `prev_hash` 立刻对不上，且断点指向后一行。
    #[test]
    fn removing_a_row_breaks_the_chain_at_the_next_row() {
        let mut rows = linked_chain(4);
        let removed = rows.remove(2);

        match verify_chain(&rows, ChainAnchor::ChainStart) {
            ChainVerification::Broken(break_at) => {
                assert_eq!(break_at.index, 2);
                assert_eq!(break_at.event_id, AuditEventId::new("ae-3"));
                assert_eq!(
                    break_at.kind,
                    ChainBreakKind::PrevHashMismatch {
                        expected: rows[1].row_hash,
                        recorded: removed.row_hash,
                    },
                    "被抽走那一行的 row_hash 正是后一行还记着的 prev_hash"
                );
            }
            other => panic!("抽走一行之后链仍然自洽：{other:?}"),
        }
    }

    /// 截断末尾**不会**被检出 —— 这是链的已知边界，写成测试免得被误以为能防。
    ///
    /// 它同时是 [`super::checkpoint`] 存在的理由：能发现截断的是签名后另存的 checkpoint。
    #[test]
    fn truncating_the_tail_is_not_detectable_by_the_chain_alone() {
        let rows = linked_chain(6);
        let truncated = &rows[..3];
        assert!(
            matches!(
                verify_chain(truncated, ChainAnchor::ChainStart),
                ChainVerification::Intact { linked_rows: 3, .. }
            ),
            "截断后的前缀仍然自洽 —— 链本身证明不了没有被截断"
        );
    }

    #[test]
    fn unlinked_legacy_rows_are_allowed_only_before_genesis() {
        let mut rows = vec![
            StoredAuditRow::unlinked(event("legacy-1", 1_600_000_000)),
            StoredAuditRow::unlinked(event("legacy-2", 1_600_000_001)),
        ];
        rows.extend(linked_chain(2));

        assert_eq!(
            verify_chain(&rows, ChainAnchor::ChainStart),
            ChainVerification::Intact {
                unlinked_prefix: 2,
                linked_rows: 2,
                head: rows[3].row_hash,
            }
        );

        // 负向：链开始之后再冒出一条未入链的行 = 有人绕过写入路径插了行。
        let mut interleaved = rows.clone();
        interleaved.push(StoredAuditRow::unlinked(event("legacy-3", 1_700_000_100)));
        match verify_chain(&interleaved, ChainAnchor::ChainStart) {
            ChainVerification::Broken(break_at) => {
                assert_eq!(break_at.index, 4);
                assert_eq!(break_at.kind, ChainBreakKind::UnlinkedRowAfterChainStart);
            }
            other => panic!("链开始后的未入链行必须被判断裂：{other:?}"),
        }
    }

    #[test]
    fn genesis_must_not_carry_a_prev_hash() {
        let mut rows = linked_chain(2);
        // 伪造一个"第二个 genesis"：把首行的 prev_hash 填上。
        let forged = Sha256Digest::of(b"forged");
        rows[0].prev_hash = Some(forged);

        match verify_chain(&rows, ChainAnchor::ChainStart) {
            ChainVerification::Broken(break_at) => {
                assert_eq!(break_at.index, 0);
                assert_eq!(
                    break_at.kind,
                    ChainBreakKind::PrevHashMismatch {
                        expected: None,
                        recorded: Some(forged),
                    }
                );
            }
            other => panic!("带 prev_hash 的 genesis 必须被判断裂：{other:?}"),
        }
    }

    #[test]
    fn prev_hash_without_row_hash_is_not_a_legal_row() {
        let mut rows = linked_chain(2);
        rows[1].row_hash = None;
        match verify_chain(&rows, ChainAnchor::ChainStart) {
            ChainVerification::Broken(break_at) => {
                assert_eq!(break_at.index, 1);
                assert_eq!(break_at.kind, ChainBreakKind::PrevHashWithoutRowHash);
            }
            other => panic!("row_hash 为空却有 prev_hash 必须被判断裂：{other:?}"),
        }
    }

    /// 分页校验：把一整条链切成两段，用第一段的 `head` 作为第二段的锚。
    #[test]
    fn segments_verify_by_handing_the_head_to_the_next_segment() {
        let rows = linked_chain(6);
        let ChainVerification::Intact { head, .. } =
            verify_chain(&rows[..3], ChainAnchor::ChainStart)
        else {
            panic!("前半段应当自洽");
        };
        let head = head.expect("前半段有链上行，head 不该为空");

        assert!(matches!(
            verify_chain(&rows[3..], ChainAnchor::ContinuingFrom(head)),
            ChainVerification::Intact { linked_rows: 3, .. }
        ));

        // 负向对照：换一个错的锚，第二段立刻断在第 0 行。
        match verify_chain(
            &rows[3..],
            ChainAnchor::ContinuingFrom(Sha256Digest::of(b"wrong")),
        ) {
            ChainVerification::Broken(break_at) => assert_eq!(break_at.index, 0),
            other => panic!("错误的锚必须让区段断裂：{other:?}"),
        }
    }

    /// `ContinuingFrom` 模式下不允许出现未入链的旧行。
    #[test]
    fn continuing_segment_rejects_unlinked_rows() {
        let rows = linked_chain(3);
        let head = rows[0].row_hash.unwrap();
        let mut tail = vec![StoredAuditRow::unlinked(event("legacy-x", 1_700_000_500))];
        tail.extend_from_slice(&rows[1..]);

        match verify_chain(&tail, ChainAnchor::ContinuingFrom(head)) {
            ChainVerification::Broken(break_at) => {
                assert_eq!(break_at.index, 0);
                assert_eq!(break_at.kind, ChainBreakKind::UnlinkedRowAfterChainStart);
            }
            other => panic!("中段的未入链行必须被判断裂：{other:?}"),
        }
    }

    #[test]
    fn empty_segment_is_vacuously_intact() {
        assert_eq!(
            verify_chain(&[], ChainAnchor::ChainStart),
            ChainVerification::Intact {
                unlinked_prefix: 0,
                linked_rows: 0,
                head: None,
            }
        );
    }

    /// genesis 的 `prev_hash` 是 NULL，而**不是**全零摘要 —— 两者的编码必须不同，
    /// 否则"链的第一行"是可以被伪造的位置。
    #[test]
    fn genesis_is_not_the_same_as_a_prev_hash_of_all_zeroes() {
        let subject = event("ae-0", 1_700_000_000);
        let zero = Sha256Digest::from_bytes([0u8; 32]);
        assert_ne!(
            subject.row_hash(PrevRowHash::Genesis),
            subject.row_hash(PrevRowHash::Linked(zero))
        );
    }

    /// 两条**不同**的行不可能算出同一个 `row_hash`：规范编码的单射性在这条链上的落点。
    ///
    /// 这里挑的是最容易撞的一组 —— 把同样的字符切在不同字段边界上。
    #[test]
    fn different_rows_never_share_a_row_hash() {
        let mut left = event("ab", 1_700_000_000);
        left.target_id = Some(AuditIdentifier::new("c").unwrap());
        let mut right = event("a", 1_700_000_000);
        right.target_id = Some(AuditIdentifier::new("bc").unwrap());

        assert_ne!(
            left.row_hash(PrevRowHash::Genesis),
            right.row_hash(PrevRowHash::Genesis)
        );

        // 正向对照：逐字段相同的两行确实算出同一个 hash（否则上一条在"hash 永远不同"的
        // 世界里也成立）。
        assert_eq!(
            event("ae-0", 1_700_000_000).row_hash(PrevRowHash::Genesis),
            event("ae-0", 1_700_000_000).row_hash(PrevRowHash::Genesis)
        );
    }
}
