//! `AUDIT_RETENTION_DAYS` 的三态解析，以及"哪些行在窗口外"的纯判定。
//!
//! # 三态必须分清，非法值**不能**折成"未配置"
//!
//! v3 §8.6 逐字：「`AUDIT_RETENTION_DAYS` 原名原义保留（未设 = 永久；≥ 1 的整数；非法值
//! 拒绝启动）」；R51 进一步把上游 `Number(raw)` 与本解析器的差异明确标为“变量名 preserve、
//! 数值语义替代”。所以 Rust 取值域是**三态**：
//!
//! | 输入 | 结果 | 后果 |
//! | --- | --- | --- |
//! | 未设 / 空串 | [`RetentionPolicy::Forever`] | 永久保留，sweep 不跑 |
//! | ≥ 1 的十进制整数 | [`RetentionPolicy::Days`] | 按窗口删 |
//! | 其它 | [`RetentionConfigError`] | **拒绝启动** |
//!
//! 把第三态折成第一态（"看不懂就当没配"）是最诱人也最危险的写法：一次拼写错误会让一份
//! 已经承诺给审计方的保留策略**静默失效**，而部署看起来一切正常。上游 `server/src/config.ts`
//! 的注释把这条讲得很清楚，本实现照办 —— 区别只在于它 `throw`，我们返回 `Err` 交给启动
//! 路径去 fail-closed（领域层不决定进程怎么死）。
//!
//! # 与上游的一处**有意分歧**：不做 JS 的数值强转
//!
//! 上游用 `Number(raw)` 再 `Number.isInteger`。本轮实测（`node -e` 跑
//! `Number(x)` + `Number.isInteger`，2026-08-22 本机 node）：
//!
//! | 输入 | 上游 `Number()` | 上游是否接受 | 本实现 |
//! | --- | --- | --- | --- |
//! | `"7"` | 7 | 是 | 接受 |
//! | `"0x10"` | 16 | **是（16 天）** | **拒绝** |
//! | `"1e3"` | 1000 | **是（1000 天）** | **拒绝** |
//! | `"+7"` | 7 | **是** | **拒绝** |
//! | `"7.0"` / `"0b101"` / `"1."` | 7 / 5 / 1 | **是** | **拒绝** |
//! | `"7.5"` / `"abc"` / `"0"` / `"-1"` | — | 否 | 拒绝 |
//!
//! 分歧发生在“`Number` 强转后是正整数、但原文不是十进制整数”的集合，方向是**收紧**。
//! 理由不是口味：台账写的是"拒绝启动而不是**强转**"，
//! 而 `Number("0x10") === 16` 恰恰就是一次强转 —— 管理员写下 `0x10`，系统执行 16 天，而
//! 保留策略是一项会被审计方逐字核对的控制。上游自己的注释也说「"我们接受了你的保留策略，
//! 但不是你写的那个"是一个坏答案」。
//!
//! **迁移可见的后果**：现网若真有部署把它写成 `1e3` / `0x10` / `+7` 等形态，切到 Rust
//! 后会拒绝启动。`openbot-migrate preflight-audit-retention` 会在 cutover 前给出不含原值的
//! 规范十进制替代值；不能表示成 `u32` 的值要求人工选择策略。
//!
//! # 删除是数据库授权的，本模块只做判定
//!
//! `audit_events` 的 append-only 由触发器 `prevent_audit_event_mutation()` 强制（仓内
//! `crates/openbot-infra/sql/baseline_0012.sql`，两个触发器
//! `audit_events_append_only`（`BEFORE DELETE OR UPDATE ... FOR EACH ROW`）与
//! `audit_events_no_truncate`（`BEFORE TRUNCATE ... FOR EACH STATEMENT`）共用它）。
//! 函数的判定顺序本身就是一条设计：
//!
//! 1. `TG_OP = 'TRUNCATE' OR TG_OP = 'UPDATE'` **无条件拒绝**，并且写在读任何设置之前 ——
//!    语句级触发器没有 `OLD` 记录，若先读设置再比 `OLD.created_at`，比较对象是 NULL、
//!    `IF` 不成立、控制流落到 `RETURN OLD`，TRUNCATE 就放行了。**这条路只在 retention
//!    sweep 已经设好窗口的那一刻可达**，正是 happy-path 测试不会走到的状态。
//! 2. DELETE 读会话 GUC `current_setting('openbot.audit_retention_days', true)`，
//!    取不到或 `< 1` 一律拒绝；
//! 3. 取到 N 时，只放行 `OLD.created_at < now() - N days` 的行 —— 换句话说
//!    `OLD.created_at >= 边界` 的行**任何设置都删不掉**。
//!
//! 本模块的 [`RetentionPolicy::classify`] 是同一条边界的纯函数版本（严格小于），
//! 用于在发 SQL 之前就把"这批行确实在窗口外"判明白。两侧判据必须同号，否则会出现
//! "应用以为删得掉、数据库拒绝"的死循环。
//!
//! # 属于 infra、但必须记在这里的三个数字
//!
//! 上游 `server/src/audit-retention.ts`：
//!
//! - **advisory lock `4_192_004`**（`SWEEP_LOCK`）：会话级锁，保证 N 个副本只有一个在扫。
//!   它必须走 sweep 自己独占的连接，不能过共享池 —— 会话锁属于某一条连接，池会在 A 上加、
//!   在 B 上放，锁就泄漏到那条连接死掉为止。`parity/tables.yaml::tbl-audit-events` 的 notes
//!   同样记着这个数字（本轮已核实）。
//! - **`BATCH = 5_000`**：一条 DELETE 删多少行。分批是因为单语句删几百万行会在"每个动作都要
//!   写"的这张表上长时间持锁。
//! - **`MAX_BATCHES = 200`**：一次 sweep 最多几批，剩下的留给下一次。
//!
//! 三者都是 infra 的实现参数，本模块**不实现**它们；记在这里是为了让后来者不必再翻一遍
//! 上游才知道这套机制长什么样，也为了让"改锁号"这种改动能被搜到。

use time::{Duration, OffsetDateTime};

use crate::text::trim_ecmascript;

use super::chain::StoredAuditRow;
use super::checkpoint::{AuditCheckpoint, AuditCheckpointKind, ChainSegment};

/// 保留天数：**≥ 1** 的整数。
///
/// newtype 而不是裸 `u32`：`0` 在这个域里不是"零天"而是非法值（触发器对 `< 1` 一律拒绝），
/// 而裸整数会让每个调用点各自记得去判一次。这里判一次，之后全链路都不必再判。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RetentionDays(u32);

impl RetentionDays {
    /// 由天数构造，`0` 返回 `None`。
    #[must_use]
    pub const fn new(days: u32) -> Option<Self> {
        if days == 0 { None } else { Some(Self(days)) }
    }

    /// 取出天数。
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// 保留策略。二态 —— 第三态（非法）在解析处就变成了 [`RetentionConfigError`]，
/// **进不到这个类型里**。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionPolicy {
    /// 未配置：永久保留。sweep 不跑，一行都不删。
    Forever,
    /// 配置为 N 天。
    Days(RetentionDays),
}

/// `AUDIT_RETENTION_DAYS` 解析失败。**调用方必须让启动失败**，不得回落成 `Forever`。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RetentionConfigError {
    /// 不是十进制整数（含小数、符号、十六进制、科学计数法、夹杂空白与任意文本）。
    #[error("audit_retention_days_not_a_whole_number")]
    NotAWholeNumber,
    /// 是整数但 `< 1`。
    #[error("audit_retention_days_below_minimum")]
    BelowMinimum,
    /// 整数但超出 `u32`。
    #[error("audit_retention_days_too_large")]
    TooLarge,
}

/// 解析 `AUDIT_RETENTION_DAYS`。
///
/// 入参是**已读出的原始值**（`None` = 环境里没有这个变量）。领域层不读环境。
///
/// 与上游 `optional()` 对齐的一处行为：**先 trim，trim 后为空等同未设**。上游
/// `environment[name]?.trim() || undefined` 就是这个语义，`.env` 文件里留一行
/// `AUDIT_RETENTION_DAYS=` 是常见写法，把它判成非法会让一批部署起不来。
///
/// # Errors
///
/// 见 [`RetentionConfigError`]。**任何一种都必须让启动失败**，理由见模块文档。
pub fn parse_retention_days(raw: Option<&str>) -> Result<RetentionPolicy, RetentionConfigError> {
    let Some(text) = raw.map(trim_ecmascript).filter(|value| !value.is_empty()) else {
        return Ok(RetentionPolicy::Forever);
    };

    // 只接受十进制数字。这一步就把 `0x10` / `1e3` / `+7` / `7.5` / `abc` 全部挡在外面 ——
    // `u32::from_str` 自己会接受前导 `+`，所以不能只靠它。
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RetentionConfigError::NotAWholeNumber);
    }

    // 前导零（`007`）是明确无歧义的十进制写法，接受。
    let days: u32 = text.parse().map_err(|_| RetentionConfigError::TooLarge)?;

    RetentionDays::new(days)
        .map(RetentionPolicy::Days)
        .ok_or(RetentionConfigError::BelowMinimum)
}

/// 删除窗口。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionWindow {
    /// 一行都不删。
    KeepEverything,
    /// 删除 `created_at` **严格早于**该时刻的行。
    DeleteBefore(OffsetDateTime),
}

/// 单行的保留判定。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowRetention {
    /// 在窗口内，必须保留。数据库同样会拒绝删它。
    Retained,
    /// 在窗口外，允许删除。
    OutsideWindow,
}

impl RetentionPolicy {
    /// 给定"现在"，算出删除窗口。`now` 由调用方传入 —— 领域层没有时钟。
    ///
    /// # 溢出时 fail-closed
    ///
    /// `now - N 天` 在 N 极大时会跑出 `OffsetDateTime` 的表示范围（`u32::MAX` 天约合 1176 万
    /// 年）。这种情况下返回 [`RetentionWindow::KeepEverything`]——一次算术溢出的正确降级是
    /// **不删**，而不是回绕成某个恰好合法的边界然后删掉一切。
    #[must_use]
    pub fn window(self, now: OffsetDateTime) -> RetentionWindow {
        match self {
            Self::Forever => RetentionWindow::KeepEverything,
            Self::Days(days) => now
                .checked_sub(Duration::days(i64::from(days.get())))
                .map_or(
                    RetentionWindow::KeepEverything,
                    RetentionWindow::DeleteBefore,
                ),
        }
    }

    /// 判定单行。
    ///
    /// 边界用**严格小于**，与触发器 `OLD.created_at >= now() - N days → 拒绝` 以及上游
    /// sweep 的 `where created_at < now() - interval` 逐字同号。恰好落在边界上的行**保留**。
    #[must_use]
    pub fn classify(self, created_at: OffsetDateTime, now: OffsetDateTime) -> RowRetention {
        match self.window(now) {
            RetentionWindow::KeepEverything => RowRetention::Retained,
            RetentionWindow::DeleteBefore(boundary) => {
                if created_at < boundary {
                    RowRetention::OutsideWindow
                } else {
                    RowRetention::Retained
                }
            }
        }
    }
}

/// 一次 retention 删除的**前置**产物：删之前要落的 closure checkpoint。
///
/// §8.6 逐字：「retention 删除窗口外的行之前，先为被删区间写一条包含首尾 `row_hash`、
/// event count 的 closure checkpoint，链边界由此保留。」
///
/// 没有它，一次合法删除与一次截断攻击在事后完全同形：链自洽、行数变少、无从分辨。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionClosurePlan {
    /// 被删区间里**未入链**（链起点之前）的旧行条数。
    ///
    /// 单独记而不是并进 `event_count`：这些行本来就不在链里，把它们算进链区间的条数会让
    /// checkpoint 记下一个与链对不上的数字。
    pub unlinked_rows_deleted: u64,
    /// 被删区间里**链上行**的封口 checkpoint。
    ///
    /// `None` 的唯一合法情形：这一批全是链起点之前的旧行 —— 没有任何链边界被移动，因此
    /// 没有边界要保留。genesis checkpoint 里的 `unlinked_rows_before` 记的是"链开始那一刻
    /// 之前有多少行"，是一条历史事实，删掉其中一部分不会让它变假。
    pub checkpoint: Option<AuditCheckpoint>,
}

/// 规划 closure checkpoint 失败。**每一种都必须让这次 sweep 停下来，不得跳过 checkpoint 直接删。**
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RetentionClosureError {
    /// 策略是永久保留，却有人要删。
    #[error("retention_closure_no_window")]
    NoRetentionWindow,
    /// 待删集合是空的 —— 没有东西要封口，调用方多半算错了。
    #[error("retention_closure_empty_selection")]
    EmptySelection,
    /// 选中的行还在窗口内。数据库也会拒绝它，这里提前拦下。
    #[error("retention_closure_row_inside_window index={index}")]
    RowInsideWindow {
        /// 越界行在传入切片中的下标。
        index: usize,
    },
    /// 行的两个 hash 列组合非法（`prev_hash` 非空而 `row_hash` 为空）。
    #[error("retention_closure_corrupt_row index={index}")]
    CorruptRow {
        /// 损坏行的下标。
        index: usize,
    },
    /// 未入链的旧行出现在链上行之后 —— 旧行只可能在 genesis 之前。
    #[error("retention_closure_unlinked_after_linked index={index}")]
    UnlinkedRowAfterLinkedRow {
        /// 越序行的下标。
        index: usize,
    },
}

/// 为一批**按 `(created_at, id)` 升序**的待删行规划 closure checkpoint。
///
/// 调用序固定：先调本函数 → 写下返回的 checkpoint（若有）→ 再发 DELETE。反过来就是
/// §8.6 那句"删除之前"的字面反面。
///
/// # Errors
///
/// 见 [`RetentionClosureError`]。函数**只判定，不删**；任何一个错误都意味着这次 sweep
/// 不该继续。
pub fn plan_retention_closure(
    rows: &[StoredAuditRow],
    policy: RetentionPolicy,
    now: OffsetDateTime,
    sequence: u64,
    checkpoint_created_at: OffsetDateTime,
) -> Result<RetentionClosurePlan, RetentionClosureError> {
    let RetentionPolicy::Days(retention_days) = policy else {
        return Err(RetentionClosureError::NoRetentionWindow);
    };
    if rows.is_empty() {
        return Err(RetentionClosureError::EmptySelection);
    }

    let mut unlinked_rows_deleted = 0u64;
    let mut linked_count = 0u64;
    let mut first_linked: Option<(&StoredAuditRow, super::hash::Sha256Digest)> = None;
    let mut last_linked: Option<(&StoredAuditRow, super::hash::Sha256Digest)> = None;

    for (index, row) in rows.iter().enumerate() {
        if policy.classify(row.event.created_at, now) == RowRetention::Retained {
            return Err(RetentionClosureError::RowInsideWindow { index });
        }

        match (row.row_hash, row.prev_hash) {
            (None, None) => {
                if first_linked.is_some() {
                    return Err(RetentionClosureError::UnlinkedRowAfterLinkedRow { index });
                }
                unlinked_rows_deleted += 1;
            }
            (None, Some(_)) => return Err(RetentionClosureError::CorruptRow { index }),
            (Some(row_hash), _) => {
                if first_linked.is_none() {
                    first_linked = Some((row, row_hash));
                }
                last_linked = Some((row, row_hash));
                linked_count += 1;
            }
        }
    }

    let checkpoint = match (first_linked, last_linked) {
        (Some((first, first_row_hash)), Some((last, last_row_hash))) => Some(AuditCheckpoint {
            sequence,
            created_at: checkpoint_created_at,
            kind: AuditCheckpointKind::Closure {
                segment: ChainSegment {
                    first_event: first.event.id.clone(),
                    first_row_hash,
                    last_event: last.event.id.clone(),
                    last_row_hash,
                    event_count: linked_count,
                },
                retention_days,
            },
        }),
        _ => None,
    };

    Ok(RetentionClosurePlan {
        unlinked_rows_deleted,
        checkpoint,
    })
}

#[cfg(test)]
mod tests {
    use openbot_contracts::ids::{ActorId, AuditEventId};

    use super::*;
    use crate::audit::chain::PrevRowHash;
    use crate::audit::event::{AuditEvent, AuditEventType};
    use crate::audit::payload::{AuditLabel, AuditPayload};

    fn at(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(seconds).unwrap()
    }

    fn event(id: &str, seconds: i64) -> AuditEvent {
        AuditEvent {
            id: AuditEventId::new(id),
            actor: Some(ActorId::new("actor-1")),
            event_type: AuditEventType::COMPUTER_ACTION_ALLOWED,
            target_kind: AuditLabel::new("browser_tab"),
            target_id: None,
            payload: AuditPayload::empty(),
            created_at: at(seconds),
        }
    }

    const DAY: i64 = 86_400;

    #[test]
    fn unset_and_blank_mean_forever() {
        assert_eq!(parse_retention_days(None), Ok(RetentionPolicy::Forever));
        assert_eq!(parse_retention_days(Some("")), Ok(RetentionPolicy::Forever));
        // 上游 `optional()` 会 trim，`AUDIT_RETENTION_DAYS=   ` 是常见写法。
        assert_eq!(
            parse_retention_days(Some("   ")),
            Ok(RetentionPolicy::Forever)
        );
        assert_eq!(
            parse_retention_days(Some("\u{FEFF}\u{3000}")),
            Ok(RetentionPolicy::Forever)
        );
    }

    #[test]
    fn a_whole_number_of_days_is_accepted() {
        assert_eq!(
            parse_retention_days(Some("30")),
            Ok(RetentionPolicy::Days(RetentionDays::new(30).unwrap()))
        );
        // trim 之后再判，与上游 `optional()` 同。
        assert_eq!(
            parse_retention_days(Some("  30  ")),
            Ok(RetentionPolicy::Days(RetentionDays::new(30).unwrap()))
        );
        assert_eq!(
            parse_retention_days(Some("\u{FEFF}\u{3000}30\u{00A0}")),
            Ok(RetentionPolicy::Days(RetentionDays::new(30).unwrap()))
        );
        // 前导零无歧义，接受。
        assert_eq!(
            parse_retention_days(Some("007")),
            Ok(RetentionPolicy::Days(RetentionDays::new(7).unwrap()))
        );
        assert_eq!(
            parse_retention_days(Some("1")),
            Ok(RetentionPolicy::Days(RetentionDays::new(1).unwrap()))
        );
    }

    /// **三态不许折叠**：非法值返回 `Err`，绝不返回 `Ok(Forever)`。
    ///
    /// 判据写成"不等于 `Ok(Forever)`"而不只是"是 Err"，因为前者才是这条不变量真正要防的
    /// 失效形态 —— 一次拼错让保留策略静默消失。
    #[test]
    fn illegal_values_are_refused_and_never_collapse_into_forever() {
        let cases = [
            ("0", RetentionConfigError::BelowMinimum),
            ("-1", RetentionConfigError::NotAWholeNumber),
            ("7.5", RetentionConfigError::NotAWholeNumber),
            ("abc", RetentionConfigError::NotAWholeNumber),
            ("7abc", RetentionConfigError::NotAWholeNumber),
            ("3 0", RetentionConfigError::NotAWholeNumber),
            ("Infinity", RetentionConfigError::NotAWholeNumber),
            ("\u{0085}30\u{0085}", RetentionConfigError::NotAWholeNumber),
            ("99999999999", RetentionConfigError::TooLarge),
        ];
        for (raw, expected) in cases {
            let actual = parse_retention_days(Some(raw));
            assert_eq!(actual, Err(expected), "{raw} 的解析结果不对");
            assert_ne!(
                actual,
                Ok(RetentionPolicy::Forever),
                "{raw} 被折成了「未配置」—— 这正是要防的静默失效"
            );
        }
    }

    /// 与上游 JS 数值强转的**有意分歧**，逐条钉死。
    ///
    /// 本轮实测（node）：`0x10` / `1e3` / `+7` / `0b101` 上游都会接受；`1_000` 是上游也
    /// 拒绝的负向对照。这条测试是“我们知道并且故意不强转”的可执行记录 —— 哪天有人为了
    /// “和上游一致”把它改成接受，会先看到这段。
    #[test]
    fn javascript_numeric_coercions_are_deliberately_refused() {
        for raw in ["0x10", "1e3", "+7", "0b101", "1_000"] {
            assert_eq!(
                parse_retention_days(Some(raw)),
                Err(RetentionConfigError::NotAWholeNumber),
                "{raw} 必须被拒绝：台账写的是「拒绝启动而不是强转」"
            );
        }
        // 正向对照：同一个解析器确实接受等价的十进制写法。
        assert_eq!(
            parse_retention_days(Some("16")),
            Ok(RetentionPolicy::Days(RetentionDays::new(16).unwrap()))
        );
        assert_eq!(
            parse_retention_days(Some("1000")),
            Ok(RetentionPolicy::Days(RetentionDays::new(1000).unwrap()))
        );
    }

    #[test]
    fn forever_never_deletes_anything() {
        let now = at(1_700_000_000);
        assert_eq!(
            RetentionPolicy::Forever.window(now),
            RetentionWindow::KeepEverything
        );
        // 一条 100 年前的行照样保留。
        assert_eq!(
            RetentionPolicy::Forever.classify(at(0), now),
            RowRetention::Retained
        );
    }

    /// 边界用**严格小于**，与触发器和上游 SQL 同号。恰好落在边界的行保留。
    #[test]
    fn the_window_boundary_is_strictly_less_than() {
        let now = at(1_700_000_000);
        let policy = RetentionPolicy::Days(RetentionDays::new(30).unwrap());
        let boundary = now - Duration::days(30);
        assert_eq!(policy.window(now), RetentionWindow::DeleteBefore(boundary));

        // 早一纳秒：可删。
        assert_eq!(
            policy.classify(boundary - Duration::nanoseconds(1), now),
            RowRetention::OutsideWindow
        );
        // 恰好在边界：保留（触发器判 `>=` 即拒绝）。
        assert_eq!(policy.classify(boundary, now), RowRetention::Retained);
        // 晚一纳秒：保留。
        assert_eq!(
            policy.classify(boundary + Duration::nanoseconds(1), now),
            RowRetention::Retained
        );
    }

    /// 天数极大导致时间算术溢出时，正确降级是**不删**。
    #[test]
    fn arithmetic_overflow_degrades_to_keeping_everything() {
        let now = at(1_700_000_000);
        let policy = RetentionPolicy::Days(RetentionDays::new(u32::MAX).unwrap());
        assert_eq!(policy.window(now), RetentionWindow::KeepEverything);
        assert_eq!(policy.classify(at(0), now), RowRetention::Retained);

        // 正向对照：同一条判定路径在正常天数下确实会给出 DeleteBefore。
        let sane = RetentionPolicy::Days(RetentionDays::new(1).unwrap());
        assert!(matches!(sane.window(now), RetentionWindow::DeleteBefore(_)));
    }

    #[test]
    fn retention_days_rejects_zero() {
        assert_eq!(RetentionDays::new(0), None);
        assert_eq!(RetentionDays::new(1).unwrap().get(), 1);
    }

    /// closure checkpoint 记下被删区间的首尾 `row_hash` 与条数。
    #[test]
    fn closure_plan_records_the_deleted_segment_boundaries() {
        let now = at(1_700_000_000);
        let policy = RetentionPolicy::Days(RetentionDays::new(30).unwrap());

        let mut prev = PrevRowHash::Genesis;
        let mut rows = Vec::new();
        for index in 0..3usize {
            let row = StoredAuditRow::link(
                event(
                    &format!("ae-{index}"),
                    1_700_000_000 - 100 * DAY + index as i64,
                ),
                prev,
            );
            prev = PrevRowHash::Linked(row.row_hash.unwrap());
            rows.push(row);
        }

        let plan = plan_retention_closure(&rows, policy, now, 5, now).unwrap();
        assert_eq!(plan.unlinked_rows_deleted, 0);
        let checkpoint = plan.checkpoint.expect("有链上行就必须产出 checkpoint");
        assert_eq!(checkpoint.sequence, 5);
        match checkpoint.kind {
            AuditCheckpointKind::Closure {
                segment,
                retention_days,
            } => {
                assert_eq!(segment.first_event, AuditEventId::new("ae-0"));
                assert_eq!(segment.first_row_hash, rows[0].row_hash.unwrap());
                assert_eq!(segment.last_event, AuditEventId::new("ae-2"));
                assert_eq!(segment.last_row_hash, rows[2].row_hash.unwrap());
                assert_eq!(segment.event_count, 3);
                assert_eq!(retention_days.get(), 30);
            }
            other => panic!("必须是 closure checkpoint，实际是 {other:?}"),
        }
    }

    /// 全是链起点之前的旧行时没有链边界被移动，因此没有 checkpoint —— 但条数仍要记下。
    #[test]
    fn deleting_only_pre_chain_rows_moves_no_chain_boundary() {
        let now = at(1_700_000_000);
        let policy = RetentionPolicy::Days(RetentionDays::new(30).unwrap());
        let rows = vec![
            StoredAuditRow::unlinked(event("legacy-1", 1_700_000_000 - 100 * DAY)),
            StoredAuditRow::unlinked(event("legacy-2", 1_700_000_000 - 99 * DAY)),
        ];

        let plan = plan_retention_closure(&rows, policy, now, 1, now).unwrap();
        assert_eq!(plan.unlinked_rows_deleted, 2);
        assert!(plan.checkpoint.is_none());
    }

    /// 混合区间：旧行在前、链上行在后，两个计数各归各的。
    #[test]
    fn a_mixed_batch_counts_unlinked_and_linked_separately() {
        let now = at(1_700_000_000);
        let policy = RetentionPolicy::Days(RetentionDays::new(30).unwrap());
        let mut rows = vec![StoredAuditRow::unlinked(event(
            "legacy-1",
            1_700_000_000 - 100 * DAY,
        ))];
        let linked = StoredAuditRow::link(
            event("ae-0", 1_700_000_000 - 99 * DAY),
            PrevRowHash::Genesis,
        );
        rows.push(linked);

        let plan = plan_retention_closure(&rows, policy, now, 2, now).unwrap();
        assert_eq!(plan.unlinked_rows_deleted, 1);
        match plan.checkpoint.unwrap().kind {
            AuditCheckpointKind::Closure { segment, .. } => assert_eq!(segment.event_count, 1),
            other => panic!("必须是 closure checkpoint，实际是 {other:?}"),
        }
    }

    /// 每一种规划错误都必须停下这次 sweep，而不是"跳过 checkpoint 照删"。
    #[test]
    fn every_planning_error_stops_the_sweep() {
        let now = at(1_700_000_000);
        let policy = RetentionPolicy::Days(RetentionDays::new(30).unwrap());
        let old = StoredAuditRow::link(
            event("ae-0", 1_700_000_000 - 100 * DAY),
            PrevRowHash::Genesis,
        );

        // 永久保留策略下不该有任何删除。
        assert_eq!(
            plan_retention_closure(
                std::slice::from_ref(&old),
                RetentionPolicy::Forever,
                now,
                1,
                now
            ),
            Err(RetentionClosureError::NoRetentionWindow)
        );
        // 空集合。
        assert_eq!(
            plan_retention_closure(&[], policy, now, 1, now),
            Err(RetentionClosureError::EmptySelection)
        );
        // 窗口内的行被选中了 —— 数据库也会拒绝，这里提前拦。
        let fresh =
            StoredAuditRow::link(event("ae-fresh", 1_700_000_000 - DAY), PrevRowHash::Genesis);
        assert_eq!(
            plan_retention_closure(&[fresh], policy, now, 1, now),
            Err(RetentionClosureError::RowInsideWindow { index: 0 })
        );
        // 两个 hash 列组合非法。
        let mut corrupt = old.clone();
        corrupt.row_hash = None;
        corrupt.prev_hash = Some(crate::audit::hash::Sha256Digest::of(b"x"));
        assert_eq!(
            plan_retention_closure(&[corrupt], policy, now, 1, now),
            Err(RetentionClosureError::CorruptRow { index: 0 })
        );
        // 旧行出现在链上行之后。
        let stray = StoredAuditRow::unlinked(event("legacy-late", 1_700_000_000 - 98 * DAY));
        assert_eq!(
            plan_retention_closure(&[old, stray], policy, now, 1, now),
            Err(RetentionClosureError::UnlinkedRowAfterLinkedRow { index: 1 })
        );
    }
}
