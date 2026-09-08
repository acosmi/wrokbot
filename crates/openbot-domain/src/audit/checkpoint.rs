//! 周期 checkpoint：链**证明不了**的那部分，由签名后另存的检查点承担。
//!
//! # 它补的是哪个洞
//!
//! [`super::chain`] 的链能发现"某一行被改过"和"中间被抽走一行"，但发现不了**整段截断**：
//! 把最后 K 行连同它们的 hash 一起删掉，剩下的链仍然自洽（`chain` 模块的
//! `truncating_the_tail_is_not_detectable_by_the_chain_alone` 就是这条事实的可执行形式）。
//!
//! checkpoint 是链之外的第二份证据：它记下"截至某时刻，链的头是这个摘要、一共这么多条"，
//! 并**签名**。之后再有人截断，链自洽但与最后一份 checkpoint 对不上。
//!
//! # 三种 checkpoint，各自补一个具体的洞（v3 §8.6）
//!
//! - [`AuditCheckpointKind::Genesis`]：链起点。它还必须记下**链起点之前有 N 行未入链** ——
//!   否则读者面对一张 40 万行、其中前 12 万行 hash 为 NULL 的表，无法判断那 12 万行是
//!   "迁移前的历史"还是"有人把 hash 列清空了"。这条数字把前者变成一句写下来的话。
//! - [`AuditCheckpointKind::Periodic`]：周期快照，记区间首尾 `row_hash` 与条数。
//! - [`AuditCheckpointKind::Closure`]：**retention 删除之前**为被删区间写的封口。§8.6 逐字：
//!   「retention 删除窗口外的行之前，先为被删区间写一条包含首尾 `row_hash`、event count 的
//!   closure checkpoint，链边界由此保留。」没有它，一次合法的 retention 删除和一次截断攻击
//!   在事后看起来完全一样。
//!
//! # 存放位置：本库表，外部 sink 可选
//!
//! §8.6 与 §28.1 R5 已裁决：checkpoint 签名后写入**本库** `audit_checkpoints` 表；外部
//! 不可变存储（S3 object-lock / 只追加文件）是**可选 sink**，未配置时 readiness 不受影响。
//! 理由是"不可变对象存储"是一项新的上线前置基础设施，把它写成硬前置等于让审计功能的可用性
//! 取决于一件运维还没做的事。代价要说清楚：只写本库时，能写库的攻击者可以连 checkpoint
//! 一起改 —— 真正的抗篡改需要那个可选 sink，本模块只保证"配了就有用"。
//!
//! # 密钥不进领域层
//!
//! [`AuditCheckpoint::sign`] 接受 `&[u8]` 而不是持有一个密钥类型：密钥的来源、轮换与生命
//! 周期是 infra 的事（§6.4）。领域层做的是给定密钥与内容的**纯函数**，这样它既可测又不会
//! 变成一个装着秘密的类型在各层之间传递。

use hmac::{Hmac, Mac};
use openbot_contracts::ids::AuditEventId;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

use super::hash::{CanonicalWriter, Sha256Digest};
use super::retention::RetentionDays;

/// checkpoint 规范编码的域名标签。与审计行的域名不同，见 [`super::hash`]。
pub const AUDIT_CHECKPOINT_DOMAIN: &str = "openbot.audit.checkpoint.v1";

/// checkpoint 的 HMAC-SHA256 签名。
///
/// 与 [`Sha256Digest`] **刻意不是同一个类型**，尽管两者都是 32 字节：
///
/// - 摘要是公开值，比较它可以用 `==`；签名是密钥的函数，比较它必须**常量时间**，
///   否则逐字节提前返回会泄漏"前几个字节猜对了"，把伪造一份签名的代价从 2^256 降到线性。
/// - 类型不同，就不可能把一个 `row_hash` 当成签名传进 `verify`。
///
/// 因此本类型**不实现** `PartialEq`：唯一的比较入口是 [`Self::verify_equals`]，
/// 一个想用 `==` 的调用点会在编译期停下来。
#[derive(Clone, Copy)]
pub struct CheckpointSignature([u8; 32]);

impl CheckpointSignature {
    /// 由原始字节构造（读库时用）。
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// 借出原始字节（写库时用）。
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// **常量时间**比较两个签名。
    #[must_use]
    pub fn verify_equals(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl core::fmt::Debug for CheckpointSignature {
    // 不打印内容。签名本身不是秘密（它是可公开验证的），但把它印进日志会让"从日志里抄一份
    // 签名贴到伪造的 checkpoint 上"变成一次复制粘贴 —— 而验证方只比对签名，不问它从哪来。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CheckpointSignature(<redacted>)")
    }
}

/// 链上一段连续区间的边界。
///
/// 首尾两端**都**要记：只记末尾的话，一次"把区间开头几行删掉再补一条 checkpoint"的操作
/// 在事后看不出来。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainSegment {
    /// 区间第一行的事件 id。
    pub first_event: AuditEventId,
    /// 区间第一行的 `row_hash`。
    pub first_row_hash: Sha256Digest,
    /// 区间最后一行的事件 id。
    pub last_event: AuditEventId,
    /// 区间最后一行的 `row_hash`。
    pub last_row_hash: Sha256Digest,
    /// 区间内的事件条数。
    pub event_count: u64,
}

impl ChainSegment {
    fn write_canonical(&self, writer: &mut CanonicalWriter) {
        writer.str(self.first_event.as_str());
        writer.digest(&self.first_row_hash);
        writer.str(self.last_event.as_str());
        writer.digest(&self.last_row_hash);
        writer.u64(self.event_count);
    }
}

/// checkpoint 的三种形态。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditCheckpointKind {
    /// 链起点。
    Genesis {
        /// genesis 行的事件 id。
        genesis_event: AuditEventId,
        /// genesis 行的 `row_hash`。
        genesis_row_hash: Sha256Digest,
        /// **链起点之前有多少行未入链**（旧行，两个 hash 列皆 NULL）。
        ///
        /// 0 是合法值，含义是"这张表从第一行起就在链里"。它与"没记这个数"必须可区分 ——
        /// 所以它是必填字段而不是 `Option`。
        unlinked_rows_before: u64,
    },
    /// 周期快照。
    Periodic {
        /// 被快照的区间。
        segment: ChainSegment,
    },
    /// retention 删除前为被删区间写的封口。
    Closure {
        /// 即将被删除的区间。
        segment: ChainSegment,
        /// 触发这次删除的保留天数 —— 把"依据哪条策略删的"钉在证据里。
        retention_days: RetentionDays,
    },
}

impl AuditCheckpointKind {
    /// 变体标签。写进规范编码的第一项，理由见 [`super::hash`]：枚举必须先写变体标签，
    /// 否则"字段序列固定"这个前提在它身上不成立。
    ///
    /// 用字面量而不是判别式数字：数字会随变体重排漂移，字面量不会。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Genesis { .. } => "genesis",
            Self::Periodic { .. } => "periodic",
            Self::Closure { .. } => "closure",
        }
    }

    fn write_canonical(&self, writer: &mut CanonicalWriter) {
        writer.str(self.as_str());
        match self {
            Self::Genesis {
                genesis_event,
                genesis_row_hash,
                unlinked_rows_before,
            } => {
                writer.str(genesis_event.as_str());
                writer.digest(genesis_row_hash);
                writer.u64(*unlinked_rows_before);
            }
            Self::Periodic { segment } => segment.write_canonical(writer),
            Self::Closure {
                segment,
                retention_days,
            } => {
                segment.write_canonical(writer);
                writer.u32(retention_days.get());
            }
        }
    }
}

/// 一条 checkpoint。写入本库 `audit_checkpoints`，可选另发一份到不可变 sink。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditCheckpoint {
    /// 单调递增的序号。
    ///
    /// 有了它，"最后一条 checkpoint 被整条删掉"也能被发现（序号出现空洞），而只靠时间戳
    /// 做不到 —— 少一条时间戳看起来就像那段时间没跑过。
    pub sequence: u64,
    /// 写下这条 checkpoint 的时刻。**由调用方传入**，领域层没有时钟。
    pub created_at: OffsetDateTime,
    /// 形态与内容。
    pub kind: AuditCheckpointKind,
}

impl AuditCheckpoint {
    /// 规范编码的字节。
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut writer = CanonicalWriter::new(AUDIT_CHECKPOINT_DOMAIN);
        writer.u64(self.sequence);
        writer.i128(self.created_at.unix_timestamp_nanos());
        self.kind.write_canonical(&mut writer);
        writer.finish()
    }

    /// 用给定密钥签名。
    ///
    /// # Errors
    ///
    /// 密钥为空时返回 [`CheckpointKeyError::EmptyKey`]。
    ///
    /// HMAC 在规范上接受任意长度的密钥（含 0 长度），所以这不是密码学库逼我们处理的错误 ——
    /// 它是一次**主动的 fail-closed**：空密钥签出来的"签名"人人算得出，而验证照样通过，
    /// 于是整套 checkpoint 会在看起来完全正常的情况下不提供任何保证。配置漏了密钥必须当场
    /// 失败，不能签出一份没有意义的签名。
    pub fn sign(&self, key: &[u8]) -> Result<CheckpointSignature, CheckpointKeyError> {
        if key.is_empty() {
            return Err(CheckpointKeyError::EmptyKey);
        }
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| CheckpointKeyError::EmptyKey)?;
        mac.update(&self.canonical_bytes());
        let bytes: [u8; 32] = mac.finalize().into_bytes().into();
        Ok(CheckpointSignature::from_bytes(bytes))
    }

    /// 校验一份签名。
    ///
    /// # Errors
    ///
    /// 密钥为空时返回 [`CheckpointKeyError::EmptyKey`]——与 [`Self::sign`] 同一条理由：
    /// 空密钥下"校验通过"不含任何信息，把它报成 `Ok(true)` 就是把一次配置事故渲染成一切正常。
    pub fn verify(
        &self,
        key: &[u8],
        signature: &CheckpointSignature,
    ) -> Result<bool, CheckpointKeyError> {
        let expected = self.sign(key)?;
        Ok(expected.verify_equals(signature))
    }
}

/// 签名密钥问题。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointKeyError {
    /// 密钥为空。理由见 [`AuditCheckpoint::sign`]。
    #[error("checkpoint_empty_signing_key")]
    EmptyKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"a-test-signing-key-not-a-real-one";

    fn digest(seed: &[u8]) -> Sha256Digest {
        Sha256Digest::of(seed)
    }

    fn segment() -> ChainSegment {
        ChainSegment {
            first_event: AuditEventId::new("ae-100"),
            first_row_hash: digest(b"first"),
            last_event: AuditEventId::new("ae-199"),
            last_row_hash: digest(b"last"),
            event_count: 100,
        }
    }

    fn periodic() -> AuditCheckpoint {
        AuditCheckpoint {
            sequence: 7,
            created_at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            kind: AuditCheckpointKind::Periodic { segment: segment() },
        }
    }

    #[test]
    fn a_signature_verifies_against_its_own_checkpoint() {
        let checkpoint = periodic();
        let signature = checkpoint.sign(KEY).unwrap();
        assert!(checkpoint.verify(KEY, &signature).unwrap());
    }

    /// **逐字段**篡改：动任何一个字段，签名都必须失效。
    ///
    /// 只测一个代表字段等于没测 —— 漏进规范编码的字段恰恰是那个不会被代表的。
    #[test]
    fn tampering_with_any_field_invalidates_the_signature() {
        let original = periodic();
        let signature = original.sign(KEY).unwrap();

        type FieldMutation = (&'static str, fn(&mut AuditCheckpoint));
        let mutations: Vec<FieldMutation> = vec![
            ("sequence", |c| c.sequence += 1),
            ("created_at", |c| {
                c.created_at = OffsetDateTime::from_unix_timestamp(1_700_000_001).unwrap();
            }),
            ("kind", |c| {
                c.kind = AuditCheckpointKind::Genesis {
                    genesis_event: AuditEventId::new("ae-0"),
                    genesis_row_hash: digest(b"g"),
                    unlinked_rows_before: 0,
                };
            }),
            ("segment.first_event", |c| {
                if let AuditCheckpointKind::Periodic { segment } = &mut c.kind {
                    segment.first_event = AuditEventId::new("ae-101");
                }
            }),
            ("segment.first_row_hash", |c| {
                if let AuditCheckpointKind::Periodic { segment } = &mut c.kind {
                    segment.first_row_hash = Sha256Digest::of(b"other-first");
                }
            }),
            ("segment.last_event", |c| {
                if let AuditCheckpointKind::Periodic { segment } = &mut c.kind {
                    segment.last_event = AuditEventId::new("ae-198");
                }
            }),
            ("segment.last_row_hash", |c| {
                if let AuditCheckpointKind::Periodic { segment } = &mut c.kind {
                    segment.last_row_hash = Sha256Digest::of(b"other-last");
                }
            }),
            ("segment.event_count", |c| {
                if let AuditCheckpointKind::Periodic { segment } = &mut c.kind {
                    segment.event_count = 99;
                }
            }),
        ];

        for (field, mutate) in mutations {
            let mut tampered = original.clone();
            mutate(&mut tampered);
            assert_ne!(tampered, original, "{field} 的变异没有真的改到东西");
            assert!(
                !tampered.verify(KEY, &signature).unwrap(),
                "改了 {field} 之后签名仍然通过 —— 该字段没进规范编码"
            );
        }
    }

    /// 换一把密钥，签名失效。正向对照证明上一条不是靠"verify 恒假"蒙混。
    #[test]
    fn a_different_key_does_not_verify() {
        let checkpoint = periodic();
        let signature = checkpoint.sign(KEY).unwrap();
        assert!(!checkpoint.verify(b"another-key", &signature).unwrap());
        assert!(checkpoint.verify(KEY, &signature).unwrap());
    }

    #[test]
    fn empty_key_is_refused_on_both_sign_and_verify() {
        let checkpoint = periodic();
        // 用 `unwrap_err` 而不是 `assert_eq!` 比整个 Result：`CheckpointSignature` 刻意不实现
        // `PartialEq`（唯一比较入口是常量时间的 `verify_equals`），于是这条设计在调用点上
        // 就长这个样子。
        assert_eq!(
            checkpoint.sign(b"").unwrap_err(),
            CheckpointKeyError::EmptyKey
        );
        let signature = checkpoint.sign(KEY).unwrap();
        assert_eq!(
            checkpoint.verify(b"", &signature),
            Err(CheckpointKeyError::EmptyKey)
        );
    }

    /// 三种形态的规范编码互不相同，即使内容"相当"。
    ///
    /// 具体到 closure 与 periodic：同一个区间、同一个序号、同一个时刻，一个是"我给这段
    /// 拍了张快照"，另一个是"我马上要把这段删了"。两者若编成同一串字节，一条 periodic
    /// 签名就能被冒充成删除授权。
    #[test]
    fn checkpoint_kinds_are_not_interchangeable() {
        let periodic_checkpoint = periodic();
        let closure_checkpoint = AuditCheckpoint {
            kind: AuditCheckpointKind::Closure {
                segment: segment(),
                retention_days: RetentionDays::new(30).unwrap(),
            },
            ..periodic()
        };
        assert_ne!(
            periodic_checkpoint.canonical_bytes(),
            closure_checkpoint.canonical_bytes()
        );

        let signature = periodic_checkpoint.sign(KEY).unwrap();
        assert!(
            !closure_checkpoint.verify(KEY, &signature).unwrap(),
            "periodic 的签名不得能验通 closure"
        );
    }

    /// closure checkpoint 记着"依据哪条 retention 策略"—— 改天数即改内容。
    #[test]
    fn closure_checkpoint_binds_the_retention_days_it_acted_on() {
        let thirty = AuditCheckpoint {
            kind: AuditCheckpointKind::Closure {
                segment: segment(),
                retention_days: RetentionDays::new(30).unwrap(),
            },
            ..periodic()
        };
        let ninety = AuditCheckpoint {
            kind: AuditCheckpointKind::Closure {
                segment: segment(),
                retention_days: RetentionDays::new(90).unwrap(),
            },
            ..periodic()
        };
        assert_ne!(thirty.canonical_bytes(), ninety.canonical_bytes());
    }

    /// genesis checkpoint 必须能记下"链起点之前有 N 行未入链"，且 N 变化即内容变化。
    ///
    /// 这条数字是读者判断"前面那批 NULL 是历史还是被人清空的"的唯一依据，它必须落在签名
    /// 覆盖的范围内 —— 一个签名管不着的计数等于没记。
    #[test]
    fn genesis_checkpoint_records_and_signs_the_unlinked_row_count() {
        let make = |count: u64| AuditCheckpoint {
            sequence: 1,
            created_at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            kind: AuditCheckpointKind::Genesis {
                genesis_event: AuditEventId::new("ae-0"),
                genesis_row_hash: digest(b"genesis"),
                unlinked_rows_before: count,
            },
        };

        let recorded = make(120_000);
        let signature = recorded.sign(KEY).unwrap();
        assert!(recorded.verify(KEY, &signature).unwrap());

        // 把"12 万行历史"改成"0 行历史"是最有价值的一次篡改：它把一段无保护的历史说成
        // 从头就在链里。必须验不过。
        assert!(!make(0).verify(KEY, &signature).unwrap());
    }

    #[test]
    fn signature_debug_does_not_print_the_bytes() {
        let signature = periodic().sign(KEY).unwrap();
        let rendered = format!("{signature:?}");
        assert_eq!(rendered, "CheckpointSignature(<redacted>)");
        // 正向对照：同一条断言手法在**确实**打印内容的类型上会失败。
        assert!(format!("{:?}", digest(b"x")).contains(&digest(b"x").to_hex()));
    }
}
