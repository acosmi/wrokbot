//! secret 的数据模型与"此刻能不能用"的纯判定。
//!
//! # v3 §6.4 逐字
//!
//! 「secret 数据模型同时记录 resource、scope、expiry、credential generation 和 revocation
//! state。」五项在这里分别是 [`SecretResource`] / [`SecretScope`] / [`SecretRecord::expires_at`] /
//! [`CredentialGeneration`] / [`RevocationState`]。
//!
//! # 为什么这五项在上游一个都没有
//!
//! 实测上游 `server/src/db/schema/core.ts::credentials`（commit `891df72f18`）只有九列：
//! `id` / `kind` / `provider` / `encrypted_value` / `key_id` / `metadata` / `revoked_at` /
//! `created_at` / `updated_at`。五项里只有 revocation 有对应列（`revoked_at`），其余四项
//! 要么散在 `metadata` 这个 `jsonb` 里（无 schema、无约束），要么根本不存在。
//!
//! 这不是"上游漏了几列"，而是几种失效模式在上游**没有名字**：
//!
//! - 没有 expiry：一把 vendor 那边已经过期的 key 在库里与一把好 key 长得一模一样，
//!   只能等某次调用 401 才发现。
//! - 没有 generation：§9.2 的 MCP 连接身份里列着 `credential_generation`，可上游没有任何列
//!   承载它 —— 于是"这条连接用的是不是最新那把凭据"这个问题问不出来。
//! - 没有 scope：上游把 vendor 实际授予的 scope 放在 `mcp_user_credentials.scope`（另一张表），
//!   凭据本身不知道自己能干什么。
//!
//! 本模块给这几件事各一个类型和一条判定。**加列本身是 §14.3 框架下的一次 expand 迁移**，
//! 归 infra，已记进交付报告。
//!
//! # 为什么 revocation 不带"原因"
//!
//! 上游 `revoked_at` 是一个裸时间戳，没有 reason 列。给它加一个封闭的原因枚举很诱人，但那
//! 会让本模块的类型无法从既有数据构造出来 —— 迁移过来的每一行都得凭空指定一个原因，而
//! 凭空指定的值就是假数据。真要有原因，它是一次 expand 迁移 + 一次 backfill 决策，不是
//! 领域层能单方面发明的东西。

use std::collections::BTreeSet;

use openbot_contracts::ids::TenantId;
use time::OffsetDateTime;

use super::binding::{KeyVersion, RecordBinding, SecretId, SecretKind, SecretPrincipal};
use super::secret::SecretClass;

/// 凭据代际计数器。
///
/// §9.2 把 `credential_generation` 列进 MCP 连接身份：一条连接必须能说出"我用的是第几代
/// 凭据"，否则轮换之后旧连接会带着旧凭据继续跑到某天没人记得为止。
///
/// 用 `u64` 而不是字符串，与 `openbot_contracts::ids` 里两个 generation 计数器同一条理由：
/// "是不是更新的一代"依赖**数值序**，字符串的字典序会判 `"10" < "9"`。
/// D-2 复算时它仍只在 vault domain 内流动，所以留在此处；第一条跨 crate 凭据/连接
/// 用例出现时再与用例同批上收，不先造空契约。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CredentialGeneration(u64);

impl CredentialGeneration {
    /// 第一代。
    pub const FIRST: Self = Self(1);

    /// 由原始计数值构造。
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// 取出原始计数值。
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// 铸造下一代。
    ///
    /// `saturating_add(1)` 而不是 `+ 1`：`+` 在 release 下**回绕到 0**，而回绕比饱和危险得多
    /// —— generation 0 会让一把早已被轮换掉的旧凭据重新成为"最新"。饱和的最坏结果是停在
    /// `u64::MAX` 不再前进，此时任何 stale 判定仍然为真（fail-closed）。
    ///
    /// 这条推理与 contracts 的 generation 计数器相同；本类型仍独立是因为它尚未跨层，
    /// 不是因为回绕语义可以另写一份。
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// 本代是否落后于 `required`。
    #[must_use]
    pub const fn is_behind(self, required: Self) -> bool {
        self.0 < required.0
    }
}

/// RFC 8707 意义上的 resource indicator：这把凭据是对**哪个**资源发的。
///
/// §9.4 逐字要求「RFC 8707 resource/audience binding」。它的作用是让一把发给
/// `https://a.example/mcp` 的 token 不能被拿去访问 `https://b.example/mcp` —— 没有它，
/// 一台被攻陷的 MCP server 可以把我们的 token 转手用在别处（§9.4 同段的
/// 「禁止 token passthrough 到……另一个 MCP server」）。
///
/// 不做 URL 解析与校验：它是**上游 vendor 回给我们的字符串**，规范化会让"我们记下的"
/// 与"对方发的"不再逐字节相同，而 audience 比对必须逐字节。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretResource(String);

impl SecretResource {
    /// 原样记下 vendor 给的 resource 标识。
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// 借出底层字符串。
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// vendor **实际授予**的 scope 集合。
///
/// # 为什么是"授予"而不是"申请"
///
/// 上游 `server/src/db/schema/plugins.ts::mcpUserCredentials.scope` 的注释逐字写着理由：
/// 「What the vendor actually granted, as it said it — not what we asked for. The two differ in
/// practice: a person can decline part of a consent screen. Storing the reply rather than the
/// request means a tool failing for want of a scope can be explained instead of being a mystery
/// about a permission we assumed we had.」
///
/// 本类型照搬这条语义。存"申请"的那一版会让 [`Self::covers`] 恒为真 —— 一个永远说"有权限"
/// 的判定器，正是那种在"功能压根没实现"的世界里表现相同的东西。
///
/// # 为什么是集合而不是原字符串
///
/// OAuth 的 scope 是空格分隔的**无序**列表（RFC 6749 §3.3）。用原字符串比对会让
/// `"read write"` 与 `"write read"` 判不等；用 `BTreeSet` 则顺序无关、重复自动折叠，
/// 并且 [`Self::to_canonical_string`] 给出一个确定性的写回形态。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecretScope(BTreeSet<String>);

impl SecretScope {
    /// 从 vendor 回的那段空格分隔字符串解析。
    ///
    /// 空 token 丢弃（`"a  b"` 与 `"a b"` 等价，RFC 6749 的 `scope-token` 不允许空串）。
    #[must_use]
    pub fn granted(raw: &str) -> Self {
        Self(
            raw.split(' ')
                .filter(|token| !token.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
        )
    }

    /// 由一组 token 构造。
    #[must_use]
    pub fn from_tokens<I, S>(tokens: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self(
            tokens
                .into_iter()
                .map(Into::into)
                .filter(|token| !token.is_empty())
                .collect(),
        )
    }

    /// 本 scope 是否覆盖 `required` 要的每一项。
    ///
    /// 空的 `required` 恒被覆盖（不需要任何权限的调用不该因为 scope 被拦）；空的**自身**
    /// 只覆盖得了空的 `required` —— 一把什么都没被授予的凭据不能被当成万能的。
    #[must_use]
    pub fn covers(&self, required: &Self) -> bool {
        required.0.is_subset(&self.0)
    }

    /// 确定性的写回形态：token 按字典序、单空格分隔。
    #[must_use]
    pub fn to_canonical_string(&self) -> String {
        self.0.iter().cloned().collect::<Vec<_>>().join(" ")
    }

    /// 有没有任何 token。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// token 个数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// 撤销状态。
///
/// 上游用 `credentials.revoked_at IS NULL` 表达同一件事，并且**保留被撤销的行**
/// （`parity/tables.yaml` 的 `tbl-credentials`：`retention=revoked_at 标记撤销但保留行`）。
/// 本类型照搬：撤销是一个**状态**，不是一次删除 —— 删掉那一行会把"它什么时候失效的"
/// 这个审计问题一并删掉。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationState {
    /// 未撤销。
    Active,
    /// 已撤销，附撤销时刻。
    Revoked {
        /// 撤销发生的时刻。由调用方传入 —— 领域层不读时钟。
        at: OffsetDateTime,
    },
}

impl RevocationState {
    /// 是否已撤销。
    #[must_use]
    pub const fn is_revoked(self) -> bool {
        matches!(self, Self::Revoked { .. })
    }
}

/// 一条 secret 的完整元数据。
///
/// **不含密文，也不含明文。** 密文在 [`super::envelope`]，明文在 [`super::secret`]。分开是
/// 为了让"列出这个部署持有什么"这类操作在类型上就拿不到任何密钥材料 —— 上游
/// `CredentialStatus` 也是这么切的（它只回 id / kind / provider / keyId / metadata / revokedAt）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretRecord {
    /// 这条记录的 id。
    pub id: SecretId,
    /// 存储层分类（数据库 `kind` 列）。
    pub kind: SecretKind,
    /// §6.4 外泄风险分类。与 [`Self::kind`] 的分工见 [`SecretKind`] 的文档。
    pub class: SecretClass,
    /// 对哪个资源发的（RFC 8707）。
    pub resource: SecretResource,
    /// vendor 实际授予的 scope。
    pub scope: SecretScope,
    /// 这条 secret 属于谁。
    pub owner: SecretPrincipal,
    /// 谁被允许用它。
    pub consumer: SecretPrincipal,
    /// 第几代。
    pub generation: CredentialGeneration,
    /// 过期时刻；`None` = 不过期（模型密钥常见）。
    ///
    /// 用 `Option` 而不是"一个很远的时间戳"：后者会在某天真的到期，而那一天没有人还记得
    /// 这个约定。
    pub expires_at: Option<OffsetDateTime>,
    /// 撤销状态。
    pub revocation: RevocationState,
}

impl SecretRecord {
    /// 这条记录在 `tenant` / `key_version` 下的 AAD 绑定。
    ///
    /// # tenant 为什么是参数而不是字段
    ///
    /// 上游 `credentials` 表**没有 tenant 列**（实测九列，见模块文档）。租户身份来自部署
    /// 上下文，不来自数据行 —— 而这恰恰是 §6.4 要把 `tenant_id` 绑进 AAD 的原因：它在行里
    /// 根本不存在，只有绑进 AAD 才对密文有约束力。
    ///
    /// 由本方法统一铸造 binding，而不是让调用方自己拼六元组：拼错 owner 或 consumer 的
    /// 后果是一条解不开的记录，而那种错误在写入时不会报错，只在下一次读取时爆发。
    #[must_use]
    pub fn binding(&self, tenant: &TenantId, key_version: KeyVersion) -> RecordBinding {
        RecordBinding::new(
            tenant.clone(),
            self.id.clone(),
            self.kind,
            self.owner.clone(),
            self.consumer.clone(),
            key_version,
        )
    }

    /// 这条 secret 此刻能不能用。
    ///
    /// # 优先级：撤销 > 过期 > 代际落后
    ///
    /// 三者可以同时成立，所以必须有一条固定的优先级，否则同一条记录在两次调用里可能报出
    /// 不同的原因。排序依据是**这个条件有多不可逆**：
    ///
    /// 1. 撤销是管理员或 IdP 的显式动作，不可逆，换一条记录也不会让它复活；
    /// 2. 过期是这条记录自身的属性，没有任何"换一条"能修好它；
    /// 3. 代际落后**是**换一条就能修好的 —— 它指向的动作是"去用新的那条"。
    ///
    /// 先报最不可逆的那个，就不会把运维支上一条走到一半撞墙的路。
    ///
    /// # 边界：`now == expires_at` 判为已过期
    ///
    /// fail-closed 的方向。过期时刻那一瞬间到底算不算有效，任何一边都能自圆其说；选"算过期"
    /// 是因为反过来的错误（多用了一瞬间）发生在 vendor 那边就是一次 401，而 401 在
    /// §9.4 里会触发一次受控 refresh —— 我们宁可自己先拒。
    #[must_use]
    pub fn usability(
        &self,
        now: OffsetDateTime,
        required_generation: CredentialGeneration,
    ) -> SecretUsability {
        if self.revocation.is_revoked() {
            return SecretUsability::Revoked;
        }
        if self.expires_at.is_some_and(|expiry| now >= expiry) {
            return SecretUsability::Expired;
        }
        if self.generation.is_behind(required_generation) {
            return SecretUsability::GenerationBehind {
                record: self.generation,
                required: required_generation,
            };
        }
        SecretUsability::Usable
    }
}

/// [`SecretRecord::usability`] 的封闭答案。
///
/// 三种不可用互相**可分辨**，理由是它们对应三种不同的运维动作：重新登记 / 刷新 / 去用新的
/// 那一条。压成一个布尔就把这三条路径合并成"它坏了"。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretUsability {
    /// 可用。
    Usable,
    /// 已被撤销。
    Revoked,
    /// 已过期。
    Expired,
    /// 代际落后于调用方要求的那一代。
    ///
    /// 两个载荷都是**我们自己铸的计数器**，不是被检查对象的数据，所以带着它们不违反
    /// [`super::error`] 那条"错误不带载荷"的规矩 —— 而且不带的话，运维看不出差了几代。
    GenerationBehind {
        /// 这条记录的代际。
        record: CredentialGeneration,
        /// 调用方要求的代际。
        required: CredentialGeneration,
    },
}

impl SecretUsability {
    /// 是否可用。
    #[must_use]
    pub const fn is_usable(self) -> bool {
        matches!(self, Self::Usable)
    }

    /// 稳定标识符，进审计与日志。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Usable => "secret_usable",
            Self::Revoked => "secret_revoked",
            Self::Expired => "secret_expired",
            Self::GenerationBehind { .. } => "secret_generation_behind",
        }
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;

    /// 一个固定的参照时刻。领域层不读时钟，测试里也就没有"今天"这个概念。
    fn epoch() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::days(20_000)
    }

    fn record() -> SecretRecord {
        SecretRecord {
            id: SecretId::new("secret-1"),
            kind: SecretKind::Model,
            class: SecretClass::ModelKey,
            resource: SecretResource::new("https://api.example.invalid/v1"),
            scope: SecretScope::granted("read write"),
            owner: SecretPrincipal::Deployment,
            consumer: SecretPrincipal::Deployment,
            generation: CredentialGeneration::new(5),
            expires_at: None,
            revocation: RevocationState::Active,
        }
    }

    /// 正向对照：一条好记录判为可用。
    ///
    /// 没有它，下面每一条"必须不可用"在"`usability` 恒返回不可用"的世界里同样通过。
    #[test]
    fn a_healthy_record_is_usable() {
        assert_eq!(
            record().usability(epoch(), CredentialGeneration::new(5)),
            SecretUsability::Usable
        );
        assert!(
            record()
                .usability(epoch(), CredentialGeneration::new(5))
                .is_usable()
        );
        // 更早的代际要求同样可用 —— "落后"是单向判据。
        assert!(
            record()
                .usability(epoch(), CredentialGeneration::new(1))
                .is_usable()
        );
    }

    /// 三种不可用各自出现时都被认出来，且**互不混淆**。
    #[test]
    fn each_unusable_reason_is_reported_on_its_own() {
        let mut revoked = record();
        revoked.revocation = RevocationState::Revoked { at: epoch() };
        assert_eq!(
            revoked.usability(epoch(), CredentialGeneration::new(5)),
            SecretUsability::Revoked
        );

        let mut expired = record();
        expired.expires_at = Some(epoch() - Duration::seconds(1));
        assert_eq!(
            expired.usability(epoch(), CredentialGeneration::new(5)),
            SecretUsability::Expired
        );

        let behind = record();
        assert_eq!(
            behind.usability(epoch(), CredentialGeneration::new(6)),
            SecretUsability::GenerationBehind {
                record: CredentialGeneration::new(5),
                required: CredentialGeneration::new(6),
            }
        );

        // 三个标识符两两不同 —— 压成同一个字符串，审计就分不开这三条运维路径。
        let mut codes = [
            SecretUsability::Usable.code(),
            SecretUsability::Revoked.code(),
            SecretUsability::Expired.code(),
            SecretUsability::GenerationBehind {
                record: CredentialGeneration::FIRST,
                required: CredentialGeneration::FIRST,
            }
            .code(),
        ];
        codes.sort_unstable();
        let mut deduped = codes.to_vec();
        deduped.dedup();
        assert_eq!(deduped.len(), codes.len());
    }

    /// 三者同时成立时，优先级固定为 撤销 > 过期 > 代际落后。
    #[test]
    fn precedence_is_revoked_then_expired_then_generation() {
        let mut all_three = record();
        all_three.revocation = RevocationState::Revoked { at: epoch() };
        all_three.expires_at = Some(epoch() - Duration::days(1));
        assert_eq!(
            all_three.usability(epoch(), CredentialGeneration::new(99)),
            SecretUsability::Revoked
        );

        // 去掉撤销，露出过期。
        let mut expired_and_behind = all_three.clone();
        expired_and_behind.revocation = RevocationState::Active;
        assert_eq!(
            expired_and_behind.usability(epoch(), CredentialGeneration::new(99)),
            SecretUsability::Expired
        );

        // 再去掉过期，露出代际落后。逐层剥开证明优先级确实是**顺序**，
        // 而不是"恒返回第一个变体"。
        let mut only_behind = expired_and_behind;
        only_behind.expires_at = None;
        assert!(matches!(
            only_behind.usability(epoch(), CredentialGeneration::new(99)),
            SecretUsability::GenerationBehind { .. }
        ));
    }

    /// 过期的边界：`now == expires_at` 判过期，前一瞬判可用。
    #[test]
    fn expiry_boundary_is_closed_on_the_expired_side() {
        let mut expiring = record();
        expiring.expires_at = Some(epoch());

        assert_eq!(
            expiring.usability(epoch(), CredentialGeneration::new(1)),
            SecretUsability::Expired,
            "恰好到点判过期（fail-closed）"
        );
        assert!(
            expiring
                .usability(
                    epoch() - Duration::nanoseconds(1),
                    CredentialGeneration::new(1)
                )
                .is_usable(),
            "到点前一瞬仍可用；没有这一条，上一条在'恒过期'的世界里也成立"
        );
    }

    /// `None` 的 expiry 永不过期 —— 哪怕参照时刻在很远的未来。
    #[test]
    fn a_record_without_expiry_never_expires() {
        assert!(
            record()
                .usability(
                    epoch() + Duration::days(100_000),
                    CredentialGeneration::new(1)
                )
                .is_usable()
        );
    }

    /// generation 饱和递增，不回绕。
    #[test]
    fn generation_saturates_instead_of_wrapping() {
        assert_eq!(CredentialGeneration::new(1).next().get(), 2);
        assert_eq!(
            CredentialGeneration::new(u64::MAX).next().get(),
            u64::MAX,
            "回绕到 0 会让一把早已被轮换掉的旧凭据重新成为最新"
        );
        assert!(CredentialGeneration::new(1).is_behind(CredentialGeneration::new(2)));
        assert!(!CredentialGeneration::new(2).is_behind(CredentialGeneration::new(2)));
        assert!(!CredentialGeneration::new(3).is_behind(CredentialGeneration::new(2)));
    }

    /// scope 解析与覆盖判定的两个方向。
    #[test]
    fn scope_covers_only_what_was_actually_granted() {
        let granted = SecretScope::granted("drive.readonly  profile email");
        assert_eq!(granted.len(), 3, "连续空格产生的空 token 必须被丢掉");
        assert_eq!(
            granted.to_canonical_string(),
            "drive.readonly email profile",
            "写回形态按字典序，确定性"
        );

        assert!(granted.covers(&SecretScope::granted("profile")));
        assert!(granted.covers(&SecretScope::granted("email profile")));
        // 顺序无关。
        assert!(granted.covers(&SecretScope::granted("profile email")));
        // 负向对照：没被授予的一项就是没有。
        assert!(!granted.covers(&SecretScope::granted("drive.write")));
        assert!(!granted.covers(&SecretScope::granted("profile drive.write")));

        // 空 required 恒被覆盖；空 granted 只覆盖得了空 required。
        assert!(granted.covers(&SecretScope::default()));
        assert!(SecretScope::default().covers(&SecretScope::default()));
        assert!(!SecretScope::default().covers(&SecretScope::granted("profile")));
        assert!(SecretScope::default().is_empty());
    }

    /// `binding()` 铸出来的六元组与记录逐字段一致。
    ///
    /// 这条挡的是"调用方自己拼 binding 拼错一项"那类错误 —— 拼错的后果是一条解不开的记录，
    /// 而它在写入时不报错。
    #[test]
    fn binding_is_minted_from_the_record_itself() {
        let record = record();
        let tenant = TenantId::new("tenant-7");
        let binding = record.binding(&tenant, KeyVersion::new(2));

        assert_eq!(binding.tenant(), &tenant);
        assert_eq!(binding.secret_id(), &record.id);
        assert_eq!(binding.kind(), record.kind);
        assert_eq!(binding.owner(), &record.owner);
        assert_eq!(binding.consumer(), &record.consumer);
        assert_eq!(binding.key_version(), KeyVersion::new(2));
    }
}
