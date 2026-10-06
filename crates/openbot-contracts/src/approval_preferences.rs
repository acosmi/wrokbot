//! remember 批准偏好的内部纯模型。
//!
//! 六键只标识持久记录，不能证明当前 actor、Bot、Thread、session 或 window 有权。
//! 这里不读数据库、不取得时钟或随机数，也不提供外部输入 wire、保存入口或执行授权。
//! 缺行默认 Ask；已保存的 Ask 仍是有稳定身份和正版本的普通记录。偏好消费者仍须另行
//! 证明当前权限及 mandatory approval、policy、grant、fresh、HumanLease 等原有边界。

use serde::Serialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::artifacts::{canonical_artifact_uuid_v7, is_valid_artifact_identity};
use crate::ids::{ActorId, BotId, DeploymentId, TenantId, ThreadId};
use crate::revision::RevisionSnapshot;

/// remember 偏好的三个封闭值；默认 Ask，不授予 effect 执行权限。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum RememberPreference {
    /// 在原有权限边界之外增加拒绝。
    Never,
    /// 在原本允许的 effect 前增加询问；缺行也使用这个默认值。
    #[default]
    Ask,
    /// 仅免除这项额外询问，不能覆盖任何强制确认或原有权限。
    AllowIfPolicy,
}

impl RememberPreference {
    /// 由数据库的闭集存储词解析；未知值是坏记录，不伪装成缺行。
    pub fn from_storage(value: &str) -> Result<Self, RememberPreferenceRecordError> {
        match value {
            "never" => Ok(Self::Never),
            "ask" => Ok(Self::Ask),
            "allow_if_policy" => Ok(Self::AllowIfPolicy),
            _ => Err(RememberPreferenceRecordError::InvalidPreference),
        }
    }

    /// 固定存储词，不是用户可见文案。
    #[must_use]
    pub const fn as_storage(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::Ask => "ask",
            Self::AllowIfPolicy => "allow_if_policy",
        }
    }
}

/// remember 偏好的正 i64 版本；私有值杜绝零版本和回绕。
///
/// 这是纯值，不证明数据库行存在、CAS 成功或原操作已提交。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RememberPreferenceRevision(i64);

impl RememberPreferenceRevision {
    /// 首次创建记录的固定版本 1，不读取外部状态。
    #[must_use]
    pub const fn first() -> Self {
        Self(1)
    }

    /// 验证数据库或受信编排传入的正版本。
    pub const fn new(value: i64) -> Result<Self, RememberPreferenceRecordError> {
        if value > 0 {
            Ok(Self(value))
        } else {
            Err(RememberPreferenceRecordError::InvalidRevision)
        }
    }

    /// 取出保持为正的存储值。
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }

    /// 推进一个版本；到顶明确拒绝，不饱和、不回绕。
    pub const fn checked_next(self) -> Result<Self, RememberPreferenceRecordError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(RememberPreferenceRecordError::RevisionOverflow),
        }
    }
}

/// 内部受信编排选择的目标；User/Bot 不接收外来的 targetId。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RememberPreferenceTarget {
    /// targetId 由完整键的 actor 身份导出。
    User,
    /// targetId 由完整键的 Bot 身份导出。
    Bot,
    /// targetId 使用指定的 opaque ThreadId，仍须另核当前可见权限。
    Thread(ThreadId),
}

impl RememberPreferenceTarget {
    /// 固定的数据库目标类别；本方法不验证当前权限。
    #[must_use]
    pub const fn as_storage_kind(&self) -> &'static str {
        match self {
            Self::User => TargetKind::User.as_storage(),
            Self::Bot => TargetKind::Bot.as_storage(),
            Self::Thread(_) => TargetKind::Thread.as_storage(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum TargetKind {
    User,
    Bot,
    Thread,
}

impl TargetKind {
    const fn as_storage(self) -> &'static str {
        match self {
            Self::User => "memory_user",
            Self::Bot => "memory_bot",
            Self::Thread => "memory_thread",
        }
    }

    fn from_storage(value: &str) -> Result<Self, RememberPreferenceRecordError> {
        match value {
            "memory_user" => Ok(Self::User),
            "memory_bot" => Ok(Self::Bot),
            "memory_thread" => Ok(Self::Thread),
            _ => Err(RememberPreferenceRecordError::InvalidTarget),
        }
    }
}

/// 完整稳定六键；各身份原样保存，只验证 UTF8 字节界限和 Unicode Cc。
///
/// deployment/tenant/actor 必须由未来 repository 自身 namespace 和当前 AuthContext
/// 导出。构造成功不证明调用方遵守该来源，也不缓存 generation/session/window 权限。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RememberPreferenceKey {
    deployment_id: DeploymentId,
    tenant_id: TenantId,
    actor_id: ActorId,
    bot_id: BotId,
    target_kind: TargetKind,
    target_id: String,
}

impl RememberPreferenceKey {
    /// 从明确目标派生六键；不修剪、截断、归一化或把 opaque 身份限定为 UUID。
    pub fn new(
        deployment_id: DeploymentId,
        tenant_id: TenantId,
        actor_id: ActorId,
        bot_id: BotId,
        target: RememberPreferenceTarget,
    ) -> Result<Self, RememberPreferenceRecordError> {
        validate_identity(deployment_id.as_str(), "deployment")?;
        validate_identity(tenant_id.as_str(), "tenant")?;
        validate_identity(actor_id.as_str(), "actor")?;
        validate_identity(bot_id.as_str(), "bot")?;
        let (target_kind, target_id) = match target {
            RememberPreferenceTarget::User => (TargetKind::User, actor_id.as_str().to_owned()),
            RememberPreferenceTarget::Bot => (TargetKind::Bot, bot_id.as_str().to_owned()),
            RememberPreferenceTarget::Thread(id) => (TargetKind::Thread, id.into_inner()),
        };
        validate_identity(&target_id, "target")?;
        Ok(Self {
            deployment_id,
            tenant_id,
            actor_id,
            bot_id,
            target_kind,
            target_id,
        })
    }

    /// 解码完整数据库六键，并拒绝未知类别及不等于 actor/Bot 的导出目标。
    pub fn from_stored(
        deployment_id: DeploymentId,
        tenant_id: TenantId,
        actor_id: ActorId,
        bot_id: BotId,
        target_kind: &str,
        target_id: impl Into<String>,
    ) -> Result<Self, RememberPreferenceRecordError> {
        let target_id = target_id.into();
        validate_identity(&target_id, "target")?;
        let target = match TargetKind::from_storage(target_kind)? {
            TargetKind::User => RememberPreferenceTarget::User,
            TargetKind::Bot => RememberPreferenceTarget::Bot,
            TargetKind::Thread => {
                RememberPreferenceTarget::Thread(ThreadId::new(target_id.clone()))
            }
        };
        let key = Self::new(deployment_id, tenant_id, actor_id, bot_id, target)?;
        if key.target_id != target_id {
            return Err(RememberPreferenceRecordError::InvalidTarget);
        }
        Ok(key)
    }

    /// 借出稳定部署身份。
    #[must_use]
    pub const fn deployment_id(&self) -> &DeploymentId {
        &self.deployment_id
    }

    /// 借出稳定租户身份。
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// 借出稳定 actor 身份；不是当前权限证明。
    #[must_use]
    pub const fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    /// 借出稳定 Bot 身份。
    #[must_use]
    pub const fn bot_id(&self) -> &BotId {
        &self.bot_id
    }

    /// 借出目标类别的固定存储词。
    #[must_use]
    pub const fn target_kind(&self) -> &'static str {
        self.target_kind.as_storage()
    }

    /// 借出原样 opaque 目标身份。
    #[must_use]
    pub fn target_id(&self) -> &str {
        &self.target_id
    }
}

fn validate_identity(
    value: &str,
    field: &'static str,
) -> Result<(), RememberPreferenceRecordError> {
    // 复用既有纯词法规则：1..512 UTF8 字节、无 Unicode Cc；不代表成果身份或读取权限。
    if is_valid_artifact_identity(value) {
        Ok(())
    } else {
        Err(RememberPreferenceRecordError::InvalidIdentity(field))
    }
}

/// 已存的完整偏好记录；稳定 ID、六键与创建时间均不提供可变入口。
///
/// 纯构造只验证记录形状，既不代表当前数据库行，也不证明 CAS、审计或提交已成功。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRememberPreference {
    id: String,
    key: RememberPreferenceKey,
    preference: RememberPreference,
    revision: RememberPreferenceRevision,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl StoredRememberPreference {
    /// 用显式注入的 ID 与时间纯构造首次记录，固定版本 1、createdAt=updatedAt。
    pub fn create(
        id: &str,
        key: RememberPreferenceKey,
        preference: RememberPreference,
        at: OffsetDateTime,
    ) -> Result<Self, RememberPreferenceRecordError> {
        Self::validated(
            id,
            key,
            preference,
            RememberPreferenceRevision::first(),
            at,
            at,
        )
    }

    /// 解码既有完整行；坏 ID、偏好、版本或任一时间均报错，不降级成 Absent。
    pub fn from_stored(
        id: &str,
        key: RememberPreferenceKey,
        preference: &str,
        revision: i64,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> Result<Self, RememberPreferenceRecordError> {
        Self::validated(
            id,
            key,
            RememberPreference::from_storage(preference)?,
            RememberPreferenceRevision::new(revision)?,
            created_at,
            updated_at,
        )
    }

    fn validated(
        id: &str,
        key: RememberPreferenceKey,
        preference: RememberPreference,
        revision: RememberPreferenceRevision,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> Result<Self, RememberPreferenceRecordError> {
        // UUID 词法辅助不铸造身份，也不引入成果权限；只复用 UUIDv7 规范字符串编码。
        let id = canonical_artifact_uuid_v7(id).ok_or(RememberPreferenceRecordError::InvalidId)?;
        validate_timestamp(created_at)?;
        validate_timestamp(updated_at)?;
        Ok(Self {
            id,
            key,
            preference,
            revision,
            created_at,
            updated_at,
        })
    }

    /// 借出规范化小写标准 UUIDv7 身份。
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// 借出完整稳定键；不代表当前用户权限。
    #[must_use]
    pub const fn key(&self) -> &RememberPreferenceKey {
        &self.key
    }

    /// 取出保存的闭集偏好；执行消费者仍须核原有权限。
    #[must_use]
    pub const fn preference(&self) -> RememberPreference {
        self.preference
    }

    /// 取出已通过纯验证的正版本。
    #[must_use]
    pub const fn revision(&self) -> RememberPreferenceRevision {
        self.revision
    }

    /// 取出显式注入的创建时间，不读取时钟。
    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// 取出显式注入的该版本更新时间，不证明它来自当前数据库。
    #[must_use]
    pub const fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// 对固定七字段生成现有三字段冲突快照；不包含凭据、权限缓存或原操作证据。
    ///
    /// 此快照仅描述传入的记录，不能证明当前权限、提交 ACK 或偏好已经生效。
    pub fn revision_snapshot(&self) -> Result<RevisionSnapshot, serde_json::Error> {
        use serde::ser::Error as _;
        let updated_at = self
            .updated_at
            .format(&Rfc3339)
            .map_err(|_| serde_json::Error::custom("remember_preference_invalid_timestamp"))?;
        let projection = PublicRememberPreference {
            id: &self.id,
            bot_id: self.key.bot_id().as_str(),
            target_kind: self.key.target_kind(),
            target_id: self.key.target_id(),
            preference: self.preference.as_storage(),
            revision: self.revision.get(),
            updated_at: &updated_at,
        };
        RevisionSnapshot::from_public(self.revision.get(), self.updated_at, &projection)
    }
}

// 只给固定摘要投影提供内部输出编码；六键/记录/selector 不因此获得 Serde 输入或输出。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicRememberPreference<'a> {
    id: &'a str,
    bot_id: &'a str,
    target_kind: &'a str,
    target_id: &'a str,
    preference: &'a str,
    revision: i64,
    updated_at: &'a str,
}

fn validate_timestamp(value: OffsetDateTime) -> Result<(), RememberPreferenceRecordError> {
    value
        .format(&Rfc3339)
        .map(|_| ())
        .map_err(|_| RememberPreferenceRecordError::InvalidTimestamp)
}

/// 数据库观察的两种纯状态；Absent 没有伪造的 ID、版本或时间。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum RememberPreferenceState {
    /// 没有记录，默认 Ask；纯状态不产生 row 或审计事实。
    #[default]
    Absent,
    /// 完整合法记录；保存 Ask 也保留其稳定身份和正版本。
    Stored(StoredRememberPreference),
}

impl RememberPreferenceState {
    /// 取出缺行或记录的偏好值，不作执行授权判断。
    #[must_use]
    pub const fn effective_preference(&self) -> RememberPreference {
        match self {
            Self::Absent => RememberPreference::Ask,
            Self::Stored(record) => record.preference(),
        }
    }

    /// 借出合法记录；Absent 保持 None，不制造版本 0 或占位身份。
    #[must_use]
    pub const fn stored(&self) -> Option<&StoredRememberPreference> {
        match self {
            Self::Absent => None,
            Self::Stored(record) => Some(record),
        }
    }
}

/// 内部纯模型解码或推进失败；不回显身份、偏好原文或其他客户数据。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RememberPreferenceRecordError {
    /// 某个身份违反固定字节长度或 Unicode Cc 规则；字段名是固定内部标签。
    #[error("remember_preference_invalid_identity field={0}")]
    InvalidIdentity(&'static str),
    /// 目标类别未知或 User/Bot 的目标身份与导出值不等。
    #[error("remember_preference_invalid_target")]
    InvalidTarget,
    /// 稳定偏好 ID 不具有标准 UUIDv7 形状。
    #[error("remember_preference_invalid_id")]
    InvalidId,
    /// 偏好不是三个固定存储词之一。
    #[error("remember_preference_invalid_preference")]
    InvalidPreference,
    /// 版本不是正 i64。
    #[error("remember_preference_invalid_revision")]
    InvalidRevision,
    /// 原版本已到 i64 上限，不能继续推进。
    #[error("remember_preference_revision_overflow")]
    RevisionOverflow,
    /// 数据库时间不能编码成规范要求的 RFC3339。
    #[error("remember_preference_invalid_timestamp")]
    InvalidTimestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFERENCE_ID: &str = "019a0300-aaaa-7000-8000-000000000001";

    fn key(target: RememberPreferenceTarget) -> RememberPreferenceKey {
        RememberPreferenceKey::new(
            DeploymentId::new("deployment-A"),
            TenantId::new("tenant-A"),
            ActorId::new("actor-A"),
            BotId::new("bot-A"),
            target,
        )
        .unwrap()
    }

    fn key_with_five_identities(
        identities: [String; 5],
    ) -> Result<RememberPreferenceKey, RememberPreferenceRecordError> {
        let [deployment, tenant, actor, bot, thread] = identities;
        RememberPreferenceKey::new(
            DeploymentId::new(deployment),
            TenantId::new(tenant),
            ActorId::new(actor),
            BotId::new(bot),
            RememberPreferenceTarget::Thread(ThreadId::new(thread)),
        )
    }

    #[test]
    fn preference_storage_vocabulary_and_default_are_closed() {
        assert_eq!(RememberPreference::default(), RememberPreference::Ask);
        for (value, stored) in [
            (RememberPreference::Never, "never"),
            (RememberPreference::Ask, "ask"),
            (RememberPreference::AllowIfPolicy, "allow_if_policy"),
        ] {
            assert_eq!(value.as_storage(), stored);
            assert_eq!(RememberPreference::from_storage(stored).unwrap(), value);
        }
        for invalid in [
            "", "Never", "Ask", "always", "allow", " ask", "ask ", "unknown",
        ] {
            assert_eq!(
                RememberPreference::from_storage(invalid),
                Err(RememberPreferenceRecordError::InvalidPreference)
            );
        }
    }

    #[test]
    fn positive_revision_advances_without_saturation_or_wrap() {
        for invalid in [0, -1, i64::MIN] {
            assert_eq!(
                RememberPreferenceRevision::new(invalid),
                Err(RememberPreferenceRecordError::InvalidRevision)
            );
        }
        assert_eq!(RememberPreferenceRevision::first().get(), 1);
        assert_eq!(
            RememberPreferenceRevision::first()
                .checked_next()
                .unwrap()
                .get(),
            2
        );
        let last = RememberPreferenceRevision::new(i64::MAX - 1)
            .unwrap()
            .checked_next()
            .unwrap();
        assert_eq!(last.get(), i64::MAX);
        assert_eq!(
            last.checked_next(),
            Err(RememberPreferenceRecordError::RevisionOverflow)
        );
    }

    #[test]
    fn targets_derive_full_keys_without_rewriting_opaque_identity() {
        let user = key(RememberPreferenceTarget::User);
        assert_eq!(user.target_kind(), "memory_user");
        assert_eq!(user.target_id(), user.actor_id().as_str());
        let bot = key(RememberPreferenceTarget::Bot);
        assert_eq!(bot.target_kind(), "memory_bot");
        assert_eq!(bot.target_id(), bot.bot_id().as_str());
        let original = " thread-部署-e\u{301}\u{200d} ";
        let thread = key(RememberPreferenceTarget::Thread(ThreadId::new(original)));
        assert_eq!(thread.deployment_id().as_str(), "deployment-A");
        assert_eq!(thread.tenant_id().as_str(), "tenant-A");
        assert_eq!(thread.actor_id().as_str(), "actor-A");
        assert_eq!(thread.bot_id().as_str(), "bot-A");
        assert_eq!(thread.target_kind(), "memory_thread");
        assert_eq!(thread.target_id(), original);
        assert_ne!(
            thread,
            key(RememberPreferenceTarget::Thread(ThreadId::new(
                original.trim()
            )))
        );
        assert_ne!(
            key(RememberPreferenceTarget::Thread(ThreadId::new("é"))),
            key(RememberPreferenceTarget::Thread(ThreadId::new("e\u{301}")))
        );
        assert_eq!(
            RememberPreferenceTarget::User.as_storage_kind(),
            "memory_user"
        );
        assert_eq!(
            RememberPreferenceTarget::Bot.as_storage_kind(),
            "memory_bot"
        );
        assert_eq!(
            RememberPreferenceTarget::Thread(ThreadId::new("t")).as_storage_kind(),
            "memory_thread"
        );
    }

    #[test]
    fn stored_key_decode_rejects_unknown_kind_or_alias_targets() {
        let decode = |kind, target| {
            RememberPreferenceKey::from_stored(
                DeploymentId::new("deployment-A"),
                TenantId::new("tenant-A"),
                ActorId::new("actor-A"),
                BotId::new("bot-A"),
                kind,
                target,
            )
        };
        for (kind, target, expected) in [
            (
                "memory_user",
                "actor-A",
                key(RememberPreferenceTarget::User),
            ),
            ("memory_bot", "bot-A", key(RememberPreferenceTarget::Bot)),
            (
                "memory_thread",
                "thread-A",
                key(RememberPreferenceTarget::Thread(ThreadId::new("thread-A"))),
            ),
        ] {
            assert_eq!(decode(kind, target).unwrap(), expected);
        }
        for (kind, target) in [
            ("memory_user", "actor-B"),
            ("memory_bot", "bot-B"),
            ("workspace", "actor-A"),
            ("MEMORY_USER", "actor-A"),
            ("memory_user ", "actor-A"),
        ] {
            assert_eq!(
                decode(kind, target),
                Err(RememberPreferenceRecordError::InvalidTarget)
            );
        }
        for target in ["".to_owned(), "a\u{85}b".to_owned(), "x".repeat(513)] {
            assert_eq!(
                decode("memory_user", &target),
                Err(RememberPreferenceRecordError::InvalidIdentity("target"))
            );
        }
    }

    #[test]
    fn all_five_identities_obey_utf8_byte_limits() {
        let at_limit = "é".repeat(256);
        assert_eq!(at_limit.len(), 512);
        let long = format!("{at_limit}x");
        assert_eq!(long.len(), 513);
        let valid: [String; 5] = core::array::from_fn(|_| at_limit.clone());
        let stored = key_with_five_identities(valid.clone()).unwrap();
        assert_eq!(stored.deployment_id().as_str(), at_limit);
        assert_eq!(stored.tenant_id().as_str(), at_limit);
        assert_eq!(stored.actor_id().as_str(), at_limit);
        assert_eq!(stored.bot_id().as_str(), at_limit);
        assert_eq!(stored.target_id(), at_limit);
        for (index, field) in ["deployment", "tenant", "actor", "bot", "target"]
            .into_iter()
            .enumerate()
        {
            for invalid in [long.as_str(), ""] {
                let mut values = valid.clone();
                values[index] = invalid.to_owned();
                assert_eq!(
                    key_with_five_identities(values),
                    Err(RememberPreferenceRecordError::InvalidIdentity(field))
                );
            }
        }
    }

    #[test]
    fn full_unicode_cc_is_rejected_while_adjacent_and_format_characters_are_allowed() {
        let mut count = 0;
        for code in (0_u32..=0x1f).chain(0x7f..=0x9f) {
            let control = char::from_u32(code).unwrap();
            for (index, field) in ["deployment", "tenant", "actor", "bot", "target"]
                .into_iter()
                .enumerate()
            {
                let mut values: [String; 5] = core::array::from_fn(|_| "valid".to_owned());
                values[index] = format!("a{control}b");
                assert_eq!(
                    key_with_five_identities(values),
                    Err(RememberPreferenceRecordError::InvalidIdentity(field)),
                    "U+{code:04X} in {field}"
                );
            }
            count += 1;
        }
        assert_eq!(count, 65);
        for allowed in ['\u{20}', '\u{7e}', '\u{a0}', '\u{200d}', '\u{2028}', '部'] {
            let identity = format!("a{allowed}b");
            let values: [String; 5] = core::array::from_fn(|_| identity.clone());
            let stored = key_with_five_identities(values).unwrap();
            assert_eq!(stored.target_id(), identity);
        }
    }

    #[test]
    fn stored_records_require_uuid_v7_positive_revision_and_rfc3339_times() {
        let at = OffsetDateTime::UNIX_EPOCH;
        let record = StoredRememberPreference::create(
            "019A0300-AAAA-7000-8000-000000000001",
            key(RememberPreferenceTarget::User),
            RememberPreference::Ask,
            at,
        )
        .unwrap();
        assert_eq!(record.id(), PREFERENCE_ID);
        for id in [
            "",
            "019a0300-aaaa-4000-8000-000000000001",
            "019a0300-aaaa-7000-7000-000000000001",
            "019a0300-aaaa-7000-z000-000000000001",
            "{019a0300-aaaa-7000-8000-000000000001}",
            "urn:uuid:019a0300-aaaa-7000-8000-000000000001",
        ] {
            assert_eq!(
                StoredRememberPreference::create(
                    id,
                    key(RememberPreferenceTarget::User),
                    RememberPreference::Ask,
                    at
                ),
                Err(RememberPreferenceRecordError::InvalidId)
            );
        }
        for revision in [0, -1, i64::MIN] {
            assert_eq!(
                StoredRememberPreference::from_stored(
                    PREFERENCE_ID,
                    key(RememberPreferenceTarget::User),
                    "ask",
                    revision,
                    at,
                    at
                ),
                Err(RememberPreferenceRecordError::InvalidRevision)
            );
        }
        assert_eq!(
            StoredRememberPreference::from_stored(
                PREFERENCE_ID,
                key(RememberPreferenceTarget::User),
                "always",
                1,
                at,
                at
            ),
            Err(RememberPreferenceRecordError::InvalidPreference)
        );
        let before_rfc = time::Date::from_calendar_date(-1, time::Month::January, 1)
            .unwrap()
            .midnight()
            .assume_utc();
        let second_offset = at.to_offset(time::UtcOffset::from_hms(0, 0, 1).unwrap());
        for invalid in [before_rfc, second_offset] {
            assert_eq!(
                StoredRememberPreference::create(
                    PREFERENCE_ID,
                    key(RememberPreferenceTarget::User),
                    RememberPreference::Ask,
                    invalid
                ),
                Err(RememberPreferenceRecordError::InvalidTimestamp)
            );
            assert_eq!(
                StoredRememberPreference::from_stored(
                    PREFERENCE_ID,
                    key(RememberPreferenceTarget::User),
                    "ask",
                    1,
                    invalid,
                    at
                ),
                Err(RememberPreferenceRecordError::InvalidTimestamp)
            );
            assert_eq!(
                StoredRememberPreference::from_stored(
                    PREFERENCE_ID,
                    key(RememberPreferenceTarget::User),
                    "ask",
                    1,
                    at,
                    invalid
                ),
                Err(RememberPreferenceRecordError::InvalidTimestamp)
            );
        }
    }

    #[test]
    fn absent_defaults_to_ask_while_stored_ask_keeps_identity_revision_and_times() {
        let absent = RememberPreferenceState::default();
        assert_eq!(absent, RememberPreferenceState::Absent);
        assert_eq!(absent.effective_preference(), RememberPreference::Ask);
        assert!(absent.stored().is_none());
        let created = OffsetDateTime::UNIX_EPOCH;
        let updated = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let first = StoredRememberPreference::create(
            PREFERENCE_ID,
            key(RememberPreferenceTarget::User),
            RememberPreference::Ask,
            created,
        )
        .unwrap();
        assert_eq!(first.revision().get(), 1);
        assert_eq!(first.created_at(), first.updated_at());
        let stored = StoredRememberPreference::from_stored(
            PREFERENCE_ID,
            first.key().clone(),
            "ask",
            9,
            created,
            updated,
        )
        .unwrap();
        let state = RememberPreferenceState::Stored(stored.clone());
        assert_ne!(state, absent);
        assert_eq!(state.effective_preference(), RememberPreference::Ask);
        assert_eq!(state.stored(), Some(&stored));
        assert_eq!(stored.id(), first.id());
        assert_eq!(stored.revision().get(), 9);
        assert_eq!(stored.created_at(), created);
        assert_eq!(stored.updated_at(), updated);
    }

    #[test]
    fn revision_snapshot_matches_independent_fixed_digest_and_exact_projection() {
        let at = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let record = StoredRememberPreference::from_stored(
            "019A0300-AAAA-7000-8000-000000000001",
            key(RememberPreferenceTarget::Thread(ThreadId::new("thread-A"))),
            "allow_if_policy",
            7,
            OffsetDateTime::UNIX_EPOCH,
            at,
        )
        .unwrap();
        // 独立预期基于以下固定紧凑 JSON 的 UTF8 字节，而非候选的投影函数：
        // {"botId":"bot-A","id":"019a0300-aaaa-7000-8000-000000000001","preference":"allow_if_policy","revision":7,"targetId":"thread-A","targetKind":"memory_thread","updatedAt":"2023-11-14T22:13:20Z"}
        let snapshot = record.revision_snapshot().unwrap();
        assert_eq!(
            serde_json::to_value(snapshot).unwrap(),
            serde_json::json!({
                "currentRevision":7,
                "currentSha256":"4e8621a4ad31c152291aa81922bb2596145240f2bc6d2c91294a9522c89ef4d1",
                "updatedAt":"2023-11-14T22:13:20Z",
            })
        );
        let different_namespace = RememberPreferenceKey::new(
            DeploymentId::new("deployment-B"),
            TenantId::new("tenant-B"),
            ActorId::new("actor-B"),
            BotId::new("bot-A"),
            RememberPreferenceTarget::Thread(ThreadId::new("thread-A")),
        )
        .unwrap();
        let same_projection = StoredRememberPreference::from_stored(
            PREFERENCE_ID,
            different_namespace,
            "allow_if_policy",
            7,
            at,
            at,
        )
        .unwrap();
        assert_eq!(same_projection.revision_snapshot().unwrap(), snapshot);
        for (preference, revision, updated) in [
            ("ask", 7, at),
            ("allow_if_policy", 8, at),
            ("allow_if_policy", 7, OffsetDateTime::UNIX_EPOCH),
        ] {
            let changed = StoredRememberPreference::from_stored(
                PREFERENCE_ID,
                record.key().clone(),
                preference,
                revision,
                at,
                updated,
            )
            .unwrap();
            assert_ne!(changed.revision_snapshot().unwrap(), snapshot);
        }
    }

    struct SerdeProbe<T>(core::marker::PhantomData<T>);
    impl<T> SerdeProbe<T> {
        const fn new() -> Self {
            Self(core::marker::PhantomData)
        }
    }
    impl<T: serde::Serialize> SerdeProbe<T> {
        fn has_serialize(&self) -> bool {
            true
        }
    }
    impl<T: serde::de::DeserializeOwned> SerdeProbe<T> {
        fn has_deserialize(&self) -> bool {
            true
        }
    }
    trait SerdeProbeFallback {
        fn has_serialize(&self) -> bool {
            false
        }
        fn has_deserialize(&self) -> bool {
            false
        }
    }
    impl<T> SerdeProbeFallback for SerdeProbe<T> {}

    #[test]
    fn internal_preference_models_have_no_serde_input_or_output() {
        macro_rules! assert_no_serde {
            ($($ty:ty),+ $(,)?) => { $(
                assert!(!SerdeProbe::<$ty>::new().has_serialize());
                assert!(!SerdeProbe::<$ty>::new().has_deserialize());
            )+ };
        }
        assert_no_serde!(
            RememberPreference,
            RememberPreferenceRevision,
            RememberPreferenceTarget,
            RememberPreferenceKey,
            StoredRememberPreference,
            RememberPreferenceState
        );
        assert!(SerdeProbe::<RevisionSnapshot>::new().has_serialize());
        assert!(SerdeProbe::<RevisionSnapshot>::new().has_deserialize());
    }
}
