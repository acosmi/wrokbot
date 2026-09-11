//! 恢复后旧授权失效与历史保留的纯计划（§14.4 / R235 / PA-05）。
//!
//! # 范围
//!
//! 本模块消费已核 [`super::plan::StructuralRestorePlan`]（及其
//! [`super::inventory::InventoryChecked`]、[`super::inventory::CheckedReceipts`]、
//! [`super::plan::IdentityBinding`]），再叠加一份只含 opaque 标识与归属关系的受控对象清单，
//! 产出可供后续事务执行器逐项核对的 [`PostRestorePlan`]。
//!
//! 它不读文件、时钟、随机数、环境或数据库，不签发 recovery epoch，不写库，
//! 不恢复 active lease / 待发送 dispatch，不重放 Unknown，也不把“disposition 已列出”
//! 解释成已经撤权。结构核验仍不证明来源真实性 / AEAD。
//!
//! 调用方 Vec **不是**快照全库证明；空清单也不表示没有失效义务。
//!
//! # 内部检查顺序
//!
//! 第一真源未规定多条件显示优先级。本核按固定内部顺序 **fail-closed 返回第一项**：
//! 有界配置 → 标识形态 → 秘密材料 → 远端 prose → 未知类别 → 重复目标 →
//! 绑定层次 → 计数 → 单段/累计长度 → 输出预算。该顺序不是对外协议。
//! 失败不产生部分可执行计划。
//!
//! # 本批明确不做
//!
//! - 重新实现 [`super::plan::plan_restore`] 或文件暂存。
//! - 铸造新身份 / 新随机 epoch，或用旧 counter+1、时间戳、固定 hash 代替。
//! - 关闭 V5-BACKUP-01 / A6 / G8 的真实失效执行与演练。

use std::collections::BTreeSet;

use crate::audit::hash::Sha256Digest;
use crate::vault::KeyVersion;

use super::inventory::{
    CheckedReceipts, InstallationIdentity, InventoryChecked, KeyBindingClaim, VaultKeyRefClaim,
};
use super::plan::{
    FollowUpRequirements, IdentityBinding, PendingProofs, ProofStatus, StructuralRestorePlan,
};

/// 受控授权对象条数上限。不是产品 API 限额。
pub const MAX_OBJECTS: u32 = 8_192;

/// 单段标识字节上限，与备份 identity 预算对齐。
pub const MAX_ID_BYTES: u16 = 128;

/// 全部标识字节合计上限。
pub const MAX_TOTAL_ID_BYTES: u64 = 1_048_576;

/// 输出计划估算字节上限。
pub const MAX_OUTPUT_BYTES: u64 = 2_097_152;

/// 对象、回执、key 和默认规则的合计条数硬上限。
pub const MAX_PLAN_ITEMS: usize = 16_384;

const CATEGORY_ORDER: [AuthMaterialKind; 9] = [
    AuthMaterialKind::AuthSession,
    AuthMaterialKind::Approval,
    AuthMaterialKind::Lease,
    AuthMaterialKind::Ticket,
    AuthMaterialKind::Capability,
    AuthMaterialKind::OauthState,
    AuthMaterialKind::RunAssertion,
    AuthMaterialKind::RemoteDeviceRegistration,
    AuthMaterialKind::ConnectionCredential,
];

/// 结构核验之后、持久化执行之前的有界配置。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostRestoreBounds {
    max_objects: u32,
    max_id_bytes: u16,
    max_total_id_bytes: u64,
    max_output_bytes: u64,
}

impl PostRestoreBounds {
    /// 本批默认上限。
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            max_objects: MAX_OBJECTS,
            max_id_bytes: MAX_ID_BYTES,
            max_total_id_bytes: MAX_TOTAL_ID_BYTES,
            max_output_bytes: MAX_OUTPUT_BYTES,
        }
    }

    /// 测试或更紧策略下的有界配置。任一上限为 0 则拒绝。
    ///
    /// # Errors
    ///
    /// 上限为 0 时返回 [`PostRestoreFault::BoundsInvalid`]。
    pub const fn try_new(
        max_objects: u32,
        max_id_bytes: u16,
        max_total_id_bytes: u64,
        max_output_bytes: u64,
    ) -> Result<Self, PostRestoreFault> {
        if max_objects == 0
            || max_id_bytes == 0
            || max_total_id_bytes == 0
            || max_output_bytes == 0
            || max_objects > MAX_OBJECTS
            || max_id_bytes > MAX_ID_BYTES
            || max_total_id_bytes > MAX_TOTAL_ID_BYTES
            || max_output_bytes > MAX_OUTPUT_BYTES
        {
            return Err(PostRestoreFault::BoundsInvalid);
        }
        Ok(Self {
            max_objects,
            max_id_bytes,
            max_total_id_bytes,
            max_output_bytes,
        })
    }

    /// 对象条数上限。
    #[must_use]
    pub const fn max_objects(self) -> u32 {
        self.max_objects
    }

    /// 单段标识字节上限。
    #[must_use]
    pub const fn max_id_bytes(self) -> u16 {
        self.max_id_bytes
    }

    /// 标识字节合计上限。
    #[must_use]
    pub const fn max_total_id_bytes(self) -> u64 {
        self.max_total_id_bytes
    }

    /// 输出估算字节上限。
    #[must_use]
    pub const fn max_output_bytes(self) -> u64 {
        self.max_output_bytes
    }
}

/// [`plan_post_restore`] 的输入。避免无界参数列表。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostRestoreRequest<'a> {
    /// 已核结构恢复计划。不能用 `inventory_verified: true` 替代。
    pub structural: &'a StructuralRestorePlan,
    /// 受控内部授权对象。空清单仍保留全局失效义务。
    pub objects: &'a [AuthObjectClaim],
    /// 有界配置。
    pub bounds: &'a PostRestoreBounds,
}

/// 调用方提供的未核授权对象。只含 opaque 标识和归属，不含 secret / cookie / token / 私钥 / 远端 prose。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthObjectClaim {
    /// 对象身份。跨类别唯一。
    pub id: String,
    /// 类别的稳定 snake_case 名。
    pub kind: String,
    /// 归属 actor。部分类别必填；禁止 `all` / `*` 这类宽泛目标。
    pub actor_id: Option<String>,
    /// 归属 dataset。必须等于已核清单。
    pub dataset_id: String,
    /// 归属 deployment。必须等于已核清单。
    pub deployment_id: String,
    /// 归属安装。必须等于**原**安装，不能绑到新安装逃避失效。
    pub installation_id: Option<String>,
    /// 快照曾声称仍 active / allow。不得据此放行。
    pub snapshot_claimed_active: bool,
}

/// §14.4 覆盖的旧授权材料类别。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthMaterialKind {
    /// 旧 auth / session。
    AuthSession,
    /// 旧 approval。
    Approval,
    /// 旧 human / computer lease。
    Lease,
    /// 旧 ticket。
    Ticket,
    /// 旧 capability。
    Capability,
    /// 旧 OAuth state。
    OauthState,
    /// 旧 run assertion。
    RunAssertion,
    /// 旧远程设备注册材料。
    RemoteDeviceRegistration,
    /// 恢复出的连接凭据。
    ConnectionCredential,
}

impl AuthMaterialKind {
    /// 稳定分类名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthSession => "auth_session",
            Self::Approval => "approval",
            Self::Lease => "lease",
            Self::Ticket => "ticket",
            Self::Capability => "capability",
            Self::OauthState => "oauth_state",
            Self::RunAssertion => "run_assertion",
            Self::RemoteDeviceRegistration => "remote_device_registration",
            Self::ConnectionCredential => "connection_credential",
        }
    }

    const fn requires_actor(self) -> bool {
        !matches!(self, Self::RemoteDeviceRegistration)
    }

    const fn requires_installation(self) -> bool {
        matches!(
            self,
            Self::Lease | Self::Ticket | Self::RemoteDeviceRegistration
        )
    }

    const fn default_disposition(self) -> ObjectDispositionKind {
        match self {
            Self::ConnectionCredential => ObjectDispositionKind::RequireReconfirm,
            Self::RemoteDeviceRegistration => ObjectDispositionKind::RequireReregistration,
            Self::AuthSession
            | Self::Approval
            | Self::Lease
            | Self::Ticket
            | Self::Capability
            | Self::OauthState
            | Self::RunAssertion => ObjectDispositionKind::RetireShortLived,
        }
    }
}

impl core::fmt::Display for AuthMaterialKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 对一类材料的缺省规则。空库存不能清掉该类义务。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CategoryRule {
    kind: AuthMaterialKind,
    default_disposition: ObjectDispositionKind,
    empty_inventory_still_requires_invalidation: bool,
}

impl CategoryRule {
    /// 材料类别。
    #[must_use]
    pub const fn kind(self) -> AuthMaterialKind {
        self.kind
    }

    /// 缺省处置。
    #[must_use]
    pub const fn default_disposition(self) -> ObjectDispositionKind {
        self.default_disposition
    }

    /// 空清单是否仍要求该类失效 / 重确认义务。
    #[must_use]
    pub const fn empty_inventory_still_requires_invalidation(self) -> bool {
        self.empty_inventory_still_requires_invalidation
    }
}

/// 单个对象的处置。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectDispositionKind {
    /// 短期授权退役，不得继续使用。
    RetireShortLived,
    /// 必须由当前主体 / 本地状态重新确认后才能使用。
    RequireReconfirm,
    /// 远程设备必须重新注册，不得自动复活旧证书。
    RequireReregistration,
}

impl ObjectDispositionKind {
    /// 稳定名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RetireShortLived => "retire_short_lived",
            Self::RequireReconfirm => "require_reconfirm",
            Self::RequireReregistration => "require_reregistration",
        }
    }
}

/// 逐对象处置。字段私有。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectDisposition {
    id: String,
    kind: AuthMaterialKind,
    disposition: ObjectDispositionKind,
    actor_id: Option<String>,
    dataset_id: String,
    deployment_id: String,
    installation_id: Option<String>,
    snapshot_claimed_active: bool,
    grants_use_from_snapshot: bool,
    restores_active_lease: bool,
    rebuilds_dispatch: bool,
    resurrects_vendor_revocation: bool,
}

impl ObjectDisposition {
    /// 对象身份。
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// 类别。
    #[must_use]
    pub const fn kind(&self) -> AuthMaterialKind {
        self.kind
    }

    /// 处置。
    #[must_use]
    pub const fn disposition(&self) -> ObjectDispositionKind {
        self.disposition
    }

    /// actor。
    #[must_use]
    pub fn actor_id(&self) -> Option<&str> {
        self.actor_id.as_deref()
    }

    /// dataset。
    #[must_use]
    pub fn dataset_id(&self) -> &str {
        &self.dataset_id
    }

    /// deployment。
    #[must_use]
    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }

    /// 原安装。
    #[must_use]
    pub fn installation_id(&self) -> Option<&str> {
        self.installation_id.as_deref()
    }

    /// 快照是否声称仍 active。
    #[must_use]
    pub const fn snapshot_claimed_active(&self) -> bool {
        self.snapshot_claimed_active
    }

    /// 是否因快照 active/allow 放行。构造结果必须为否。
    #[must_use]
    pub const fn grants_use_from_snapshot(&self) -> bool {
        self.grants_use_from_snapshot
    }

    /// 是否恢复 active lease。
    #[must_use]
    pub const fn restores_active_lease(&self) -> bool {
        self.restores_active_lease
    }

    /// 是否重建待发送 dispatch。
    #[must_use]
    pub const fn rebuilds_dispatch(&self) -> bool {
        self.rebuilds_dispatch
    }

    /// 是否宣称可复活厂商已撤销账号。
    #[must_use]
    pub const fn resurrects_vendor_revocation(&self) -> bool {
        self.resurrects_vendor_revocation
    }
}

/// 已核回执的保留分类。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptClass {
    /// 已提交。
    Committed,
    /// Unknown，只 reconciliation。
    Unknown,
    /// 工具回执。
    Tool,
}

impl ReceiptClass {
    /// 稳定名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Unknown => "unknown",
            Self::Tool => "tool",
        }
    }
}

/// 一条回执的保留描述。不改 ID、不改归类。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptRetention {
    id: String,
    class: ReceiptClass,
    original_class_preserved: bool,
    dispatch_scheduled: bool,
    unknown_promoted: bool,
    unknown_retryable: bool,
    unconfirmed_reconciliation: bool,
}

impl ReceiptRetention {
    /// 回执身份。
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// 原归类。
    #[must_use]
    pub const fn class(&self) -> ReceiptClass {
        self.class
    }

    /// 是否保持原归类。
    #[must_use]
    pub const fn original_class_preserved(&self) -> bool {
        self.original_class_preserved
    }

    /// 是否安排 dispatch / 重放。
    #[must_use]
    pub const fn dispatch_scheduled(&self) -> bool {
        self.dispatch_scheduled
    }

    /// Unknown 是否被升为成功。
    #[must_use]
    pub const fn unknown_promoted(&self) -> bool {
        self.unknown_promoted
    }

    /// Unknown 是否变为可重试。
    #[must_use]
    pub const fn unknown_retryable(&self) -> bool {
        self.unknown_retryable
    }

    /// 已发未确认是否只进入 reconciliation。
    #[must_use]
    pub const fn unconfirmed_reconciliation(&self) -> bool {
        self.unconfirmed_reconciliation
    }
}

/// 长期解密 key 的保留引用。授权失效不得删除历史解密能力。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoricalDecryptRef {
    key_id: String,
    key_version: KeyVersion,
    canary: Sha256Digest,
    retain_decrypt_capability: bool,
    removed_by_auth_invalidation: bool,
}

impl HistoricalDecryptRef {
    /// key ID。
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// key 版本。
    #[must_use]
    pub const fn key_version(&self) -> KeyVersion {
        self.key_version
    }

    /// canary 引用。
    #[must_use]
    pub const fn canary(&self) -> Sha256Digest {
        self.canary
    }

    /// 是否保留历史解密能力。
    #[must_use]
    pub const fn retain_decrypt_capability(&self) -> bool {
        self.retain_decrypt_capability
    }

    /// 是否因授权失效被删除。
    #[must_use]
    pub const fn removed_by_auth_invalidation(&self) -> bool {
        self.removed_by_auth_invalidation
    }
}

/// 新 recovery epoch 的派生方式。本核只允许“执行前新随机”，不会签发。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryEpochDerivation {
    /// 后续 owner 必须新铸造独立随机 epoch。
    FreshRandomRequired,
}

/// 新随机 recovery epoch 义务。本模块不铸造。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryEpochObligation {
    required: bool,
    issued: bool,
    derivation: RecoveryEpochDerivation,
}

impl RecoveryEpochObligation {
    /// 是否要求铸造。
    #[must_use]
    pub const fn required(self) -> bool {
        self.required
    }

    /// 本核是否已经签发。
    #[must_use]
    pub const fn issued(self) -> bool {
        self.issued
    }

    /// 派生方式。
    #[must_use]
    pub const fn derivation(self) -> RecoveryEpochDerivation {
        self.derivation
    }

    /// 是否用旧 counter+1。
    #[must_use]
    pub const fn uses_old_counter_plus_one(self) -> bool {
        !matches!(
            self.derivation,
            RecoveryEpochDerivation::FreshRandomRequired
        )
    }

    /// 是否用时间戳代替随机 epoch。
    #[must_use]
    pub const fn uses_timestamp(self) -> bool {
        !matches!(
            self.derivation,
            RecoveryEpochDerivation::FreshRandomRequired
        )
    }

    /// 是否用固定 hash 代替随机 epoch。
    #[must_use]
    pub const fn uses_fixed_hash(self) -> bool {
        !matches!(
            self.derivation,
            RecoveryEpochDerivation::FreshRandomRequired
        )
    }
}

/// 不依赖调用方 Vec 是否为空的全局义务。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GlobalObligations {
    epoch: RecoveryEpochObligation,
    invalidate_old_auth_and_control: bool,
    invalidate_performed: bool,
    reconfirm_credentials: bool,
    keep_receipts: bool,
    must_not_replay_unknown: bool,
    caller_inventory_is_complete_snapshot: bool,
    listed_dispositions_already_revoked: bool,
}

impl GlobalObligations {
    /// epoch 义务。
    #[must_use]
    pub const fn epoch(self) -> RecoveryEpochObligation {
        self.epoch
    }

    /// 是否要求失效旧授权 / 控制态。
    #[must_use]
    pub const fn invalidate_old_auth_and_control(self) -> bool {
        self.invalidate_old_auth_and_control
    }

    /// 本核是否已经执行撤权。
    #[must_use]
    pub const fn invalidate_performed(self) -> bool {
        self.invalidate_performed
    }

    /// 是否要求重确认凭据。
    #[must_use]
    pub const fn reconfirm_credentials(self) -> bool {
        self.reconfirm_credentials
    }

    /// 是否要求保留回执。
    #[must_use]
    pub const fn keep_receipts(self) -> bool {
        self.keep_receipts
    }

    /// Unknown 是否禁止重放。
    #[must_use]
    pub const fn must_not_replay_unknown(self) -> bool {
        self.must_not_replay_unknown
    }

    /// 调用方 Vec 是否被当成全库证明。
    #[must_use]
    pub const fn caller_inventory_is_complete_snapshot(self) -> bool {
        self.caller_inventory_is_complete_snapshot
    }

    /// 列出 disposition 是否等于已经撤权。
    #[must_use]
    pub const fn listed_dispositions_already_revoked(self) -> bool {
        self.listed_dispositions_already_revoked
    }
}

/// 恢复后授权失效与历史保留计划。不是 RestoreAuthorized，也不是 Application Ready。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostRestorePlan {
    source_bundle: super::BundleIdentity,
    source_barrier: super::BarrierIdentity,
    source_manifest: Sha256Digest,
    identity: IdentityBinding,
    pending: PendingProofs,
    follow_up: FollowUpRequirements,
    original_installation: InstallationIdentity,
    global: GlobalObligations,
    category_rules: Vec<CategoryRule>,
    object_dispositions: Vec<ObjectDisposition>,
    receipt_retentions: Vec<ReceiptRetention>,
    historical_decrypt_refs: Vec<HistoricalDecryptRef>,
    input_object_count: u32,
    identifier_bytes: u64,
    output_bytes: u64,
}

impl PostRestorePlan {
    /// 此计划所属的结构已核 bundle；不是 AEAD 证明。
    #[must_use]
    pub fn source_bundle(&self) -> &super::BundleIdentity {
        &self.source_bundle
    }
    /// 此计划所属的一致性屏障。
    #[must_use]
    pub fn source_barrier(&self) -> &super::BarrierIdentity {
        &self.source_barrier
    }
    /// 原清单登记的 manifest 摘要；执行器仍须核实际来源和字节。
    #[must_use]
    pub const fn source_manifest(&self) -> Sha256Digest {
        self.source_manifest
    }
    /// 沿用结构计划的安装映射。本核不 Fresh 重派生。
    #[must_use]
    pub fn identity(&self) -> &IdentityBinding {
        &self.identity
    }

    /// 原结构计划携带的待证明项。
    #[must_use]
    pub const fn pending_proofs(&self) -> PendingProofs {
        self.pending
    }

    /// 结构计划的后续义务。
    #[must_use]
    pub const fn follow_up(&self) -> FollowUpRequirements {
        self.follow_up
    }

    /// 快照原安装。对象绑定必须指向它。
    #[must_use]
    pub fn original_installation(&self) -> &InstallationIdentity {
        &self.original_installation
    }

    /// 全局义务。
    #[must_use]
    pub const fn global(&self) -> GlobalObligations {
        self.global
    }

    /// 九类缺省规则，与调用方 Vec 是否为空无关。
    #[must_use]
    pub fn category_rules(&self) -> &[CategoryRule] {
        &self.category_rules
    }

    /// 逐对象处置，输入顺序、无重复目标。
    #[must_use]
    pub fn object_dispositions(&self) -> &[ObjectDisposition] {
        &self.object_dispositions
    }

    /// 已核回执的逐项保留。
    #[must_use]
    pub fn receipt_retentions(&self) -> &[ReceiptRetention] {
        &self.receipt_retentions
    }

    /// 长期解密 key 引用。
    #[must_use]
    pub fn historical_decrypt_refs(&self) -> &[HistoricalDecryptRef] {
        &self.historical_decrypt_refs
    }

    /// 输入对象条数。
    #[must_use]
    pub const fn input_object_count(&self) -> u32 {
        self.input_object_count
    }

    /// 标识字节合计。
    #[must_use]
    pub const fn identifier_bytes(&self) -> u64 {
        self.identifier_bytes
    }

    /// 输出估算字节。
    #[must_use]
    pub const fn output_bytes(&self) -> u64 {
        self.output_bytes
    }

    /// 是否保留业务 dataset / deployment / tenant。
    #[must_use]
    pub fn preserves_business_identity(&self) -> bool {
        self.identity.preserves_business_identity()
            && match &self.identity {
                IdentityBinding::SameInstallation { dataset, .. }
                | IdentityBinding::NewInstallation { dataset, .. } => {
                    dataset.as_str() == self.original_dataset()
                }
            }
    }

    /// 是否套用 Fresh 身份派生。
    #[must_use]
    pub fn applies_fresh_identity_derivation(&self) -> bool {
        self.identity.applies_fresh_identity_derivation()
            || self
                .object_dispositions
                .iter()
                .any(|item| item.dataset_id != self.original_dataset())
    }

    /// 新安装是否保留 record ID。
    #[must_use]
    pub fn preserves_record_ids(&self) -> bool {
        match &self.identity {
            IdentityBinding::SameInstallation { .. } => true,
            IdentityBinding::NewInstallation {
                record_ids_preserved,
                ..
            } => *record_ids_preserved,
        }
    }

    /// 不授予 RestoreAuthorized。扫描携带的证明状态，而不是另写一个恒 false。
    #[must_use]
    pub fn restore_authorized(&self) -> bool {
        !matches!(self.pending.restore_authorized(), ProofStatus::NotGranted)
    }

    /// 不授予 Application Ready。
    #[must_use]
    pub fn application_ready(&self) -> bool {
        !matches!(self.pending.application_ready(), ProofStatus::NotGranted)
    }

    /// 本核是否签发了 recovery epoch。
    #[must_use]
    pub fn issues_recovery_epoch(&self) -> bool {
        self.global.epoch.issued()
            || self.global.epoch.uses_old_counter_plus_one()
            || self.global.epoch.uses_timestamp()
            || self.global.epoch.uses_fixed_hash()
    }

    /// 是否安排 Unknown 重放。扫描回执集合。
    #[must_use]
    pub fn schedules_unknown_replay(&self) -> bool {
        self.receipt_retentions.iter().any(|item| {
            item.class == ReceiptClass::Unknown
                && (item.dispatch_scheduled || item.unknown_retryable || item.unknown_promoted)
        }) || !self.follow_up.must_not_replay_unknown()
            || !self.global.must_not_replay_unknown
    }

    /// 是否恢复 active lease。扫描对象集合。
    #[must_use]
    pub fn restores_active_lease(&self) -> bool {
        self.object_dispositions
            .iter()
            .any(|item| item.kind == AuthMaterialKind::Lease && item.restores_active_lease)
    }

    /// 是否重建待发送 dispatch。扫描对象与回执。
    #[must_use]
    pub fn restores_dispatch(&self) -> bool {
        self.object_dispositions
            .iter()
            .any(|item| item.rebuilds_dispatch)
            || self
                .receipt_retentions
                .iter()
                .any(|item| item.dispatch_scheduled)
    }

    /// 是否因快照 active/allow 放行。扫描对象集合。
    #[must_use]
    pub fn snapshot_active_grants_use(&self) -> bool {
        self.object_dispositions
            .iter()
            .any(|item| item.snapshot_claimed_active && item.grants_use_from_snapshot)
    }

    /// 是否把 Unknown 升为成功。扫描回执集合。
    #[must_use]
    pub fn promotes_unknown_to_success(&self) -> bool {
        self.receipt_retentions
            .iter()
            .any(|item| item.class == ReceiptClass::Unknown && item.unknown_promoted)
    }

    /// 是否宣称可复活厂商已撤销账号。扫描凭据对象。
    #[must_use]
    pub fn resurrects_vendor_revoked_account(&self) -> bool {
        self.object_dispositions.iter().any(|item| {
            item.kind == AuthMaterialKind::ConnectionCredential && item.resurrects_vendor_revocation
        })
    }

    /// 历史解密能力是否因授权失效被删。扫描 key 引用。
    #[must_use]
    pub fn deletes_historical_decrypt_keys(&self) -> bool {
        self.historical_decrypt_refs
            .iter()
            .any(|item| item.removed_by_auth_invalidation || !item.retain_decrypt_capability)
    }

    /// 调用方 Vec 是否被当成全库证明。
    #[must_use]
    pub fn caller_vec_proves_complete_snapshot(&self) -> bool {
        self.global.caller_inventory_is_complete_snapshot
    }

    /// 列出 disposition 是否等于已经撤权。
    #[must_use]
    pub fn listed_dispositions_mean_already_revoked(&self) -> bool {
        self.global.listed_dispositions_already_revoked || self.global.invalidate_performed
    }

    /// 是否写数据库。本核不执行 effect；若未来误把执行标志写入集合，这里会扫到。
    #[must_use]
    pub fn writes_database(&self) -> bool {
        self.global.invalidate_performed
    }

    /// 是否生成密钥。
    #[must_use]
    pub fn generates_keys(&self) -> bool {
        self.historical_decrypt_refs
            .iter()
            .any(|item| !item.retain_decrypt_capability)
            && self.global.epoch.issued()
    }

    fn original_dataset(&self) -> &str {
        match &self.identity {
            IdentityBinding::SameInstallation { dataset, .. }
            | IdentityBinding::NewInstallation { dataset, .. } => dataset.as_str(),
        }
    }
}

/// 恢复后计划失败。只携带本模块分类，不回显秘密或远端文案。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PostRestoreFault {
    /// 有界配置非法。
    #[error("backup_post_restore_bounds_invalid")]
    BoundsInvalid,
    /// 标识空、越界或含路径分隔。
    #[error("backup_post_restore_identity_invalid")]
    IdentityInvalid,
    /// 禁止的秘密材料名。
    #[error("backup_post_restore_secret_material_forbidden")]
    SecretMaterialForbidden,
    /// 远端错误 prose 或空白句子。
    #[error("backup_post_restore_prose_rejected")]
    ProseRejected,
    /// 未知材料类别。
    #[error("backup_post_restore_unknown_category")]
    UnknownCategory,
    /// 失效目标重复。
    #[error("backup_post_restore_duplicate_target")]
    DuplicateTarget,
    /// 归属层次错误或宽泛跨 actor/dataset 处置。
    #[error("backup_post_restore_binding_mismatch")]
    BindingMismatch,
    /// 计数越界。
    #[error("backup_post_restore_count_out_of_bounds")]
    CountOutOfBounds,
    /// 长度或输出预算越界。
    #[error("backup_post_restore_length_out_of_bounds")]
    LengthOutOfBounds,
    /// 累计长度 checked 失败。
    #[error("backup_post_restore_accumulated_overflow")]
    AccumulatedOverflow,
}

impl PostRestoreFault {
    /// 稳定 code。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BoundsInvalid => "backup_post_restore_bounds_invalid",
            Self::IdentityInvalid => "backup_post_restore_identity_invalid",
            Self::SecretMaterialForbidden => "backup_post_restore_secret_material_forbidden",
            Self::ProseRejected => "backup_post_restore_prose_rejected",
            Self::UnknownCategory => "backup_post_restore_unknown_category",
            Self::DuplicateTarget => "backup_post_restore_duplicate_target",
            Self::BindingMismatch => "backup_post_restore_binding_mismatch",
            Self::CountOutOfBounds => "backup_post_restore_count_out_of_bounds",
            Self::LengthOutOfBounds => "backup_post_restore_length_out_of_bounds",
            Self::AccumulatedOverflow => "backup_post_restore_accumulated_overflow",
        }
    }
}

/// 从已核结构计划生成逐类 / 逐对象失效与历史保留计划。
///
/// # Errors
///
/// 越界、重复、未知类别、错误绑定、秘密材料或 prose 均返回 [`PostRestoreFault`]，
/// 不留下部分可执行计划。
pub fn plan_post_restore(
    request: PostRestoreRequest<'_>,
) -> Result<PostRestorePlan, PostRestoreFault> {
    let bounds = request.bounds;
    if bounds.max_objects == 0
        || bounds.max_id_bytes == 0
        || bounds.max_total_id_bytes == 0
        || bounds.max_output_bytes == 0
    {
        return Err(PostRestoreFault::BoundsInvalid);
    }

    let inventory = request.structural.inventory();
    let original_installation = inventory.original_installation();
    let count =
        u32::try_from(request.objects.len()).map_err(|_| PostRestoreFault::AccumulatedOverflow)?;
    if count > bounds.max_objects {
        return Err(PostRestoreFault::CountOutOfBounds);
    }

    // Validate all lengths and budgets through borrowed views before copying identifiers.
    let mut seen = BTreeSet::new();
    let mut identifier_bytes = 0_u64;
    let identity = request.structural.identity();
    let identity_ids = match identity {
        IdentityBinding::SameInstallation {
            installation,
            dataset,
            deployment,
            tenant,
        } => vec![
            installation.as_str(),
            dataset.as_str(),
            deployment.as_str(),
            tenant.as_str(),
        ],
        IdentityBinding::NewInstallation {
            original_installation,
            new_installation,
            dataset,
            deployment,
            tenant,
            ..
        } => vec![
            original_installation.as_str(),
            new_installation.as_str(),
            dataset.as_str(),
            deployment.as_str(),
            tenant.as_str(),
        ],
    };
    for id in identity_ids.into_iter().chain([
        inventory.bundle().bundle_id.as_str(),
        inventory.barrier().as_str(),
        original_installation.as_str(),
    ]) {
        if id.is_empty() || id.len() > usize::from(bounds.max_id_bytes) {
            return Err(PostRestoreFault::IdentityInvalid);
        }
        identifier_bytes = add_bytes(identifier_bytes, id.len())?;
    }
    if identifier_bytes > bounds.max_total_id_bytes {
        return Err(PostRestoreFault::LengthOutOfBounds);
    }
    let mut validated = Vec::new();
    for claim in request.objects {
        let checked = check_object(claim, inventory, original_installation, bounds)?;
        if !seen.insert(checked.id) {
            return Err(PostRestoreFault::DuplicateTarget);
        }
        identifier_bytes = add_bytes(identifier_bytes, checked.id.len())?;
        if let Some(actor) = &checked.actor_id {
            identifier_bytes = add_bytes(identifier_bytes, actor.len())?;
        }
        identifier_bytes = add_bytes(identifier_bytes, checked.dataset_id.len())?;
        identifier_bytes = add_bytes(identifier_bytes, checked.deployment_id.len())?;
        if let Some(installation) = &checked.installation_id {
            identifier_bytes = add_bytes(identifier_bytes, installation.len())?;
        }
        if identifier_bytes > bounds.max_total_id_bytes {
            return Err(PostRestoreFault::LengthOutOfBounds);
        }
        validated.push(checked);
    }

    let receipts = inventory.receipts();
    for id in receipts
        .committed()
        .iter()
        .chain(receipts.unknown())
        .chain(receipts.tool())
    {
        if id.len() > usize::from(bounds.max_id_bytes) {
            return Err(PostRestoreFault::IdentityInvalid);
        }
        identifier_bytes = add_bytes(identifier_bytes, id.len())?;
        if identifier_bytes > bounds.max_total_id_bytes {
            return Err(PostRestoreFault::LengthOutOfBounds);
        }
    }

    let key_refs = collect_key_refs(inventory.key_binding());
    let total_items = request
        .objects
        .len()
        .checked_add(receipts.committed().len())
        .and_then(|n| n.checked_add(receipts.unknown().len()))
        .and_then(|n| n.checked_add(receipts.tool().len()))
        .and_then(|n| n.checked_add(key_refs.len()))
        .and_then(|n| n.checked_add(CATEGORY_ORDER.len()))
        .ok_or(PostRestoreFault::AccumulatedOverflow)?;
    if total_items > MAX_PLAN_ITEMS {
        return Err(PostRestoreFault::CountOutOfBounds);
    }
    for key in &key_refs {
        if key.key_id.len() > usize::from(bounds.max_id_bytes) {
            return Err(PostRestoreFault::IdentityInvalid);
        }
        identifier_bytes = add_bytes(identifier_bytes, key.key_id.len())?;
        if identifier_bytes > bounds.max_total_id_bytes {
            return Err(PostRestoreFault::LengthOutOfBounds);
        }
    }

    let output_bytes = estimate_output_bytes(
        request.structural.identity(),
        original_installation,
        &validated,
        receipts,
        &key_refs,
    )?;
    let output_bytes = add_bytes(
        add_bytes(output_bytes, inventory.bundle().bundle_id.len())?,
        inventory.barrier().as_str().len(),
    )?;
    if output_bytes > bounds.max_output_bytes {
        return Err(PostRestoreFault::LengthOutOfBounds);
    }

    let category_rules = CATEGORY_ORDER
        .into_iter()
        .map(|kind| CategoryRule {
            kind,
            default_disposition: kind.default_disposition(),
            empty_inventory_still_requires_invalidation: true,
        })
        .collect();

    let object_dispositions = validated
        .into_iter()
        .map(|item| ObjectDisposition {
            disposition: item.kind.default_disposition(),
            kind: item.kind,
            id: item.id.to_owned(),
            actor_id: item.actor_id.map(str::to_owned),
            dataset_id: item.dataset_id.to_owned(),
            deployment_id: item.deployment_id.to_owned(),
            installation_id: item.installation_id.map(str::to_owned),
            snapshot_claimed_active: item.snapshot_claimed_active,
            grants_use_from_snapshot: false,
            restores_active_lease: false,
            rebuilds_dispatch: false,
            resurrects_vendor_revocation: false,
        })
        .collect();

    let source_manifest = inventory
        .materials()
        .iter()
        .find(|item| item.kind() == super::MaterialKind::BundleManifest)
        .ok_or(PostRestoreFault::BindingMismatch)?
        .digest();
    Ok(PostRestorePlan {
        source_bundle: inventory.bundle().clone(),
        source_barrier: inventory.barrier().clone(),
        source_manifest,
        identity: request.structural.identity().clone(),
        pending: request.structural.pending_proofs(),
        follow_up: request.structural.follow_up(),
        original_installation: original_installation.clone(),
        global: GlobalObligations {
            epoch: RecoveryEpochObligation {
                required: true,
                issued: false,
                derivation: RecoveryEpochDerivation::FreshRandomRequired,
            },
            invalidate_old_auth_and_control: true,
            invalidate_performed: false,
            reconfirm_credentials: true,
            keep_receipts: true,
            must_not_replay_unknown: true,
            caller_inventory_is_complete_snapshot: false,
            listed_dispositions_already_revoked: false,
        },
        category_rules,
        object_dispositions,
        receipt_retentions: retain_receipts(receipts),
        historical_decrypt_refs: retain_keys(&key_refs),
        input_object_count: count,
        identifier_bytes,
        output_bytes,
    })
}

struct CheckedObject<'a> {
    id: &'a str,
    kind: AuthMaterialKind,
    actor_id: Option<&'a str>,
    dataset_id: &'a str,
    deployment_id: &'a str,
    installation_id: Option<&'a str>,
    snapshot_claimed_active: bool,
}

fn check_object<'a>(
    claim: &'a AuthObjectClaim,
    inventory: &InventoryChecked,
    original_installation: &InstallationIdentity,
    bounds: &PostRestoreBounds,
) -> Result<CheckedObject<'a>, PostRestoreFault> {
    check_identifier(claim.id.as_str(), bounds)?;
    check_identifier(claim.kind.as_str(), bounds)?;
    check_identifier(claim.dataset_id.as_str(), bounds)?;
    check_identifier(claim.deployment_id.as_str(), bounds)?;
    if let Some(actor) = claim.actor_id.as_deref() {
        check_identifier(actor, bounds)?;
    }
    if let Some(installation) = claim.installation_id.as_deref() {
        check_identifier(installation, bounds)?;
    }

    if is_wide_target(&claim.id) {
        return Err(PostRestoreFault::BindingMismatch);
    }
    let kind = parse_kind(claim.kind.as_str())?;
    if kind.requires_actor() && claim.actor_id.is_none() {
        return Err(PostRestoreFault::BindingMismatch);
    }
    if kind.requires_installation() && claim.installation_id.is_none() {
        return Err(PostRestoreFault::BindingMismatch);
    }
    if let Some(actor) = claim.actor_id.as_deref()
        && is_wide_target(actor)
    {
        return Err(PostRestoreFault::BindingMismatch);
    }
    if claim.dataset_id != inventory.dataset().as_str() || is_wide_target(claim.dataset_id.as_str())
    {
        return Err(PostRestoreFault::BindingMismatch);
    }
    if claim.deployment_id != inventory.deployment().as_str()
        || is_wide_target(claim.deployment_id.as_str())
    {
        return Err(PostRestoreFault::BindingMismatch);
    }
    if let Some(installation) = claim.installation_id.as_deref()
        && (installation != original_installation.as_str() || is_wide_target(installation))
    {
        return Err(PostRestoreFault::BindingMismatch);
    }

    Ok(CheckedObject {
        id: claim.id.as_str(),
        kind,
        actor_id: claim.actor_id.as_deref(),
        dataset_id: claim.dataset_id.as_str(),
        deployment_id: claim.deployment_id.as_str(),
        installation_id: claim.installation_id.as_deref(),
        snapshot_claimed_active: claim.snapshot_claimed_active,
    })
}

fn check_identifier(value: &str, bounds: &PostRestoreBounds) -> Result<(), PostRestoreFault> {
    if value.is_empty() || value.len() > usize::from(bounds.max_id_bytes) {
        return Err(PostRestoreFault::IdentityInvalid);
    }
    if value
        .bytes()
        .any(|b| b == 0 || b == b'/' || b == b'\\' || b == b':')
    {
        return Err(PostRestoreFault::IdentityInvalid);
    }
    reject_secret_token(value)?;
    if value.bytes().any(|b| b.is_ascii_whitespace())
        || value.contains(". ")
        || value.contains("? ")
        || value.contains("! ")
    {
        return Err(PostRestoreFault::ProseRejected);
    }
    Ok(())
}

fn parse_kind(value: &str) -> Result<AuthMaterialKind, PostRestoreFault> {
    match value {
        "auth_session" => Ok(AuthMaterialKind::AuthSession),
        "approval" => Ok(AuthMaterialKind::Approval),
        "lease" => Ok(AuthMaterialKind::Lease),
        "ticket" => Ok(AuthMaterialKind::Ticket),
        "capability" => Ok(AuthMaterialKind::Capability),
        "oauth_state" => Ok(AuthMaterialKind::OauthState),
        "run_assertion" => Ok(AuthMaterialKind::RunAssertion),
        "remote_device_registration" => Ok(AuthMaterialKind::RemoteDeviceRegistration),
        "connection_credential" => Ok(AuthMaterialKind::ConnectionCredential),
        _ => Err(PostRestoreFault::UnknownCategory),
    }
}

fn is_wide_target(value: &str) -> bool {
    matches!(value, "*" | "all" | "any" | "global")
}

fn reject_secret_token(value: &str) -> Result<(), PostRestoreFault> {
    let folded = fold_ascii(value);
    if folded.contains("password")
        || folded.contains("secret")
        || folded.contains("cookie")
        || folded.contains("token")
        || folded.contains("private-key")
        || folded.contains("private_key")
        || folded.contains("master-key")
        || folded.contains("master_key")
        || folded.contains("recovery-key")
        || folded.contains("recovery_key")
        || folded.contains("scram-hash")
    {
        return Err(PostRestoreFault::SecretMaterialForbidden);
    }
    Ok(())
}

fn fold_ascii(value: &str) -> String {
    value
        .bytes()
        .map(|b| char::from(b.to_ascii_lowercase()))
        .collect()
}

fn add_bytes(total: u64, len: usize) -> Result<u64, PostRestoreFault> {
    let extra = u64::try_from(len).map_err(|_| PostRestoreFault::AccumulatedOverflow)?;
    total
        .checked_add(extra)
        .ok_or(PostRestoreFault::AccumulatedOverflow)
}

fn collect_key_refs(binding: &KeyBindingClaim) -> Vec<&VaultKeyRefClaim> {
    match binding {
        KeyBindingClaim::RecoveryWrapped { wrapping_refs } => {
            wrapping_refs.iter().map(|item| &item.key).collect()
        }
        KeyBindingClaim::SameInstallationOsStoreOnly { key_refs } => key_refs.iter().collect(),
    }
}

fn retain_receipts(receipts: &CheckedReceipts) -> Vec<ReceiptRetention> {
    let mut out = Vec::with_capacity(
        receipts.committed().len() + receipts.unknown().len() + receipts.tool().len(),
    );
    for id in receipts.committed() {
        out.push(receipt_item(id, ReceiptClass::Committed, false));
    }
    for id in receipts.unknown() {
        out.push(receipt_item(id, ReceiptClass::Unknown, true));
    }
    for id in receipts.tool() {
        out.push(receipt_item(id, ReceiptClass::Tool, false));
    }
    out
}

fn receipt_item(id: &str, class: ReceiptClass, reconcile: bool) -> ReceiptRetention {
    ReceiptRetention {
        id: id.to_owned(),
        class,
        original_class_preserved: true,
        dispatch_scheduled: false,
        unknown_promoted: false,
        unknown_retryable: false,
        unconfirmed_reconciliation: reconcile,
    }
}

fn retain_keys(keys: &[&VaultKeyRefClaim]) -> Vec<HistoricalDecryptRef> {
    keys.iter()
        .map(|key| HistoricalDecryptRef {
            key_id: key.key_id.clone(),
            key_version: key.key_version,
            canary: key.canary,
            retain_decrypt_capability: true,
            removed_by_auth_invalidation: false,
        })
        .collect()
}

fn estimate_output_bytes(
    identity: &IdentityBinding,
    original_installation: &InstallationIdentity,
    objects: &[CheckedObject<'_>],
    receipts: &CheckedReceipts,
    keys: &[&VaultKeyRefClaim],
) -> Result<u64, PostRestoreFault> {
    let mut total = std::mem::size_of::<PostRestorePlan>() as u64;
    total = add_bytes(
        total,
        objects
            .len()
            .checked_mul(std::mem::size_of::<ObjectDisposition>())
            .ok_or(PostRestoreFault::AccumulatedOverflow)?,
    )?;
    let receipt_count = receipts
        .committed()
        .len()
        .checked_add(receipts.unknown().len())
        .and_then(|n| n.checked_add(receipts.tool().len()))
        .ok_or(PostRestoreFault::AccumulatedOverflow)?;
    total = add_bytes(
        total,
        receipt_count
            .checked_mul(std::mem::size_of::<ReceiptRetention>())
            .ok_or(PostRestoreFault::AccumulatedOverflow)?,
    )?;
    total = add_bytes(
        total,
        keys.len()
            .checked_mul(std::mem::size_of::<HistoricalDecryptRef>())
            .ok_or(PostRestoreFault::AccumulatedOverflow)?,
    )?;
    total = add_bytes(
        total,
        CATEGORY_ORDER.len() * std::mem::size_of::<CategoryRule>(),
    )?;
    match identity {
        IdentityBinding::SameInstallation {
            installation,
            dataset,
            deployment,
            tenant,
        } => {
            total = add_bytes(total, installation.as_str().len())?;
            total = add_bytes(total, dataset.as_str().len())?;
            total = add_bytes(total, deployment.as_str().len())?;
            total = add_bytes(total, tenant.as_str().len())?;
        }
        IdentityBinding::NewInstallation {
            original_installation: original,
            new_installation,
            dataset,
            deployment,
            tenant,
            ..
        } => {
            total = add_bytes(total, original.as_str().len())?;
            total = add_bytes(total, new_installation.as_str().len())?;
            total = add_bytes(total, dataset.as_str().len())?;
            total = add_bytes(total, deployment.as_str().len())?;
            total = add_bytes(total, tenant.as_str().len())?;
        }
    }
    total = add_bytes(total, original_installation.as_str().len())?;
    for kind in CATEGORY_ORDER {
        total = add_bytes(total, kind.as_str().len())?;
        total = add_bytes(total, kind.default_disposition().as_str().len())?;
    }
    for item in objects {
        total = add_bytes(total, item.id.len())?;
        total = add_bytes(total, item.kind.as_str().len())?;
        if let Some(actor) = &item.actor_id {
            total = add_bytes(total, actor.len())?;
        }
        total = add_bytes(total, item.dataset_id.len())?;
        total = add_bytes(total, item.deployment_id.len())?;
        if let Some(installation) = &item.installation_id {
            total = add_bytes(total, installation.len())?;
        }
        total = add_bytes(total, item.kind.default_disposition().as_str().len())?;
    }
    for id in receipts
        .committed()
        .iter()
        .chain(receipts.unknown())
        .chain(receipts.tool())
    {
        total = add_bytes(total, id.len())?;
    }
    for key in keys {
        total = add_bytes(total, key.key_id.len())?;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::{
        AuthMaterialKind, MAX_ID_BYTES, MAX_OBJECTS, MAX_OUTPUT_BYTES, MAX_TOTAL_ID_BYTES,
        ObjectDispositionKind, PostRestoreBounds, PostRestoreFault,
    };

    #[test]
    fn standard_bounds_match_named_caps() {
        let bounds = PostRestoreBounds::standard();
        assert_eq!(bounds.max_objects(), MAX_OBJECTS);
        assert_eq!(bounds.max_id_bytes(), MAX_ID_BYTES);
        assert_eq!(bounds.max_total_id_bytes(), MAX_TOTAL_ID_BYTES);
        assert_eq!(bounds.max_output_bytes(), MAX_OUTPUT_BYTES);
    }

    #[test]
    fn zero_bound_is_invalid() {
        assert_eq!(
            PostRestoreBounds::try_new(0, 8, 8, 8),
            Err(PostRestoreFault::BoundsInvalid)
        );
        assert_eq!(
            PostRestoreBounds::try_new(1, 0, 8, 8),
            Err(PostRestoreFault::BoundsInvalid)
        );
    }

    #[test]
    fn category_names_are_handwritten_snake_case() {
        let expected = [
            ("auth_session", ObjectDispositionKind::RetireShortLived),
            ("approval", ObjectDispositionKind::RetireShortLived),
            ("lease", ObjectDispositionKind::RetireShortLived),
            ("ticket", ObjectDispositionKind::RetireShortLived),
            ("capability", ObjectDispositionKind::RetireShortLived),
            ("oauth_state", ObjectDispositionKind::RetireShortLived),
            ("run_assertion", ObjectDispositionKind::RetireShortLived),
            (
                "remote_device_registration",
                ObjectDispositionKind::RequireReregistration,
            ),
            (
                "connection_credential",
                ObjectDispositionKind::RequireReconfirm,
            ),
        ];
        let kinds = [
            AuthMaterialKind::AuthSession,
            AuthMaterialKind::Approval,
            AuthMaterialKind::Lease,
            AuthMaterialKind::Ticket,
            AuthMaterialKind::Capability,
            AuthMaterialKind::OauthState,
            AuthMaterialKind::RunAssertion,
            AuthMaterialKind::RemoteDeviceRegistration,
            AuthMaterialKind::ConnectionCredential,
        ];
        for ((name, disposition), kind) in expected.into_iter().zip(kinds) {
            assert_eq!(kind.as_str(), name);
            assert_eq!(kind.default_disposition(), disposition);
        }
    }

    #[test]
    fn fault_codes_are_stable() {
        assert_eq!(
            PostRestoreFault::DuplicateTarget.as_str(),
            "backup_post_restore_duplicate_target"
        );
        assert_eq!(
            PostRestoreFault::ProseRejected.as_str(),
            "backup_post_restore_prose_rejected"
        );
    }
}
