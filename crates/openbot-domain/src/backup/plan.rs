//! 同机 / 新安装恢复计划。正式入口是 [`plan_restore`]。
//!
//! 计划保留 committed / Unknown / 工具回执，列出后续 owner 必须处理的身份绑定、
//! 新随机 recovery epoch、旧授权失效和凭据重新确认。本模块不签发 epoch、不写库、
//! 不生成密钥、不恢复 dispatch、不重放工具。

use crate::audit::hash::Sha256Digest;

use super::inventory::{
    BackupInventoryClaim, BarrierIdentity, BundleIdentity, CheckedMaterial, CompatibilitySet,
    DatasetIdentity, EmptyReason, InstallationIdentity, InventoryBounds, InventoryChecked,
    InventoryFault, KeyBindingClaim, MaterialKind, VaultKeyRefClaim, check_inventory,
    validate_identity,
};
use openbot_contracts::ids::{DeploymentId, TenantId};

/// 恢复模式。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestoreMode {
    /// 同机恢复：安装身份保持。
    SameInstallation,
    /// 新安装恢复：保留业务身份，创建新的安装绑定。
    NewInstallation {
        /// 调用方提供的新安装身份。本模块不生成随机 ID。
        new_installation: InstallationIdentity,
    },
}

/// 受控目标条件。不信任备份自己删除必需类或改写业务身份。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlledRestoreTarget {
    /// 恢复模式。
    pub mode: RestoreMode,
    /// 期望保留的 dataset。
    pub dataset: DatasetIdentity,
    /// 期望保留的 deployment。
    pub deployment: DeploymentId,
    /// 期望保留的 tenant。
    pub tenant: TenantId,
    /// 原安装。
    pub original_installation: InstallationIdentity,
    /// 期望 schema checksum。
    pub schema_checksum: Sha256Digest,
    /// 期望 migration checksum（有界，按名字排序后逐项核同）。
    pub migration_checksums: Vec<(String, Sha256Digest)>,
    /// 期望兼容三元组。
    pub compatibility: CompatibilitySet,
    /// 新格式是否必须有可运行恢复构建。
    pub requires_restore_build: bool,
    /// 期望的 vault key 引用（ID/版本/canary）。
    pub vault_keys: Vec<VaultKeyRefClaim>,
    /// dataset 是否无 profile。
    pub profiles_empty: bool,
    /// dataset 是否无 workspace。
    pub workspaces_empty: bool,
    /// 必须出现的 Unknown 回执数。
    pub unknown_receipts: u32,
    /// 容量策略：保留原现场 + 受控余量。新暂存按清单声明合计。
    pub capacity: CapacityPolicy,
}

/// 容量策略。不能只比较压缩包长度。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapacityPolicy {
    /// 保留原现场所需字节。
    pub original_site_bytes: u64,
    /// 受控余量。
    pub margin_bytes: u64,
}

/// 实际观察。缺项时不得猜测“应该兼容”。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreObservations {
    /// 观察到的 schema checksum。
    pub schema_checksum: Option<Sha256Digest>,
    /// 观察到的 migration checksum。
    pub migration_checksums: Option<Vec<(String, Sha256Digest)>>,
    /// 观察到的兼容三元组。
    pub compatibility: Option<CompatibilitySet>,
    /// 是否存在可运行恢复构建。
    pub restore_build_present: Option<bool>,
    /// 可用容量。
    pub capacity: CapacityObservation,
}

/// 容量观察。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityObservation {
    /// 未提供容量事实。
    Missing,
    /// 可用字节。
    Available {
        /// 实际可用。
        bytes: u64,
    },
}

/// [`plan_restore`] 的输入。避免无界参数列表。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestoreRequest<'a> {
    /// 未核清单。
    pub claim: &'a BackupInventoryClaim,
    /// 受控目标。
    pub target: &'a ControlledRestoreTarget,
    /// 实际观察。
    pub observations: &'a RestoreObservations,
    /// 有界配置。
    pub bounds: &'a InventoryBounds,
}

/// 证明状态。本批结构核验不会把待验项写成已证明。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofStatus {
    /// 尚未由后续 owner 证明。
    Pending,
    /// 本批明确未授予。
    NotGranted,
}

/// 结构核验之后仍待后续 owner 完成的证明。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingProofs {
    aead_authenticity: ProofStatus,
    postgres_wal_recovery: ProofStatus,
    key_canary_decrypt: ProofStatus,
    atomic_switch: ProofStatus,
    application_ready: ProofStatus,
    restore_authorized: ProofStatus,
}

impl PendingProofs {
    const fn pending() -> Self {
        Self {
            aead_authenticity: ProofStatus::Pending,
            postgres_wal_recovery: ProofStatus::Pending,
            key_canary_decrypt: ProofStatus::Pending,
            atomic_switch: ProofStatus::Pending,
            application_ready: ProofStatus::NotGranted,
            restore_authorized: ProofStatus::NotGranted,
        }
    }

    /// AEAD / 来源真实性。
    #[must_use]
    pub const fn aead_authenticity(self) -> ProofStatus {
        self.aead_authenticity
    }

    /// PostgreSQL / WAL 可恢复性。
    #[must_use]
    pub const fn postgres_wal_recovery(self) -> ProofStatus {
        self.postgres_wal_recovery
    }

    /// key canary 解密。
    #[must_use]
    pub const fn key_canary_decrypt(self) -> ProofStatus {
        self.key_canary_decrypt
    }

    /// 原子切换。
    #[must_use]
    pub const fn atomic_switch(self) -> ProofStatus {
        self.atomic_switch
    }

    /// Application Ready。恒为未授予。
    #[must_use]
    pub const fn application_ready(self) -> ProofStatus {
        self.application_ready
    }

    /// RestoreAuthorized。恒为未授予。
    #[must_use]
    pub const fn restore_authorized(self) -> ProofStatus {
        self.restore_authorized
    }
}

/// 后续 owner 必须处理、本模块不会执行的动作。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FollowUpRequirements {
    bind_installation_to_dataset: bool,
    mint_new_recovery_epoch: bool,
    invalidate_old_auth_and_control: bool,
    reconfirm_credentials: bool,
    keep_committed_unknown_and_tool_receipts: bool,
    must_not_replay_unknown: bool,
}

impl FollowUpRequirements {
    const fn required(bind_installation_to_dataset: bool) -> Self {
        Self {
            bind_installation_to_dataset,
            mint_new_recovery_epoch: true,
            invalidate_old_auth_and_control: true,
            reconfirm_credentials: true,
            keep_committed_unknown_and_tool_receipts: true,
            must_not_replay_unknown: true,
        }
    }

    /// 是否需要把新安装绑定到保留的 dataset。
    #[must_use]
    pub const fn bind_installation_to_dataset(self) -> bool {
        self.bind_installation_to_dataset
    }

    /// 是否要求后续铸造新的随机 recovery epoch（本模块不铸造）。
    #[must_use]
    pub const fn mint_new_recovery_epoch(self) -> bool {
        self.mint_new_recovery_epoch
    }

    /// 旧授权/控制态必须失效。
    #[must_use]
    pub const fn invalidate_old_auth_and_control(self) -> bool {
        self.invalidate_old_auth_and_control
    }

    /// 凭据必须重新确认后才能使用。
    #[must_use]
    pub const fn reconfirm_credentials(self) -> bool {
        self.reconfirm_credentials
    }

    /// 必须保留 committed / Unknown / 工具回执。
    #[must_use]
    pub const fn keep_committed_unknown_and_tool_receipts(self) -> bool {
        self.keep_committed_unknown_and_tool_receipts
    }

    /// Unknown 不得安排重放。
    #[must_use]
    pub const fn must_not_replay_unknown(self) -> bool {
        self.must_not_replay_unknown
    }
}

/// 身份绑定动作。新安装保留业务 ID，不套 Fresh 派生。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityBinding {
    /// 同机：安装与业务身份均保持。
    SameInstallation {
        /// 安装。
        installation: InstallationIdentity,
        /// dataset。
        dataset: DatasetIdentity,
        /// deployment。
        deployment: DeploymentId,
        /// tenant。
        tenant: TenantId,
    },
    /// 新安装：业务身份保持，安装另造。
    NewInstallation {
        /// 原安装。
        original_installation: InstallationIdentity,
        /// 新安装。
        new_installation: InstallationIdentity,
        /// 保留的 dataset。
        dataset: DatasetIdentity,
        /// 保留的 deployment。
        deployment: DeploymentId,
        /// 保留的 tenant。
        tenant: TenantId,
        /// 原 record ID 必须保留。
        record_ids_preserved: bool,
    },
}

impl IdentityBinding {
    /// 是否保留业务 dataset/deployment/tenant。
    #[must_use]
    pub fn preserves_business_identity(&self) -> bool {
        true
    }

    /// 是否套用 Fresh 的身份派生改名旧数据。恒为否。
    #[must_use]
    pub const fn applies_fresh_identity_derivation(&self) -> bool {
        false
    }
}

/// 不完整：缺必要材料或观察事实，不猜测兼容。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncompleteRestore {
    reason: IncompleteReason,
    inventory: Option<InventoryChecked>,
    pending: PendingProofs,
}

impl IncompleteRestore {
    /// 不完整原因。
    #[must_use]
    pub fn reason(&self) -> IncompleteReason {
        self.reason
    }

    /// 若结构已核过，提供已核清单。
    #[must_use]
    pub fn inventory(&self) -> Option<&InventoryChecked> {
        self.inventory.as_ref()
    }

    /// 待验证明。
    #[must_use]
    pub fn pending_proofs(&self) -> PendingProofs {
        self.pending
    }

    /// 不是 Ready。
    #[must_use]
    pub const fn ready(&self) -> bool {
        false
    }
}

/// 不完整原因。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncompleteReason {
    /// 缺一类必需材料。
    MissingRequired(MaterialKind),
    /// 空类没有受控条件解释。
    EmptyWithoutReason(MaterialKind),
    /// 缺 key 包装引用。
    MissingKeyWrappingRef,
    /// 缺 WAL。
    MissingWal,
    /// 缺 migration checksum。
    MissingMigrationChecksum,
    /// 缺兼容恢复构建事实。
    MissingRestoreBuild,
    /// 缺容量事实。
    MissingCapacityFacts,
    /// 观察缺 schema/兼容事实。
    MissingCompatibilityFacts,
    /// Unknown 回执被遗漏。
    MissingUnknownReceipts,
}

/// 阻塞：策略不允许继续，且尚未修改原数据。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockedRestore {
    reason: BlockedReason,
    inventory: InventoryChecked,
    pending: PendingProofs,
}

impl BlockedRestore {
    /// 阻塞原因。
    #[must_use]
    pub fn reason(&self) -> BlockedReason {
        self.reason
    }

    /// 已核清单。
    #[must_use]
    pub fn inventory(&self) -> &InventoryChecked {
        &self.inventory
    }

    /// 待验证明。
    #[must_use]
    pub fn pending_proofs(&self) -> PendingProofs {
        self.pending
    }

    /// 不是 RestoreAuthorized。
    #[must_use]
    pub const fn restore_authorized(&self) -> bool {
        false
    }
}

/// 阻塞原因。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockedReason {
    /// same-installation-only 却请求换机。
    SameInstallationOnly,
    /// 试图改名业务身份。
    WouldRenameBusinessIdentity,
    /// 新安装未提供不同的安装身份。
    NewInstallReusedInstallation,
    /// 目标与观察的发行不兼容。
    IncompatibleRelease,
    /// schema / migration 与观察不一致。
    SchemaMismatch,
    /// key ID 与受控目标不符。
    KeyIdMismatch,
    /// canary 引用与受控目标不符。
    CanaryMismatch,
    /// 可用容量不足以同时覆盖新暂存、原现场和余量。
    InsufficientCapacity,
}

/// 结构/材料核验通过后的恢复计划。不是已鉴真、已解密或可开放 Application。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructuralRestorePlan {
    inventory: InventoryChecked,
    identity: IdentityBinding,
    follow_up: FollowUpRequirements,
    pending: PendingProofs,
    required_capacity_bytes: u64,
}

impl StructuralRestorePlan {
    /// 已核清单。
    #[must_use]
    pub fn inventory(&self) -> &InventoryChecked {
        &self.inventory
    }

    /// 身份绑定。
    #[must_use]
    pub fn identity(&self) -> &IdentityBinding {
        &self.identity
    }

    /// 后续要求。
    #[must_use]
    pub fn follow_up(&self) -> FollowUpRequirements {
        self.follow_up
    }

    /// 待验证明。
    #[must_use]
    pub fn pending_proofs(&self) -> PendingProofs {
        self.pending
    }

    /// 新暂存 + 原现场 + 余量。
    #[must_use]
    pub fn required_capacity_bytes(&self) -> u64 {
        self.required_capacity_bytes
    }

    /// 摘要相符不是 AEAD 证明。
    #[must_use]
    pub const fn digest_match_proves_aead(&self) -> bool {
        false
    }

    /// WAL 文件名齐全不是 PG recovery 证明。
    #[must_use]
    pub const fn wal_names_prove_postgres_recovery(&self) -> bool {
        false
    }

    /// 不授予 RestoreAuthorized。
    #[must_use]
    pub const fn restore_authorized(&self) -> bool {
        false
    }

    /// 不授予 Application Ready。
    #[must_use]
    pub const fn application_ready(&self) -> bool {
        false
    }

    /// 不签发 recovery epoch。
    #[must_use]
    pub const fn issues_recovery_epoch(&self) -> bool {
        false
    }

    /// 不写数据库。
    #[must_use]
    pub const fn writes_database(&self) -> bool {
        false
    }

    /// 不生成密钥。
    #[must_use]
    pub const fn generates_keys(&self) -> bool {
        false
    }

    /// 不恢复 dispatch。
    #[must_use]
    pub const fn restores_dispatch(&self) -> bool {
        false
    }

    /// 不重放 Unknown。
    #[must_use]
    pub fn schedules_unknown_replay(&self) -> bool {
        !self.follow_up.must_not_replay_unknown()
    }

    /// 同机目录复制不是完整恢复。
    #[must_use]
    pub const fn directory_copy_is_complete_restore(&self) -> bool {
        false
    }

    /// bundle / dataset / 屏障身份，供暂存层引用。
    #[must_use]
    pub fn bundle(&self) -> &BundleIdentity {
        self.inventory.bundle()
    }

    /// 屏障。
    #[must_use]
    pub fn barrier(&self) -> &BarrierIdentity {
        self.inventory.barrier()
    }

    /// 材料。
    #[must_use]
    pub fn materials(&self) -> &[CheckedMaterial] {
        self.inventory.materials()
    }
}

/// [`plan_restore`] 的封闭结果。没有 Ready 变体。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// 清单结构非法。
    Rejected(InventoryFault),
    /// 缺必要材料或观察。
    Incomplete(IncompleteRestore),
    /// 策略阻塞，原数据不得修改。
    Blocked(BlockedRestore),
    /// 结构计划。后续证明仍待验。
    StructuralPlan(StructuralRestorePlan),
}

impl RestoreOutcome {
    /// 是否为结构计划。
    #[must_use]
    pub const fn is_structural_plan(&self) -> bool {
        matches!(self, Self::StructuralPlan(_))
    }

    /// 永远不是产品 Ready。
    #[must_use]
    pub const fn product_ready(&self) -> bool {
        false
    }

    /// 永远不是 RestoreAuthorized。
    #[must_use]
    pub const fn restore_authorized(&self) -> bool {
        false
    }
}

/// 正式计划入口。每类正反例必须从此进入，而不是同构 helper。
#[must_use]
pub fn plan_restore(request: RestoreRequest<'_>) -> RestoreOutcome {
    if let Err(fault) = validate_target(request.target, request.bounds) {
        return RestoreOutcome::Rejected(fault);
    }
    let checked = match check_inventory(request.claim, request.bounds) {
        Ok(value) => value,
        Err(fault) => return RestoreOutcome::Rejected(fault),
    };
    if let Some(reason) = missing_required(&checked, request.target) {
        return incomplete(reason, Some(checked));
    }
    if let Some(reason) = identity_block(&checked, request.target) {
        return blocked(reason, checked);
    }
    if let Some(reason) = key_block(&checked, request.target) {
        return blocked(reason, checked);
    }
    if let Some(reason) = compatibility_outcome(&checked, request.target, request.observations) {
        return reason.into_outcome(checked);
    }
    let required_capacity = match required_capacity_bytes(&checked, request.target) {
        Ok(bytes) => bytes,
        Err(()) => {
            return RestoreOutcome::Rejected(InventoryFault::AccumulatedOverflow);
        }
    };
    match request.observations.capacity {
        CapacityObservation::Missing => {
            return incomplete(IncompleteReason::MissingCapacityFacts, Some(checked));
        }
        CapacityObservation::Available { bytes } => {
            if bytes < required_capacity {
                return blocked(BlockedReason::InsufficientCapacity, checked);
            }
        }
    }
    if request.target.unknown_receipts > 0
        && checked.receipts().unknown().len() < request.target.unknown_receipts as usize
    {
        return incomplete(IncompleteReason::MissingUnknownReceipts, Some(checked));
    }

    let (identity, bind_new) = match &request.target.mode {
        RestoreMode::SameInstallation => (
            IdentityBinding::SameInstallation {
                installation: checked.original_installation().clone(),
                dataset: checked.dataset().clone(),
                deployment: checked.deployment().clone(),
                tenant: checked.tenant().clone(),
            },
            false,
        ),
        RestoreMode::NewInstallation { new_installation } => (
            IdentityBinding::NewInstallation {
                original_installation: checked.original_installation().clone(),
                new_installation: new_installation.clone(),
                dataset: checked.dataset().clone(),
                deployment: checked.deployment().clone(),
                tenant: checked.tenant().clone(),
                record_ids_preserved: true,
            },
            true,
        ),
    };

    RestoreOutcome::StructuralPlan(StructuralRestorePlan {
        inventory: checked,
        identity,
        follow_up: FollowUpRequirements::required(bind_new),
        pending: PendingProofs::pending(),
        required_capacity_bytes: required_capacity,
    })
}

enum CompatGate {
    Incomplete(IncompleteReason),
    Blocked(BlockedReason),
}

impl CompatGate {
    fn into_outcome(self, inventory: InventoryChecked) -> RestoreOutcome {
        match self {
            Self::Incomplete(reason) => incomplete(reason, Some(inventory)),
            Self::Blocked(reason) => blocked(reason, inventory),
        }
    }
}

fn incomplete(reason: IncompleteReason, inventory: Option<InventoryChecked>) -> RestoreOutcome {
    RestoreOutcome::Incomplete(IncompleteRestore {
        reason,
        inventory,
        pending: PendingProofs::pending(),
    })
}

fn blocked(reason: BlockedReason, inventory: InventoryChecked) -> RestoreOutcome {
    RestoreOutcome::Blocked(BlockedRestore {
        reason,
        inventory,
        pending: PendingProofs::pending(),
    })
}

fn validate_target(
    target: &ControlledRestoreTarget,
    bounds: &InventoryBounds,
) -> Result<(), InventoryFault> {
    validate_identity(target.dataset.as_str(), bounds)?;
    validate_identity(target.deployment.as_str(), bounds)?;
    validate_identity(target.tenant.as_str(), bounds)?;
    validate_identity(target.original_installation.as_str(), bounds)?;
    if let RestoreMode::NewInstallation { new_installation } = &target.mode {
        validate_identity(new_installation.as_str(), bounds)?;
    }
    if target.migration_checksums.len() > bounds.max_entries() as usize {
        return Err(InventoryFault::CountOutOfBounds);
    }
    if target.vault_keys.len() > bounds.max_entries() as usize {
        return Err(InventoryFault::CountOutOfBounds);
    }
    for (name, _) in &target.migration_checksums {
        validate_identity(name, bounds)?;
    }
    for key in &target.vault_keys {
        validate_identity(key.key_id.as_str(), bounds)?;
    }
    Ok(())
}

fn has_regular_file(inventory: &InventoryChecked, kind: MaterialKind) -> bool {
    inventory
        .materials()
        .iter()
        .any(|item| item.kind() == kind && !item.directory())
}

fn empty_explained(inventory: &InventoryChecked, kind: MaterialKind, reason: EmptyReason) -> bool {
    inventory
        .explained_empty()
        .iter()
        .any(|item| item.kind == kind && item.reason == reason)
}

fn missing_required(
    inventory: &InventoryChecked,
    target: &ControlledRestoreTarget,
) -> Option<IncompleteReason> {
    const REQUIRED: [MaterialKind; 7] = [
        MaterialKind::BundleManifest,
        MaterialKind::PostgresBase,
        MaterialKind::PostgresConfig,
        MaterialKind::SchemaChecksum,
        MaterialKind::MigrationChecksum,
        MaterialKind::CompatibilityRecord,
        MaterialKind::AuditCheckpointObject,
    ];
    for kind in REQUIRED {
        if !has_regular_file(inventory, kind) {
            return Some(IncompleteReason::MissingRequired(kind));
        }
    }
    if !has_regular_file(inventory, MaterialKind::WalSegment) {
        return Some(IncompleteReason::MissingWal);
    }
    match &inventory.key_binding() {
        KeyBindingClaim::RecoveryWrapped { wrapping_refs } if wrapping_refs.is_empty() => {
            return Some(IncompleteReason::MissingKeyWrappingRef);
        }
        KeyBindingClaim::RecoveryWrapped { wrapping_refs } => {
            for wrap in wrapping_refs {
                let Some(found) = inventory
                    .materials()
                    .iter()
                    .find(|item| item.id() == &wrap.wrapping_object_id)
                else {
                    return Some(IncompleteReason::MissingKeyWrappingRef);
                };
                if found.kind() != MaterialKind::KeyWrappingObject || found.directory() {
                    return Some(IncompleteReason::MissingKeyWrappingRef);
                }
            }
        }
        KeyBindingClaim::SameInstallationOsStoreOnly { key_refs } if key_refs.is_empty() => {
            return Some(IncompleteReason::MissingKeyWrappingRef);
        }
        KeyBindingClaim::SameInstallationOsStoreOnly { .. } => {}
    }
    match inventory
        .materials()
        .iter()
        .find(|item| item.id() == &inventory.audit().material_id)
    {
        None => {
            return Some(IncompleteReason::MissingRequired(
                MaterialKind::AuditCheckpointObject,
            ));
        }
        Some(found) if found.kind() != MaterialKind::AuditCheckpointObject || found.directory() => {
            return Some(IncompleteReason::MissingRequired(
                MaterialKind::AuditCheckpointObject,
            ));
        }
        Some(_) => {}
    }

    if has_regular_file(inventory, MaterialKind::ProfileInventory) {
        if target.profiles_empty {
            return Some(IncompleteReason::EmptyWithoutReason(
                MaterialKind::ProfileInventory,
            ));
        }
    } else if target.profiles_empty {
        if !empty_explained(
            inventory,
            MaterialKind::ProfileInventory,
            EmptyReason::DatasetContainsNoProfiles,
        ) {
            return Some(IncompleteReason::EmptyWithoutReason(
                MaterialKind::ProfileInventory,
            ));
        }
    } else {
        return Some(IncompleteReason::MissingRequired(
            MaterialKind::ProfileInventory,
        ));
    }

    if has_regular_file(inventory, MaterialKind::WorkspaceInventory) {
        if target.workspaces_empty {
            return Some(IncompleteReason::EmptyWithoutReason(
                MaterialKind::WorkspaceInventory,
            ));
        }
    } else if target.workspaces_empty {
        if !empty_explained(
            inventory,
            MaterialKind::WorkspaceInventory,
            EmptyReason::DatasetContainsNoWorkspaces,
        ) {
            return Some(IncompleteReason::EmptyWithoutReason(
                MaterialKind::WorkspaceInventory,
            ));
        }
    } else {
        return Some(IncompleteReason::MissingRequired(
            MaterialKind::WorkspaceInventory,
        ));
    }

    if inventory
        .explained_empty()
        .iter()
        .any(|item| !item.kind.empty_may_be_explained())
    {
        let kind = inventory
            .explained_empty()
            .iter()
            .find(|item| !item.kind.empty_may_be_explained())
            .map(|item| item.kind)
            .unwrap_or(MaterialKind::PostgresBase);
        return Some(IncompleteReason::EmptyWithoutReason(kind));
    }
    None
}

fn identity_block(
    inventory: &InventoryChecked,
    target: &ControlledRestoreTarget,
) -> Option<BlockedReason> {
    if inventory.dataset() != &target.dataset
        || inventory.deployment() != &target.deployment
        || inventory.tenant() != &target.tenant
    {
        return Some(BlockedReason::WouldRenameBusinessIdentity);
    }
    if inventory.original_installation() != &target.original_installation {
        return Some(BlockedReason::WouldRenameBusinessIdentity);
    }
    match &target.mode {
        RestoreMode::SameInstallation => None,
        RestoreMode::NewInstallation { new_installation } => {
            if inventory.same_installation_only() {
                return Some(BlockedReason::SameInstallationOnly);
            }
            if new_installation == inventory.original_installation() {
                return Some(BlockedReason::NewInstallReusedInstallation);
            }
            None
        }
    }
}

fn key_block(
    inventory: &InventoryChecked,
    target: &ControlledRestoreTarget,
) -> Option<BlockedReason> {
    let refs: Vec<&VaultKeyRefClaim> = match inventory.key_binding() {
        KeyBindingClaim::RecoveryWrapped { wrapping_refs } => {
            wrapping_refs.iter().map(|item| &item.key).collect()
        }
        KeyBindingClaim::SameInstallationOsStoreOnly { key_refs } => key_refs.iter().collect(),
    };
    if refs.len() != target.vault_keys.len() {
        return Some(BlockedReason::KeyIdMismatch);
    }
    for expected in &target.vault_keys {
        let Some(found) = refs.iter().find(|item| item.key_id == expected.key_id) else {
            return Some(BlockedReason::KeyIdMismatch);
        };
        if found.key_version != expected.key_version {
            return Some(BlockedReason::KeyIdMismatch);
        }
        if found.canary != expected.canary {
            return Some(BlockedReason::CanaryMismatch);
        }
    }
    None
}

fn compatibility_outcome(
    inventory: &InventoryChecked,
    target: &ControlledRestoreTarget,
    observations: &RestoreObservations,
) -> Option<CompatGate> {
    if inventory.compatibility() != &target.compatibility {
        return Some(CompatGate::Blocked(BlockedReason::IncompatibleRelease));
    }
    let Some(observed_schema) = observations.schema_checksum else {
        return Some(CompatGate::Incomplete(
            IncompleteReason::MissingCompatibilityFacts,
        ));
    };
    if observed_schema != target.schema_checksum {
        return Some(CompatGate::Blocked(BlockedReason::SchemaMismatch));
    }
    let Some(observed_migrations) = observations.migration_checksums.as_ref() else {
        return Some(CompatGate::Incomplete(
            IncompleteReason::MissingMigrationChecksum,
        ));
    };
    if observed_migrations != &target.migration_checksums {
        return Some(CompatGate::Blocked(BlockedReason::SchemaMismatch));
    }
    if !has_regular_file(inventory, MaterialKind::MigrationChecksum) {
        return Some(CompatGate::Incomplete(
            IncompleteReason::MissingMigrationChecksum,
        ));
    }
    let Some(observed_compat) = observations.compatibility.as_ref() else {
        return Some(CompatGate::Incomplete(
            IncompleteReason::MissingCompatibilityFacts,
        ));
    };
    if observed_compat != &target.compatibility {
        return Some(CompatGate::Blocked(BlockedReason::IncompatibleRelease));
    }
    if target.requires_restore_build {
        match observations.restore_build_present {
            Some(true) => {}
            Some(false) | None => {
                return Some(CompatGate::Incomplete(
                    IncompleteReason::MissingRestoreBuild,
                ));
            }
        }
    }
    None
}

fn required_capacity_bytes(
    inventory: &InventoryChecked,
    target: &ControlledRestoreTarget,
) -> Result<u64, ()> {
    inventory
        .total_declared_bytes()
        .checked_add(target.capacity.original_site_bytes)
        .and_then(|sum| sum.checked_add(target.capacity.margin_bytes))
        .ok_or(())
}
