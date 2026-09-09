//! 未核备份清单与核验后的材料结果。
//!
//! 未核输入可以自由构造；[`InventoryChecked`] 的字段私有，不能由 Serde 或结构体字面量
//! 从外部拼出来。引用类型不保存 secret / master / recovery key、口令或可验证秘密 hash。

use std::collections::{BTreeMap, BTreeSet};

use openbot_contracts::ids::{DeploymentId, TenantId};

use crate::audit::hash::Sha256Digest;
use crate::vault::binding::KeyVersion;

/// 结构核验的显式有界配置。所有累计运算走 checked，溢出不得当 0。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InventoryBounds {
    max_entries: u32,
    max_path_bytes: u16,
    max_path_depth: u8,
    max_entry_bytes: u64,
    max_total_bytes: u64,
    max_id_bytes: u16,
    max_receipts: u32,
}

impl InventoryBounds {
    /// 本批结构核验默认上限。不是产品备份格式，也不是无界 Vec 的替代说法。
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            max_entries: 4_096,
            max_path_bytes: 255,
            max_path_depth: 8,
            max_entry_bytes: 64 * 1024 * 1024,
            max_total_bytes: 4 * 1024 * 1024 * 1024,
            max_id_bytes: 128,
            max_receipts: 8_192,
        }
    }

    /// 测试或更紧策略下的有界配置。任一上限为 0 则拒绝。
    ///
    /// # Errors
    ///
    /// 上限为 0 时返回 [`InventoryFault::BoundsInvalid`]。
    pub const fn try_new(
        max_entries: u32,
        max_path_bytes: u16,
        max_path_depth: u8,
        max_entry_bytes: u64,
        max_total_bytes: u64,
        max_id_bytes: u16,
        max_receipts: u32,
    ) -> Result<Self, InventoryFault> {
        if max_entries == 0
            || max_path_bytes == 0
            || max_path_depth == 0
            || max_entry_bytes == 0
            || max_total_bytes == 0
            || max_id_bytes == 0
            || max_receipts == 0
        {
            return Err(InventoryFault::BoundsInvalid);
        }
        Ok(Self {
            max_entries,
            max_path_bytes,
            max_path_depth,
            max_entry_bytes,
            max_total_bytes,
            max_id_bytes,
            max_receipts,
        })
    }

    /// 条目数量上限。
    #[must_use]
    pub const fn max_entries(self) -> u32 {
        self.max_entries
    }

    /// 相对路径字节上限。
    #[must_use]
    pub const fn max_path_bytes(self) -> u16 {
        self.max_path_bytes
    }

    /// 路径深度上限。
    #[must_use]
    pub const fn max_path_depth(self) -> u8 {
        self.max_path_depth
    }

    /// 单条声明长度上限。
    #[must_use]
    pub const fn max_entry_bytes(self) -> u64 {
        self.max_entry_bytes
    }

    /// 全包声明长度上限（未压缩材料合计，不是压缩包长度）。
    #[must_use]
    pub const fn max_total_bytes(self) -> u64 {
        self.max_total_bytes
    }

    /// 标识符字节上限。
    #[must_use]
    pub const fn max_id_bytes(self) -> u16 {
        self.max_id_bytes
    }

    /// 回执条数上限。
    #[must_use]
    pub const fn max_receipts(self) -> u32 {
        self.max_receipts
    }
}

/// 结构核验失败。只携带本模块的分类，不回显路径原文或摘要字节。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum InventoryFault {
    /// 有界配置非法。
    #[error("backup_bounds_invalid")]
    BoundsInvalid,
    /// 标识符空或越界。
    #[error("backup_identity_invalid")]
    IdentityInvalid,
    /// 相对路径非法（绝对、上跳、平台逃逸、空段、越界）。
    #[error("backup_path_invalid")]
    PathInvalid,
    /// 禁止的秘密材料名或秘密字段。
    #[error("backup_secret_material_forbidden")]
    SecretMaterialForbidden,
    /// 条目身份重复。
    #[error("backup_duplicate_id")]
    DuplicateId,
    /// 相对路径重复。
    #[error("backup_duplicate_path")]
    DuplicatePath,
    /// 文件与目录前缀冲突，或大小写/别名冲突。
    #[error("backup_prefix_or_alias_conflict")]
    PrefixOrAliasConflict,
    /// 声明长度越界。
    #[error("backup_length_out_of_bounds")]
    LengthOutOfBounds,
    /// 条目计数越界。
    #[error("backup_count_out_of_bounds")]
    CountOutOfBounds,
    /// 累计长度 checked 失败（不得回绕成 0）。
    #[error("backup_accumulated_overflow")]
    AccumulatedOverflow,
    /// 条目引用了错误的 bundle。
    #[error("backup_bundle_mismatch")]
    BundleMismatch,
    /// 条目引用了错误的 dataset。
    #[error("backup_dataset_mismatch")]
    DatasetMismatch,
    /// 条目引用了错误的一致性屏障。
    #[error("backup_barrier_mismatch")]
    BarrierMismatch,
    /// 目录条目声明了非零长度。
    #[error("backup_directory_length")]
    DirectoryLength,
    /// 跨引用的材料类与声明不符（例如包装引用指向 PG 配置）。
    #[error("backup_cross_reference_mismatch")]
    CrossReferenceMismatch,
    /// 材料形态非法（例如密文包装对象被声明为目录）。
    #[error("backup_material_shape_invalid")]
    MaterialShapeInvalid,
    /// 回执集合与 `unknown` 标志不一致。
    #[error("backup_receipt_category_mismatch")]
    ReceiptCategoryMismatch,
    /// 空类声明与实际材料或受控条件不相容，或重复越界。
    #[error("backup_empty_category_inconsistent")]
    EmptyCategoryInconsistent,
}

/// 备份材料类别。清单不得靠 `optional=true` 自行删类。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MaterialKind {
    /// bundle 清单本身。
    BundleManifest,
    /// PostgreSQL base 快照。
    PostgresBase,
    /// WAL 段。
    WalSegment,
    /// PostgreSQL 配置。
    PostgresConfig,
    /// schema checksum 对象。
    SchemaChecksum,
    /// 单条 migration checksum 对象。
    MigrationChecksum,
    /// 仍保持密文的 key 包装对象。
    KeyWrappingObject,
    /// profile 清单。
    ProfileInventory,
    /// workspace 清单。
    WorkspaceInventory,
    /// 应用/PG/Engine/UI 兼容记录。
    CompatibilityRecord,
    /// audit checkpoint 对象。
    AuditCheckpointObject,
}

impl MaterialKind {
    /// 稳定分类名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BundleManifest => "bundle_manifest",
            Self::PostgresBase => "postgres_base",
            Self::WalSegment => "wal_segment",
            Self::PostgresConfig => "postgres_config",
            Self::SchemaChecksum => "schema_checksum",
            Self::MigrationChecksum => "migration_checksum",
            Self::KeyWrappingObject => "key_wrapping_object",
            Self::ProfileInventory => "profile_inventory",
            Self::WorkspaceInventory => "workspace_inventory",
            Self::CompatibilityRecord => "compatibility_record",
            Self::AuditCheckpointObject => "audit_checkpoint",
        }
    }

    /// 该类是否允许在受控条件下为空。
    #[must_use]
    pub const fn empty_may_be_explained(self) -> bool {
        matches!(self, Self::ProfileInventory | Self::WorkspaceInventory)
    }
}

impl core::fmt::Display for MaterialKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 受控空类理由。不能用任意 optional 跳过。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EmptyReason {
    /// 目标条件声明该 dataset 没有 profile。
    DatasetContainsNoProfiles,
    /// 目标条件声明该 dataset 没有 workspace。
    DatasetContainsNoWorkspaces,
}

/// 一条被声明为空的材料类。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmptyCategoryClaim {
    /// 被声明为空的类。
    pub kind: MaterialKind,
    /// 受控理由。
    pub reason: EmptyReason,
}

/// 版本化 bundle 身份。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BundleIdentity {
    /// bundle 标识。
    pub bundle_id: String,
    /// 清单格式版本（本批不冻结对外格式，只作结构字段）。
    pub format_version: u32,
}

/// 业务 dataset 身份。恢复时必须保留，不得按 Fresh 规则改名。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DatasetIdentity {
    /// dataset 标识。
    pub dataset_id: String,
}

impl DatasetIdentity {
    /// 由字符串构造未核身份。
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            dataset_id: value.into(),
        }
    }

    /// 借出标识。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.dataset_id
    }
}

/// 原安装或新安装身份。新安装恢复时另造，不覆盖业务 dataset。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InstallationIdentity {
    /// 安装标识。
    pub installation_id: String,
}

impl InstallationIdentity {
    /// 由字符串构造未核身份。
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            installation_id: value.into(),
        }
    }

    /// 借出标识。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.installation_id
    }
}

/// 一致性屏障身份。PG 与 profile/workspace 必须引用同一屏障。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BarrierIdentity {
    /// 屏障标识。
    pub barrier_id: String,
}

impl BarrierIdentity {
    /// 由字符串构造未核身份。
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            barrier_id: value.into(),
        }
    }

    /// 借出标识。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.barrier_id
    }
}

/// 材料条目身份。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MaterialId(String);

impl MaterialId {
    /// 由字符串构造未核身份。
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// 借出标识。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 核验后的相对路径。只能由本模块构造。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelativePath(String);

impl RelativePath {
    /// 借出相对路径。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 一条未核材料声明。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterialClaim {
    /// 条目身份。
    pub id: MaterialId,
    /// 材料类。
    pub kind: MaterialKind,
    /// 声称的相对路径。
    pub relative_path: String,
    /// 是否为目录。
    pub directory: bool,
    /// 声明字节数。
    pub declared_bytes: u64,
    /// 声明内容摘要。相符仍不是 AEAD 证明。
    pub digest: Sha256Digest,
    /// 声称所属 bundle。
    pub bundle_id: String,
    /// 声称所属 dataset。
    pub dataset_id: String,
    /// 声称所属一致性屏障。
    pub barrier_id: String,
}

/// Vault key 的非秘密引用：ID / 版本 / canary 身份。不含密钥材料。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultKeyRefClaim {
    /// key ID。
    pub key_id: String,
    /// key 版本。
    pub key_version: KeyVersion,
    /// canary 记录身份（不是密钥 hash）。
    pub canary: Sha256Digest,
}

/// 恢复包装对象引用。对象本身仍是密文材料。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappingRefClaim {
    /// 被包装的 key 引用。
    pub key: VaultKeyRefClaim,
    /// 对应的密文包装材料 id。
    pub wrapping_object_id: MaterialId,
}

/// 密钥恢复绑定方式。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyBindingClaim {
    /// 具备独立 recovery 包装，可评估新安装计划。
    RecoveryWrapped {
        /// 包装引用集合。
        wrapping_refs: Vec<WrappingRefClaim>,
    },
    /// 仅依赖原 OS key store，只能同机恢复。
    SameInstallationOsStoreOnly {
        /// 原机 key 引用。
        key_refs: Vec<VaultKeyRefClaim>,
    },
}

/// SCRAM 恢复关系（非口令、非 secret hash）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScramRelationClaim {
    /// 关系标识。
    pub relation_id: String,
    /// 是否绑定原 OS store。
    pub bound_to_original_os_store: bool,
}

/// audit checkpoint 引用。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditCheckpointClaim {
    /// checkpoint 材料 id。
    pub material_id: MaterialId,
    /// 链头摘要引用。
    pub head_digest: Sha256Digest,
    /// 事件条数。
    pub event_count: u64,
}

/// 发行组件兼容三元组。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentRev {
    /// 组件名（application / postgres / engine / ui）。
    pub name: String,
    /// 发行 epoch。
    pub epoch: u32,
    /// 已验构建摘要。
    pub digest: Sha256Digest,
}

/// 应用 / PG / Engine / UI 兼容信息。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompatibilitySet {
    /// 应用。
    pub application: ComponentRev,
    /// PostgreSQL sidecar。
    pub postgres: ComponentRev,
    /// Engine。
    pub engine: ComponentRev,
    /// UI bundle。
    pub ui: ComponentRev,
}

/// 一条已提交或 Unknown 回执声明。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptClaim {
    /// 回执身份。
    pub id: String,
    /// 是否为 Unknown（否则视为已提交/工具回执按其集合划分）。
    pub unknown: bool,
}

/// 备份保留的 committed / Unknown / 工具回执。
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ReceiptSetClaim {
    /// 已提交。
    pub committed: Vec<ReceiptClaim>,
    /// Unknown，必须保留且不得安排重放。
    pub unknown: Vec<ReceiptClaim>,
    /// 工具回执。
    pub tool: Vec<ReceiptClaim>,
}

/// 一份未核备份材料清单。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupInventoryClaim {
    /// bundle。
    pub bundle: BundleIdentity,
    /// 业务 dataset。
    pub dataset: DatasetIdentity,
    /// deployment。
    pub deployment: DeploymentId,
    /// tenant。
    pub tenant: TenantId,
    /// 原安装。
    pub original_installation: InstallationIdentity,
    /// 一致性屏障。
    pub barrier: BarrierIdentity,
    /// 密钥绑定。
    pub key_binding: KeyBindingClaim,
    /// SCRAM 关系。
    pub scram: ScramRelationClaim,
    /// audit checkpoint。
    pub audit: AuditCheckpointClaim,
    /// 兼容信息。
    pub compatibility: CompatibilitySet,
    /// 材料条目。
    pub materials: Vec<MaterialClaim>,
    /// 有理由的空类。
    pub empty_categories: Vec<EmptyCategoryClaim>,
    /// 回执。
    pub receipts: ReceiptSetClaim,
}

/// 核验后的单条材料。字段私有。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedMaterial {
    id: MaterialId,
    kind: MaterialKind,
    path: RelativePath,
    directory: bool,
    declared_bytes: u64,
    digest: Sha256Digest,
}

impl CheckedMaterial {
    /// 条目身份。
    #[must_use]
    pub fn id(&self) -> &MaterialId {
        &self.id
    }

    /// 材料类。
    #[must_use]
    pub fn kind(&self) -> MaterialKind {
        self.kind
    }

    /// 相对路径。
    #[must_use]
    pub fn path(&self) -> &RelativePath {
        &self.path
    }

    /// 是否目录。
    #[must_use]
    pub fn directory(&self) -> bool {
        self.directory
    }

    /// 声明字节。
    #[must_use]
    pub fn declared_bytes(&self) -> u64 {
        self.declared_bytes
    }

    /// 声明摘要。
    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

/// 核验后的回执集合。字段私有。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedReceipts {
    committed: Vec<String>,
    unknown: Vec<String>,
    tool: Vec<String>,
}

impl CheckedReceipts {
    /// 已提交回执身份。
    #[must_use]
    pub fn committed(&self) -> &[String] {
        &self.committed
    }

    /// Unknown 回执身份。计划必须保留，不得安排重放。
    #[must_use]
    pub fn unknown(&self) -> &[String] {
        &self.unknown
    }

    /// 工具回执身份。
    #[must_use]
    pub fn tool(&self) -> &[String] {
        &self.tool
    }
}

/// 结构核验通过的清单。不能从外部字段或 Serde 构造。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InventoryChecked {
    bundle: BundleIdentity,
    dataset: DatasetIdentity,
    deployment: DeploymentId,
    tenant: TenantId,
    original_installation: InstallationIdentity,
    barrier: BarrierIdentity,
    key_binding: KeyBindingClaim,
    scram: ScramRelationClaim,
    audit: AuditCheckpointClaim,
    compatibility: CompatibilitySet,
    materials: Vec<CheckedMaterial>,
    receipts: CheckedReceipts,
    total_declared_bytes: u64,
    explained_empty: Vec<EmptyCategoryClaim>,
}

impl InventoryChecked {
    /// bundle。
    #[must_use]
    pub fn bundle(&self) -> &BundleIdentity {
        &self.bundle
    }

    /// dataset。
    #[must_use]
    pub fn dataset(&self) -> &DatasetIdentity {
        &self.dataset
    }

    /// deployment。
    #[must_use]
    pub fn deployment(&self) -> &DeploymentId {
        &self.deployment
    }

    /// tenant。
    #[must_use]
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// 原安装。
    #[must_use]
    pub fn original_installation(&self) -> &InstallationIdentity {
        &self.original_installation
    }

    /// 一致性屏障。
    #[must_use]
    pub fn barrier(&self) -> &BarrierIdentity {
        &self.barrier
    }

    /// 密钥绑定。
    #[must_use]
    pub fn key_binding(&self) -> &KeyBindingClaim {
        &self.key_binding
    }

    /// SCRAM 关系。
    #[must_use]
    pub fn scram(&self) -> &ScramRelationClaim {
        &self.scram
    }

    /// audit checkpoint。
    #[must_use]
    pub fn audit(&self) -> &AuditCheckpointClaim {
        &self.audit
    }

    /// 兼容信息。
    #[must_use]
    pub fn compatibility(&self) -> &CompatibilitySet {
        &self.compatibility
    }

    /// 已核材料。
    #[must_use]
    pub fn materials(&self) -> &[CheckedMaterial] {
        &self.materials
    }

    /// 已核回执。
    #[must_use]
    pub fn receipts(&self) -> &CheckedReceipts {
        &self.receipts
    }

    /// 全包声明字节（未压缩合计）。
    #[must_use]
    pub fn total_declared_bytes(&self) -> u64 {
        self.total_declared_bytes
    }

    /// 受控解释过的空类。
    #[must_use]
    pub fn explained_empty(&self) -> &[EmptyCategoryClaim] {
        &self.explained_empty
    }

    /// 是否仅依赖原 OS store。
    #[must_use]
    pub fn same_installation_only(&self) -> bool {
        matches!(
            self.key_binding,
            KeyBindingClaim::SameInstallationOsStoreOnly { .. }
        )
    }
}

pub(super) fn check_inventory(
    claim: &BackupInventoryClaim,
    bounds: &InventoryBounds,
) -> Result<InventoryChecked, InventoryFault> {
    validate_identity(claim.bundle.bundle_id.as_str(), bounds)?;
    validate_identity(claim.dataset.as_str(), bounds)?;
    validate_identity(claim.deployment.as_str(), bounds)?;
    validate_identity(claim.tenant.as_str(), bounds)?;
    validate_identity(claim.original_installation.as_str(), bounds)?;
    validate_identity(claim.barrier.as_str(), bounds)?;
    validate_identity(claim.scram.relation_id.as_str(), bounds)?;
    validate_identity(claim.audit.material_id.as_str(), bounds)?;
    reject_secret_token(claim.bundle.bundle_id.as_str())?;
    reject_secret_token(claim.dataset.as_str())?;
    reject_secret_token(claim.scram.relation_id.as_str())?;

    check_compatibility(&claim.compatibility, bounds)?;
    let receipts = check_receipts(&claim.receipts, bounds)?;
    let (materials, total_declared_bytes) = check_materials(claim, bounds)?;
    check_key_binding_structure(&claim.key_binding, &materials, bounds)?;
    check_audit_reference(&claim.audit, &materials)?;
    let explained_empty = check_empty_categories(&claim.empty_categories, &materials, bounds)?;

    Ok(InventoryChecked {
        bundle: claim.bundle.clone(),
        dataset: claim.dataset.clone(),
        deployment: claim.deployment.clone(),
        tenant: claim.tenant.clone(),
        original_installation: claim.original_installation.clone(),
        barrier: claim.barrier.clone(),
        key_binding: claim.key_binding.clone(),
        scram: claim.scram.clone(),
        audit: claim.audit.clone(),
        compatibility: claim.compatibility.clone(),
        materials,
        receipts,
        total_declared_bytes,
        explained_empty,
    })
}

fn check_receipts(
    claim: &ReceiptSetClaim,
    bounds: &InventoryBounds,
) -> Result<CheckedReceipts, InventoryFault> {
    let mut seen = BTreeSet::new();
    let mut count: u32 = 0;
    let mut committed = Vec::new();
    let mut unknown = Vec::new();
    let mut tool = Vec::new();
    for (bucket, items, expect_unknown) in [
        (&mut committed, claim.committed.as_slice(), false),
        (&mut unknown, claim.unknown.as_slice(), true),
        (&mut tool, claim.tool.as_slice(), false),
    ] {
        for item in items {
            count = count
                .checked_add(1)
                .ok_or(InventoryFault::AccumulatedOverflow)?;
            if count > bounds.max_receipts {
                return Err(InventoryFault::CountOutOfBounds);
            }
            validate_identity(item.id.as_str(), bounds)?;
            if item.unknown != expect_unknown {
                return Err(InventoryFault::ReceiptCategoryMismatch);
            }
            if !seen.insert(item.id.as_str()) {
                return Err(InventoryFault::DuplicateId);
            }
            bucket.push(item.id.clone());
        }
    }
    Ok(CheckedReceipts {
        committed,
        unknown,
        tool,
    })
}

fn check_materials(
    claim: &BackupInventoryClaim,
    bounds: &InventoryBounds,
) -> Result<(Vec<CheckedMaterial>, u64), InventoryFault> {
    let mut count: u32 = 0;
    let mut total: u64 = 0;
    let mut ids = BTreeSet::new();
    let mut paths: BTreeMap<String, bool> = BTreeMap::new();
    let mut folded: BTreeMap<String, ()> = BTreeMap::new();
    let mut checked = Vec::new();

    for item in &claim.materials {
        count = count
            .checked_add(1)
            .ok_or(InventoryFault::AccumulatedOverflow)?;
        if count > bounds.max_entries {
            return Err(InventoryFault::CountOutOfBounds);
        }
        validate_identity(item.id.as_str(), bounds)?;
        if !ids.insert(item.id.as_str()) {
            return Err(InventoryFault::DuplicateId);
        }
        reject_secret_token(item.id.as_str())?;
        reject_secret_path(item.relative_path.as_str())?;
        let path = parse_relative_path(item.relative_path.as_str(), bounds)?;
        if item.bundle_id != claim.bundle.bundle_id {
            return Err(InventoryFault::BundleMismatch);
        }
        if item.dataset_id != claim.dataset.as_str() {
            return Err(InventoryFault::DatasetMismatch);
        }
        if item.barrier_id != claim.barrier.as_str() {
            return Err(InventoryFault::BarrierMismatch);
        }
        if item.directory {
            if item.declared_bytes != 0 {
                return Err(InventoryFault::DirectoryLength);
            }
        } else if item.declared_bytes > bounds.max_entry_bytes {
            return Err(InventoryFault::LengthOutOfBounds);
        }
        total = total
            .checked_add(item.declared_bytes)
            .ok_or(InventoryFault::AccumulatedOverflow)?;
        if total > bounds.max_total_bytes {
            return Err(InventoryFault::LengthOutOfBounds);
        }
        if paths.contains_key(&path.0) {
            return Err(InventoryFault::DuplicatePath);
        }
        let folded_key = fold_ascii(&path.0);
        if folded.contains_key(&folded_key) {
            return Err(InventoryFault::PrefixOrAliasConflict);
        }
        for (existing, is_dir) in &paths {
            if prefix_conflict(&path.0, item.directory, existing, *is_dir) {
                return Err(InventoryFault::PrefixOrAliasConflict);
            }
        }
        folded.insert(folded_key, ());
        paths.insert(path.0.clone(), item.directory);
        checked.push(CheckedMaterial {
            id: item.id.clone(),
            kind: item.kind,
            path,
            directory: item.directory,
            declared_bytes: item.declared_bytes,
            digest: item.digest,
        });
    }
    Ok((checked, total))
}

fn check_key_binding_structure(
    binding: &KeyBindingClaim,
    materials: &[CheckedMaterial],
    bounds: &InventoryBounds,
) -> Result<(), InventoryFault> {
    match binding {
        KeyBindingClaim::RecoveryWrapped { wrapping_refs } => {
            if wrapping_refs.len() > bounds.max_entries as usize {
                return Err(InventoryFault::CountOutOfBounds);
            }
            let mut seen = BTreeSet::new();
            for wrap in wrapping_refs {
                validate_identity(wrap.key.key_id.as_str(), bounds)?;
                validate_identity(wrap.wrapping_object_id.as_str(), bounds)?;
                reject_secret_token(wrap.key.key_id.as_str())?;
                if !seen.insert(wrap.wrapping_object_id.as_str()) {
                    return Err(InventoryFault::DuplicateId);
                }
                match materials
                    .iter()
                    .find(|item| item.id == wrap.wrapping_object_id)
                {
                    None => {
                        // 缺包装对象由计划层标 Incomplete，这里只挡错误类别/形态。
                    }
                    Some(found) => {
                        if found.kind != MaterialKind::KeyWrappingObject {
                            return Err(InventoryFault::CrossReferenceMismatch);
                        }
                        if found.directory {
                            return Err(InventoryFault::MaterialShapeInvalid);
                        }
                    }
                }
            }
            Ok(())
        }
        KeyBindingClaim::SameInstallationOsStoreOnly { key_refs } => {
            if key_refs.len() > bounds.max_entries as usize {
                return Err(InventoryFault::CountOutOfBounds);
            }
            for key in key_refs {
                validate_identity(key.key_id.as_str(), bounds)?;
                reject_secret_token(key.key_id.as_str())?;
            }
            Ok(())
        }
    }
}

fn check_audit_reference(
    audit: &AuditCheckpointClaim,
    materials: &[CheckedMaterial],
) -> Result<(), InventoryFault> {
    if let Some(found) = materials.iter().find(|item| item.id == audit.material_id) {
        if found.kind != MaterialKind::AuditCheckpointObject {
            return Err(InventoryFault::CrossReferenceMismatch);
        }
        if found.directory {
            return Err(InventoryFault::MaterialShapeInvalid);
        }
    }
    Ok(())
}

fn check_compatibility(
    set: &CompatibilitySet,
    bounds: &InventoryBounds,
) -> Result<(), InventoryFault> {
    for rev in [&set.application, &set.postgres, &set.engine, &set.ui] {
        validate_identity(rev.name.as_str(), bounds)?;
    }
    Ok(())
}

fn check_empty_categories(
    claims: &[EmptyCategoryClaim],
    materials: &[CheckedMaterial],
    bounds: &InventoryBounds,
) -> Result<Vec<EmptyCategoryClaim>, InventoryFault> {
    const MAX_EMPTY_CATEGORIES: u32 = 8;
    let limit = bounds.max_entries.min(MAX_EMPTY_CATEGORIES);
    if claims.len() > limit as usize {
        return Err(InventoryFault::CountOutOfBounds);
    }
    let mut seen = BTreeSet::new();
    let mut explained = Vec::new();
    for item in claims {
        if !item.kind.empty_may_be_explained() {
            return Err(InventoryFault::EmptyCategoryInconsistent);
        }
        if !seen.insert(item.kind) {
            return Err(InventoryFault::EmptyCategoryInconsistent);
        }
        if materials.iter().any(|material| material.kind == item.kind) {
            return Err(InventoryFault::EmptyCategoryInconsistent);
        }
        explained.push(*item);
    }
    Ok(explained)
}

pub(super) fn validate_identity(
    value: &str,
    bounds: &InventoryBounds,
) -> Result<(), InventoryFault> {
    if value.is_empty() || value.len() > usize::from(bounds.max_id_bytes) {
        return Err(InventoryFault::IdentityInvalid);
    }
    if value
        .bytes()
        .any(|b| b == 0 || b == b'/' || b == b'\\' || b == b':')
    {
        return Err(InventoryFault::IdentityInvalid);
    }
    Ok(())
}

fn reject_secret_token(value: &str) -> Result<(), InventoryFault> {
    let folded = fold_ascii(value);
    if folded.contains("password")
        || folded.contains("secret")
        || folded.contains("master-key")
        || folded.contains("master_key")
        || folded.contains("recovery-key")
        || folded.contains("recovery_key")
        || folded.contains("scram-hash")
    {
        return Err(InventoryFault::SecretMaterialForbidden);
    }
    Ok(())
}

fn reject_secret_path(path: &str) -> Result<(), InventoryFault> {
    reject_secret_token(path)?;
    let last = path.rsplit('/').next().unwrap_or(path);
    if fold_ascii(last) == "password.txt" {
        return Err(InventoryFault::SecretMaterialForbidden);
    }
    Ok(())
}

fn parse_relative_path(
    raw: &str,
    bounds: &InventoryBounds,
) -> Result<RelativePath, InventoryFault> {
    if raw.is_empty() || raw.len() > usize::from(bounds.max_path_bytes) {
        return Err(InventoryFault::PathInvalid);
    }
    if raw.starts_with('/') || raw.starts_with('\\') {
        return Err(InventoryFault::PathInvalid);
    }
    if raw.as_bytes().contains(&0) || raw.contains('\\') {
        return Err(InventoryFault::PathInvalid);
    }
    let mut depth: u8 = 0;
    for (index, part) in raw.split('/').enumerate() {
        if part.is_empty() || part == "." || part == ".." {
            return Err(InventoryFault::PathInvalid);
        }
        if index == 0 && part.len() >= 2 && part.as_bytes()[1] == b':' {
            return Err(InventoryFault::PathInvalid);
        }
        depth = depth
            .checked_add(1)
            .ok_or(InventoryFault::AccumulatedOverflow)?;
        if depth > bounds.max_path_depth {
            return Err(InventoryFault::PathInvalid);
        }
    }
    Ok(RelativePath(raw.to_owned()))
}

fn fold_ascii(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphabetic() {
                ch.to_ascii_lowercase()
            } else {
                ch
            }
        })
        .collect()
}

fn prefix_conflict(left: &str, left_dir: bool, right: &str, right_dir: bool) -> bool {
    if left == right {
        return true;
    }
    let left_prefix = if left_dir {
        format!("{left}/")
    } else {
        String::new()
    };
    let right_prefix = if right_dir {
        format!("{right}/")
    } else {
        String::new()
    };
    (!left_prefix.is_empty() && right.starts_with(&left_prefix))
        || (!right_prefix.is_empty() && left.starts_with(&right_prefix))
        || (!left_dir && right.starts_with(&format!("{left}/")))
        || (!right_dir && left.starts_with(&format!("{right}/")))
}
