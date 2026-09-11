//! 升级、紧急回退与恢复格式切换的纯兼容性预检（§14.1 / §14.3 / §14.4 / §16.2 / §20.5）。
//!
//! # 范围
//!
//! 本模块比较**运行中快照**与**候选快照**的内部结构条件，产出 [`PreflightPlan`]：
//! 待执行步骤与待证明项。它不读文件、网络、OS、系统时钟或随机数，不解析任意 SQL，
//! 不产出 downgrade SQL，也不把调用方填入的 `signature_described_valid` 当成已验签。
//!
//! 成功结果的名称停在「计划」。本核没有 `InstallAuthorized` / `RollbackAuthorized` /
//! `RestoreAuthorized` / Ready；即使证明声明全为真，授权类证明仍为 [`ProofStatus::NotGranted`]。
//!
//! [`CompatibilitySet`] / [`ComponentRev`] / [`Sha256Digest`] 复用既有备份结构。
//! Tauri / Electron / PostgreSQL **major** 与兼容范围是本模块内部事实，不改备份 wire，
//! 也不把既有 `epoch` 当作 major。
//!
//! 当前仓库的 protocol 4 / release epoch 5 只是输入里可能出现的事实，**不是**“禁止再升级”
//! 的硬编码上限。候选内部一致也不等于包已验签。
//!
//! # 内部检查顺序
//!
//! 第一真源未规定多条件显示优先级。本核按固定内部顺序 **fail-closed 返回第一项**：
//! 标识/清单边界 → 组件集合 → 启动事实自洽 → writer → schema 种类与账本 →
//! 意图下的 schema 关系 → 恢复格式/恢复构建 → major/epoch 方向与同批禁令 →
//! 紧急回退授权声明是否存在。该顺序不是对外协议。
//!
//! # 本批明确不做
//!
//! - 真实验签、公证、单独回退授权核验、资源完整性、PG 恢复/迁移、原子切换。
//! - 更新器、安装器、签名检查器、GK-02 候选验收记录检查器。
//! - 关闭 V5-UPGRADE-01 / V5-RELEASE-01 / A6 / A7 / G8。

use std::collections::BTreeSet;

use crate::audit::hash::Sha256Digest;
use crate::backup::{CompatibilitySet, ComponentRev, ProofStatus};

/// 组件清单条数上限。四件套加有限反例，不是无界 Vec。
pub const MAX_COMPONENTS: usize = 16;

/// 迁移账本条数上限。
pub const MAX_MIGRATIONS: usize = 256;

/// 标识、迁移名、格式 id 的最大字节数。与备份 identity 预算对齐。
pub const MAX_ID_BYTES: usize = 128;

/// 待执行步骤条数上限。
pub const MAX_PENDING_ACTIONS: usize = 8;

/// 调用方声明的操作意图。不是已授权的安装/回退/恢复。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OperationIntent {
    /// 普通升级。候选不得低于运行中的 epoch / rust major。
    Upgrade,
    /// 紧急回退到上一已验签名 Rust build 的结构条件。授权仍待核验。
    EmergencyRollback,
    /// 恢复格式切换。无兼容上一版本时必须带匹配的恢复构建描述。
    RestoreFormatSwitch,
}

/// 候选将安装的 writer。回旧 Intelligence/TypeScript writer 一律拒绝。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterKind {
    /// Rust native writer。
    RustNative,
    /// 已退役的 Intelligence / TypeScript writer。
    IntelligenceTypeScript,
}

/// 调用方对一条 schema 变更的分类。本核不解析 SQL 来猜。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemaChangeKind {
    /// 新表。
    NewTable,
    /// 可空列。
    NullableColumn,
    /// 回填。
    Backfill,
    /// 索引。
    Index,
    /// 非破坏性 constraint validation。
    NonDestructiveConstraint,
    /// drop。兼容期禁止。
    Drop,
    /// rename。兼容期禁止。
    Rename,
    /// 类型收紧。兼容期禁止。
    TypeTightening,
    /// 主键改写。兼容期禁止。
    PrimaryKeyRewrite,
    /// 未知。不能凭同形放行。
    Unknown,
}

impl SchemaChangeKind {
    const fn is_expand(self) -> bool {
        matches!(
            self,
            Self::NewTable
                | Self::NullableColumn
                | Self::Backfill
                | Self::Index
                | Self::NonDestructiveConstraint
        )
    }
}

/// 兼容范围的内部表示。未知/无界不能当“全兼容”。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompatibilityRange {
    /// 未提供。
    Unknown,
    /// 无上界/无下界。
    Unbounded,
    /// 闭区间。`min_core > max_core` 视为矛盾输入。
    Inclusive {
        /// 含。
        min_core: u32,
        /// 含。
        max_core: u32,
    },
}

/// 新格式相对上一版本的声明。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompatiblePreviousClaim {
    /// 未证明是否存在上一兼容版本。
    Unknown,
    /// 明确没有兼容的上一版本。
    None,
    /// 具名上一格式。
    Identified {
        /// 上一格式 id。
        format_id: String,
    },
}

/// 组件集合声明。完整四件套可经 [`Self::from_set`] 复用既有类型。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentSetClaim {
    /// 未核列表。缺件、重复、未知名在预检时拒绝。
    pub entries: Vec<ComponentRev>,
}

impl ComponentSetClaim {
    /// 从既有兼容四件套构造。仍会在预检时核对其内部 `name` 与 epoch。
    #[must_use]
    pub fn from_set(set: CompatibilitySet) -> Self {
        Self {
            entries: vec![set.application, set.postgres, set.engine, set.ui],
        }
    }
}

/// 一次发行的四类 major。与 `ComponentRev.epoch` 分开。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseMajors {
    /// Rust / 应用 core major。
    pub rust_core: u16,
    /// Tauri major。
    pub tauri: u16,
    /// Electron / Chromium major。
    pub electron: u16,
    /// PostgreSQL major。
    pub postgres: u16,
}

/// 启动要求的协议、epoch、core 与兼容范围。全部由调用方作为事实提供。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartupFacts {
    /// 运行/候选声明的协议版本。0 视为缺失。
    pub protocol: u32,
    /// sidecar / 启动器声明的协议。必须与 [`Self::protocol`] 相同。
    pub sidecar_protocol: u32,
    /// 启动要求的归属 epoch。必须与组件集合一致。0 视为缺失。
    pub release_epoch: u32,
    /// 本发行的 core 标识。内部 u32，不是对外版本字符串。
    pub core_identity: u32,
    /// sidecar 声明的最低兼容 core。
    pub minimum_compatible_core: u32,
    /// 兼容范围。
    pub compatibility_range: CompatibilityRange,
}

/// 一条迁移账本声明。checksum 缺失则拒绝。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationClaim {
    /// 迁移名字。
    pub name: String,
    /// SQL 原文摘要。本核不读 SQL。
    pub checksum: Option<Sha256Digest>,
    /// 调用方分类。
    pub change: SchemaChangeKind,
}

/// schema / 迁移清单。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaInventoryClaim {
    /// schema 范围（例如 `public`）。缺失或漂移拒绝。
    pub scope: String,
    /// 清单摘要。缺失拒绝。
    pub checksum: Option<Sha256Digest>,
    /// 有序账本。
    pub migrations: Vec<MigrationClaim>,
}

/// 恢复格式声明。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreFormatClaim {
    /// 当前格式 id。
    pub format_id: String,
    /// 上一兼容格式。
    pub compatible_previous: CompatiblePreviousClaim,
}

/// 恢复构建的合成描述。`described_runnable` 不是实机可运行证明。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreBuildClaim {
    /// 该构建对应的格式。
    pub format_id: String,
    /// 构建摘要。
    pub digest: Sha256Digest,
    /// 调用方是否描述为可运行。
    pub described_runnable: bool,
}

/// 证明声明。全为真也不能清零待核验义务。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofClaims {
    /// 描述为签名有效。
    pub signature_described_valid: bool,
    /// 描述为已公证。
    pub notarization_described_valid: bool,
    /// 描述为已有单独回退授权材料。紧急回退缺此项则不能形成计划。
    pub rollback_authorization_described: bool,
}

/// 运行中或候选的完整快照。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseSnapshot {
    /// 组件集合。
    pub components: ComponentSetClaim,
    /// 四类 major。
    pub majors: ReleaseMajors,
    /// 启动事实。
    pub startup: StartupFacts,
    /// schema 清单。
    pub schema: SchemaInventoryClaim,
    /// 恢复格式。
    pub restore_format: RestoreFormatClaim,
    /// 可选恢复构建描述。
    pub restore_build: Option<RestoreBuildClaim>,
    /// writer。
    pub writer: WriterKind,
}

/// [`plan_upgrade_preflight`] 的输入。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreflightRequest<'a> {
    /// 意图。
    pub intent: OperationIntent,
    /// 当前运行快照。
    pub running: &'a ReleaseSnapshot,
    /// 候选快照。
    pub candidate: &'a ReleaseSnapshot,
    /// 独立安装历史中具名的上一 Rust build；不是候选自报签名。
    pub previous_build: Option<&'a ReleaseSnapshot>,
    /// 上一构建对当前 expanded schema 的兼容描述，必须绑定完整当前清单摘要。
    pub rollback_schema: Option<Sha256Digest>,
    /// 证明声明。
    pub proof_claims: &'a ProofClaims,
}

/// 结构条件满足后仍须由后续 owner 执行的步骤。不含 SQL。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PendingAction {
    /// 真实验签。
    VerifySignatures,
    /// 公证。
    Notarize,
    /// 单独回退授权核验。
    VerifyRollbackAuthorization,
    /// 资源完整性。
    VerifyResourceIntegrity,
    /// 施加 expand-only 迁移（不在本核生成 SQL）。
    ApplyExpandMigrations,
    /// PostgreSQL major 升级编排。
    PostgresMajorUpgrade,
    /// 核验恢复构建。
    VerifyRestoreBuild,
    /// 原子切换。
    AtomicSwitch,
}

impl PendingAction {
    /// 稳定字面量。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VerifySignatures => "verify_signatures",
            Self::Notarize => "notarize",
            Self::VerifyRollbackAuthorization => "verify_rollback_authorization",
            Self::VerifyResourceIntegrity => "verify_resource_integrity",
            Self::ApplyExpandMigrations => "apply_expand_migrations",
            Self::PostgresMajorUpgrade => "postgres_major_upgrade",
            Self::VerifyRestoreBuild => "verify_restore_build",
            Self::AtomicSwitch => "atomic_switch",
        }
    }
}

/// 成功计划上仍待完成的证明。授权三类恒为未授予。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingProofs {
    signature_verification: ProofStatus,
    notarization: ProofStatus,
    rollback_authorization: ProofStatus,
    resource_integrity: ProofStatus,
    postgres_restore_or_migrate: ProofStatus,
    restore_build: ProofStatus,
    atomic_switch: ProofStatus,
    install_authorized: ProofStatus,
    rollback_authorized: ProofStatus,
    restore_authorized: ProofStatus,
}

impl PendingProofs {
    fn for_plan(intent: OperationIntent, need_restore_build: bool) -> Self {
        let rollback_slot = match intent {
            OperationIntent::EmergencyRollback => ProofStatus::Pending,
            OperationIntent::Upgrade | OperationIntent::RestoreFormatSwitch => {
                ProofStatus::NotGranted
            }
        };
        let restore_build = if need_restore_build {
            ProofStatus::Pending
        } else {
            ProofStatus::NotGranted
        };
        Self {
            signature_verification: ProofStatus::Pending,
            notarization: ProofStatus::Pending,
            rollback_authorization: rollback_slot,
            resource_integrity: ProofStatus::Pending,
            postgres_restore_or_migrate: ProofStatus::Pending,
            restore_build,
            atomic_switch: ProofStatus::Pending,
            install_authorized: ProofStatus::NotGranted,
            rollback_authorized: ProofStatus::NotGranted,
            restore_authorized: ProofStatus::NotGranted,
        }
    }

    /// 签名核验。
    #[must_use]
    pub const fn signature_verification(self) -> ProofStatus {
        self.signature_verification
    }

    /// 公证。
    #[must_use]
    pub const fn notarization(self) -> ProofStatus {
        self.notarization
    }

    /// 单独回退授权。升级意图下本核不授予该槽为已证明。
    #[must_use]
    pub const fn rollback_authorization(self) -> ProofStatus {
        self.rollback_authorization
    }

    /// 资源完整性。
    #[must_use]
    pub const fn resource_integrity(self) -> ProofStatus {
        self.resource_integrity
    }

    /// PG 恢复或迁移。
    #[must_use]
    pub const fn postgres_restore_or_migrate(self) -> ProofStatus {
        self.postgres_restore_or_migrate
    }

    /// 恢复构建。
    #[must_use]
    pub const fn restore_build(self) -> ProofStatus {
        self.restore_build
    }

    /// 原子切换。
    #[must_use]
    pub const fn atomic_switch(self) -> ProofStatus {
        self.atomic_switch
    }

    /// 安装许可。本核恒为未授予。
    #[must_use]
    pub const fn install_authorized(self) -> ProofStatus {
        self.install_authorized
    }

    /// 回退许可。本核恒为未授予。
    #[must_use]
    pub const fn rollback_authorized(self) -> ProofStatus {
        self.rollback_authorized
    }

    /// 恢复许可。本核恒为未授予。
    #[must_use]
    pub const fn restore_authorized(self) -> ProofStatus {
        self.restore_authorized
    }
}

/// 内部结构条件满足后的待证明计划。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreflightPlan {
    running: ReleaseSnapshot,
    candidate: ReleaseSnapshot,
    previous_build: Option<ReleaseSnapshot>,
    rollback_schema: Option<Sha256Digest>,
    intent: OperationIntent,
    pending_actions: Vec<PendingAction>,
    pending_proofs: PendingProofs,
}

impl PreflightPlan {
    /// 已检查的运行快照；执行器必须与当前现场重新核同。
    #[must_use]
    pub fn running(&self) -> &ReleaseSnapshot {
        &self.running
    }
    /// 已检查的候选快照；不能把计划用于另一包。
    #[must_use]
    pub fn candidate(&self) -> &ReleaseSnapshot {
        &self.candidate
    }
    /// 被检查的意图。
    #[must_use]
    pub const fn intent(&self) -> OperationIntent {
        self.intent
    }

    /// 待执行步骤，闭集、去重、稳定顺序。
    #[must_use]
    pub fn pending_actions(&self) -> &[PendingAction] {
        &self.pending_actions
    }

    /// 待证明项。
    #[must_use]
    pub const fn pending_proofs(&self) -> PendingProofs {
        self.pending_proofs
    }
}

/// 预检失败。稳定 code，不回显远端文案或 SQL。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PreflightFault {
    /// 缺少必需组件。
    #[error("upgrade_preflight_missing_component")]
    MissingComponent,
    /// 重复组件。
    #[error("upgrade_preflight_duplicate_component")]
    DuplicateComponent,
    /// 未知组件名。
    #[error("upgrade_preflight_unknown_component")]
    UnknownComponent,
    /// 组件归属 epoch 不一致。
    #[error("upgrade_preflight_mixed_release_epoch")]
    MixedReleaseEpoch,
    /// 组件 digest 互相矛盾。
    #[error("upgrade_preflight_digest_contradiction")]
    DigestContradiction,
    /// 协议事实互相矛盾。
    #[error("upgrade_preflight_protocol_contradiction")]
    ProtocolContradiction,
    /// 启动 epoch 与组件 epoch 不一致。
    #[error("upgrade_preflight_release_epoch_contradiction")]
    ReleaseEpochContradiction,
    /// 最低 core 不满足。
    #[error("upgrade_preflight_minimum_core_incompatible")]
    MinimumCoreIncompatible,
    /// 兼容范围未知。
    #[error("upgrade_preflight_unknown_compatibility_range")]
    UnknownCompatibilityRange,
    /// 兼容范围无界。
    #[error("upgrade_preflight_unbounded_compatibility_range")]
    UnboundedCompatibilityRange,
    /// PG major 与 Tauri major 同一 release。
    #[error("upgrade_preflight_pg_major_with_tauri_major")]
    PgMajorWithTauriMajor,
    /// PG major 与 Electron major 同一 release。
    #[error("upgrade_preflight_pg_major_with_electron_major")]
    PgMajorWithElectronMajor,
    /// 普通降级。
    #[error("upgrade_preflight_ordinary_downgrade")]
    OrdinaryDowngrade,
    /// 回旧 Intelligence/TypeScript writer。
    #[error("upgrade_preflight_forbidden_writer")]
    ForbiddenWriter,
    /// 变更不属于 expand 集合。
    #[error("upgrade_preflight_schema_change_not_expand")]
    SchemaChangeNotExpand,
    /// 迁移名字缺失或漂移。
    #[error("upgrade_preflight_migration_name_drift")]
    MigrationNameDrift,
    /// 缺 checksum。
    #[error("upgrade_preflight_migration_checksum_missing")]
    MigrationChecksumMissing,
    /// checksum 漂移。
    #[error("upgrade_preflight_migration_checksum_drift")]
    MigrationChecksumDrift,
    /// schema 范围缺失。
    #[error("upgrade_preflight_schema_scope_missing")]
    SchemaScopeMissing,
    /// schema 范围漂移。
    #[error("upgrade_preflight_schema_scope_drift")]
    SchemaScopeDrift,
    /// schema 清单摘要缺失。
    #[error("upgrade_preflight_schema_checksum_missing")]
    SchemaChecksumMissing,
    /// 新格式缺少匹配恢复构建。
    #[error("upgrade_preflight_restore_build_missing")]
    RestoreBuildMissing,
    /// 恢复构建格式不匹配。
    #[error("upgrade_preflight_restore_build_format_mismatch")]
    RestoreBuildFormatMismatch,
    /// 恢复格式未知。
    #[error("upgrade_preflight_restore_format_unknown")]
    RestoreFormatUnknown,
    /// 紧急回退缺少独立授权声明。
    #[error("upgrade_preflight_missing_rollback_authorization")]
    MissingRollbackAuthorization,
    /// 空描述。
    #[error("upgrade_preflight_input_empty")]
    InputEmpty,
    /// 过长描述。
    #[error("upgrade_preflight_input_too_long")]
    InputTooLong,
    /// 重复描述。
    #[error("upgrade_preflight_input_duplicate")]
    InputDuplicate,
    /// 条数越界。
    #[error("upgrade_preflight_count_out_of_bounds")]
    CountOutOfBounds,
    /// 标识字符非法。
    #[error("upgrade_preflight_identity_invalid")]
    IdentityInvalid,
    /// major 为 0 或缺失。
    #[error("upgrade_preflight_major_invalid")]
    MajorInvalid,
    /// 协议或 epoch 缺失。
    #[error("upgrade_preflight_startup_fact_missing")]
    StartupFactMissing,
    /// 矛盾输入。
    #[error("upgrade_preflight_inconsistent_facts")]
    InconsistentFacts,
}

impl PreflightFault {
    /// 稳定 code。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingComponent => "upgrade_preflight_missing_component",
            Self::DuplicateComponent => "upgrade_preflight_duplicate_component",
            Self::UnknownComponent => "upgrade_preflight_unknown_component",
            Self::MixedReleaseEpoch => "upgrade_preflight_mixed_release_epoch",
            Self::DigestContradiction => "upgrade_preflight_digest_contradiction",
            Self::ProtocolContradiction => "upgrade_preflight_protocol_contradiction",
            Self::ReleaseEpochContradiction => "upgrade_preflight_release_epoch_contradiction",
            Self::MinimumCoreIncompatible => "upgrade_preflight_minimum_core_incompatible",
            Self::UnknownCompatibilityRange => "upgrade_preflight_unknown_compatibility_range",
            Self::UnboundedCompatibilityRange => "upgrade_preflight_unbounded_compatibility_range",
            Self::PgMajorWithTauriMajor => "upgrade_preflight_pg_major_with_tauri_major",
            Self::PgMajorWithElectronMajor => "upgrade_preflight_pg_major_with_electron_major",
            Self::OrdinaryDowngrade => "upgrade_preflight_ordinary_downgrade",
            Self::ForbiddenWriter => "upgrade_preflight_forbidden_writer",
            Self::SchemaChangeNotExpand => "upgrade_preflight_schema_change_not_expand",
            Self::MigrationNameDrift => "upgrade_preflight_migration_name_drift",
            Self::MigrationChecksumMissing => "upgrade_preflight_migration_checksum_missing",
            Self::MigrationChecksumDrift => "upgrade_preflight_migration_checksum_drift",
            Self::SchemaScopeMissing => "upgrade_preflight_schema_scope_missing",
            Self::SchemaScopeDrift => "upgrade_preflight_schema_scope_drift",
            Self::SchemaChecksumMissing => "upgrade_preflight_schema_checksum_missing",
            Self::RestoreBuildMissing => "upgrade_preflight_restore_build_missing",
            Self::RestoreBuildFormatMismatch => "upgrade_preflight_restore_build_format_mismatch",
            Self::RestoreFormatUnknown => "upgrade_preflight_restore_format_unknown",
            Self::MissingRollbackAuthorization => {
                "upgrade_preflight_missing_rollback_authorization"
            }
            Self::InputEmpty => "upgrade_preflight_input_empty",
            Self::InputTooLong => "upgrade_preflight_input_too_long",
            Self::InputDuplicate => "upgrade_preflight_input_duplicate",
            Self::CountOutOfBounds => "upgrade_preflight_count_out_of_bounds",
            Self::IdentityInvalid => "upgrade_preflight_identity_invalid",
            Self::MajorInvalid => "upgrade_preflight_major_invalid",
            Self::StartupFactMissing => "upgrade_preflight_startup_fact_missing",
            Self::InconsistentFacts => "upgrade_preflight_inconsistent_facts",
        }
    }
}

struct CheckedComponents {
    set: CompatibilitySet,
    epoch: u32,
}

struct CheckedSchema {
    scope: String,
    checksum: Sha256Digest,
    migrations: Vec<CheckedMigration>,
}

struct CheckedMigration {
    name: String,
    checksum: Sha256Digest,
    change: SchemaChangeKind,
}

struct CheckedRestoreFormat {
    format_id: String,
    previous: CheckedPrevious,
}

enum CheckedPrevious {
    None,
    Identified(String),
}

struct CheckedRestoreBuild {
    format_id: String,
    described_runnable: bool,
}

struct CheckedSnapshot {
    core_identity: u32,
    components: CheckedComponents,
    majors: ReleaseMajors,
    schema: CheckedSchema,
    restore_format: CheckedRestoreFormat,
    restore_build: Option<CheckedRestoreBuild>,
    writer: WriterKind,
}

/// 比较运行中与候选快照，只在内部结构条件成立时返回待证明计划。
///
/// # Errors
///
/// 缺失、未知、不一致、越界、禁止的 major 组合、普通降级、非 expand schema、
/// 旧 writer 或无法证明的恢复格式均返回 [`PreflightFault`]。
pub fn plan_upgrade_preflight(
    request: PreflightRequest<'_>,
) -> Result<PreflightPlan, PreflightFault> {
    let running = check_snapshot(request.running)?;
    let candidate = check_snapshot(request.candidate)?;
    if candidate.writer != WriterKind::RustNative {
        return Err(PreflightFault::ForbiddenWriter);
    }
    check_schema_relationship(request.intent, &running.schema, &candidate.schema)?;
    let format_switch = running.restore_format.format_id != candidate.restore_format.format_id;
    let need_restore_build =
        check_restore_format(request.intent, format_switch, &running, &candidate)?;
    check_direction(request.intent, &running, &candidate)?;
    if request.intent == OperationIntent::EmergencyRollback
        && !request.proof_claims.rollback_authorization_described
    {
        return Err(PreflightFault::MissingRollbackAuthorization);
    }

    if request.intent == OperationIntent::EmergencyRollback {
        let previous = request
            .previous_build
            .ok_or(PreflightFault::InconsistentFacts)?;
        // Full equality includes component digests, protocol, schema and restore-build identity.
        if previous != request.candidate
            || previous.writer != WriterKind::RustNative
            || request.rollback_schema != request.running.schema.checksum
        {
            return Err(PreflightFault::InconsistentFacts);
        }
    } else if request.previous_build.is_some() || request.rollback_schema.is_some() {
        return Err(PreflightFault::InconsistentFacts);
    }
    let mut actions = BTreeSet::new();
    actions.insert(PendingAction::VerifySignatures);
    actions.insert(PendingAction::Notarize);
    actions.insert(PendingAction::VerifyResourceIntegrity);
    actions.insert(PendingAction::AtomicSwitch);
    if candidate.schema.migrations.len() > running.schema.migrations.len() {
        actions.insert(PendingAction::ApplyExpandMigrations);
    }
    if candidate.majors.postgres > running.majors.postgres {
        actions.insert(PendingAction::PostgresMajorUpgrade);
    }
    if request.intent == OperationIntent::EmergencyRollback {
        actions.insert(PendingAction::VerifyRollbackAuthorization);
    }
    if need_restore_build {
        actions.insert(PendingAction::VerifyRestoreBuild);
    }
    if actions.len() > MAX_PENDING_ACTIONS {
        return Err(PreflightFault::CountOutOfBounds);
    }

    let _ = request.proof_claims.signature_described_valid;
    let _ = request.proof_claims.notarization_described_valid;

    Ok(PreflightPlan {
        running: request.running.clone(),
        candidate: request.candidate.clone(),
        previous_build: request.previous_build.cloned(),
        rollback_schema: request.rollback_schema,
        intent: request.intent,
        pending_actions: actions.into_iter().collect(),
        pending_proofs: PendingProofs::for_plan(request.intent, need_restore_build),
    })
}

fn check_snapshot(snapshot: &ReleaseSnapshot) -> Result<CheckedSnapshot, PreflightFault> {
    let components = check_components(&snapshot.components)?;
    check_majors(snapshot.majors)?;
    check_startup(&snapshot.startup, components.epoch)?;
    let schema = check_schema(&snapshot.schema)?;
    let restore_format = check_restore_format_claim(&snapshot.restore_format)?;
    let restore_build = match &snapshot.restore_build {
        None => None,
        Some(build) => Some(check_restore_build(build)?),
    };
    if let Some(build) = &restore_build {
        if build.format_id != restore_format.format_id {
            return Err(PreflightFault::RestoreBuildFormatMismatch);
        }
        if !build.described_runnable {
            return Err(PreflightFault::RestoreBuildMissing);
        }
    }
    Ok(CheckedSnapshot {
        core_identity: snapshot.startup.core_identity,
        components,
        majors: snapshot.majors,
        schema,
        restore_format,
        restore_build,
        writer: snapshot.writer,
    })
}

fn check_components(claim: &ComponentSetClaim) -> Result<CheckedComponents, PreflightFault> {
    let entries = &claim.entries;
    if entries.len() > MAX_COMPONENTS {
        return Err(PreflightFault::CountOutOfBounds);
    }
    if entries.is_empty() {
        return Err(PreflightFault::MissingComponent);
    }

    let mut by_name: [Option<&ComponentRev>; 4] = [None, None, None, None];
    let mut digests = BTreeSet::new();
    let mut epoch = None;
    for item in entries {
        check_identity(&item.name)?;
        let index = match item.name.as_str() {
            "application" => 0,
            "postgres" => 1,
            "engine" => 2,
            "ui" => 3,
            _ => return Err(PreflightFault::UnknownComponent),
        };
        if by_name[index].is_some() {
            return Err(PreflightFault::DuplicateComponent);
        }
        if item.epoch == 0 {
            return Err(PreflightFault::StartupFactMissing);
        }
        match epoch {
            None => epoch = Some(item.epoch),
            Some(existing) if existing != item.epoch => {
                return Err(PreflightFault::MixedReleaseEpoch);
            }
            Some(_) => {}
        }
        if !digests.insert(item.digest) {
            return Err(PreflightFault::DigestContradiction);
        }
        by_name[index] = Some(item);
    }

    let [Some(application), Some(postgres), Some(engine), Some(ui)] = by_name else {
        return Err(PreflightFault::MissingComponent);
    };
    Ok(CheckedComponents {
        set: CompatibilitySet {
            application: application.clone(),
            postgres: postgres.clone(),
            engine: engine.clone(),
            ui: ui.clone(),
        },
        epoch: epoch.ok_or(PreflightFault::StartupFactMissing)?,
    })
}

fn check_majors(majors: ReleaseMajors) -> Result<(), PreflightFault> {
    if majors.rust_core == 0 || majors.tauri == 0 || majors.electron == 0 || majors.postgres == 0 {
        return Err(PreflightFault::MajorInvalid);
    }
    Ok(())
}

fn check_startup(facts: &StartupFacts, component_epoch: u32) -> Result<(), PreflightFault> {
    if facts.protocol == 0 || facts.sidecar_protocol == 0 || facts.release_epoch == 0 {
        return Err(PreflightFault::StartupFactMissing);
    }
    if facts.core_identity == 0 || facts.minimum_compatible_core == 0 {
        return Err(PreflightFault::StartupFactMissing);
    }
    if facts.protocol != facts.sidecar_protocol {
        return Err(PreflightFault::ProtocolContradiction);
    }
    if facts.release_epoch != component_epoch {
        return Err(PreflightFault::ReleaseEpochContradiction);
    }
    if facts.minimum_compatible_core > facts.core_identity {
        return Err(PreflightFault::MinimumCoreIncompatible);
    }
    match facts.compatibility_range {
        CompatibilityRange::Unknown => return Err(PreflightFault::UnknownCompatibilityRange),
        CompatibilityRange::Unbounded => return Err(PreflightFault::UnboundedCompatibilityRange),
        CompatibilityRange::Inclusive { min_core, max_core } => {
            if min_core > max_core {
                return Err(PreflightFault::InconsistentFacts);
            }
            if facts.core_identity < min_core || facts.core_identity > max_core {
                return Err(PreflightFault::MinimumCoreIncompatible);
            }
            if facts.minimum_compatible_core < min_core {
                return Err(PreflightFault::MinimumCoreIncompatible);
            }
        }
    }
    Ok(())
}

fn check_schema(claim: &SchemaInventoryClaim) -> Result<CheckedSchema, PreflightFault> {
    if claim.scope.is_empty() {
        return Err(PreflightFault::SchemaScopeMissing);
    }
    check_identity(&claim.scope)?;
    let checksum = claim
        .checksum
        .ok_or(PreflightFault::SchemaChecksumMissing)?;
    if claim.migrations.len() > MAX_MIGRATIONS {
        return Err(PreflightFault::CountOutOfBounds);
    }
    if claim.migrations.is_empty() {
        return Err(PreflightFault::InputEmpty);
    }
    let mut names = BTreeSet::new();
    let mut migrations = Vec::with_capacity(claim.migrations.len());
    for item in &claim.migrations {
        check_identity(&item.name)?;
        if !names.insert(item.name.as_str()) {
            return Err(PreflightFault::InputDuplicate);
        }
        let digest = item
            .checksum
            .ok_or(PreflightFault::MigrationChecksumMissing)?;
        if !item.change.is_expand() {
            return Err(PreflightFault::SchemaChangeNotExpand);
        }
        migrations.push(CheckedMigration {
            name: item.name.clone(),
            checksum: digest,
            change: item.change,
        });
    }
    Ok(CheckedSchema {
        scope: claim.scope.clone(),
        checksum,
        migrations,
    })
}

fn check_restore_format_claim(
    claim: &RestoreFormatClaim,
) -> Result<CheckedRestoreFormat, PreflightFault> {
    check_identity(&claim.format_id)?;
    let previous = match &claim.compatible_previous {
        CompatiblePreviousClaim::Unknown => return Err(PreflightFault::RestoreFormatUnknown),
        CompatiblePreviousClaim::None => CheckedPrevious::None,
        CompatiblePreviousClaim::Identified { format_id } => {
            check_identity(format_id)?;
            CheckedPrevious::Identified(format_id.clone())
        }
    };
    Ok(CheckedRestoreFormat {
        format_id: claim.format_id.clone(),
        previous,
    })
}

fn check_restore_build(claim: &RestoreBuildClaim) -> Result<CheckedRestoreBuild, PreflightFault> {
    check_identity(&claim.format_id)?;
    Ok(CheckedRestoreBuild {
        format_id: claim.format_id.clone(),
        described_runnable: claim.described_runnable,
    })
}

fn check_schema_relationship(
    intent: OperationIntent,
    running: &CheckedSchema,
    candidate: &CheckedSchema,
) -> Result<(), PreflightFault> {
    if running.scope != candidate.scope {
        return Err(PreflightFault::SchemaScopeDrift);
    }
    match intent {
        OperationIntent::Upgrade | OperationIntent::RestoreFormatSwitch => {
            assert_prefix(running, candidate)?;
        }
        OperationIntent::EmergencyRollback => {
            assert_prefix(candidate, running)?;
        }
    }
    if running.migrations.len() == candidate.migrations.len()
        && running.checksum != candidate.checksum
    {
        return Err(PreflightFault::InconsistentFacts);
    }
    if running.migrations.len() != candidate.migrations.len()
        && running.checksum == candidate.checksum
    {
        return Err(PreflightFault::InconsistentFacts);
    }
    Ok(())
}

fn assert_prefix(prefix: &CheckedSchema, full: &CheckedSchema) -> Result<(), PreflightFault> {
    if prefix.migrations.len() > full.migrations.len() {
        return Err(PreflightFault::MigrationNameDrift);
    }
    for (older, newer) in prefix.migrations.iter().zip(full.migrations.iter()) {
        if older.name != newer.name {
            return Err(PreflightFault::MigrationNameDrift);
        }
        if older.checksum != newer.checksum {
            return Err(PreflightFault::MigrationChecksumDrift);
        }
        if older.change != newer.change {
            return Err(PreflightFault::InconsistentFacts);
        }
    }
    for extra in full.migrations.iter().skip(prefix.migrations.len()) {
        if !extra.change.is_expand() {
            return Err(PreflightFault::SchemaChangeNotExpand);
        }
    }
    Ok(())
}

fn check_restore_format(
    intent: OperationIntent,
    format_switch: bool,
    running: &CheckedSnapshot,
    candidate: &CheckedSnapshot,
) -> Result<bool, PreflightFault> {
    if intent == OperationIntent::EmergencyRollback {
        return Ok(false);
    }
    if intent == OperationIntent::RestoreFormatSwitch && !format_switch {
        return Err(PreflightFault::InconsistentFacts);
    }
    if !format_switch {
        return Ok(false);
    }

    let has_compatible_previous = match &candidate.restore_format.previous {
        CheckedPrevious::Identified(previous) if previous == &running.restore_format.format_id => {
            true
        }
        CheckedPrevious::Identified(_) => return Err(PreflightFault::RestoreFormatUnknown),
        CheckedPrevious::None => false,
    };

    if has_compatible_previous {
        return Ok(matches!(
            &candidate.restore_build,
            Some(build) if build.format_id == candidate.restore_format.format_id
        ));
    }

    match &candidate.restore_build {
        None => Err(PreflightFault::RestoreBuildMissing),
        Some(build) if build.format_id != candidate.restore_format.format_id => {
            Err(PreflightFault::RestoreBuildFormatMismatch)
        }
        Some(build) if !build.described_runnable => Err(PreflightFault::RestoreBuildMissing),
        Some(_) => Ok(true),
    }
}

fn check_direction(
    intent: OperationIntent,
    running: &CheckedSnapshot,
    candidate: &CheckedSnapshot,
) -> Result<(), PreflightFault> {
    let pg_major = candidate.majors.postgres != running.majors.postgres;
    let tauri_major = candidate.majors.tauri != running.majors.tauri;
    let electron_major = candidate.majors.electron != running.majors.electron;

    match intent {
        OperationIntent::Upgrade | OperationIntent::RestoreFormatSwitch => {
            if candidate.core_identity < running.core_identity
                || candidate.components.epoch < running.components.epoch
                || candidate.majors.rust_core < running.majors.rust_core
                || candidate.majors.tauri < running.majors.tauri
                || candidate.majors.electron < running.majors.electron
                || candidate.majors.postgres < running.majors.postgres
            {
                return Err(PreflightFault::OrdinaryDowngrade);
            }
            if pg_major && tauri_major {
                return Err(PreflightFault::PgMajorWithTauriMajor);
            }
            if pg_major && electron_major {
                return Err(PreflightFault::PgMajorWithElectronMajor);
            }
            Ok(())
        }
        OperationIntent::EmergencyRollback => {
            if running.writer != WriterKind::RustNative {
                return Err(PreflightFault::ForbiddenWriter);
            }
            if candidate.core_identity > running.core_identity
                || candidate.components.epoch > running.components.epoch
                || candidate.majors.rust_core > running.majors.rust_core
            {
                return Err(PreflightFault::InconsistentFacts);
            }
            if pg_major || tauri_major || electron_major {
                return Err(PreflightFault::InconsistentFacts);
            }
            if candidate.components.epoch == running.components.epoch
                && candidate.majors == running.majors
                && candidate.components.set == running.components.set
            {
                return Err(PreflightFault::InconsistentFacts);
            }
            if candidate.restore_format.format_id != running.restore_format.format_id {
                match &running.restore_format.previous {
                    CheckedPrevious::Identified(previous)
                        if previous == &candidate.restore_format.format_id => {}
                    _ => return Err(PreflightFault::RestoreFormatUnknown),
                }
            }
            Ok(())
        }
    }
}

fn check_identity(value: &str) -> Result<(), PreflightFault> {
    if value.is_empty() {
        return Err(PreflightFault::InputEmpty);
    }
    if value.len() > MAX_ID_BYTES {
        return Err(PreflightFault::InputTooLong);
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
    {
        return Err(PreflightFault::IdentityInvalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::of(label.as_bytes())
    }

    fn rev(name: &str, epoch: u32) -> ComponentRev {
        ComponentRev {
            name: name.to_owned(),
            epoch,
            digest: digest(name),
        }
    }

    fn named(epoch: u32) -> ComponentSetClaim {
        ComponentSetClaim::from_set(CompatibilitySet {
            application: rev("application", epoch),
            postgres: rev("postgres", epoch),
            engine: rev("engine", epoch),
            ui: rev("ui", epoch),
        })
    }

    fn majors() -> ReleaseMajors {
        ReleaseMajors {
            rust_core: 1,
            tauri: 2,
            electron: 43,
            postgres: 17,
        }
    }

    fn startup(epoch: u32, protocol: u32) -> StartupFacts {
        StartupFacts {
            protocol,
            sidecar_protocol: protocol,
            release_epoch: epoch,
            core_identity: 10,
            minimum_compatible_core: 8,
            compatibility_range: CompatibilityRange::Inclusive {
                min_core: 8,
                max_core: 12,
            },
        }
    }

    fn schema() -> SchemaInventoryClaim {
        SchemaInventoryClaim {
            scope: "public".to_owned(),
            checksum: Some(digest("schema-v1")),
            migrations: vec![MigrationClaim {
                name: "native_0031_model_snapshot".to_owned(),
                checksum: Some(digest("m31")),
                change: SchemaChangeKind::NewTable,
            }],
        }
    }

    fn restore_format() -> RestoreFormatClaim {
        RestoreFormatClaim {
            format_id: "restore-v1".to_owned(),
            compatible_previous: CompatiblePreviousClaim::Identified {
                format_id: "restore-v0".to_owned(),
            },
        }
    }

    fn snapshot(epoch: u32, protocol: u32) -> ReleaseSnapshot {
        ReleaseSnapshot {
            components: named(epoch),
            majors: majors(),
            startup: startup(epoch, protocol),
            schema: schema(),
            restore_format: restore_format(),
            restore_build: None,
            writer: WriterKind::RustNative,
        }
    }

    fn claims() -> ProofClaims {
        ProofClaims {
            signature_described_valid: true,
            notarization_described_valid: true,
            rollback_authorization_described: true,
        }
    }

    #[test]
    fn protocol_four_release_epoch_five_are_not_frozen_against_upgrade() {
        let running = snapshot(5, 4);
        let mut candidate = snapshot(6, 5);
        candidate.components = named(6);
        candidate.startup.release_epoch = 6;
        candidate.startup.protocol = 5;
        candidate.startup.sidecar_protocol = 5;
        let plan = plan_upgrade_preflight(PreflightRequest {
            previous_build: None,
            rollback_schema: None,
            intent: OperationIntent::Upgrade,
            running: &running,
            candidate: &candidate,
            proof_claims: &claims(),
        })
        .expect("epoch 5 / protocol 4 must remain upgradable");
        assert_eq!(plan.intent(), OperationIntent::Upgrade);
        assert_eq!(
            plan.pending_proofs().install_authorized(),
            ProofStatus::NotGranted
        );
    }

    #[test]
    fn success_plan_never_grants_install_rollback_or_restore_authorization() {
        let running = snapshot(5, 4);
        let mut candidate = snapshot(5, 4);
        candidate.components = ComponentSetClaim::from_set(CompatibilitySet {
            application: ComponentRev {
                name: "application".to_owned(),
                epoch: 5,
                digest: digest("application-security"),
            },
            postgres: rev("postgres", 5),
            engine: rev("engine", 5),
            ui: rev("ui", 5),
        });
        let plan = plan_upgrade_preflight(PreflightRequest {
            previous_build: None,
            rollback_schema: None,
            intent: OperationIntent::Upgrade,
            running: &running,
            candidate: &candidate,
            proof_claims: &claims(),
        })
        .expect("security expand");
        let proofs = plan.pending_proofs();
        assert_eq!(proofs.install_authorized(), ProofStatus::NotGranted);
        assert_eq!(proofs.rollback_authorized(), ProofStatus::NotGranted);
        assert_eq!(proofs.restore_authorized(), ProofStatus::NotGranted);
        assert_eq!(proofs.signature_verification(), ProofStatus::Pending);
        assert!(
            plan.pending_actions()
                .contains(&PendingAction::VerifySignatures)
        );
        assert!(
            plan.pending_actions()
                .iter()
                .all(|action| !action.as_str().contains("SQL") && !action.as_str().contains("DROP"))
        );
    }

    #[test]
    fn zero_major_is_rejected() {
        let running = snapshot(5, 4);
        let mut candidate = snapshot(5, 4);
        candidate.majors.postgres = 0;
        assert_eq!(
            plan_upgrade_preflight(PreflightRequest {
                previous_build: None,
                rollback_schema: None,
                intent: OperationIntent::Upgrade,
                running: &running,
                candidate: &candidate,
                proof_claims: &claims(),
            }),
            Err(PreflightFault::MajorInvalid)
        );
    }

    #[test]
    fn inclusive_range_with_min_greater_than_max_is_inconsistent() {
        let running = snapshot(5, 4);
        let mut candidate = snapshot(5, 4);
        candidate.startup.compatibility_range = CompatibilityRange::Inclusive {
            min_core: 12,
            max_core: 8,
        };
        assert_eq!(
            plan_upgrade_preflight(PreflightRequest {
                previous_build: None,
                rollback_schema: None,
                intent: OperationIntent::Upgrade,
                running: &running,
                candidate: &candidate,
                proof_claims: &claims(),
            }),
            Err(PreflightFault::InconsistentFacts)
        );
    }

    #[test]
    fn fault_codes_are_closed_literals() {
        assert_eq!(
            PreflightFault::OrdinaryDowngrade.as_str(),
            "upgrade_preflight_ordinary_downgrade"
        );
        assert_eq!(PendingAction::AtomicSwitch.as_str(), "atomic_switch");
    }
}
