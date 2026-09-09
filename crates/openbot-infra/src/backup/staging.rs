//! 正式 staging coordinator：预检 → 新建私有 staging → 有界读取/校验/写入 → 持久化确认。

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::backup::{PendingProofs, RestoreOutcome, StructuralRestorePlan};
use sha2::{Digest, Sha256};

use super::StagingFault;
use super::checked_fs::{
    MAX_CHUNK_BYTES, PathIdentity, bind_directory, check_dir, check_file, file_at, identity_of,
    open_dir_at, persist_file, read_next, revalidate_handle, validate_component, verify_owned_dir,
};

/// 暂存有界配置。配置不能替代运行时边界。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StagingBounds {
    max_chunk_bytes: usize,
    max_entries: u32,
    max_total_bytes: u64,
    max_entry_bytes: u64,
}

impl StagingBounds {
    /// 产品默认：单块≤4MiB。
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            max_chunk_bytes: MAX_CHUNK_BYTES,
            max_entries: 4_096,
            max_total_bytes: 4 * 1024 * 1024 * 1024,
            max_entry_bytes: 64 * 1024 * 1024,
        }
    }

    /// 更紧的测试边界。块大小必须落在 1..=4MiB。
    #[must_use]
    pub fn try_new(
        max_chunk_bytes: usize,
        max_entries: u32,
        max_total_bytes: u64,
        max_entry_bytes: u64,
    ) -> Option<Self> {
        if max_chunk_bytes == 0
            || max_chunk_bytes > MAX_CHUNK_BYTES
            || max_entries == 0
            || max_total_bytes == 0
            || max_entry_bytes == 0
        {
            return None;
        }
        Some(Self {
            max_chunk_bytes,
            max_entries,
            max_total_bytes,
            max_entry_bytes,
        })
    }

    /// 单块上限。
    #[must_use]
    pub const fn max_chunk_bytes(self) -> usize {
        self.max_chunk_bytes
    }
}

/// 取消标志。每个阶段都检查。
#[derive(Debug)]
pub struct CancelFlag {
    cancelled: AtomicBool,
}

impl Default for CancelFlag {
    fn default() -> Self {
        Self::new()
    }
}

impl CancelFlag {
    /// 未取消。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
        }
    }

    /// 请求取消。
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// 是否已取消。
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    fn check(&self) -> Result<(), StagingFault> {
        if self.is_cancelled() {
            Err(StagingFault::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// 单块。coordinator 同时只持有一块。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chunk {
    sequence: u32,
    payload: Vec<u8>,
    terminal: bool,
}

impl Chunk {
    /// 构造一块。超过 4MiB 拒绝。
    ///
    /// # Errors
    ///
    /// 块太大时返回 [`StagingFault::ChunkTooLarge`]。
    pub fn try_new(sequence: u32, payload: Vec<u8>, terminal: bool) -> Result<Self, StagingFault> {
        if payload.len() > MAX_CHUNK_BYTES {
            return Err(StagingFault::ChunkTooLarge);
        }
        Ok(Self {
            sequence,
            payload,
            terminal,
        })
    }

    /// 序号。
    #[must_use]
    pub fn sequence(&self) -> u32 {
        self.sequence
    }

    /// 载荷。
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// 是否终态块。
    #[must_use]
    pub fn terminal(&self) -> bool {
        self.terminal
    }
}

/// 条目流。一次只产出下一块。
pub trait EntryStream {
    /// 下一块。`None` 表示流结束（必须已经见过终态块）。
    ///
    /// # Errors
    ///
    /// 源流非法或 I/O 失败。
    fn next_chunk(&mut self) -> Result<Option<Chunk>, StagingFault>;
}

/// 材料源端口。
pub trait MaterialSource {
    /// 按已核材料 id 打开流。
    ///
    /// # Errors
    ///
    /// 未登记、路径非法或打开失败。
    fn open_entry(&mut self, id: &str) -> Result<Box<dyn EntryStream>, StagingFault>;
}

/// 单次写入失败。`confirmed_bytes` 是本调用已确认写入的前缀，不是猜测的 0。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SinkWriteError {
    fault: StagingFault,
    confirmed_bytes: u64,
}

impl SinkWriteError {
    /// 构造。`confirmed_bytes` 为本次调用已确认前缀。
    #[must_use]
    pub const fn new(fault: StagingFault, confirmed_bytes: u64) -> Self {
        Self {
            fault,
            confirmed_bytes,
        }
    }

    /// 失败分类。
    #[must_use]
    pub const fn fault(&self) -> StagingFault {
        self.fault
    }

    /// 本调用已确认写入的字节。
    #[must_use]
    pub const fn confirmed_bytes(&self) -> u64 {
        self.confirmed_bytes
    }
}

/// 文件写入端口。
pub trait FileSink {
    /// 写入一块。成功返回本调用确认字节；失败带已确认前缀。
    ///
    /// # Errors
    ///
    /// 写失败或容量耗尽。
    fn write(&mut self, bytes: &[u8]) -> Result<u64, SinkWriteError>;
    /// 持久化。
    ///
    /// # Errors
    ///
    /// sync 失败或句柄被替换。
    fn persist(&mut self, expected_len: u64, limit: u64) -> Result<(), StagingFault>;
}

/// 受控目录。身份私有，不能由外部 dev/ino 字段伪造。
#[derive(Clone, Debug)]
pub struct OwnedDir {
    handle: Arc<File>,
    path: PathBuf,
    identity: PathIdentity,
}

impl OwnedDir {
    /// 路径只作显示/对照，不构成删除或写入授权。
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.path
    }
}

/// 受控普通文件。身份私有。
#[derive(Clone, Debug)]
pub struct OwnedFile {
    handle: Arc<File>,
    path: PathBuf,
    identity: PathIdentity,
}

impl OwnedFile {
    /// 路径只作显示/对照，不构成删除授权。
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.path
    }
}

/// 文件系统端口。创建/删除/sync 必须在同一次操作里核归属。
pub trait FsPort {
    /// 绑定已存在的普通目录。
    ///
    /// # Errors
    ///
    /// 不是普通目录或无法证明身份。
    fn bind_dir(&self, path: &Path) -> Result<OwnedDir, StagingFault>;
    /// 在已绑定父目录下新建私有子目录。
    ///
    /// # Errors
    ///
    /// 父目录被替换、已存在或创建失败。
    fn create_private_dir(&self, parent: &OwnedDir, name: &str) -> Result<OwnedDir, StagingFault>;
    /// 在已绑定父目录下 no-clobber 新建文件。
    ///
    /// # Errors
    ///
    /// 父目录被替换、已存在或创建失败。
    fn create_file_noclobber(
        &self,
        parent: &OwnedDir,
        name: &str,
    ) -> Result<(OwnedFile, Box<dyn FileSink>), StagingFault>;
    /// 按已绑定身份 fsync 目录。
    ///
    /// # Errors
    ///
    /// 身份不符或 sync 失败。
    fn sync_dir(&self, dir: &OwnedDir) -> Result<(), StagingFault>;
    /// 在已绑定父目录下检查子名是否存在。
    ///
    /// # Errors
    ///
    /// 父目录被替换或检查失败。
    fn child_exists(&self, parent: &OwnedDir, name: &str) -> Result<bool, StagingFault>;
    /// 删除已绑定普通文件。父目录与文件身份在本次调用内核验。
    ///
    /// # Errors
    ///
    /// 身份不符或删除失败。不符时不得删除未知对象。
    fn remove_file(&self, parent: &OwnedDir, file: &OwnedFile) -> Result<(), StagingFault>;
    /// 删除已绑定空目录。
    ///
    /// # Errors
    ///
    /// 身份不符、非空或删除失败。
    fn remove_dir(&self, parent: &OwnedDir, dir: &OwnedDir) -> Result<(), StagingFault>;
}

/// 真实 OS 文件系统。
#[derive(Clone, Copy, Debug, Default)]
pub struct StdFs;

struct StdFileSink {
    file: File,
}

fn write_counted(file: &mut File, bytes: &[u8]) -> Result<u64, SinkWriteError> {
    let mut done = 0_usize;
    while done < bytes.len() {
        match file.write(&bytes[done..]) {
            Ok(0) => {
                return Err(SinkWriteError::new(StagingFault::WriteFailed, done as u64));
            }
            Ok(n) => done += n,
            Err(err) => {
                return Err(SinkWriteError::new(
                    super::checked_fs::io_fail(err, true),
                    done as u64,
                ));
            }
        }
    }
    Ok(done as u64)
}

impl FileSink for StdFileSink {
    fn write(&mut self, bytes: &[u8]) -> Result<u64, SinkWriteError> {
        write_counted(&mut self.file, bytes)
    }

    fn persist(&mut self, expected_len: u64, limit: u64) -> Result<(), StagingFault> {
        persist_file(&mut self.file, expected_len, limit)
    }
}

fn child_path(parent: &OwnedDir, name: &str) -> Result<PathBuf, StagingFault> {
    validate_component(name)?;
    Ok(parent.path.join(name))
}

impl FsPort for StdFs {
    fn bind_dir(&self, path: &Path) -> Result<OwnedDir, StagingFault> {
        let handle = Arc::new(bind_directory(path)?);
        let identity = identity_of(&handle.metadata().map_err(|_| StagingFault::OpenFailed)?)?;
        Ok(OwnedDir {
            handle,
            path: path.to_path_buf(),
            identity,
        })
    }
    fn create_private_dir(&self, parent: &OwnedDir, name: &str) -> Result<OwnedDir, StagingFault> {
        let path = child_path(parent, name)?;
        verify_owned_dir(
            &parent.path,
            parent.identity,
            StagingFault::DestinationReplaced,
        )?;
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, mkdirat};
            mkdirat(
                parent.handle.as_ref(),
                name,
                Mode::RUSR | Mode::WUSR | Mode::XUSR,
            )
            .map_err(|e| {
                if e == rustix::io::Errno::EXIST {
                    StagingFault::StagingExists
                } else {
                    StagingFault::WriteFailed
                }
            })?;
            let handle = Arc::new(open_dir_at(&parent.handle, std::ffi::OsStr::new(name))?);
            let metadata = handle.metadata().map_err(|_| StagingFault::OpenFailed)?;
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o777 != 0o700 {
                return Err(StagingFault::ParentUnsafe);
            }
            Ok(OwnedDir {
                identity: identity_of(&metadata)?,
                handle,
                path,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(StagingFault::OsBindingUnprovable)
        }
    }
    fn create_file_noclobber(
        &self,
        parent: &OwnedDir,
        name: &str,
    ) -> Result<(OwnedFile, Box<dyn FileSink>), StagingFault> {
        let path = child_path(parent, name)?;
        verify_owned_dir(
            &parent.path,
            parent.identity,
            StagingFault::DestinationReplaced,
        )?;
        // Only this descriptor, never parent.path, participates in the actual create syscall.
        let file = file_at(&parent.handle, std::ffi::OsStr::new(name), true, 0)?;
        let identity = identity_of(&file.metadata().map_err(|_| StagingFault::OpenFailed)?)?;
        let handle = Arc::new(file.try_clone().map_err(|_| StagingFault::OpenFailed)?);
        Ok((
            OwnedFile {
                handle,
                path,
                identity,
            },
            Box::new(StdFileSink { file }),
        ))
    }
    fn sync_dir(&self, dir: &OwnedDir) -> Result<(), StagingFault> {
        check_dir(
            &dir.handle
                .metadata()
                .map_err(|_| StagingFault::SyncFailed)?,
        )?;
        dir.handle.sync_all().map_err(|_| StagingFault::SyncFailed)
    }
    fn child_exists(&self, parent: &OwnedDir, name: &str) -> Result<bool, StagingFault> {
        validate_component(name)?;
        #[cfg(unix)]
        {
            match rustix::fs::statat(
                parent.handle.as_ref(),
                name,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            ) {
                Ok(_) => Ok(true),
                Err(rustix::io::Errno::NOENT) => Ok(false),
                Err(_) => Err(StagingFault::OpenFailed),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = parent;
            Err(StagingFault::OsBindingUnprovable)
        }
    }
    fn remove_file(&self, _parent: &OwnedDir, _file: &OwnedFile) -> Result<(), StagingFault> {
        // unlinkat binds the parent but cannot atomically compare-and-unlink the leaf inode.
        // Keep failed staging as explicit residue; never delete an object that may be replaced.
        Err(StagingFault::OsBindingUnprovable)
    }
    fn remove_dir(&self, _parent: &OwnedDir, _dir: &OwnedDir) -> Result<(), StagingFault> {
        Err(StagingFault::OsBindingUnprovable)
    }
}

/// 暂存请求：在已有父目录下新建唯一 slot，不复用。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagingRequest {
    /// 已存在的父目录。
    pub parent: PathBuf,
    /// 单个相对分量，不得已存在。
    pub slot: String,
}

/// coordinator 输入。
pub struct StagingInput<'a> {
    /// domain 计划结果。非结构计划时写入数 0。
    pub outcome: &'a RestoreOutcome,
    /// 材料源。
    pub source: &'a mut dyn MaterialSource,
    /// 目标。
    pub request: &'a StagingRequest,
    /// 取消。
    pub cancel: &'a CancelFlag,
    /// 文件系统。
    pub fs: &'a dyn FsPort,
    /// 运行时边界。
    pub bounds: StagingBounds,
}

/// 清理结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CleanupReport {
    /// 尚未创建 staging。
    NotCreated,
    /// 已确认删除本次 staging。
    Removed,
    /// 无法确认清理，保留路径供人工处理。
    Residue {
        /// 残留目录。
        staging_path: PathBuf,
    },
}

/// 暂存成功。不是恢复授权。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagingCompleted {
    staging_path: PathBuf,
    files_written: u32,
    bytes_read: u64,
    bytes_written: u64,
    digest_integrity: bool,
    pending: PendingProofs,
}

impl StagingCompleted {
    /// staging 根。
    #[must_use]
    pub fn staging_path(&self) -> &Path {
        &self.staging_path
    }

    /// 成功写入的文件数。
    #[must_use]
    pub fn files_written(&self) -> u32 {
        self.files_written
    }

    /// 实际读取字节。
    #[must_use]
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// 实际写入字节。
    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// 结构摘要是否与清单声明相符。不是 AEAD。
    #[must_use]
    pub fn digest_integrity(&self) -> bool {
        self.digest_integrity
    }

    /// 待验证明（AEAD/PG/canary/切换/Ready 均未授予）。
    #[must_use]
    pub fn pending_proofs(&self) -> PendingProofs {
        self.pending
    }

    /// 不授予恢复切换。
    #[must_use]
    pub const fn grants_restore_switch(&self) -> bool {
        false
    }

    /// 不授予 Application Ready。
    #[must_use]
    pub const fn application_ready(&self) -> bool {
        false
    }

    /// 没有 `verified=true` 的真实性证明。
    #[must_use]
    pub const fn aead_authenticated(&self) -> bool {
        false
    }
}

/// 暂存失败。原现场保持。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagingFailure {
    fault: StagingFault,
    files_written: u32,
    bytes_written: u64,
    original_site_preserved: bool,
    cleanup: CleanupReport,
}

impl StagingFailure {
    /// 失败分类。
    #[must_use]
    pub fn fault(&self) -> StagingFault {
        self.fault
    }

    /// 失败前已写入文件数。
    #[must_use]
    pub fn files_written(&self) -> u32 {
        self.files_written
    }

    /// 失败前已写入字节。
    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// 原现场是否保持。本批写入只发生在新 staging。
    #[must_use]
    pub fn original_site_preserved(&self) -> bool {
        self.original_site_preserved
    }

    /// 清理报告。
    #[must_use]
    pub fn cleanup(&self) -> &CleanupReport {
        &self.cleanup
    }
}

/// coordinator 结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StagingOutcome {
    /// 暂存完成，后续证明仍待验。
    Completed(StagingCompleted),
    /// 失败。
    Failed(StagingFailure),
}

impl StagingOutcome {
    /// 写入文件数。
    #[must_use]
    pub fn files_written(&self) -> u32 {
        match self {
            Self::Completed(done) => done.files_written,
            Self::Failed(fail) => fail.files_written,
        }
    }
}

/// 正式入口。
#[must_use]
pub fn run_staging(input: StagingInput<'_>) -> StagingOutcome {
    match run_staging_inner(input) {
        Ok(done) => StagingOutcome::Completed(done),
        Err(fail) => StagingOutcome::Failed(fail),
    }
}

fn fail(
    fault: StagingFault,
    files_written: u32,
    bytes_written: u64,
    cleanup: CleanupReport,
    unbound_mutation: bool,
) -> StagingFailure {
    StagingFailure {
        fault,
        files_written,
        bytes_written,
        original_site_preserved: !unbound_mutation,
        cleanup,
    }
}

fn run_staging_inner(input: StagingInput<'_>) -> Result<StagingCompleted, StagingFailure> {
    let StagingInput {
        outcome,
        source,
        request,
        cancel,
        fs,
        bounds,
    } = input;
    let RestoreOutcome::StructuralPlan(plan) = outcome else {
        return Err(fail(
            StagingFault::PlanNotStructural,
            0,
            0,
            CleanupReport::NotCreated,
            false,
        ));
    };
    let parent = match fs.bind_dir(&request.parent) {
        Ok(dir) => dir,
        Err(fault) => {
            return Err(fail(fault, 0, 0, CleanupReport::NotCreated, false));
        }
    };
    if let Err(fault) = precheck(plan, request, fs, &parent, cancel, bounds) {
        return Err(fail(fault, 0, 0, CleanupReport::NotCreated, false));
    }
    let root = match fs.create_private_dir(&parent, &request.slot) {
        Ok(dir) => dir,
        Err(fault) => {
            return Err(fail(fault, 0, 0, CleanupReport::NotCreated, false));
        }
    };
    let mut created = CreatedSet {
        slot: request.slot.clone(),
        parent,
        root,
        dirs: Vec::new(),
        files: Vec::new(),
        unbound_mutation: false,
    };
    match write_entries(plan, source, fs, cancel, bounds, &mut created) {
        Ok(done) => Ok(done),
        Err((fault, files_written, bytes_written)) => {
            let unbound = created.unbound_mutation;
            let cleanup = cleanup_owned(fs, &created);
            Err(fail(fault, files_written, bytes_written, cleanup, unbound))
        }
    }
}

struct TrackedDir {
    dir: OwnedDir,
    relative: String,
}

struct CreatedFile {
    parent: OwnedDir,
    file: OwnedFile,
    relative: String,
}

struct CreatedSet {
    slot: String,
    parent: OwnedDir,
    root: OwnedDir,
    dirs: Vec<TrackedDir>,
    files: Vec<CreatedFile>,
    unbound_mutation: bool,
}

fn precheck(
    plan: &StructuralRestorePlan,
    request: &StagingRequest,
    fs: &dyn FsPort,
    parent: &OwnedDir,
    cancel: &CancelFlag,
    bounds: StagingBounds,
) -> Result<(), StagingFault> {
    cancel.check()?;
    validate_slot(&request.slot)?;
    if fs.child_exists(parent, &request.slot)? {
        return Err(StagingFault::StagingExists);
    }
    let entries =
        u32::try_from(plan.materials().len()).map_err(|_| StagingFault::PrecheckRejected)?;
    if entries > bounds.max_entries {
        return Err(StagingFault::PrecheckRejected);
    }
    if plan.inventory().total_declared_bytes() > bounds.max_total_bytes {
        return Err(StagingFault::CapacityExhausted);
    }
    for material in plan.materials() {
        if material.directory() {
            continue;
        }
        if material.declared_bytes() > bounds.max_entry_bytes {
            return Err(StagingFault::LengthExceeded);
        }
    }
    Ok(())
}

fn validate_slot(slot: &str) -> Result<(), StagingFault> {
    validate_component(slot)
}

fn leaf_name(relative: &str) -> Result<&str, StagingFault> {
    let name = relative
        .rsplit('/')
        .next()
        .filter(|part| !part.is_empty())
        .ok_or(StagingFault::PathInvalid)?;
    validate_component(name)?;
    Ok(name)
}

fn write_entries(
    plan: &StructuralRestorePlan,
    source: &mut dyn MaterialSource,
    fs: &dyn FsPort,
    cancel: &CancelFlag,
    bounds: StagingBounds,
    created: &mut CreatedSet,
) -> Result<StagingCompleted, (StagingFault, u32, u64)> {
    let mut files_written: u32 = 0;
    let mut bytes_read: u64 = 0;
    let mut bytes_written: u64 = 0;
    let mut seen_ids = BTreeSet::new();
    for material in plan.materials() {
        if let Err(fault) = cancel.check() {
            return Err((fault, files_written, bytes_written));
        }
        let id = material.id().as_str();
        if !seen_ids.insert(id.to_owned()) {
            return Err((
                StagingFault::UnregisteredEntry,
                files_written,
                bytes_written,
            ));
        }
        let rel = material.path().as_str();
        let parent = ensure_parents(fs, rel, created)
            .map_err(|fault| (fault, files_written, bytes_written))?;
        let name = leaf_name(rel).map_err(|fault| (fault, files_written, bytes_written))?;
        if material.directory() {
            let dir = fs
                .create_private_dir(&parent, name)
                .map_err(|fault| (fault, files_written, bytes_written))?;
            created.dirs.push(TrackedDir {
                dir,
                relative: rel.to_owned(),
            });
            continue;
        }
        let mut stream = source
            .open_entry(id)
            .map_err(|fault| (fault, files_written, bytes_written))?;
        let (file, mut sink) = fs
            .create_file_noclobber(&parent, name)
            .map_err(|fault| (fault, files_written, bytes_written))?;
        created.files.push(CreatedFile {
            parent,
            file,
            relative: rel.to_owned(),
        });
        match copy_one(
            stream.as_mut(),
            sink.as_mut(),
            material.declared_bytes(),
            material.digest(),
            bounds,
            cancel,
        ) {
            Ok(copied) => {
                bytes_read = bytes_read.checked_add(copied).ok_or((
                    StagingFault::CapacityExhausted,
                    files_written,
                    bytes_written,
                ))?;
                bytes_written = bytes_written.checked_add(copied).ok_or((
                    StagingFault::CapacityExhausted,
                    files_written,
                    bytes_written,
                ))?;
                if bytes_written > bounds.max_total_bytes {
                    return Err((
                        StagingFault::CapacityExhausted,
                        files_written,
                        bytes_written,
                    ));
                }
                files_written = files_written.checked_add(1).ok_or((
                    StagingFault::CapacityExhausted,
                    files_written,
                    bytes_written,
                ))?;
            }
            Err(progress) => {
                let total = bytes_written
                    .checked_add(progress.bytes)
                    .unwrap_or(bytes_written);
                return Err((progress.fault, files_written, total));
            }
        }
    }
    cancel
        .check()
        .map_err(|fault| (fault, files_written, bytes_written))?;
    persist_directories(fs, created).map_err(|fault| (fault, files_written, bytes_written))?;
    confirm_outputs(plan, created, bounds)
        .map_err(|fault| (fault, files_written, bytes_written))?;
    cancel
        .check()
        .map_err(|fault| (fault, files_written, bytes_written))?;
    Ok(StagingCompleted {
        staging_path: created.root.path.clone(),
        files_written,
        bytes_read,
        bytes_written,
        digest_integrity: true,
        pending: plan.pending_proofs(),
    })
}

fn ensure_parents(
    fs: &dyn FsPort,
    relative: &str,
    created: &mut CreatedSet,
) -> Result<OwnedDir, StagingFault> {
    let parts: Vec<&str> = relative.split('/').collect();
    if parts.iter().any(|part| part.is_empty()) {
        return Err(StagingFault::PathInvalid);
    }
    if parts.len() <= 1 {
        return Ok(created.root.clone());
    }
    let mut parent = created.root.clone();
    let mut acc = String::new();
    for part in &parts[..parts.len() - 1] {
        validate_component(part)?;
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(part);
        if let Some(existing) = created.dirs.iter().find(|dir| dir.relative == acc) {
            parent = existing.dir.clone();
            continue;
        }
        if fs.child_exists(&parent, part)? {
            return Err(StagingFault::StagingExists);
        }
        let dir = fs.create_private_dir(&parent, part)?;
        created.dirs.push(TrackedDir {
            dir: dir.clone(),
            relative: acc.clone(),
        });
        parent = dir;
    }
    Ok(parent)
}

struct CopyProgress {
    fault: StagingFault,
    bytes: u64,
}

fn copy_one(
    stream: &mut dyn EntryStream,
    sink: &mut dyn FileSink,
    declared: u64,
    expected_digest: Sha256Digest,
    bounds: StagingBounds,
    cancel: &CancelFlag,
) -> Result<u64, CopyProgress> {
    let fail = |fault: StagingFault, bytes: u64| CopyProgress { fault, bytes };
    let mut hasher = Sha256::new();
    let mut written: u64 = 0;
    let mut seq: u32 = 0;
    let mut terminal = false;
    loop {
        cancel.check().map_err(|fault| fail(fault, written))?;
        let Some(chunk) = stream.next_chunk().map_err(|fault| fail(fault, written))? else {
            break;
        };
        cancel.check().map_err(|fault| fail(fault, written))?;
        if terminal {
            return Err(fail(StagingFault::ExtraTail, written));
        }
        if chunk.sequence != seq {
            return Err(fail(StagingFault::Reordered, written));
        }
        if chunk.payload.len() > bounds.max_chunk_bytes || chunk.payload.len() > MAX_CHUNK_BYTES {
            return Err(fail(StagingFault::ChunkTooLarge, written));
        }
        let add = chunk.payload.len() as u64;
        let next = written
            .checked_add(add)
            .ok_or_else(|| fail(StagingFault::CapacityExhausted, written))?;
        if next > declared || next > bounds.max_entry_bytes {
            return Err(fail(StagingFault::LengthExceeded, written));
        }
        hasher.update(chunk.payload());
        match sink.write(chunk.payload()) {
            Ok(n) => {
                if n != add {
                    let total = written.checked_add(n).unwrap_or(written);
                    return Err(fail(StagingFault::WriteFailed, total));
                }
                written = next;
            }
            Err(err) => {
                let total = written
                    .checked_add(err.confirmed_bytes())
                    .unwrap_or(written);
                return Err(fail(err.fault(), total));
            }
        }
        terminal = chunk.terminal;
        seq = seq
            .checked_add(1)
            .ok_or_else(|| fail(StagingFault::CapacityExhausted, written))?;
    }
    cancel.check().map_err(|fault| fail(fault, written))?;
    if !terminal {
        return Err(fail(StagingFault::MissingTerminal, written));
    }
    if written != declared {
        return Err(fail(StagingFault::ShortRead, written));
    }
    let digest = Sha256Digest::from_bytes(hasher.finalize().into());
    if digest != expected_digest {
        return Err(fail(StagingFault::DigestMismatch, written));
    }
    sink.persist(declared, bounds.max_entry_bytes)
        .map_err(|fault| fail(fault, written))?;
    cancel.check().map_err(|fault| fail(fault, written))?;
    Ok(written)
}

fn persist_directories(fs: &dyn FsPort, created: &CreatedSet) -> Result<(), StagingFault> {
    for dir in created.dirs.iter().rev() {
        fs.sync_dir(&dir.dir)?;
    }
    fs.sync_dir(&created.root)?;
    fs.sync_dir(&created.parent)?;
    Ok(())
}

fn confirm_outputs(
    plan: &StructuralRestorePlan,
    created: &CreatedSet,
    bounds: StagingBounds,
) -> Result<(), StagingFault> {
    verify_owned_dir(
        &created.root.path,
        created.root.identity,
        StagingFault::DestinationReplaced,
    )?;
    for dir in &created.dirs {
        verify_owned_dir(
            &dir.dir.path,
            dir.dir.identity,
            StagingFault::DestinationReplaced,
        )?;
    }
    for material in plan.materials() {
        if material.directory() {
            continue;
        }
        let Some(owned) = created
            .files
            .iter()
            .find(|item| item.relative == material.path().as_str())
        else {
            return Err(StagingFault::DestinationReplaced);
        };
        let name = owned
            .file
            .path
            .file_name()
            .ok_or(StagingFault::PathInvalid)?;
        let current = file_at(&owned.parent.handle, name, false, bounds.max_entry_bytes)?;
        if identity_of(&current.metadata().map_err(|_| StagingFault::OpenFailed)?)?
            != owned.file.identity
        {
            return Err(StagingFault::DestinationReplaced);
        }
        let digest = hash_owned_file(&owned.file, material.declared_bytes(), bounds)?;
        if digest != material.digest() {
            return Err(StagingFault::DestinationReplaced);
        }
    }
    Ok(())
}

fn hash_owned_file(
    owned: &OwnedFile,
    expected_len: u64,
    bounds: StagingBounds,
) -> Result<Sha256Digest, StagingFault> {
    // Hash the retained descriptor with independent cursor, not a reopened pathname.
    let mut file = owned
        .handle
        .try_clone()
        .map_err(|_| StagingFault::OpenFailed)?;
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))
        .map_err(|_| StagingFault::OpenFailed)?;
    let metadata = file.metadata().map_err(|_| StagingFault::OpenFailed)?;
    check_file(&metadata, bounds.max_entry_bytes)?;
    if identity_of(&metadata)? != owned.identity {
        return Err(StagingFault::DestinationReplaced);
    }
    if metadata.len() != expected_len {
        return Err(StagingFault::DestinationReplaced);
    }
    let mut hasher = Sha256::new();
    let mut already = 0_u64;
    let chunk = bounds.max_chunk_bytes.min(MAX_CHUNK_BYTES);
    loop {
        revalidate_handle(&file, &metadata, bounds.max_entry_bytes)?;
        let remaining = expected_len.saturating_sub(already);
        if remaining == 0 {
            break;
        }
        let take = remaining.min(chunk as u64) as usize;
        let mut buf = vec![0_u8; take];
        let n = file
            .read(&mut buf)
            .map_err(|err| super::checked_fs::io_fail(err, false))?;
        if n == 0 {
            return Err(StagingFault::ShortRead);
        }
        hasher.update(&buf[..n]);
        already = already
            .checked_add(n as u64)
            .ok_or(StagingFault::CapacityExhausted)?;
        if already > expected_len {
            return Err(StagingFault::LengthExceeded);
        }
    }
    let extra = {
        let mut one = [0_u8; 1];
        match file.read(&mut one) {
            Ok(0) => 0,
            Ok(_) => 1,
            Err(err) => return Err(super::checked_fs::io_fail(err, false)),
        }
    };
    if extra != 0 {
        return Err(StagingFault::ExtraTail);
    }
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn parent_of_dir<'a>(created: &'a CreatedSet, relative: &str) -> Option<&'a OwnedDir> {
    match relative.rsplit_once('/') {
        None => Some(&created.root),
        Some((parent_rel, _)) => created
            .dirs
            .iter()
            .find(|dir| dir.relative == parent_rel)
            .map(|dir| &dir.dir),
    }
}

fn cleanup_owned(fs: &dyn FsPort, created: &CreatedSet) -> CleanupReport {
    let residue = || CleanupReport::Residue {
        staging_path: created.root.path.clone(),
    };
    for item in created.files.iter().rev() {
        if fs.remove_file(&item.parent, &item.file).is_err() {
            return residue();
        }
    }
    for item in created.dirs.iter().rev() {
        let Some(parent) = parent_of_dir(created, &item.relative) else {
            return residue();
        };
        if fs.remove_dir(parent, &item.dir).is_err() {
            return residue();
        }
    }
    if fs.remove_dir(&created.parent, &created.root).is_err() {
        return residue();
    }
    match fs.child_exists(&created.parent, &created.slot) {
        Ok(false) => CleanupReport::Removed,
        _ => residue(),
    }
}

struct TrackedSourceFile {
    parent: Arc<File>,
    name: std::ffi::OsString,
    identity: PathIdentity,
}

/// 目录树材料源：只打开清单已登记的普通文件，拒绝额外项与链接。
pub struct FileTreeSource {
    root: PathBuf,
    root_identity: PathIdentity,
    files: BTreeMap<String, TrackedSourceFile>,
    chunk_size: usize,
    limit: u64,
}

impl FileTreeSource {
    /// 扫描 root，必须与计划材料集合一致。
    ///
    /// # Errors
    ///
    /// 额外文件、链接、特殊文件或路径逃逸。
    pub fn open(
        root: &Path,
        plan: &StructuralRestorePlan,
        bounds: StagingBounds,
    ) -> Result<Self, StagingFault> {
        let root_handle = Arc::new(bind_directory(root)?);
        let root_identity = identity_of(
            &root_handle
                .metadata()
                .map_err(|_| StagingFault::OpenFailed)?,
        )?;
        let (expected_files, expected_dirs) = expected_tree(plan);
        let mut found = BTreeMap::new();
        let mut found_dirs = BTreeSet::new();
        let mut pending = vec![(root_handle, root.to_path_buf())];
        let mut entries = 0_u32;
        while let Some((dir, path)) = pending.pop() {
            verify_owned_dir(root, root_identity, StagingFault::SourceReplaced)?;
            #[cfg(unix)]
            {
                use rustix::fs::{AtFlags, Dir, FileType, statat};
                use std::os::unix::ffi::OsStrExt;
                let iter = Dir::read_from(dir.as_ref()).map_err(|_| StagingFault::OpenFailed)?;
                for item in iter {
                    let item = item.map_err(|_| StagingFault::OpenFailed)?;
                    let name = std::ffi::OsStr::from_bytes(item.file_name().to_bytes());
                    if name == "." || name == ".." {
                        continue;
                    }
                    entries = entries
                        .checked_add(1)
                        .ok_or(StagingFault::CapacityExhausted)?;
                    if entries > bounds.max_entries {
                        return Err(StagingFault::PrecheckRejected);
                    }
                    let child = path.join(name);
                    let rel = relative_from(root, &child)?;
                    let st = statat(dir.as_ref(), name, AtFlags::SYMLINK_NOFOLLOW)
                        .map_err(|_| StagingFault::OpenFailed)?;
                    if FileType::from_raw_mode(st.st_mode) == FileType::Directory {
                        if !expected_dirs.contains(&rel) {
                            return Err(StagingFault::UnregisteredEntry);
                        }
                        let opened = Arc::new(open_dir_at(&dir, name)?);
                        found_dirs.insert(rel);
                        pending.push((opened, child));
                        continue;
                    }
                    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
                        return Err(StagingFault::LinkOrSpecialFile);
                    }
                    if !expected_files.contains(&rel) {
                        return Err(StagingFault::UnregisteredEntry);
                    }
                    let file = file_at(&dir, name, false, bounds.max_entry_bytes)?;
                    let identity =
                        identity_of(&file.metadata().map_err(|_| StagingFault::OpenFailed)?)?;
                    if found
                        .insert(
                            rel.clone(),
                            TrackedSourceFile {
                                parent: dir.clone(),
                                name: name.to_owned(),
                                identity,
                            },
                        )
                        .is_some()
                    {
                        return Err(StagingFault::UnregisteredEntry);
                    }
                }
            }
            #[cfg(not(unix))]
            {
                let _ = (dir, path, entries);
                return Err(StagingFault::OsBindingUnprovable);
            }
        }
        for expected in &expected_dirs {
            if !found_dirs.contains(expected) {
                return Err(StagingFault::UnregisteredEntry);
            }
        }
        let mut files = BTreeMap::new();
        for material in plan.materials() {
            if material.directory() {
                continue;
            }
            let Some(tracked) = found.remove(material.path().as_str()) else {
                return Err(StagingFault::UnregisteredEntry);
            };
            files.insert(material.id().as_str().to_owned(), tracked);
        }
        if !found.is_empty() {
            return Err(StagingFault::UnregisteredEntry);
        }
        Ok(Self {
            root: root.to_path_buf(),
            root_identity,
            files,
            chunk_size: bounds.max_chunk_bytes,
            limit: bounds.max_entry_bytes,
        })
    }
}

fn expected_tree(plan: &StructuralRestorePlan) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut files = BTreeSet::new();
    let mut dirs = BTreeSet::new();
    for material in plan.materials() {
        let path = material.path().as_str();
        if material.directory() {
            dirs.insert(path.to_owned());
        } else {
            files.insert(path.to_owned());
        }
        let parts: Vec<&str> = path.split('/').collect();
        let parents = if material.directory() {
            parts.as_slice()
        } else if parts.len() > 1 {
            &parts[..parts.len() - 1]
        } else {
            &[]
        };
        let mut acc = String::new();
        for (index, part) in parents.iter().enumerate() {
            if index > 0 {
                acc.push('/');
            }
            acc.push_str(part);
            dirs.insert(acc.clone());
        }
    }
    (files, dirs)
}

fn relative_from(root: &Path, path: &Path) -> Result<String, StagingFault> {
    let stripped = path
        .strip_prefix(root)
        .map_err(|_| StagingFault::PathInvalid)?;
    let mut out = String::new();
    for (index, part) in stripped.components().enumerate() {
        let std::path::Component::Normal(name) = part else {
            return Err(StagingFault::PathInvalid);
        };
        let name = name.to_str().ok_or(StagingFault::PathInvalid)?;
        if index > 0 {
            out.push('/');
        }
        out.push_str(name);
    }
    if out.is_empty() {
        return Err(StagingFault::PathInvalid);
    }
    Ok(out)
}

struct FileStream {
    file: File,
    before: std::fs::Metadata,
    expected: u64,
    already: u64,
    chunk_size: usize,
    limit: u64,
    seq: u32,
    terminal_emitted: bool,
}

impl EntryStream for FileStream {
    fn next_chunk(&mut self) -> Result<Option<Chunk>, StagingFault> {
        if self.terminal_emitted {
            return Ok(None);
        }
        revalidate_handle(&self.file, &self.before, self.limit)?;
        let buf = read_next(
            &mut self.file,
            &self.before,
            self.limit,
            self.expected,
            self.already,
            self.chunk_size,
        )?;
        let n = buf.len() as u64;
        self.already = self
            .already
            .checked_add(n)
            .ok_or(StagingFault::CapacityExhausted)?;
        let terminal = self.already == self.expected;
        if terminal {
            revalidate_handle(&self.file, &self.before, self.limit)?;
            self.terminal_emitted = true;
        } else if n == 0 {
            return Err(StagingFault::ShortRead);
        }
        let chunk = Chunk::try_new(self.seq, buf, terminal)?;
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or(StagingFault::CapacityExhausted)?;
        Ok(Some(chunk))
    }
}

impl MaterialSource for FileTreeSource {
    fn open_entry(&mut self, id: &str) -> Result<Box<dyn EntryStream>, StagingFault> {
        let tracked = self.files.get(id).ok_or(StagingFault::UnregisteredEntry)?;
        verify_owned_dir(&self.root, self.root_identity, StagingFault::SourceReplaced)?;
        let file = file_at(&tracked.parent, &tracked.name, false, self.limit)?;
        let metadata = file.metadata().map_err(|_| StagingFault::OpenFailed)?;
        if identity_of(&metadata)? != tracked.identity {
            return Err(StagingFault::SourceReplaced);
        }
        Ok(Box::new(FileStream {
            file,
            expected: metadata.len(),
            already: 0,
            chunk_size: self.chunk_size,
            limit: self.limit,
            seq: 0,
            terminal_emitted: false,
            before: metadata,
        }))
    }
}

/// 测试用脚本源流。不是产品归档读取器。
pub struct ScriptedSource {
    entries: BTreeMap<String, VecDeque<Result<Chunk, StagingFault>>>,
    busy: Arc<AtomicBool>,
    reentered: Arc<AtomicBool>,
    pulls: Arc<AtomicU32>,
}

impl ScriptedSource {
    /// 空源。
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            busy: Arc::new(AtomicBool::new(false)),
            reentered: Arc::new(AtomicBool::new(false)),
            pulls: Arc::new(AtomicU32::new(0)),
        }
    }

    /// 登记一条流。
    pub fn insert(&mut self, id: impl Into<String>, chunks: Vec<Result<Chunk, StagingFault>>) {
        self.entries.insert(id.into(), VecDeque::from(chunks));
    }

    /// `next_chunk` 是否被重入。coordinator 应为 false。
    #[must_use]
    pub fn reentered(&self) -> bool {
        self.reentered.load(Ordering::SeqCst)
    }

    /// 拉取块次数。
    #[must_use]
    pub fn pulls(&self) -> u32 {
        self.pulls.load(Ordering::SeqCst)
    }
}

impl Default for ScriptedSource {
    fn default() -> Self {
        Self::new()
    }
}

struct ScriptedStream {
    chunks: VecDeque<Result<Chunk, StagingFault>>,
    busy: Arc<AtomicBool>,
    reentered: Arc<AtomicBool>,
    pulls: Arc<AtomicU32>,
}

impl EntryStream for ScriptedStream {
    fn next_chunk(&mut self) -> Result<Option<Chunk>, StagingFault> {
        if self.busy.swap(true, Ordering::SeqCst) {
            self.reentered.store(true, Ordering::SeqCst);
            return Err(StagingFault::ConcurrentChunk);
        }
        self.pulls.fetch_add(1, Ordering::SeqCst);
        let item = self.chunks.pop_front();
        self.busy.store(false, Ordering::SeqCst);
        match item {
            None => Ok(None),
            Some(item) => item.map(Some),
        }
    }
}

impl MaterialSource for ScriptedSource {
    fn open_entry(&mut self, id: &str) -> Result<Box<dyn EntryStream>, StagingFault> {
        let chunks = self
            .entries
            .remove(id)
            .ok_or(StagingFault::UnregisteredEntry)?;
        Ok(Box::new(ScriptedStream {
            chunks,
            busy: self.busy.clone(),
            reentered: self.reentered.clone(),
            pulls: self.pulls.clone(),
        }))
    }
}

/// 可注入写/sync/删除故障的 FsPort。测试边界工厂，不是产品 FS。
pub struct FaultInjectingFs {
    inner: StdFs,
    fail_write_after: Option<u32>,
    fail_sync: bool,
    fail_remove: bool,
    writes: Arc<AtomicU32>,
}

impl FaultInjectingFs {
    /// 包装 StdFs。
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: StdFs,
            fail_write_after: None,
            fail_sync: false,
            fail_remove: false,
            writes: Arc::new(AtomicU32::new(0)),
        }
    }

    /// 第 n 次 write 失败（从 1 计）。
    #[must_use]
    pub fn fail_write_after(mut self, n: u32) -> Self {
        self.fail_write_after = Some(n);
        self
    }

    /// persist/sync 失败。
    #[must_use]
    pub fn fail_sync(mut self) -> Self {
        self.fail_sync = true;
        self
    }

    /// 清理删除失败，制造残留。
    #[must_use]
    pub fn fail_remove(mut self) -> Self {
        self.fail_remove = true;
        self
    }
}

impl Default for FaultInjectingFs {
    fn default() -> Self {
        Self::new()
    }
}

struct FaultySink {
    inner: Box<dyn FileSink>,
    fail_write_after: Option<u32>,
    fail_sync: bool,
    writes: Arc<AtomicU32>,
}

impl FileSink for FaultySink {
    fn write(&mut self, bytes: &[u8]) -> Result<u64, SinkWriteError> {
        let n = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_write_after == Some(n) {
            return Err(SinkWriteError::new(StagingFault::WriteFailed, 0));
        }
        self.inner.write(bytes)
    }

    fn persist(&mut self, expected_len: u64, limit: u64) -> Result<(), StagingFault> {
        if self.fail_sync {
            return Err(StagingFault::SyncFailed);
        }
        self.inner.persist(expected_len, limit)
    }
}

impl FsPort for FaultInjectingFs {
    fn bind_dir(&self, path: &Path) -> Result<OwnedDir, StagingFault> {
        self.inner.bind_dir(path)
    }

    fn create_private_dir(&self, parent: &OwnedDir, name: &str) -> Result<OwnedDir, StagingFault> {
        self.inner.create_private_dir(parent, name)
    }

    fn create_file_noclobber(
        &self,
        parent: &OwnedDir,
        name: &str,
    ) -> Result<(OwnedFile, Box<dyn FileSink>), StagingFault> {
        let (owned, inner) = self.inner.create_file_noclobber(parent, name)?;
        Ok((
            owned,
            Box::new(FaultySink {
                inner,
                fail_write_after: self.fail_write_after,
                fail_sync: self.fail_sync,
                writes: self.writes.clone(),
            }),
        ))
    }

    fn sync_dir(&self, dir: &OwnedDir) -> Result<(), StagingFault> {
        if self.fail_sync {
            return Err(StagingFault::SyncFailed);
        }
        self.inner.sync_dir(dir)
    }

    fn child_exists(&self, parent: &OwnedDir, name: &str) -> Result<bool, StagingFault> {
        self.inner.child_exists(parent, name)
    }

    fn remove_file(&self, parent: &OwnedDir, file: &OwnedFile) -> Result<(), StagingFault> {
        if self.fail_remove {
            return Err(StagingFault::WriteFailed);
        }
        self.inner.remove_file(parent, file)
    }

    fn remove_dir(&self, parent: &OwnedDir, dir: &OwnedDir) -> Result<(), StagingFault> {
        if self.fail_remove {
            return Err(StagingFault::WriteFailed);
        }
        self.inner.remove_dir(parent, dir)
    }
}
