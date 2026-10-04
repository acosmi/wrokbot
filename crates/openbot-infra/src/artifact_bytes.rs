//! 私有成果字节基础。文件描述符来自可信宿主，不接受业务路径。
//!
//! blob 是预期字节绑定；只有 stage/install/open_verified 各自成功时才证明所核字节。
//! 本层不能代表产品 available 或读取授权。
//! PG 配额/来源/回执、当前 actor 可见性、一次性读取句柄及一致性备份由后续编排负责。
//! 同步磁盘 I/O 必须由宿主在阻塞任务内调用，不占异步执行器线程。
//! 目录写者须是可信宿主；0700 不隔离同 UID 敌对进程或额外 ACL 授权。
//! 描述符/身份复核检测替换，但不声称原子 compare-unlink 或 OS 沙箱证明。

use std::fs::{File, Metadata};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;

use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};
use sha2::{Digest, Sha256};
use uuid::{Uuid, Variant};

// Same frozen limits across WASM-safe contracts, domain arithmetic and native byte storage.
pub use openbot_contracts::artifacts::{MAX_ARTIFACT_BYTES, MAX_ARTIFACT_READ_CHUNK_BYTES};
const COPY_BUFFER_BYTES: usize = 64 * 1024;

#[cfg(all(test, feature = "server-runtime"))]
#[path = "artifact_bytes/registration_tests.rs"]
mod registration_tests;

#[cfg(feature = "server-runtime")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArtifactByteStorageLocation {
    Staging,
    Object,
}

#[cfg(feature = "server-runtime")]
impl ArtifactByteStorageLocation {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::Object => "object",
        }
    }
}

#[cfg(feature = "server-runtime")]
pub(crate) enum ArtifactByteProbe {
    Absent,
    Retained {
        location: ArtifactByteStorageLocation,
        byte_length: u64,
        sha256: [u8; 32],
    },
    Indeterminate,
}

/// 内部磁盘错误；不携本机路径、正文或底层 OS 错误消息。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactByteError {
    /// 宿主尝试放宽冻结上限或传入非 UUIDv7 身份。
    #[error("invalid artifact byte binding")]
    InvalidBinding,
    /// 声明长度超出宿主允许的单成果大小。
    #[error("artifact byte limit exceeded")]
    TooLarge,
    /// 实际可用磁盘字节不足；本检查不是跨进程配额预留。
    #[error("insufficient artifact storage space")]
    InsufficientSpace,
    /// 输入的实际长度与声明不符。
    #[error("artifact input length mismatch")]
    LengthMismatch,
    /// 输入或已安装对象的真实摘要与绑定不符。
    #[error("artifact content mismatch")]
    ContentMismatch,
    /// 目录/文件不是私有普通对象，或观察期间被替换。
    #[error("unsafe artifact storage object")]
    UnsafeObject,
    /// 不覆写已有目标，包括 symlink 或已有同 ID 文件。
    #[error("artifact storage object already exists")]
    AlreadyExists,
    /// 磁盘 I/O 未完成。不能据此发布链接或自动重放登记。
    #[error("artifact storage operation failed")]
    Io,
    /// 显式清理失败；留下私有孤立对象供后续恢复核查。
    #[error("artifact staging cleanup failed")]
    CleanupFailed,
    /// 读取缓冲必须非空且不超过冻结块大小。
    #[error("invalid artifact read chunk")]
    InvalidChunk,
}

/// 可持久化的内部字节绑定。没有路径或权限事实，不能作为下载凭据。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactBlob {
    id: Uuid,
    byte_length: u64,
    sha256: [u8; 32],
}

impl ArtifactBlob {
    /// 由可信持久化记录恢复绑定；读取时仍重核实际字节。
    pub fn from_record(
        id: Uuid,
        byte_length: u64,
        sha256: [u8; 32],
    ) -> Result<Self, ArtifactByteError> {
        if id.get_version_num() != 7 || id.get_variant() != Variant::RFC4122 {
            return Err(ArtifactByteError::InvalidBinding);
        }
        if byte_length > MAX_ARTIFACT_BYTES {
            return Err(ArtifactByteError::TooLarge);
        }
        Ok(Self {
            id,
            byte_length,
            sha256,
        })
    }

    /// Rust 铸造的 UUIDv7；仅对象定位，不授予权限。
    #[must_use]
    pub const fn id(&self) -> Uuid {
        self.id
    }
    /// 预期/持久化绑定的字节长度；构造本身没有验证存储。
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }
    /// 预期/持久化绑定的 SHA-256；构造本身没有验证存储。
    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
}
impl Identity {
    fn of(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

struct StoreDirectories {
    root: File,
    staging: File,
    objects: File,
    owner: u32,
}
impl StoreDirectories {
    fn check_private(&self) -> Result<(), ArtifactByteError> {
        for directory in [&self.root, &self.staging, &self.objects] {
            check_directory(
                &directory.metadata().map_err(|_| ArtifactByteError::Io)?,
                self.owner,
            )?;
        }
        Ok(())
    }
}

/// 描述符绑定的本节点磁盘适配器；不读环境、不打开任何用户业务路径。
pub struct ArtifactByteStore {
    directories: Arc<StoreDirectories>,
    max_byte_length: u64,
}

/// 私有 staging 中已经核长度/摘要并 fsync 的成果；不能发布为 available。
/// 丢弃时尽力清理，调用方需确定清理结果时使用 [`Self::discard`]。
pub struct VerifiedArtifactStage {
    directories: Arc<StoreDirectories>,
    file: File,
    blob: ArtifactBlob,
    armed: bool,
}

impl VerifiedArtifactStage {
    /// 只读取已验证的内部绑定，不能将此事实当成 PG 登记或授权。
    #[must_use]
    pub const fn blob(&self) -> &ArtifactBlob {
        &self.blob
    }

    /// 显式清理未安装对象，目录同步成功后返回。
    pub fn discard(mut self) -> Result<(), ArtifactByteError> {
        remove_stage(&self.directories, &self.blob.id.to_string(), &self.file)?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for VerifiedArtifactStage {
    fn drop(&mut self) {
        if self.armed {
            // Drop 不声称清理成功。崩溃/清理失败后的孤立 staging 仍需恢复清理器。
            let _ = remove_stage(&self.directories, &self.blob.id.to_string(), &self.file);
        }
    }
}

impl ArtifactByteStore {
    /// 绑定可信宿主已经打开的 0700 私有根目录。所有后续 I/O 相对该描述符。
    /// 此调用可创建 staging/objects 私有子目录；不接受用户或模型给出的路径。
    pub fn bind_private_root(root: File, max_byte_length: u64) -> Result<Self, ArtifactByteError> {
        if max_byte_length > MAX_ARTIFACT_BYTES {
            return Err(ArtifactByteError::InvalidBinding);
        }
        let metadata = root.metadata().map_err(|_| ArtifactByteError::Io)?;
        check_directory(&metadata, metadata.uid())?;
        let owner = metadata.uid();
        let staging = private_directory(&root, "staging", owner)?;
        let objects = private_directory(&root, "objects", owner)?;
        root.sync_all().map_err(|_| ArtifactByteError::Io)?;
        Ok(Self {
            directories: Arc::new(StoreDirectories {
                root,
                staging,
                objects,
                owner,
            }),
            max_byte_length,
        })
    }

    /// 先核声明长度与真实磁盘余量，再有界落盘；完全一致才返回 staging。
    /// PG workspace/Run 配额必须在编排层另行原子预留；磁盘余量只是当前快照。
    pub fn stage(
        &self,
        input: &mut impl Read,
        byte_length: u64,
        expected_sha256: [u8; 32],
    ) -> Result<VerifiedArtifactStage, ArtifactByteError> {
        let blob = ArtifactBlob::from_record(Uuid::now_v7(), byte_length, expected_sha256)?;
        self.stage_for(input, &blob)
    }

    /// 可信编排先铸造成果的稳定身份后落盘，可在失败时登记准确 failed_partial。
    /// 这里只消费预期绑定，不将其当作读取权或已提交的登记回执。
    pub fn stage_for(
        &self,
        input: &mut impl Read,
        blob: &ArtifactBlob,
    ) -> Result<VerifiedArtifactStage, ArtifactByteError> {
        let byte_length = blob.byte_length;
        if byte_length > self.max_byte_length {
            return Err(ArtifactByteError::TooLarge);
        }
        self.directories.check_private()?;
        let space =
            rustix::fs::fstatvfs(&self.directories.staging).map_err(|_| ArtifactByteError::Io)?;
        let available = space
            .f_bavail
            .checked_mul(space.f_frsize)
            .ok_or(ArtifactByteError::Io)?;
        if byte_length > available {
            return Err(ArtifactByteError::InsufficientSpace);
        }
        let name = blob.id.to_string();
        let mut file = File::from(
            rustix::fs::openat(
                &self.directories.staging,
                &name,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(map_open_error)?,
        );
        let result =
            write_verified(&mut file, input, blob, self.directories.owner).and_then(|()| {
                self.directories
                    .staging
                    .sync_all()
                    .map_err(|_| ArtifactByteError::Io)
            });
        if let Err(error) = result {
            // 错误路径的清理本身也需可观察，不能吞掉孤立 staging。
            remove_stage(&self.directories, &name, &file)?;
            return Err(error);
        }
        Ok(VerifiedArtifactStage {
            directories: Arc::clone(&self.directories),
            file,
            blob: blob.clone(),
            armed: true,
        })
    }

    /// 将已核字节用 NOREPLACE 原子安装；先实际存在才可由后续 PG 事务登记。
    /// 成功不是产品登记回执；失败或崩溃可留下私有孤立对象，不自动重放事务。
    pub fn install(
        &self,
        mut stage: VerifiedArtifactStage,
    ) -> Result<ArtifactBlob, ArtifactByteError> {
        if !Arc::ptr_eq(&self.directories, &stage.directories) {
            return Err(ArtifactByteError::InvalidBinding);
        }
        self.directories.check_private()?;
        let name = stage.blob.id.to_string();
        let original = stage.file.metadata().map_err(|_| ArtifactByteError::Io)?;
        check_file(&original, self.directories.owner, stage.blob.byte_length)?;
        let current = open_object(&self.directories.staging, &name)?;
        if Identity::of(&current.metadata().map_err(|_| ArtifactByteError::Io)?)
            != Identity::of(&original)
        {
            return Err(ArtifactByteError::UnsafeObject);
        }
        rustix::fs::renameat_with(
            &self.directories.staging,
            &name,
            &self.directories.objects,
            &name,
            RenameFlags::NOREPLACE,
        )
        .map_err(map_open_error)?;
        stage.armed = false;
        self.directories
            .objects
            .sync_all()
            .map_err(|_| ArtifactByteError::Io)?;
        self.directories
            .staging
            .sync_all()
            .map_err(|_| ArtifactByteError::Io)?;
        self.directories
            .root
            .sync_all()
            .map_err(|_| ArtifactByteError::Io)?;
        let installed = self.open_verified(&stage.blob)?;
        if Identity::of(
            &installed
                .file
                .metadata()
                .map_err(|_| ArtifactByteError::Io)?,
        ) != Identity::of(&original)
        {
            return Err(ArtifactByteError::UnsafeObject);
        }
        Ok(stage.blob.clone())
    }

    /// 重新核普通文件、实际长度与摘要后返回内部有界 reader。
    /// 当前 actor/source-thread 授权、session/window 绑定及一次性句柄由上层负责。
    pub fn open_verified(
        &self,
        blob: &ArtifactBlob,
    ) -> Result<ArtifactBlobReader, ArtifactByteError> {
        if blob.byte_length > self.max_byte_length {
            return Err(ArtifactByteError::TooLarge);
        }
        self.directories.check_private()?;
        let mut file = open_object(&self.directories.objects, &blob.id.to_string())?;
        let original = file.metadata().map_err(|_| ArtifactByteError::Io)?;
        check_file(&original, self.directories.owner, blob.byte_length)?;
        verify_digest(&mut file, blob)?;
        if FileObservation::of(&original)
            != FileObservation::of(&file.metadata().map_err(|_| ArtifactByteError::Io)?)
        {
            return Err(ArtifactByteError::UnsafeObject);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| ArtifactByteError::Io)?;
        Ok(ArtifactBlobReader {
            file,
            observation: FileObservation::of(&original),
            remaining: blob.byte_length,
            failed: false,
        })
    }

    /// Reobserve the original stable object after synchronous IO has ended. Expected bytes are
    /// deliberately absent from this interface; this is no actor or operation authorization.
    #[cfg(feature = "server-runtime")]
    pub(crate) fn probe_actual(&self, id: Uuid) -> ArtifactByteProbe {
        self.probe_actual_inner(id)
            .unwrap_or(ArtifactByteProbe::Indeterminate)
    }

    #[cfg(feature = "server-runtime")]
    fn probe_actual_inner(&self, id: Uuid) -> Result<ArtifactByteProbe, ArtifactByteError> {
        if id.get_version_num() != 7 || id.get_variant() != Variant::RFC4122 {
            return Err(ArtifactByteError::InvalidBinding);
        }
        self.directories.check_private()?;
        let name = id.to_string();
        let staging = probe_open(&self.directories.staging, &name)?;
        let object = probe_open(&self.directories.objects, &name)?;
        let retained = match (staging, object) {
            (None, None) => None,
            (Some(file), None) => Some((ArtifactByteStorageLocation::Staging, file)),
            (None, Some(file)) => Some((ArtifactByteStorageLocation::Object, file)),
            (Some(_), Some(_)) => return Err(ArtifactByteError::UnsafeObject),
        };
        let observation = if let Some((location, mut file)) = retained {
            let before = file.metadata().map_err(|_| ArtifactByteError::Io)?;
            if !before.is_file()
                || before.uid() != self.directories.owner
                || before.nlink() != 1
                || !matches!(before.mode() & 0o7777, 0o400 | 0o600)
                || before.len() > self.max_byte_length
                || before.dev()
                    != self
                        .directories
                        .root
                        .metadata()
                        .map_err(|_| ArtifactByteError::Io)?
                        .dev()
            {
                return Err(ArtifactByteError::UnsafeObject);
            }
            let mut remaining = before.len();
            let mut hash = Sha256::new();
            let mut buffer = [0u8; COPY_BUFFER_BYTES];
            while remaining > 0 {
                let length = remaining.min(COPY_BUFFER_BYTES as u64) as usize;
                file.read_exact(&mut buffer[..length])
                    .map_err(|_| ArtifactByteError::Io)?;
                hash.update(&buffer[..length]);
                remaining -= length as u64;
            }
            if file
                .read(&mut buffer[..1])
                .map_err(|_| ArtifactByteError::Io)?
                != 0
            {
                return Err(ArtifactByteError::UnsafeObject);
            }
            file.sync_all().map_err(|_| ArtifactByteError::Io)?;
            if FileObservation::of(&before)
                != FileObservation::of(&file.metadata().map_err(|_| ArtifactByteError::Io)?)
            {
                return Err(ArtifactByteError::UnsafeObject);
            }
            // Verify the directory still selects this exact file, including after its fsync.
            let directory = match location {
                ArtifactByteStorageLocation::Staging => &self.directories.staging,
                ArtifactByteStorageLocation::Object => &self.directories.objects,
            };
            let current = probe_open(directory, &name)?.ok_or(ArtifactByteError::UnsafeObject)?;
            if FileObservation::of(&before)
                != FileObservation::of(&current.metadata().map_err(|_| ArtifactByteError::Io)?)
            {
                return Err(ArtifactByteError::UnsafeObject);
            }
            ArtifactByteProbe::Retained {
                location,
                byte_length: before.len(),
                sha256: hash.finalize().into(),
            }
        } else {
            ArtifactByteProbe::Absent
        };
        self.directories
            .staging
            .sync_all()
            .map_err(|_| ArtifactByteError::Io)?;
        self.directories
            .objects
            .sync_all()
            .map_err(|_| ArtifactByteError::Io)?;
        self.directories
            .root
            .sync_all()
            .map_err(|_| ArtifactByteError::Io)?;
        self.directories.check_private()?;
        if matches!(observation, ArtifactByteProbe::Absent)
            && (probe_open(&self.directories.staging, &name)?.is_some()
                || probe_open(&self.directories.objects, &name)?.is_some())
        {
            return Err(ArtifactByteError::UnsafeObject);
        }
        Ok(observation)
    }
}

#[cfg(feature = "server-runtime")]
fn probe_open(directory: &File, name: &str) -> Result<Option<File>, ArtifactByteError> {
    match rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(file) => Ok(Some(File::from(file))),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(map_open_error(error)),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileObservation {
    identity: Identity,
    length: u64,
    mode: u32,
    links: u64,
    owner: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}
impl FileObservation {
    fn of(m: &Metadata) -> Self {
        Self {
            identity: Identity::of(m),
            length: m.len(),
            mode: m.mode(),
            links: m.nlink(),
            owner: m.uid(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
        }
    }
}

/// 单个已核实际字节的 reader。不可 Clone，不暴露 fd 或实现任意长度 Read。
pub struct ArtifactBlobReader {
    file: File,
    observation: FileObservation,
    remaining: u64,
    failed: bool,
}
impl ArtifactBlobReader {
    /// Recheck the original retained FD without reading bytes or reopening another object.
    #[cfg(feature = "server-runtime")]
    pub(crate) fn verify_current_descriptor(&self) -> Result<(), ArtifactByteError> {
        if self.failed {
            return Err(ArtifactByteError::Io);
        }
        self.check_observation()
    }
    /// 在调用方缓冲中返回 ≤4MiB；修改/截断/替换拒绝，EOF 返回0。
    /// 外部单次句柄/单在途响应限制仍必须由 transport 的句柄管理器落实。
    pub fn read_chunk(&mut self, output: &mut [u8]) -> Result<usize, ArtifactByteError> {
        if output.is_empty() || output.len() > MAX_ARTIFACT_READ_CHUNK_BYTES {
            return Err(ArtifactByteError::InvalidChunk);
        }
        if self.failed {
            return Err(ArtifactByteError::Io);
        }
        if let Err(error) = self.check_observation() {
            self.failed = true;
            return Err(error);
        }
        let length = usize::try_from(self.remaining.min(output.len() as u64))
            .map_err(|_| ArtifactByteError::Io)?;
        if let Err(_error) = self.file.read_exact(&mut output[..length]) {
            self.failed = true;
            output[..length].fill(0);
            return Err(ArtifactByteError::Io);
        }
        if let Err(error) = self.check_observation() {
            self.failed = true;
            output[..length].fill(0);
            return Err(error);
        }
        self.remaining -= length as u64;
        Ok(length)
    }
    fn check_observation(&self) -> Result<(), ArtifactByteError> {
        let observed = self.file.metadata().map_err(|_| ArtifactByteError::Io)?;
        if FileObservation::of(&observed) != self.observation {
            return Err(ArtifactByteError::UnsafeObject);
        }
        Ok(())
    }
}

fn private_directory(root: &File, name: &str, owner: u32) -> Result<File, ArtifactByteError> {
    match rustix::fs::mkdirat(root, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(_) => return Err(ArtifactByteError::Io),
    }
    let file = File::from(
        rustix::fs::openat(
            root,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_open_error)?,
    );
    let metadata = file.metadata().map_err(|_| ArtifactByteError::Io)?;
    check_directory(&metadata, owner)?;
    if metadata.dev() != root.metadata().map_err(|_| ArtifactByteError::Io)?.dev() {
        return Err(ArtifactByteError::UnsafeObject);
    }
    Ok(file)
}

fn check_directory(metadata: &Metadata, owner: u32) -> Result<(), ArtifactByteError> {
    if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o7777 != 0o700 {
        return Err(ArtifactByteError::UnsafeObject);
    }
    Ok(())
}
fn check_file(metadata: &Metadata, owner: u32, length: u64) -> Result<(), ArtifactByteError> {
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o400
    {
        return Err(ArtifactByteError::UnsafeObject);
    }
    if metadata.len() != length {
        return Err(ArtifactByteError::LengthMismatch);
    }
    Ok(())
}
fn open_object(directory: &File, name: &str) -> Result<File, ArtifactByteError> {
    rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(map_open_error)
}
fn map_open_error(error: rustix::io::Errno) -> ArtifactByteError {
    match error {
        rustix::io::Errno::EXIST => ArtifactByteError::AlreadyExists,
        rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => ArtifactByteError::UnsafeObject,
        _ => ArtifactByteError::Io,
    }
}
fn remove_stage(
    directories: &StoreDirectories,
    name: &str,
    expected: &File,
) -> Result<(), ArtifactByteError> {
    // 已观察到叶子替换时不盲删。核身份后 unlink 依赖可信目录写者；不是原子 compare-unlink。
    let current =
        open_object(&directories.staging, name).map_err(|_| ArtifactByteError::CleanupFailed)?;
    let current = current
        .metadata()
        .map_err(|_| ArtifactByteError::CleanupFailed)?;
    let original = expected
        .metadata()
        .map_err(|_| ArtifactByteError::CleanupFailed)?;
    if !current.is_file() || Identity::of(&current) != Identity::of(&original) {
        return Err(ArtifactByteError::CleanupFailed);
    }
    rustix::fs::unlinkat(&directories.staging, name, AtFlags::empty())
        .map_err(|_| ArtifactByteError::CleanupFailed)?;
    directories
        .staging
        .sync_all()
        .map_err(|_| ArtifactByteError::CleanupFailed)
}
fn write_verified(
    file: &mut File,
    input: &mut impl Read,
    blob: &ArtifactBlob,
    owner: u32,
) -> Result<(), ArtifactByteError> {
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    let mut remaining = blob.byte_length;
    let mut hash = Sha256::new();
    while remaining > 0 {
        let limit = remaining.min(COPY_BUFFER_BYTES as u64) as usize;
        let read = match input.read(&mut buffer[..limit]) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ArtifactByteError::Io),
            Ok(0) => return Err(ArtifactByteError::LengthMismatch),
            Ok(length) => length,
        };
        file.write_all(&buffer[..read])
            .map_err(|_| ArtifactByteError::Io)?;
        hash.update(&buffer[..read]);
        remaining -= read as u64;
    }
    loop {
        match input.read(&mut buffer[..1]) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ArtifactByteError::Io),
            Ok(0) => break,
            Ok(_) => return Err(ArtifactByteError::LengthMismatch),
        }
    }
    if <[u8; 32]>::from(hash.finalize()) != blob.sha256 {
        return Err(ArtifactByteError::ContentMismatch);
    }
    file.sync_all().map_err(|_| ArtifactByteError::Io)?;
    rustix::fs::fchmod(&*file, Mode::RUSR).map_err(|_| ArtifactByteError::Io)?;
    file.sync_all().map_err(|_| ArtifactByteError::Io)?;
    check_file(
        &file.metadata().map_err(|_| ArtifactByteError::Io)?,
        owner,
        blob.byte_length,
    )?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| ArtifactByteError::Io)?;
    // 校验的是实际落盘字节，不能只用输入流的摘要声称存储一致。
    verify_digest(file, blob)
}
fn verify_digest(file: &mut File, blob: &ArtifactBlob) -> Result<(), ArtifactByteError> {
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    let mut hash = Sha256::new();
    let mut remaining = blob.byte_length;
    while remaining > 0 {
        let length = remaining.min(COPY_BUFFER_BYTES as u64) as usize;
        file.read_exact(&mut buffer[..length])
            .map_err(|_| ArtifactByteError::LengthMismatch)?;
        hash.update(&buffer[..length]);
        remaining -= length as u64;
    }
    if file
        .read(&mut buffer[..1])
        .map_err(|_| ArtifactByteError::Io)?
        != 0
    {
        return Err(ArtifactByteError::LengthMismatch);
    }
    if <[u8; 32]>::from(hash.finalize()) != blob.sha256 {
        return Err(ArtifactByteError::ContentMismatch);
    }
    Ok(())
}
