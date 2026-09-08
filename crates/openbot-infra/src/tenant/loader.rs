//! Tenant Package 五份 YAML 的有界文件读取、显式环境展开与 checksum。

use std::path::Path;

use openbot_application::tenant::package::{
    LoadedTenantPackage, TENANT_PACKAGE_FILENAMES, TenantPackageEnvironment, TenantPackageError,
    TenantPackageFile, TenantPackageFiles, expand_environment, validate_tenant_package,
};
use sha2::{Digest, Sha256};

/// 单个 Tenant Package YAML 文件最大 1 MiB。
pub const MAX_TENANT_PACKAGE_FILE_BYTES: usize = 1024 * 1024;

/// 文件加载失败；不保留文件内容、环境值或 OS 路径错误文本。
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TenantPackageLoadError {
    /// 文件不存在或不可读。
    #[error("tenant_package_file_unavailable file={file:?}")]
    FileUnavailable {
        /// 固定文件标识。
        file: TenantPackageFile,
    },
    /// 文件超过有界输入上限。
    #[error("tenant_package_file_too_large file={file:?}")]
    FileTooLarge {
        /// 固定文件标识。
        file: TenantPackageFile,
    },
    /// 文件不是 UTF-8。
    #[error("tenant_package_file_not_utf8 file={file:?}")]
    FileNotUtf8 {
        /// 固定文件标识。
        file: TenantPackageFile,
    },
    /// 文件系统 path 无法稳定表示为 UTF-8 provenance。
    #[error("tenant_package_source_path_invalid")]
    SourcePathInvalid,
    /// 纯展开/校验失败。
    #[error(transparent)]
    Package(#[from] TenantPackageError),
}

/// 只读取第一真源规定的五份 YAML；`theme.css` 即使存在也不打开。
///
/// # Errors
///
/// 缺文件、超限、非 UTF-8、环境缺值或 package 校验失败时返回稳定错误。
pub fn load_tenant_package(
    source: &Path,
    environment: &TenantPackageEnvironment,
) -> Result<LoadedTenantPackage, TenantPackageLoadError> {
    let descriptors = [
        (TENANT_PACKAGE_FILENAMES[0], TenantPackageFile::Brand),
        (TENANT_PACKAGE_FILENAMES[1], TenantPackageFile::Agents),
        (TENANT_PACKAGE_FILENAMES[2], TenantPackageFile::Channels),
        (TENANT_PACKAGE_FILENAMES[3], TenantPackageFile::Model),
        (TENANT_PACKAGE_FILENAMES[4], TenantPackageFile::Knowledge),
    ];
    let mut expanded = Vec::with_capacity(descriptors.len());
    for (name, file) in descriptors {
        let bytes = std::fs::read(source.join(name)).map_err(|error| {
            tracing::error!(file = file.as_str(), kind = ?error.kind(), "tenant package 文件读取失败");
            TenantPackageLoadError::FileUnavailable { file }
        })?;
        if bytes.len() > MAX_TENANT_PACKAGE_FILE_BYTES {
            return Err(TenantPackageLoadError::FileTooLarge { file });
        }
        let text =
            String::from_utf8(bytes).map_err(|_| TenantPackageLoadError::FileNotUtf8 { file })?;
        expanded.push(expand_environment(&text, file, environment)?);
    }
    let checksum = {
        let mut hash = Sha256::new();
        for (index, content) in expanded.iter().enumerate() {
            if index > 0 {
                hash.update(b"\n");
            }
            hash.update(content.as_bytes());
        }
        format!("{:x}", hash.finalize())
    };
    let mut contents = expanded.into_iter();
    let package = validate_tenant_package(TenantPackageFiles {
        brand: contents.next().expect("五文件固定第 1 项"),
        agents: contents.next().expect("五文件固定第 2 项"),
        channels: contents.next().expect("五文件固定第 3 项"),
        model: contents.next().expect("五文件固定第 4 项"),
        knowledge: contents.next().expect("五文件固定第 5 项"),
    })?;
    let source_path = source
        .to_str()
        .filter(|value| !value.is_empty())
        .ok_or(TenantPackageLoadError::SourcePathInvalid)?
        .to_owned();
    LoadedTenantPackage::new(package, source_path, checksum).map_err(Into::into)
}
