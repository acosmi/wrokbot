use std::ffi::{OsStr, OsString, c_void};
use std::fs::{File, OpenOptions};
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle, RawHandle};
use std::os::windows::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::ExitStatus;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::NamedPipeServer;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_NOT_FOUND, FILETIME, FreeLibrary, GetLastError, HANDLE, HANDLE_FLAG_INHERIT,
    INVALID_HANDLE_VALUE, LocalFree, SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::Credentials::{
    CRED_MAX_CREDENTIAL_BLOB_SIZE, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW,
    CredDeleteW, CredFree, CredReadW, CredWriteW,
};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, CreateWellKnownSid, DACL_SECURITY_INFORMATION, DISABLE_MAX_PRIVILEGE,
    GetSecurityDescriptorDacl, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
    IsTokenRestricted, LABEL_SECURITY_INFORMATION, LUA_TOKEN, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES,
    SetFileSecurityW, SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DEFAULT_DACL, TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER,
    TokenDefaultDacl, TokenIntegrityLevel, TokenUser, WRITE_RESTRICTED, WinRestrictedCodeSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::LibraryLoader::{
    BeginUpdateResourceW, EndUpdateResourceW, FindResourceW, LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE,
    LOAD_LIBRARY_AS_IMAGE_RESOURCE, LoadLibraryExW, LoadResource, LockResource, SizeofResource,
    UpdateResourceW,
};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, CreatePipe, GetNamedPipeClientProcessId, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
use windows_sys::Win32::System::SystemServices::{
    SECURITY_MANDATORY_HIGH_RID, SECURITY_MANDATORY_MEDIUM_RID,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetExitCodeProcess, GetProcessTimes, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcess, OpenProcessToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};
use zeroize::Zeroize as _;

use crate::WindowsSandboxError;
use crate::command_line::{encode_command_line, filetime_ticks_to_unix_millis};

const PIPE_BUFFER_BYTES: u32 = 64 * 1024;
const PROCESS_SYNCHRONIZE: u32 = 0x0010_0000;
const MAX_GENERIC_CREDENTIAL_BYTES: usize = 128;

/// Owned Credential Manager plaintext that zeroizes unless explicitly transferred onward.
pub struct WindowsCredentialSecret(Vec<u8>);

impl WindowsCredentialSecret {
    /// Borrow plaintext only for immediate protocol framing or test comparison.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Transfer the unique allocation into another zeroizing owner such as `SecretBytes`.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        let this = core::mem::ManuallyDrop::new(self);
        unsafe { core::ptr::read(&this.0) }
    }
}

impl core::fmt::Debug for WindowsCredentialSecret {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("WindowsCredentialSecret([REDACTED])")
    }
}

impl Drop for WindowsCredentialSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Read one current-user generic Credential Manager blob without exposing raw Win32 pointers.
pub fn read_generic_credential(
    target: &str,
) -> Result<Option<WindowsCredentialSecret>, WindowsSandboxError> {
    let target = credential_target(target)?;
    let mut raw = core::ptr::null_mut::<CREDENTIALW>();
    let read = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw) };
    if read == 0 {
        let code = unsafe { GetLastError() };
        if code == ERROR_NOT_FOUND {
            return Ok(None);
        }
        return Err(io::Error::from_raw_os_error(code as i32).into());
    }
    if raw.is_null() {
        return Err(WindowsSandboxError::InvalidInput);
    }
    let buffer = CredentialBuffer(raw);
    let credential = unsafe { &*buffer.0 };
    let size = usize::try_from(credential.CredentialBlobSize)
        .map_err(|_| WindowsSandboxError::InvalidInput)?;
    if credential.Type != CRED_TYPE_GENERIC
        || size == 0
        || size > MAX_GENERIC_CREDENTIAL_BYTES
        || credential.CredentialBlob.is_null()
    {
        return Err(WindowsSandboxError::InvalidInput);
    }
    let bytes = unsafe { core::slice::from_raw_parts(credential.CredentialBlob, size) }.to_vec();
    drop(buffer);
    Ok(Some(WindowsCredentialSecret(bytes)))
}

/// Create or replace one current-user, local-machine-persistent generic credential.
pub fn write_generic_credential(target: &str, secret: &[u8]) -> Result<(), WindowsSandboxError> {
    let mut target = credential_target(target)?;
    if secret.is_empty()
        || secret.len() > MAX_GENERIC_CREDENTIAL_BYTES
        || secret.len() > CRED_MAX_CREDENTIAL_BLOB_SIZE as usize
    {
        return Err(WindowsSandboxError::InvalidInput);
    }
    let credential = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: target.as_mut_ptr(),
        CredentialBlobSize: u32::try_from(secret.len())
            .map_err(|_| WindowsSandboxError::InvalidInput)?,
        CredentialBlob: secret.as_ptr().cast_mut(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        ..CREDENTIALW::default()
    };
    let written = unsafe { CredWriteW(&credential, 0) };
    if written == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

/// Delete the exact current-user generic credential; unknown is an idempotent `false`.
pub fn delete_generic_credential(target: &str) -> Result<bool, WindowsSandboxError> {
    let target = credential_target(target)?;
    let deleted = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
    if deleted != 0 {
        return Ok(true);
    }
    let code = unsafe { GetLastError() };
    if code == ERROR_NOT_FOUND {
        Ok(false)
    } else {
        Err(io::Error::from_raw_os_error(code as i32).into())
    }
}

fn credential_target(value: &str) -> Result<Vec<u16>, WindowsSandboxError> {
    if value.is_empty() || value.len() > 512 || value.contains('\0') {
        return Err(WindowsSandboxError::InvalidInput);
    }
    let encoded = OsStr::new(value)
        .encode_wide()
        .chain(core::iter::once(0))
        .collect::<Vec<_>>();
    if encoded.len() <= 1 || encoded.len() > 513 {
        return Err(WindowsSandboxError::InvalidInput);
    }
    Ok(encoded)
}

struct CredentialBuffer(*mut CREDENTIALW);

impl Drop for CredentialBuffer {
    fn drop(&mut self) {
        if self.0.is_null() {
            return;
        }
        unsafe {
            let credential = &mut *self.0;
            let size = usize::try_from(credential.CredentialBlobSize).unwrap_or(0);
            if !credential.CredentialBlob.is_null()
                && size <= CRED_MAX_CREDENTIAL_BLOB_SIZE as usize
            {
                for index in 0..size {
                    core::ptr::write_volatile(credential.CredentialBlob.add(index), 0);
                }
            }
            CredFree(self.0.cast());
        }
    }
}

/// Exact OS identity used with PID to reject PID reuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessIdentity {
    pid: u32,
    creation_filetime_ticks: u64,
}

impl ProcessIdentity {
    /// Process identifier returned by the kernel.
    #[must_use]
    pub const fn pid(self) -> u32 {
        self.pid
    }

    /// Exact 100 ns FILETIME creation timestamp (epoch 1601-01-01 UTC).
    #[must_use]
    pub const fn creation_filetime_ticks(self) -> u64 {
        self.creation_filetime_ticks
    }

    /// Milliseconds since the Unix epoch, matching Electron `ProcessMetric.creationTime`.
    pub fn creation_unix_millis(self) -> Result<f64, WindowsSandboxError> {
        filetime_ticks_to_unix_millis(self.creation_filetime_ticks)
    }
}

/// Fully specified restricted Engine spawn. All paths must already exist and be canonical.
pub struct SpawnPolicy {
    executable: PathBuf,
    args: Vec<OsString>,
    working_directory: PathBuf,
    profile_directory: PathBuf,
    temp_directory: PathBuf,
    max_processes: u32,
    max_job_memory_bytes: usize,
}

impl SpawnPolicy {
    /// Validate one closed launch policy before any ACL/token/process mutation occurs.
    pub fn new(
        executable: impl Into<PathBuf>,
        args: Vec<OsString>,
        working_directory: impl Into<PathBuf>,
        profile_directory: impl Into<PathBuf>,
        temp_directory: impl Into<PathBuf>,
        max_processes: u32,
        max_job_memory_bytes: usize,
    ) -> Result<Self, WindowsSandboxError> {
        let policy = Self {
            executable: executable.into(),
            args,
            working_directory: working_directory.into(),
            profile_directory: profile_directory.into(),
            temp_directory: temp_directory.into(),
            max_processes,
            max_job_memory_bytes,
        };
        if !policy.executable.is_absolute()
            || !policy.executable.is_file()
            || !policy.working_directory.is_absolute()
            || !policy.working_directory.is_dir()
            || !policy.profile_directory.is_absolute()
            || !policy.profile_directory.is_dir()
            || !policy.temp_directory.is_absolute()
            || !policy.temp_directory.is_dir()
            || policy.max_processes == 0
            || policy.max_job_memory_bytes == 0
        {
            return Err(WindowsSandboxError::InvalidInput);
        }
        for path in [
            &policy.executable,
            &policy.working_directory,
            &policy.profile_directory,
            &policy.temp_directory,
        ] {
            validate_wide(path.as_os_str())?;
        }
        for arg in &policy.args {
            validate_wide(arg)?;
        }
        Ok(policy)
    }
}

/// A restricted Engine root process and its kill-on-close Job Object.
pub struct RestrictedChild {
    process: OwnedHandle,
    job: OwnedHandle,
    identity: ProcessIdentity,
    stdin: Option<File>,
}

impl RestrictedChild {
    /// Exact identity captured from the live process handle before resume.
    #[must_use]
    pub const fn identity(&self) -> ProcessIdentity {
        self.identity
    }

    /// Take the sole parent-side stdin writer used for the one-line boot capability.
    pub fn take_stdin(&mut self) -> Option<File> {
        self.stdin.take()
    }

    /// Verify a reported descendant is the exact live process and is contained in this Job.
    pub fn verify_job_member(
        &self,
        pid: u32,
        creation_unix_millis: f64,
    ) -> Result<ProcessIdentity, WindowsSandboxError> {
        if pid == 0 || !creation_unix_millis.is_finite() || creation_unix_millis <= 0.0 {
            return Err(WindowsSandboxError::PeerIdentity);
        }
        let process = open_process(pid)?;
        let identity = identity_from_handle(pid, raw(&process))?;
        if identity.creation_unix_millis()? != creation_unix_millis {
            return Err(WindowsSandboxError::PeerIdentity);
        }
        let mut contained = 0;
        // SAFETY: both handles are live and `contained` is a valid output pointer.
        if unsafe { IsProcessInJob(raw(&process), raw(&self.job), &mut contained) } == 0 {
            return Err(last_error());
        }
        if contained == 0 {
            return Err(WindowsSandboxError::PeerIdentity);
        }
        Ok(identity)
    }

    /// Nonblocking root-process status.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, WindowsSandboxError> {
        let process = raw(&self.process);
        // SAFETY: `process` is exclusively owned by `self` and remains valid for this call.
        let wait = unsafe { WaitForSingleObject(process, 0) };
        if wait == WAIT_TIMEOUT {
            return Ok(None);
        }
        if wait != WAIT_OBJECT_0 {
            return Err(last_error());
        }
        let mut code = 0u32;
        // SAFETY: the live process handle and output pointer are valid.
        if unsafe { GetExitCodeProcess(process, &mut code) } == 0 {
            return Err(last_error());
        }
        Ok(Some(ExitStatus::from_raw(code)))
    }

    /// Terminate every process in the Job. No process-level fallback is allowed.
    pub fn kill(&mut self) -> Result<(), WindowsSandboxError> {
        // SAFETY: `job` is a valid Job Object exclusively owned by `self`.
        if unsafe { TerminateJobObject(raw(&self.job), 1) } == 0 {
            return Err(last_error());
        }
        Ok(())
    }
}

impl Drop for RestrictedChild {
    fn drop(&mut self) {
        // KILL_ON_JOB_CLOSE is authoritative; explicit termination bounds cleanup before handles
        // are released and is safe to repeat after a normal child exit.
        unsafe {
            let _ = TerminateJobObject(raw(&self.job), 1);
        }
    }
}

/// Create a medium-integrity, write-restricted process inside a bounded Job, then resume it.
pub fn spawn_restricted(policy: &SpawnPolicy) -> Result<RestrictedChild, WindowsSandboxError> {
    secure_engine_directory(&policy.profile_directory)?;
    secure_engine_directory(&policy.temp_directory)?;

    let token = restricted_write_token()?;
    let job = create_job(policy.max_processes, policy.max_job_memory_bytes)?;
    let (stdin_parent, stdin_child) = anonymous_stdin_pipe()?;
    let stdout_null = inheritable_null()?;
    let stderr_null = inheritable_null()?;
    let inherited = [
        raw(&stdin_child),
        raw_file(&stdout_null),
        raw_file(&stderr_null),
    ];
    let attributes = AttributeList::new(&inherited, raw(&job))?;

    let executable = wide_null(policy.executable.as_os_str())?;
    let mut command_line = encode_command_line(policy.executable.as_os_str(), &policy.args)?;
    let working_directory = wide_null(policy.working_directory.as_os_str())?;
    let environment = engine_environment(&policy.profile_directory, &policy.temp_directory)?;
    let mut startup: STARTUPINFOEXW = unsafe { MaybeUninit::zeroed().assume_init() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = inherited[0];
    startup.StartupInfo.hStdOutput = inherited[1];
    startup.StartupInfo.hStdError = inherited[2];
    startup.lpAttributeList = attributes.as_ptr();
    let mut process_info: PROCESS_INFORMATION = unsafe { MaybeUninit::zeroed().assume_init() };

    // SAFETY: all string/environment buffers and the initialized STARTUPINFOEX attribute list
    // outlive the call. Only the three handles in `inherited` are inheritable and allowlisted.
    let created = unsafe {
        CreateProcessAsUserW(
            raw(&token),
            executable.as_ptr(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            environment.as_ptr().cast(),
            working_directory.as_ptr(),
            (&raw const startup.StartupInfo),
            &mut process_info,
        )
    };
    if created == 0 {
        return Err(last_error());
    }

    let process = match owned_handle(process_info.hProcess) {
        Ok(process) => process,
        Err(error) => {
            // A successful CreateProcess call must return both handles, but fail closed if the
            // contract is ever violated. The raw thread handle is closed when present.
            if !process_info.hThread.is_null() && process_info.hThread != INVALID_HANDLE_VALUE {
                // SAFETY: CreateProcess returned this unaliased thread handle to this scope.
                unsafe { CloseHandle(process_info.hThread) };
            }
            return Err(error);
        }
    };
    let thread = match owned_handle(process_info.hThread) {
        Ok(thread) => thread,
        Err(error) => {
            terminate_and_reap(raw(&process));
            return Err(error);
        }
    };
    let identity = match identity_from_handle(process_info.dwProcessId, raw(&process)) {
        Ok(identity) => identity,
        Err(error) => {
            terminate_and_reap(raw(&process));
            return Err(error);
        }
    };
    // SAFETY: this is the one suspended main thread returned by CreateProcessAsUserW.
    if unsafe { ResumeThread(raw(&thread)) } == u32::MAX {
        let error = last_error();
        terminate_and_reap(raw(&process));
        return Err(error);
    }
    drop(thread);
    drop(stdin_child);
    drop(stdout_null);
    drop(stderr_null);

    Ok(RestrictedChild {
        process,
        job,
        identity,
        stdin: Some(File::from(stdin_parent)),
    })
}

/// Security descriptor used by both private Engine pipes.
pub fn current_user_pipe_security_sddl() -> Result<String, WindowsSandboxError> {
    let sid = current_user_sid_string()?;
    Ok(format!("D:P(A;;GA;;;{sid})(A;;GA;;;RC)S:(ML;;NW;;;LW)"))
}

/// Grant the write-restricted Engine SID only on one protected, low-label directory tree.
pub fn secure_engine_directory(path: &Path) -> Result<(), WindowsSandboxError> {
    secure_integrity_directory(path, "LW", true)
}

fn secure_integrity_directory(
    path: &Path,
    integrity_sid: &str,
    grant_restricted_code: bool,
) -> Result<(), WindowsSandboxError> {
    if !path.is_absolute() || !path.is_dir() {
        return Err(WindowsSandboxError::InvalidInput);
    }
    if !matches!(integrity_sid, "LW" | "ME") {
        return Err(WindowsSandboxError::InvalidInput);
    }
    let sid = current_user_sid_string()?;
    let restricted_ace = if grant_restricted_code {
        "(A;OICI;FA;;;RC)"
    } else {
        ""
    };
    let descriptor = SecurityDescriptor::from_sddl(&format!(
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid}){restricted_ace}S:(ML;OICI;NW;;;{integrity_sid})"
    ))?;
    let path = wide_null(path.as_os_str())?;
    // SAFETY: `path` is NUL-terminated and descriptor remains live for the complete call.
    let ok = unsafe {
        SetFileSecurityW(
            path.as_ptr(),
            DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION
                | LABEL_SECURITY_INFORMATION,
            descriptor.as_ptr(),
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// Transactionally replace one string-named PE resource using the language-neutral entry.
pub fn replace_pe_resource(
    executable: &Path,
    resource_type: &str,
    resource_name: &str,
    bytes: &[u8],
) -> Result<(), WindowsSandboxError> {
    if !executable.is_absolute()
        || !executable.is_file()
        || bytes.is_empty()
        || bytes.len() > u32::MAX as usize
    {
        return Err(WindowsSandboxError::InvalidInput);
    }
    let executable = wide_null(executable.as_os_str())?;
    let resource_type = resource_identifier(resource_type)?;
    let resource_name = resource_identifier(resource_name)?;
    // SAFETY: the path is NUL-terminated. The returned update handle is consumed exactly once by
    // EndUpdateResourceW through `ResourceUpdate`.
    let handle = unsafe { BeginUpdateResourceW(executable.as_ptr(), 0) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    let mut update = ResourceUpdate(Some(handle));
    // Language 0 is MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL); Electron uses FindResourceW
    // without a language, so the OS language fallback selects this neutral entry.
    // SAFETY: all identifiers/data remain live for the complete call.
    if unsafe {
        UpdateResourceW(
            handle,
            resource_type.as_ptr(),
            resource_name.as_ptr(),
            0,
            bytes.as_ptr().cast(),
            bytes.len() as u32,
        )
    } == 0
    {
        return Err(last_error());
    }
    update.commit()
}

/// Read one PE resource without executing the image; used to verify the exact bytes just written.
pub fn read_pe_resource(
    executable: &Path,
    resource_type: &str,
    resource_name: &str,
) -> Result<Vec<u8>, WindowsSandboxError> {
    if !executable.is_absolute() || !executable.is_file() {
        return Err(WindowsSandboxError::InvalidInput);
    }
    let executable = wide_null(executable.as_os_str())?;
    let resource_type = resource_identifier(resource_type)?;
    let resource_name = resource_identifier(resource_name)?;
    // SAFETY: the absolute path is NUL-terminated and LOAD_LIBRARY_AS_IMAGE_RESOURCE prevents
    // static initialization/code execution. `LoadedModule` owns the returned mapping.
    let module = unsafe {
        LoadLibraryExW(
            executable.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_IMAGE_RESOURCE,
        )
    };
    if module.is_null() {
        return Err(last_error());
    }
    let module = LoadedModule(module);
    // SAFETY: module is a live data-file mapping and both resource identifiers are NUL-terminated.
    let resource =
        unsafe { FindResourceW(module.0, resource_name.as_ptr(), resource_type.as_ptr()) };
    if resource.is_null() {
        return Err(last_error());
    }
    // SAFETY: resource was returned for this exact live module.
    let loaded = unsafe { LoadResource(module.0, resource) };
    if loaded.is_null() {
        return Err(last_error());
    }
    let size = unsafe { SizeofResource(module.0, resource) };
    let data = unsafe { LockResource(loaded) };
    if size == 0 || data.is_null() {
        return Err(last_error());
    }
    // SAFETY: LockResource exposes exactly SizeofResource bytes for the lifetime of `module`.
    Ok(unsafe { std::slice::from_raw_parts(data.cast::<u8>(), size as usize) }.to_vec())
}

/// One local-only, one-instance Engine Named Pipe listener.
pub struct NamedPipeListener {
    server: NamedPipeServer,
}

impl NamedPipeListener {
    /// Bind one random authority-owned pipe name with an exact current-user/low-integrity ACL.
    pub fn bind(path: &Path) -> Result<Self, WindowsSandboxError> {
        let path_text = path.to_str().ok_or(WindowsSandboxError::InvalidInput)?;
        if !valid_pipe_name(path_text) {
            return Err(WindowsSandboxError::InvalidInput);
        }
        let path = wide_null(path.as_os_str())?;
        let descriptor = SecurityDescriptor::from_sddl(&current_user_pipe_security_sddl()?)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.as_ptr().cast(),
            bInheritHandle: 0,
        };
        // SAFETY: all pointers remain valid during CreateNamedPipeW. The OS copies the security
        // descriptor; the returned handle has exclusive ownership transferred to Tokio below.
        let handle = unsafe {
            CreateNamedPipeW(
                path.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                PIPE_BUFFER_BYTES,
                PIPE_BUFFER_BYTES,
                0,
                &attributes,
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(last_error());
        }
        // SAFETY: `handle` is newly created, not aliased, overlapped, and ownership is transferred
        // exactly once. Tokio closes it even if registration fails.
        let server = unsafe { NamedPipeServer::from_raw_handle(handle as RawHandle) }?;
        Ok(Self { server })
    }

    /// Accept exactly one client; no replacement pipe instance is created.
    pub async fn accept(self) -> Result<NamedPipeConnection, WindowsSandboxError> {
        self.server.connect().await?;
        Ok(NamedPipeConnection { inner: self.server })
    }
}

/// Connected server side of one private Engine Named Pipe.
pub struct NamedPipeConnection {
    inner: NamedPipeServer,
}

impl NamedPipeConnection {
    /// Read the peer PID from the pipe, reopen that exact process, and capture creation FILETIME.
    pub fn peer_identity(&self) -> Result<ProcessIdentity, WindowsSandboxError> {
        let mut pid = 0u32;
        // SAFETY: `inner` owns a connected server handle and `pid` is a valid output pointer.
        if unsafe { GetNamedPipeClientProcessId(raw_pipe(&self.inner), &mut pid) } == 0 || pid == 0
        {
            return Err(last_error());
        }
        identity_for_pid(pid)
    }

    /// Require both PID and exact 100 ns creation time to match the spawned child.
    pub fn verify_peer(&self, expected: ProcessIdentity) -> Result<(), WindowsSandboxError> {
        (self.peer_identity()? == expected)
            .then_some(())
            .ok_or(WindowsSandboxError::PeerIdentity)
    }
}

impl AsyncRead for NamedPipeConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for NamedPipeConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn valid_pipe_name(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix(r"\\.\pipe\ob-eng-") else {
        return false;
    };
    !suffix.is_empty()
        && value.len() <= 256
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn restricted_write_token() -> Result<OwnedHandle, WindowsSandboxError> {
    let mut base = std::ptr::null_mut();
    // SAFETY: output pointer is valid; the resulting handle is immediately moved into RAII.
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
            &mut base,
        )
    } == 0
    {
        return Err(last_error());
    }
    let base = owned_handle(base)?;
    let mut restricted_sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut restricted_sid_len = restricted_sid.len() as u32;
    // SAFETY: fixed storage is at least SECURITY_MAX_SID_SIZE and the output length is valid.
    if unsafe {
        CreateWellKnownSid(
            WinRestrictedCodeSid,
            std::ptr::null_mut(),
            restricted_sid.as_mut_ptr().cast(),
            &mut restricted_sid_len,
        )
    } == 0
    {
        return Err(last_error());
    }
    let restriction = SID_AND_ATTRIBUTES {
        Sid: restricted_sid.as_mut_ptr().cast(),
        Attributes: 0,
    };
    let mut restricted = std::ptr::null_mut();
    // SAFETY: base is a live primary token; the one restricting SID stays alive for the call.
    if unsafe {
        CreateRestrictedToken(
            raw(&base),
            DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            1,
            &restriction,
            &mut restricted,
        )
    } == 0
    {
        return Err(last_error());
    }
    let restricted = owned_handle(restricted)?;
    set_restricted_default_dacl(raw(&restricted))?;
    verify_medium_integrity(raw(&restricted))?;
    // SAFETY: `restricted` is a valid token handle.
    if unsafe { IsTokenRestricted(raw(&restricted)) } == 0 {
        return Err(WindowsSandboxError::TokenIntegrity);
    }
    Ok(restricted)
}

fn set_restricted_default_dacl(token: HANDLE) -> Result<(), WindowsSandboxError> {
    let user_sid = current_user_sid_string()?;
    let descriptor =
        SecurityDescriptor::from_sddl(&format!("D:P(A;;GA;;;SY)(A;;GA;;;{user_sid})(A;;GA;;;RC)"))?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = std::ptr::null_mut();
    // SAFETY: descriptor is live and all output pointers are valid.
    if unsafe {
        GetSecurityDescriptorDacl(descriptor.as_ptr(), &mut present, &mut dacl, &mut defaulted)
    } == 0
        || present == 0
        || dacl.is_null()
    {
        return Err(last_error());
    }
    let default_dacl = TOKEN_DEFAULT_DACL { DefaultDacl: dacl };
    // SAFETY: token and descriptor/DACL are live; SetTokenInformation copies the DACL.
    if unsafe {
        SetTokenInformation(
            token,
            TokenDefaultDacl,
            (&raw const default_dacl).cast(),
            size_of::<TOKEN_DEFAULT_DACL>() as u32,
        )
    } == 0
    {
        return Err(last_error());
    }
    Ok(())
}

fn verify_medium_integrity(token: HANDLE) -> Result<(), WindowsSandboxError> {
    let mut needed = 0u32;
    // SAFETY: documented sizing call with a null buffer.
    unsafe {
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    if needed < size_of::<TOKEN_MANDATORY_LABEL>() as u32 {
        return Err(WindowsSandboxError::TokenIntegrity);
    }
    let mut storage = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    // SAFETY: aligned storage is at least `needed` bytes and all outputs remain live.
    if unsafe {
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            storage.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(last_error());
    }
    let label = unsafe { &*storage.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() };
    // SAFETY: the SID came from a successful TokenIntegrityLevel query and remains in `storage`.
    let count = unsafe { GetSidSubAuthorityCount(label.Label.Sid) };
    if count.is_null() || unsafe { *count } == 0 {
        return Err(WindowsSandboxError::TokenIntegrity);
    }
    // SAFETY: count is positive and the final subauthority index is in the valid SID.
    let rid = unsafe { GetSidSubAuthority(label.Label.Sid, u32::from(*count - 1)) };
    if rid.is_null() {
        return Err(WindowsSandboxError::TokenIntegrity);
    }
    let rid = unsafe { *rid };
    (rid >= SECURITY_MANDATORY_MEDIUM_RID as u32 && rid < SECURITY_MANDATORY_HIGH_RID as u32)
        .then_some(())
        .ok_or(WindowsSandboxError::TokenIntegrity)
}

fn create_job(
    max_processes: u32,
    max_job_memory_bytes: usize,
) -> Result<OwnedHandle, WindowsSandboxError> {
    // SAFETY: null security/name creates a private unnamed Job Object.
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    let job = owned_handle(job)?;
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION =
        unsafe { MaybeUninit::zeroed().assume_init() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_JOB_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit = max_processes;
    limits.JobMemoryLimit = max_job_memory_bytes;
    // SAFETY: `limits` is fully initialized and the size exactly matches the selected class.
    if unsafe {
        SetInformationJobObject(
            raw(&job),
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        return Err(last_error());
    }
    Ok(job)
}

struct AttributeList {
    storage: Vec<usize>,
    pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
    handles: Box<[HANDLE]>,
    job: Box<HANDLE>,
}

impl AttributeList {
    fn new(handles: &[HANDLE], job: HANDLE) -> Result<Self, WindowsSandboxError> {
        let mut bytes = 0usize;
        // SAFETY: the documented sizing call uses a null list and fills `bytes`.
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut bytes);
        }
        if bytes == 0 {
            return Err(last_error());
        }
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        let pointer = storage.as_mut_ptr().cast();
        // SAFETY: aligned storage is at least the exact requested byte count.
        if unsafe { InitializeProcThreadAttributeList(pointer, 2, 0, &mut bytes) } == 0 {
            return Err(last_error());
        }
        let handles = handles.to_vec().into_boxed_slice();
        let job = Box::new(job);
        let list = Self {
            storage,
            pointer,
            handles,
            job,
        };
        // SAFETY: both borrowed buffers outlive process creation; the API copies neither pointer
        // but only consults it while the attribute list is in use.
        if unsafe {
            UpdateProcThreadAttribute(
                list.pointer,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                list.handles.as_ptr().cast(),
                std::mem::size_of_val(list.handles.as_ref()),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            return Err(last_error());
        }
        if unsafe {
            UpdateProcThreadAttribute(
                list.pointer,
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                (&raw const *list.job).cast(),
                size_of::<HANDLE>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            return Err(last_error());
        }
        Ok(list)
    }

    fn as_ptr(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        let _ = self.storage.len();
        self.pointer
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: initialized once and deleted exactly once while backing storage is still alive.
        unsafe { DeleteProcThreadAttributeList(self.pointer) };
    }
}

fn anonymous_stdin_pipe() -> Result<(OwnedHandle, OwnedHandle), WindowsSandboxError> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let mut read = std::ptr::null_mut();
    let mut write = std::ptr::null_mut();
    // SAFETY: both output pointers and the initialized security attributes are valid.
    if unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) } == 0 {
        return Err(last_error());
    }
    let read = owned_handle(read)?;
    let write = owned_handle(write)?;
    // Parent writer must never be inherited, even outside the explicit attribute-list defense.
    // SAFETY: write is a live owned handle.
    if unsafe { SetHandleInformation(raw(&write), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(last_error());
    }
    Ok((write, read))
}

fn inheritable_null() -> Result<File, WindowsSandboxError> {
    let file = OpenOptions::new().read(true).write(true).open("NUL")?;
    // SAFETY: file owns a live kernel handle. Only the child gets a duplicate reference through
    // explicit CreateProcess handle inheritance; this parent File remains uniquely owned.
    if unsafe { SetHandleInformation(raw_file(&file), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) }
        == 0
    {
        return Err(last_error());
    }
    Ok(file)
}

fn engine_environment(profile: &Path, temp: &Path) -> Result<Vec<u16>, WindowsSandboxError> {
    // Read the real OS directory, not a potentially poisoned inherited SystemRoot or PATH.
    let mut directory = vec![0_u16; 32_768];
    // SAFETY: directory is a writable buffer of exactly the stated UTF-16 capacity. Zero means
    // failure and a required size at/above capacity is rejected before reading the returned data.
    let length =
        unsafe { GetSystemWindowsDirectoryW(directory.as_mut_ptr(), directory.len() as u32) };
    if length == 0 {
        return Err(last_error());
    }
    if length as usize >= directory.len() {
        return Err(WindowsSandboxError::InvalidInput);
    }
    let system_root = String::from_utf16(&directory[..length as usize])
        .map_err(|_| WindowsSandboxError::InvalidInput)?;
    let profile_text = profile.to_str().ok_or(WindowsSandboxError::InvalidInput)?;
    let temp_text = temp.to_str().ok_or(WindowsSandboxError::InvalidInput)?;
    let block =
        crate::environment::engine_environment_block(&system_root, profile_text, temp_text)?;
    for child in [
        profile.join("AppData").join("Local"),
        profile.join("AppData").join("Roaming"),
    ] {
        std::fs::create_dir_all(child)?;
    }
    Ok(block)
}

fn identity_for_pid(pid: u32) -> Result<ProcessIdentity, WindowsSandboxError> {
    let process = open_process(pid)?;
    identity_from_handle(pid, raw(&process))
}

fn open_process(pid: u32) -> Result<OwnedHandle, WindowsSandboxError> {
    // SAFETY: PID is an integer obtained from the kernel; no handle inheritance is requested.
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    owned_handle(process)
}

fn identity_from_handle(pid: u32, process: HANDLE) -> Result<ProcessIdentity, WindowsSandboxError> {
    let mut creation: FILETIME = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut exit: FILETIME = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut kernel: FILETIME = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut user: FILETIME = unsafe { MaybeUninit::zeroed().assume_init() };
    // SAFETY: process has query rights and all four output pointers are valid.
    if unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        return Err(last_error());
    }
    let ticks = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    filetime_ticks_to_unix_millis(ticks)?;
    Ok(ProcessIdentity {
        pid,
        creation_filetime_ticks: ticks,
    })
}

fn current_user_sid_string() -> Result<String, WindowsSandboxError> {
    let mut token = std::ptr::null_mut();
    // SAFETY: output pointer is valid and ownership transfers to `OwnedHandle`.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(last_error());
    }
    let token = owned_handle(token)?;
    let mut needed = 0u32;
    // SAFETY: documented sizing call with null buffer.
    unsafe {
        GetTokenInformation(raw(&token), TokenUser, std::ptr::null_mut(), 0, &mut needed);
    }
    if needed < size_of::<TOKEN_USER>() as u32 {
        return Err(last_error());
    }
    let mut storage = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    // SAFETY: aligned storage has at least `needed` bytes and remains live through SID conversion.
    if unsafe {
        GetTokenInformation(
            raw(&token),
            TokenUser,
            storage.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(last_error());
    }
    let token_user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    let mut text = std::ptr::null_mut();
    // SAFETY: SID points into the live token-information buffer and text is a valid out-pointer.
    if unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut text) } == 0 || text.is_null() {
        return Err(last_error());
    }
    let text = LocalAllocation(text.cast());
    let mut length = 0usize;
    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated LocalAlloc string.
    unsafe {
        while *text.0.cast::<u16>().add(length) != 0 {
            length += 1;
        }
        Ok(String::from_utf16_lossy(std::slice::from_raw_parts(
            text.0.cast::<u16>(),
            length,
        )))
    }
}

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn from_sddl(value: &str) -> Result<Self, WindowsSandboxError> {
        let value = wide_null(OsStr::new(value))?;
        let mut descriptor = std::ptr::null_mut();
        let mut size = 0u32;
        // SAFETY: value is NUL-terminated and both output pointers are valid.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                value.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                &mut size,
            )
        } == 0
            || descriptor.is_null()
        {
            return Err(last_error());
        }
        Ok(Self(descriptor))
    }

    fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: descriptor was allocated by LocalAlloc and is released exactly once.
        unsafe {
            let _ = LocalFree(self.0.cast());
        }
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: pointer was allocated by LocalAlloc and is released exactly once.
        unsafe {
            let _ = LocalFree(self.0);
        }
    }
}

struct ResourceUpdate(Option<HANDLE>);

impl ResourceUpdate {
    fn commit(&mut self) -> Result<(), WindowsSandboxError> {
        let handle = self.0.take().ok_or(WindowsSandboxError::InvalidInput)?;
        // SAFETY: update handle is live and consumed exactly once; FALSE commits atomically.
        if unsafe { EndUpdateResourceW(handle, 0) } == 0 {
            return Err(last_error());
        }
        Ok(())
    }
}

impl Drop for ResourceUpdate {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            // SAFETY: an uncommitted live update handle is consumed exactly once; TRUE discards.
            unsafe {
                let _ = EndUpdateResourceW(handle, 1);
            }
        }
    }
}

struct LoadedModule(windows_sys::Win32::Foundation::HMODULE);

impl Drop for LoadedModule {
    fn drop(&mut self) {
        // SAFETY: this module was returned by LoadLibraryExW and is released exactly once.
        unsafe {
            let _ = FreeLibrary(self.0);
        }
    }
}

fn terminate_and_reap(process: HANDLE) {
    // SAFETY: process is live and exclusively owned by the failed spawn path.
    unsafe {
        let _ = TerminateProcess(process, 1);
        let _ = WaitForSingleObject(process, u32::MAX);
    }
}

fn wide_null(value: &OsStr) -> Result<Vec<u16>, WindowsSandboxError> {
    let mut units = value.encode_wide().collect::<Vec<_>>();
    if units.is_empty() || units.contains(&0) {
        return Err(WindowsSandboxError::InvalidInput);
    }
    units.push(0);
    Ok(units)
}

fn resource_identifier(value: &str) -> Result<Vec<u16>, WindowsSandboxError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(WindowsSandboxError::InvalidInput);
    }
    wide_null(OsStr::new(value))
}

fn validate_wide(value: &OsStr) -> Result<(), WindowsSandboxError> {
    (!value.is_empty() && !value.encode_wide().any(|unit| unit == 0))
        .then_some(())
        .ok_or(WindowsSandboxError::InvalidInput)
}

fn raw(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle() as HANDLE
}

fn raw_file(file: &File) -> HANDLE {
    file.as_raw_handle() as HANDLE
}

fn raw_pipe(pipe: &NamedPipeServer) -> HANDLE {
    pipe.as_raw_handle() as HANDLE
}

fn owned_handle(handle: HANDLE) -> Result<OwnedHandle, WindowsSandboxError> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    // SAFETY: caller transfers one newly returned, unaliased owned handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
}

fn last_error() -> WindowsSandboxError {
    WindowsSandboxError::Os(io::Error::last_os_error())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    use tokio::net::windows::named_pipe::ClientOptions;

    use super::*;

    #[tokio::test]
    async fn named_pipe_peer_identity_binds_pid_and_exact_creation_time() {
        let path = PathBuf::from(format!(
            r"\\.\pipe\ob-eng-{:08x}.identity",
            std::process::id()
        ));
        let listener = NamedPipeListener::bind(&path).expect("listener");
        let expected = identity_for_pid(std::process::id()).expect("current identity");
        let client = ClientOptions::new().open(&path).expect("client");
        let connection = listener.accept().await.expect("accept");
        connection.verify_peer(expected).expect("exact peer");
        assert_eq!(connection.peer_identity().unwrap(), expected);
        drop(client);
    }

    #[test]
    fn pe_resource_update_round_trips_exact_bytes_without_loading_code() {
        let root = test_root("pe-resource");
        fs::create_dir_all(&root).expect("root");
        let executable = root.join("fixture.exe");
        fs::copy(std::env::current_exe().expect("current exe"), &executable).expect("copy PE");
        let payload = br#"[{"file":"resources\\app.asar","alg":"sha256","value":"fixture"}]"#;
        replace_pe_resource(&executable, "Integrity", "ElectronAsar", payload).expect("replace");
        assert_eq!(
            read_pe_resource(&executable, "Integrity", "ElectronAsar").expect("read"),
            payload
        );
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn credential_target_and_blob_bounds_are_closed() {
        assert!(credential_target("Example_Product_PostgreSQL_17_instance").is_ok());
        assert!(credential_target("").is_err());
        assert!(credential_target("nul\0inside").is_err());
        assert!(credential_target(&"x".repeat(513)).is_err());
        assert!(write_generic_credential("valid-target", &[]).is_err());
        assert!(
            write_generic_credential("valid-target", &[0_u8; MAX_GENERIC_CREDENTIAL_BYTES + 1])
                .is_err()
        );
    }

    #[test]
    #[ignore = "需要Windows当前用户Credential Manager真机读写"]
    fn credential_manager_generic_round_trip_and_delete() {
        let target = format!("Example_Product_PostgreSQL_Test_{}", std::process::id());
        let _ = delete_generic_credential(&target);
        assert!(read_generic_credential(&target).unwrap().is_none());
        let secret = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        write_generic_credential(&target, secret).unwrap();
        let read = read_generic_credential(&target).unwrap().unwrap();
        assert_eq!(read.expose(), secret);
        assert!(!format!("{read:?}").contains(std::str::from_utf8(secret).unwrap()));
        assert!(delete_generic_credential(&target).unwrap());
        assert!(read_generic_credential(&target).unwrap().is_none());
    }

    #[test]
    #[ignore = "P1 Windows real-machine restricted-token/Job/ACL spike"]
    fn restricted_write_process_writes_profile_but_not_medium_outside() {
        let root = test_root("restricted-process");
        let profile = root.join("profile");
        let temp = root.join("temp");
        let outside = root.join("outside");
        fs::create_dir_all(&profile).expect("profile");
        fs::create_dir_all(&temp).expect("temp");
        fs::create_dir_all(&outside).expect("outside");
        secure_integrity_directory(&outside, "ME", false).expect("medium outside");

        let allowed = profile.join("allowed.txt");
        let escaped = outside.join("escaped.txt");
        let command = format!(
            "echo allowed>\"{}\" & echo escaped>\"{}\"",
            allowed.display(),
            escaped.display()
        );
        let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
        let executable = PathBuf::from(system_root).join("System32/cmd.exe");
        let policy = SpawnPolicy::new(
            &executable,
            vec![
                OsString::from("/D"),
                OsString::from("/S"),
                OsString::from("/C"),
                OsString::from(command),
            ],
            &root,
            &profile,
            &temp,
            2,
            256 * 1024 * 1024,
        )
        .expect("policy");
        let mut child = spawn_restricted(&policy).expect("restricted spawn");
        drop(child.take_stdin());
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().expect("wait") {
                break status;
            }
            assert!(Instant::now() < deadline, "restricted child timed out");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(!status.success(), "outside write unexpectedly succeeded");
        assert_eq!(
            fs::read_to_string(&allowed).expect("allowed write"),
            "allowed\r\n"
        );
        assert!(!escaped.exists(), "low-integrity child wrote medium object");
        drop(child);
        fs::remove_dir_all(root).expect("cleanup");
    }

    fn test_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "openbot-windows-sandbox-{label}-{}",
            std::process::id()
        ))
    }
}
