//! Audited macOS-only FFI implementation. No symbol in this module signals a process.

use crate::ProcessObservationError;
use core_foundation_sys::base::{
    CFAllocatorRef, CFGetTypeID, CFRelease, CFTypeRef, kCFAllocatorDefault,
};
use core_foundation_sys::dictionary::{CFDictionaryRef, CFMutableDictionaryRef};
use core_foundation_sys::string::{
    CFStringCreateWithBytes, CFStringGetCString, CFStringGetTypeID, CFStringRef,
    kCFStringEncodingUTF8,
};
use std::ffi::{c_char, c_int, c_uint, c_void};
use std::mem::{MaybeUninit, size_of};

const IOPM_ROOT_DOMAIN_CLASS: &[u8] = b"IOPMrootDomain\0";
const BOOT_SESSION_UUID_KEY: &[u8] = b"BootSessionUUID";
const UUID_TEXT_BYTES: usize = 36;
const UUID_BUFFER_BYTES: usize = UUID_TEXT_BYTES + 1;
const IO_OBJECT_NULL: IoObject = 0;
const MACH_PORT_NULL: MachPort = 0;

type IoObject = c_uint;
type IoService = IoObject;
type IoRegistryEntry = IoObject;
type IoOptionBits = c_uint;
type MachPort = c_uint;
type KernReturn = c_int;

// SAFETY: these declarations exactly mirror the macOS SDK's IOKitLib.h signatures for immutable
// matching/property reads and owned-object release. Call sites below validate every returned handle,
// preserve input lifetimes, and apply the documented consume/Create ownership rules.
#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IOServiceMatching(name: *const c_char) -> CFMutableDictionaryRef;
    fn IOServiceGetMatchingService(main_port: MachPort, matching: CFDictionaryRef) -> IoService;
    fn IORegistryEntryCreateCFProperty(
        entry: IoRegistryEntry,
        key: CFStringRef,
        allocator: CFAllocatorRef,
        options: IoOptionBits,
    ) -> CFTypeRef;
    fn IOObjectRelease(object: IoObject) -> KernReturn;
}

pub(super) struct Observation {
    pub(super) start_seconds: u64,
    pub(super) start_microseconds: u32,
    pub(super) boot_session: [u8; 16],
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ProcessBirth {
    pub(super) pid: i32,
    pub(super) start_seconds: u64,
    pub(super) start_microseconds: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct BootSession([u8; 16]);

/// Perform exactly one bracketed four-read sequence with no retry.
pub(super) fn observe(pid: i32) -> Result<Observation, ProcessObservationError> {
    let boot_a = read_boot_session();
    let process_a = read_process_birth(pid);
    let process_b = read_process_birth(pid);
    let boot_b = read_boot_session();

    let boot_a = boot_a?;
    let process_a = process_a?;
    let process_b = process_b?;
    let boot_b = boot_b?;
    if boot_a != boot_b || process_a != process_b {
        return Err(ProcessObservationError::ObservationChanged);
    }
    Ok(Observation {
        start_seconds: process_a.start_seconds,
        start_microseconds: process_a.start_microseconds,
        boot_session: boot_a.0,
    })
}

pub(super) fn read_process_birth_for_openers(pid: i32) -> Result<ProcessBirth, ProcessObservationError> {
    read_process_birth(pid)
}

pub(super) fn read_boot_session_for_openers() -> Result<[u8; 16], ProcessObservationError> {
    Ok(read_boot_session()?.0)
}

fn read_process_birth(pid: i32) -> Result<ProcessBirth, ProcessObservationError> {
    let buffer_size = c_int::try_from(size_of::<libc::proc_bsdinfo>())
        .map_err(|_| ProcessObservationError::ProcessDataInvalid)?;
    // A zeroed `proc_bsdinfo` is valid because every field in the pinned layout is an integer or
    // byte array. Zeroing also prevents an SPI implementation that leaves a non-consumed field
    // untouched from exposing uninitialized bytes after an otherwise exact-size return.
    let mut information = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    // SAFETY: `information` is initialized to a valid all-zero `proc_bsdinfo`, writable and
    // correctly aligned for exactly `buffer_size` bytes; `pid` is a positive signed pid_t value;
    // flavor and layout come from the same pinned libc 0.2.189 Apple target declarations. We only
    // consume the returned value after an exact-size return.
    let returned = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            information.as_mut_ptr().cast::<c_void>(),
            buffer_size,
        )
    };
    if returned != buffer_size {
        return Err(ProcessObservationError::ProcessUnavailable);
    }
    // SAFETY: the buffer started as a valid all-zero `proc_bsdinfo`; the exact-size success check
    // above is the libproc contract for one complete reply, and short/failed writes are rejected.
    let information = unsafe { information.assume_init() };
    if information.pbi_pid != pid as u32
        || information.pbi_start_tvsec == 0
        || information.pbi_start_tvusec >= 1_000_000
        || information.pbi_status == libc::SZOMB
    {
        return Err(ProcessObservationError::ProcessDataInvalid);
    }
    Ok(ProcessBirth {
        pid,
        start_seconds: information.pbi_start_tvsec,
        start_microseconds: information.pbi_start_tvusec as u32,
    })
}

fn read_boot_session() -> Result<BootSession, ProcessObservationError> {
    // SAFETY: the static byte string is NUL-terminated and lives for the call. The returned
    // matching dictionary follows Create ownership and is consumed by
    // `IOServiceGetMatchingService`, including its failure path, so it must not be released here.
    let matching = unsafe { IOServiceMatching(IOPM_ROOT_DOMAIN_CLASS.as_ptr().cast::<c_char>()) };
    if matching.is_null() {
        return Err(ProcessObservationError::BootUnavailable);
    }
    // SAFETY: `matching` is the owned dictionary returned immediately above; this API consumes
    // that reference. `MACH_PORT_NULL` is the documented default IOKit main port.
    let root = unsafe {
        IOServiceGetMatchingService(MACH_PORT_NULL, matching.cast_const() as CFDictionaryRef)
    };
    let root = OwnedIoObject::new(root).ok_or(ProcessObservationError::BootUnavailable)?;

    // SAFETY: `kCFAllocatorDefault` is an immutable CoreFoundation global allocator reference.
    let allocator = unsafe { kCFAllocatorDefault };
    // SAFETY: the key bytes are valid bounded UTF-8, the byte count is exact and the allocator is
    // the CoreFoundation default. Create ownership transfers to `OwnedCf` below on success.
    let key = unsafe {
        CFStringCreateWithBytes(
            allocator,
            BOOT_SESSION_UUID_KEY.as_ptr(),
            BOOT_SESSION_UUID_KEY.len() as isize,
            kCFStringEncodingUTF8,
            0,
        )
    };
    let key = OwnedCf::new(key.cast::<c_void>()).ok_or(ProcessObservationError::BootUnavailable)?;
    // SAFETY: `root` is a live IOKit registry object and `key` is a live CFString for the duration
    // of this call. The allocator is valid and options zero is the only documented option. A
    // non-null result follows Create ownership and is immediately wrapped for release.
    let property =
        unsafe { IORegistryEntryCreateCFProperty(root.get(), key.get().cast(), allocator, 0) };
    let property = OwnedCf::new(property).ok_or(ProcessObservationError::BootUnavailable)?;
    // SAFETY: `property` is a live non-null CF object owned by this scope. Type inspection does not
    // consume it, and `CFStringGetTypeID` takes no input object.
    let is_string = unsafe { CFGetTypeID(property.get()) == CFStringGetTypeID() };
    if !is_string {
        return Err(ProcessObservationError::BootUnavailable);
    }

    let mut utf8 = [0 as c_char; UUID_BUFFER_BYTES];
    // SAFETY: the exact type check above proves `property` is a CFString. `utf8` is writable for
    // the advertised bounded length, including one byte for the trailing NUL.
    let copied = unsafe {
        CFStringGetCString(
            property.get().cast(),
            utf8.as_mut_ptr(),
            utf8.len() as isize,
            kCFStringEncodingUTF8,
        )
    };
    if copied == 0 || utf8[UUID_TEXT_BYTES] != 0 {
        return Err(ProcessObservationError::BootUnavailable);
    }
    parse_uuid(&utf8[..UUID_TEXT_BYTES]).ok_or(ProcessObservationError::BootUnavailable)
}

fn parse_uuid(value: &[c_char]) -> Option<BootSession> {
    if value.len() != UUID_TEXT_BYTES {
        return None;
    }
    let mut output = [0_u8; 16];
    let mut output_index = 0;
    let mut high_nibble = None;
    for (index, raw) in value.iter().copied().enumerate() {
        let byte = raw as u8;
        if matches!(index, 8 | 13 | 18 | 23) {
            if byte != b'-' {
                return None;
            }
            continue;
        }
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        if let Some(high) = high_nibble.take() {
            let slot = output.get_mut(output_index)?;
            *slot = (high << 4) | nibble;
            output_index += 1;
        } else {
            high_nibble = Some(nibble);
        }
    }
    if high_nibble.is_some() || output_index != output.len() || output.iter().all(|byte| *byte == 0)
    {
        return None;
    }
    Some(BootSession(output))
}

struct OwnedIoObject(IoObject);

impl OwnedIoObject {
    fn new(object: IoObject) -> Option<Self> {
        if object == IO_OBJECT_NULL {
            None
        } else {
            Some(Self(object))
        }
    }

    fn get(&self) -> IoObject {
        self.0
    }
}

impl Drop for OwnedIoObject {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a non-null owned IOKit object returned by a Create/Copy API and is
        // released exactly once here. This wrapper is neither Clone nor manually Send/Sync.
        let _ = unsafe { IOObjectRelease(self.0) };
    }
}

struct OwnedCf(CFTypeRef);

impl OwnedCf {
    fn new(object: CFTypeRef) -> Option<Self> {
        if object.is_null() {
            None
        } else {
            Some(Self(object))
        }
    }

    fn get(&self) -> CFTypeRef {
        self.0
    }
}

impl Drop for OwnedCf {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a non-null CF object returned under Create ownership and is released
        // exactly once here. This wrapper is neither Clone nor manually Send/Sync.
        unsafe { CFRelease(self.0) };
    }
}
