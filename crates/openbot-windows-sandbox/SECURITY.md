# Windows unsafe boundary security notes

Owners: `openbot-computer::engine` and `openbot-desktop::postgres_sidecar`.

This crate is the sole workspace exception to `unsafe_code = deny`. It exists because the
first-source ten-crate rule explicitly permits a crate for an independent security boundary and
the safe standard library cannot create a restricted-token process, authenticate a Named Pipe
peer, or access the current user's Windows Credential Manager.

The Windows implementation may call only these Win32 mechanisms:

- token: `OpenProcessToken`, `CreateRestrictedToken`, `SetTokenInformation`, `IsTokenRestricted`;
- process identity/lifecycle: `CreateProcessAsUserW`, `GetProcessTimes`, `OpenProcess`, wait/exit,
  terminate/resume, and `CloseHandle`;
- environment: read-only `GetSystemWindowsDirectoryW` to construct an Engine-only Unicode block;
  no inheritance or enumeration of the parent's environment;
- confinement: Job Object create/configure/terminate, low-integrity directory ACL/label;
- IPC: one-instance, local-only, overlapped Named Pipe plus `GetNamedPipeClientProcessId`;
- packaging: transactional PE resource update and read-only resource verification;
- secrets: `CredReadW` / `CredWriteW` / `CredDeleteW` / `CredFree` for one bounded
  `CRED_TYPE_GENERIC`, current-user, `CRED_PERSIST_LOCAL_MACHINE` item;
- allocation/conversion needed to build SIDs and security descriptors.

Invariants:

1. No raw handle or pointer crosses the public API.
2. The restricted child is created suspended and attached to a preconfigured Job before resume.
3. Breakaway flags are never enabled; Job close kills the whole process tree.
4. Handle inheritance is an explicit three-handle allowlist (stdin plus null stdout/stderr).
5. The token disables maximum privileges, is a LUA token, stays medium integrity, and uses
   `WRITE_RESTRICTED` with the Restricted Code SID; its default DACL includes that SID.
6. Profile/temp directories have a protected current-user/System/Restricted-Code DACL and an
   inheritable low label; unrelated medium objects do not grant the restricting SID.
7. Named Pipes reject remote clients, are non-inheritable, random, current-user-only, and low-label.
8. Peer acceptance requires both exact spawned PID and exact 100 ns creation FILETIME.
9. Any setup failure closes owned handles; a post-create failure terminates and reaps the child.
10. Credential target names are bounded UTF-16 without NUL; secret blobs are 1–128 bytes (well
    below the Win32 2,560-byte maximum), use no attributes/username/alias, and never expose a raw
    `CREDENTIALW` pointer.
11. The OS-returned credential blob is copied once, overwritten byte-for-byte with volatile zeroes,
    then released with `CredFree`. The public owner redacts `Debug`, zeroizes on drop, and can only
    transfer its unique allocation explicitly into Desktop `SecretBytes`.
12. The Engine environment has exactly nine fixed keys. HOME/USERPROFILE/AppData point into the
    scoped profile, TEMP/TMP into its temp directory, and PATH/SystemRoot/WINDIR derive only from
    the actual OS Windows directory. No provider/DB credential, loader injection variable,
    SSLKEYLOGFILE, inherited PATH, or drive-current-directory entry is copied. This does not change
    Windows Known Folder APIs or claim additional filesystem/network sandbox enforcement.

The boundary is `Degraded`, not `Enforced`: proxy arguments and a write-restricted token do not
constitute a Windows network or executable-path allowlist and do not resist another malicious
process running as the same user. P1 remains red until the Windows real-machine conformance test
proves Electron compatibility, renderer sandbox state, process limits, cleanup, and negative
controls. Static cross-compilation is not runtime evidence. Credential Manager is likewise not a
Windows runtime success until its ignored real-machine round trip is run; compile-only proves API
shape, not logon-session availability or persistence behavior.
