//! Closed Engine-only environment block. No parent-environment iterator is accepted.

use crate::WindowsSandboxError;

const MAX_ENVIRONMENT_UNITS: usize = 32_767;

pub(crate) fn engine_environment_block(
    system_root: &str,
    profile: &str,
    temp: &str,
) -> Result<Vec<u16>, WindowsSandboxError> {
    // GetSystemWindowsDirectoryW documents `C:` when Windows is installed at the drive root.
    // This one API result means the absolute root; arbitrary drive-relative paths stay invalid.
    let root_drive = match system_root.as_bytes() {
        [drive, b':'] if drive.is_ascii_alphabetic() => Some(format!("{system_root}\\")),
        _ => None,
    };
    let system_root = root_drive.as_deref().unwrap_or(system_root);
    for value in [system_root, profile, temp] {
        if value.is_empty()
            || value.contains(['\0', '\r', '\n'])
            || value.encode_utf16().count() > MAX_ENVIRONMENT_UNITS
            || !absolute_windows_path(value)
        {
            return Err(WindowsSandboxError::InvalidInput);
        }
    }
    // Only the OS-returned Windows directory enters PATH. Never copy a parent's PATH, loader
    // settings, proxy/SSL key-log configuration, credentials, or drive-current-directory entries.
    if system_root.contains(';') {
        return Err(WindowsSandboxError::InvalidInput);
    }
    let root = system_root.trim_end_matches(['/', '\\']);
    let home = profile.trim_end_matches(['/', '\\']);
    let mut values = [
        ("APPDATA", format!("{home}\\AppData\\Roaming")),
        ("HOME", profile.to_owned()),
        ("LOCALAPPDATA", format!("{home}\\AppData\\Local")),
        ("PATH", format!("{root}\\System32;{system_root}")),
        ("SystemRoot", system_root.to_owned()),
        ("TEMP", temp.to_owned()),
        ("TMP", temp.to_owned()),
        ("USERPROFILE", profile.to_owned()),
        ("WINDIR", system_root.to_owned()),
    ];
    values.sort_by_key(|(key, _)| key.to_ascii_uppercase());
    let mut block = Vec::new();
    for (key, value) in values {
        block.extend(key.encode_utf16());
        block.push(u16::from(b'='));
        block.extend(value.encode_utf16());
        block.push(0);
        if block.len() >= MAX_ENVIRONMENT_UNITS {
            return Err(WindowsSandboxError::InvalidInput);
        }
    }
    block.push(0);
    Ok(block)
}

fn absolute_windows_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    (bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\'))
        || (value.starts_with("\\\\")
            && value[2..].split('\\').filter(|s| !s.is_empty()).count() >= 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_block_is_closed_sorted_unicode_and_double_terminated() {
        let block =
            engine_environment_block(r"C:\Windows", r"\\?\C:\Scoped\用户", r"\\?\C:\Scoped\临时")
                .unwrap();
        assert!(block.ends_with(&[0, 0]));
        let text = String::from_utf16(&block).unwrap();
        let values: Vec<_> = text.split('\0').filter(|value| !value.is_empty()).collect();
        let keys: Vec<_> = values
            .iter()
            .map(|value| value.split_once('=').unwrap().0)
            .collect();
        assert_eq!(
            keys,
            [
                "APPDATA",
                "HOME",
                "LOCALAPPDATA",
                "PATH",
                "SystemRoot",
                "TEMP",
                "TMP",
                "USERPROFILE",
                "WINDIR"
            ]
        );
        assert!(values.contains(&r"PATH=C:\Windows\System32;C:\Windows"));
        assert!(values.contains(&r"HOME=\\?\C:\Scoped\用户"));
        assert!(values.contains(&r"TEMP=\\?\C:\Scoped\临时"));
        assert!(values.contains(&r"LOCALAPPDATA=\\?\C:\Scoped\用户\AppData\Local"));
        let root_install = engine_environment_block("C:", r"C:\scope", r"C:\temp").unwrap();
        assert!(
            String::from_utf16(&root_install)
                .unwrap()
                .contains("SystemRoot=C:\\\0")
        );
    }

    #[test]
    fn malformed_or_unbounded_inputs_cannot_create_an_environment_block() {
        for value in [
            "",
            "C:relative",
            "relative",
            "C:\\bad\0suffix",
            "C:\\bad\nnext",
        ] {
            assert!(engine_environment_block(value, r"C:\scope", r"C:\temp").is_err());
        }
        assert!(
            engine_environment_block(r"C:\Windows;C:\injected", r"C:\scope", r"C:\temp").is_err()
        );
        assert!(
            engine_environment_block(
                r"C:\Windows",
                &format!("C:\\{}", "a".repeat(32_767)),
                r"C:\temp"
            )
            .is_err()
        );
    }
}
