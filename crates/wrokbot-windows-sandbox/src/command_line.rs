//! Pure Windows wire helpers; kept platform-independent so quoting/time conversion test on macOS.

use crate::WindowsSandboxError;

/// FILETIME ticks between 1601-01-01 and 1970-01-01 (100 ns per tick).
pub const FILETIME_UNIX_EPOCH_TICKS: u64 = 116_444_736_000_000_000;

/// Convert FILETIME exactly as Chromium does: truncate 100 ns ticks to microseconds, then expose
/// floating milliseconds since Unix epoch for Electron `ProcessMetric.creationTime`.
pub fn filetime_ticks_to_unix_millis(ticks: u64) -> Result<f64, WindowsSandboxError> {
    let unix_ticks = ticks
        .checked_sub(FILETIME_UNIX_EPOCH_TICKS)
        .ok_or(WindowsSandboxError::CreationTime)?;
    Ok((unix_ticks / 10) as f64 / 1_000.0)
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn encode_command_line(
    executable: &std::ffi::OsStr,
    args: &[std::ffi::OsString],
) -> Result<Vec<u16>, WindowsSandboxError> {
    let executable = executable
        .to_str()
        .ok_or(WindowsSandboxError::InvalidInput)?;
    let mut command = quote_argument(executable)?;
    for arg in args {
        command.push(' ');
        command.push_str(&quote_argument(
            arg.to_str().ok_or(WindowsSandboxError::InvalidInput)?,
        )?);
    }
    if command.len() > 32_767 {
        return Err(WindowsSandboxError::InvalidInput);
    }
    Ok(command.encode_utf16().chain(std::iter::once(0)).collect())
}

#[cfg_attr(not(windows), allow(dead_code))]
fn quote_argument(value: &str) -> Result<String, WindowsSandboxError> {
    if value.contains('\0') {
        return Err(WindowsSandboxError::InvalidInput);
    }
    if !value.is_empty()
        && !value
            .bytes()
            .any(|byte| matches!(byte, b' ' | b'\t' | b'"'))
    {
        return Ok(value.to_owned());
    }

    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    let mut backslashes = 0usize;
    for character in value.chars() {
        match character {
            '\\' => backslashes += 1,
            '"' => {
                output.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                output.push('"');
                backslashes = 0;
            }
            _ => {
                output.extend(std::iter::repeat_n('\\', backslashes));
                output.push(character);
                backslashes = 0;
            }
        }
    }
    output.extend(std::iter::repeat_n('\\', backslashes * 2));
    output.push('"');
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_empty_spaces_quotes_and_trailing_backslashes() {
        assert_eq!(quote_argument("plain").unwrap(), "plain");
        assert_eq!(quote_argument("").unwrap(), "\"\"");
        assert_eq!(quote_argument("two words").unwrap(), "\"two words\"");
        assert_eq!(quote_argument("a\\\"b").unwrap(), "\"a\\\\\\\"b\"");
        assert_eq!(quote_argument("a b\\").unwrap(), "\"a b\\\\\"");
        assert!(quote_argument("bad\0value").is_err());
    }

    #[test]
    fn filetime_conversion_is_checked_and_millisecond_exact() {
        assert!(filetime_ticks_to_unix_millis(FILETIME_UNIX_EPOCH_TICKS - 1).is_err());
        assert_eq!(
            filetime_ticks_to_unix_millis(FILETIME_UNIX_EPOCH_TICKS + 12_345_678).unwrap(),
            1_234.567
        );
    }
}
