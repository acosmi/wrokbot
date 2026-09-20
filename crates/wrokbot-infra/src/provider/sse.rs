//! Incremental SSE `data:` decoder；保留 UTF-8 分片并限制单事件/总 pending。

const MAX_SSE_EVENT_BYTES: usize = 1024 * 1024;
const MAX_SSE_PENDING_BYTES: usize = 2 * MAX_SSE_EVENT_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SseDecodeError {
    #[error("sse_event_too_large")]
    TooLarge,
    #[error("sse_invalid_utf8")]
    InvalidUtf8,
    #[error("sse_incomplete_event")]
    Incomplete,
}

#[derive(Debug, Default)]
pub struct SseDecoder {
    pending: Vec<u8>,
    data: Vec<u8>,
}

impl SseDecoder {
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<String>, SseDecodeError> {
        if bytes.len() > MAX_SSE_PENDING_BYTES.saturating_sub(self.pending.len()) {
            return Err(SseDecodeError::TooLarge);
        }
        self.pending.extend_from_slice(bytes);
        let mut output = Vec::new();
        while let Some(newline) = self.pending.iter().position(|byte| *byte == b'\n') {
            let mut line = self.pending.drain(..=newline).collect::<Vec<_>>();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.is_empty() {
                if !self.data.is_empty() {
                    if self.data.last() == Some(&b'\n') {
                        self.data.pop();
                    }
                    let data = core::str::from_utf8(&self.data)
                        .map_err(|_| SseDecodeError::InvalidUtf8)?
                        .to_owned();
                    self.data.clear();
                    output.push(data);
                }
                continue;
            }
            if line.first() == Some(&b':') {
                continue;
            }
            if let Some(value) = line.strip_prefix(b"data:") {
                let value = value.strip_prefix(b" ").unwrap_or(value);
                if value.len() > MAX_SSE_EVENT_BYTES.saturating_sub(self.data.len()) {
                    return Err(SseDecodeError::TooLarge);
                }
                self.data.extend_from_slice(value);
                self.data.push(b'\n');
            }
        }
        Ok(output)
    }

    pub fn finish(&self) -> Result<(), SseDecodeError> {
        if self.pending.is_empty() && self.data.is_empty() {
            Ok(())
        } else {
            Err(SseDecodeError::Incomplete)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_and_multiline_data_survive_arbitrary_chunks() {
        let wire = "event: ignored\r\ndata: {\"delta\":\"蟹\"}\r\ndata: second\r\n\r\n: ping\n\n";
        let mut decoder = SseDecoder::default();
        let mut output = Vec::new();
        for chunk in wire.as_bytes().chunks(2) {
            output.extend(decoder.push(chunk).unwrap());
        }
        assert_eq!(output, ["{\"delta\":\"蟹\"}\nsecond"]);
        assert_eq!(decoder.finish(), Ok(()));
    }

    #[test]
    fn invalid_utf8_and_incomplete_tail_fail_closed() {
        let mut decoder = SseDecoder::default();
        assert_eq!(
            decoder.push(b"data: \xff\n\n"),
            Err(SseDecodeError::InvalidUtf8)
        );
        let mut decoder = SseDecoder::default();
        assert!(decoder.push(b"data: partial").unwrap().is_empty());
        assert_eq!(decoder.finish(), Err(SseDecodeError::Incomplete));
    }
}
