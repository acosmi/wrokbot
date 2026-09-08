//! Independent bounded binary image ingress (v4 §11.2 / §12.2).

use openbot_contracts::engine::{
    ENGINE_FRAME_FIXED_HEADER_BYTES, ENGINE_FRAME_HELLO_MAGIC, ENGINE_FRAME_MAGIC,
    ENGINE_PROTOCOL_VERSION, MAX_ENGINE_IMAGE_BYTES,
};
use openbot_contracts::ids::{ComputerGeneration, ComputerId, TabId};
use tokio::io::{AsyncRead, AsyncReadExt as _};

use super::protocol::BootToken;
use super::scope::EngineRoleKind;

mod jpeg;

const MAX_FRAME_WIDTH: u32 = 1280;
const MAX_FRAME_HEIGHT: u32 = 800;

/// Image payload format. P1 production/conformance supports JPEG only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageFormat {
    /// JPEG capture with fixed quality 70.
    Jpeg,
}

/// One image frame after all scope/generation/ordering/bounds checks.
#[derive(Clone, Debug, PartialEq)]
pub struct EngineFrame {
    sequence: u64,
    captured_at_ms: i64,
    width: u32,
    height: u32,
    device_scale_factor: f32,
    page_scale_factor: f32,
    scroll_x: f32,
    scroll_y: f32,
    screencast_session_id: u32,
    format: ImageFormat,
    bytes: Vec<u8>,
}

impl EngineFrame {
    #[cfg(any(test, feature = "testkit"))]
    pub(crate) fn for_test(sequence: u64, captured_at_ms: i64, scroll_y: f32) -> Self {
        Self {
            sequence,
            captured_at_ms,
            width: 1280,
            height: 800,
            device_scale_factor: 1.0,
            page_scale_factor: 1.0,
            scroll_x: 0.0,
            scroll_y,
            screencast_session_id: u32::try_from(sequence).unwrap_or(u32::MAX),
            format: ImageFormat::Jpeg,
            bytes: jpeg::test_image(),
        }
    }

    /// Monotonic sequence within this engine generation.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// CDP frame-swap timestamp converted from seconds to Unix milliseconds by the shim.
    #[must_use]
    pub const fn captured_at_ms(&self) -> i64 {
        self.captured_at_ms
    }

    /// Device screen width in device-independent pixels (DIP), as defined by CDP metadata.
    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// Device screen height in device-independent pixels (DIP), as defined by CDP metadata.
    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// Renderer device scale factor sampled by the fixed non-free runtime probe.
    #[must_use]
    pub const fn device_scale_factor(&self) -> f32 {
        self.device_scale_factor
    }

    /// Page scale factor reported by CDP screencast metadata.
    #[must_use]
    pub const fn page_scale_factor(&self) -> f32 {
        self.page_scale_factor
    }

    /// Horizontal page scroll in CSS pixels.
    #[must_use]
    pub const fn scroll_x(&self) -> f32 {
        self.scroll_x
    }

    /// Vertical page scroll in CSS pixels.
    #[must_use]
    pub const fn scroll_y(&self) -> f32 {
        self.scroll_y
    }

    pub(crate) const fn screencast_session_id(&self) -> u32 {
        self.screencast_session_id
    }

    /// Validated image format.
    #[must_use]
    pub const fn format(&self) -> ImageFormat {
        self.format
    }

    /// Validated compressed image bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Stateful frame decoder. A new instance is required after generation/tab changes.
pub struct EngineFrameReader {
    role: EngineRoleKind,
    computer_id: ComputerId,
    generation: ComputerGeneration,
    tab_id: TabId,
    last_sequence: u64,
}

impl EngineFrameReader {
    /// Bind a decoder to one exact role/computer/generation/tab authority tuple.
    #[must_use]
    pub fn new(
        role: EngineRoleKind,
        computer_id: ComputerId,
        generation: ComputerGeneration,
        tab_id: TabId,
    ) -> Self {
        Self {
            role,
            computer_id,
            generation,
            tab_id,
            last_sequence: 0,
        }
    }

    /// Read and validate one complete frame.
    pub async fn read<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<EngineFrame, EngineFrameError> {
        let mut fixed = [0_u8; ENGINE_FRAME_FIXED_HEADER_BYTES];
        reader
            .read_exact(&mut fixed)
            .await
            .map_err(|_| EngineFrameError::Truncated)?;
        if &fixed[..8] != ENGINE_FRAME_MAGIC {
            return Err(EngineFrameError::Magic);
        }
        if u16::from_le_bytes(fixed[8..10].try_into().expect("fixed slice"))
            != ENGINE_PROTOCOL_VERSION
        {
            return Err(EngineFrameError::ProtocolVersion);
        }
        let role = match fixed[10] {
            0 => EngineRoleKind::BrowserComputer,
            1 => EngineRoleKind::SandboxedComponent,
            _ => return Err(EngineFrameError::Role),
        };
        if role != self.role {
            return Err(EngineFrameError::Role);
        }
        let format = match fixed[11] {
            1 => ImageFormat::Jpeg,
            _ => return Err(EngineFrameError::Format),
        };
        let header_length = usize::try_from(u32::from_le_bytes(
            fixed[12..16].try_into().expect("fixed slice"),
        ))
        .map_err(|_| EngineFrameError::HeaderBounds)?;
        let payload_length = usize::try_from(u32::from_le_bytes(
            fixed[16..20].try_into().expect("fixed slice"),
        ))
        .map_err(|_| EngineFrameError::PayloadBounds)?;
        if payload_length == 0 || payload_length > MAX_ENGINE_IMAGE_BYTES {
            return Err(EngineFrameError::PayloadBounds);
        }
        let generation = u64::from_le_bytes(fixed[20..28].try_into().expect("fixed slice"));
        if generation != self.generation.get() {
            return Err(EngineFrameError::Generation);
        }
        let sequence = u64::from_le_bytes(fixed[28..36].try_into().expect("fixed slice"));
        if sequence <= self.last_sequence {
            return Err(EngineFrameError::Sequence);
        }
        let captured_at_ms = i64::from_le_bytes(fixed[36..44].try_into().expect("fixed slice"));
        if captured_at_ms <= 0 {
            return Err(EngineFrameError::Metadata);
        }
        let width = u32::from_le_bytes(fixed[44..48].try_into().expect("fixed slice"));
        let height = u32::from_le_bytes(fixed[48..52].try_into().expect("fixed slice"));
        if width == 0 || height == 0 || width > MAX_FRAME_WIDTH || height > MAX_FRAME_HEIGHT {
            return Err(EngineFrameError::Dimensions);
        }
        let device_scale_factor =
            f32::from_le_bytes(fixed[52..56].try_into().expect("fixed slice"));
        let page_scale_factor = f32::from_le_bytes(fixed[56..60].try_into().expect("fixed slice"));
        let scroll_x = f32::from_le_bytes(fixed[60..64].try_into().expect("fixed slice"));
        let scroll_y = f32::from_le_bytes(fixed[64..68].try_into().expect("fixed slice"));
        if !device_scale_factor.is_finite()
            || device_scale_factor <= 0.0
            || !page_scale_factor.is_finite()
            || page_scale_factor <= 0.0
            || !scroll_x.is_finite()
            || !scroll_y.is_finite()
        {
            return Err(EngineFrameError::Metadata);
        }
        let screencast_session_id =
            u32::from_le_bytes(fixed[68..72].try_into().expect("fixed slice"));
        let computer_length = usize::from(u16::from_le_bytes(
            fixed[72..74].try_into().expect("fixed slice"),
        ));
        let tab_length = usize::from(u16::from_le_bytes(
            fixed[74..76].try_into().expect("fixed slice"),
        ));
        if computer_length == 0
            || tab_length == 0
            || computer_length > 256
            || tab_length > 256
            || header_length != ENGINE_FRAME_FIXED_HEADER_BYTES + computer_length + tab_length
        {
            return Err(EngineFrameError::HeaderBounds);
        }
        let mut ids = vec![0_u8; computer_length + tab_length];
        reader
            .read_exact(&mut ids)
            .await
            .map_err(|_| EngineFrameError::Truncated)?;
        let computer =
            std::str::from_utf8(&ids[..computer_length]).map_err(|_| EngineFrameError::Scope)?;
        let tab =
            std::str::from_utf8(&ids[computer_length..]).map_err(|_| EngineFrameError::Scope)?;
        if computer != self.computer_id.as_str() || tab != self.tab_id.as_str() {
            return Err(EngineFrameError::Scope);
        }
        let mut bytes = vec![0_u8; payload_length];
        reader
            .read_exact(&mut bytes)
            .await
            .map_err(|_| EngineFrameError::Truncated)?;
        // Compressed byte limits do not bound bitmap allocations. Validate physical JPEG
        // dimensions before publication; the independent CDP DIP metadata remains unchanged.
        jpeg::validate(&bytes)?;
        self.last_sequence = sequence;
        Ok(EngineFrame {
            sequence,
            captured_at_ms,
            width,
            height,
            device_scale_factor,
            page_scale_factor,
            scroll_x,
            scroll_y,
            screencast_session_id,
            format,
            bytes,
        })
    }
}

pub(crate) async fn read_frame_hello<R: AsyncRead + Unpin>(
    reader: &mut R,
    token: &BootToken,
) -> Result<(), EngineFrameError> {
    let mut hello = [0_u8; 24];
    reader
        .read_exact(&mut hello)
        .await
        .map_err(|_| EngineFrameError::Truncated)?;
    if &hello[..8] != ENGINE_FRAME_HELLO_MAGIC || &hello[8..] != token.bytes() {
        return Err(EngineFrameError::Authentication);
    }
    Ok(())
}

/// Stable binary frame rejection reasons.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum EngineFrameError {
    /// Stream ended before a complete bounded frame arrived.
    #[error("engine_frame_truncated")]
    Truncated,
    /// Frame magic did not match the only accepted format.
    #[error("engine_frame_magic")]
    Magic,
    /// Protocol version was stale or unknown.
    #[error("engine_frame_protocol_version")]
    ProtocolVersion,
    /// Role tag did not match the Rust-minted engine role.
    #[error("engine_frame_role")]
    Role,
    /// Image format was outside the P1 closed set.
    #[error("engine_frame_format")]
    Format,
    /// Variable header lengths were impossible or over bounds.
    #[error("engine_frame_header_bounds")]
    HeaderBounds,
    /// Payload length was zero or exceeded 8 MiB.
    #[error("engine_frame_payload_bounds")]
    PayloadBounds,
    /// Computer generation was stale.
    #[error("engine_frame_generation")]
    Generation,
    /// Frame sequence repeated or moved backwards.
    #[error("engine_frame_sequence")]
    Sequence,
    /// DIP or physical JPEG dimensions were zero or exceeded the fixed 1280×800 contract.
    #[error("engine_frame_dimensions")]
    Dimensions,
    /// Timestamp, scale, scroll, or CDP frame identity metadata was malformed.
    #[error("engine_frame_metadata")]
    Metadata,
    /// Computer/tab scope did not exactly match the Rust-owned session.
    #[error("engine_frame_scope")]
    Scope,
    /// JPEG marker structure was malformed or outside the supported 8-bit DCT subset.
    #[error("engine_frame_image_shape")]
    ImageShape,
    /// Binary ingress token preface did not match the one-shot boot capability.
    #[error("engine_frame_authentication")]
    Authentication,
}

#[cfg(test)]
mod tests {
    use openbot_contracts::engine::{
        ENGINE_FRAME_FIXED_HEADER_BYTES, ENGINE_FRAME_MAGIC, ENGINE_PROTOCOL_VERSION,
    };
    use openbot_contracts::ids::{ComputerGeneration, ComputerId, TabId};

    use super::{EngineFrameError, EngineFrameReader};
    use crate::engine::EngineRoleKind;

    fn frame(generation: u64, sequence: u64, computer: &str, tab: &str) -> Vec<u8> {
        let image = super::jpeg::test_image();
        frame_with_image(generation, sequence, computer, tab, &image)
    }

    fn frame_with_image(
        generation: u64,
        sequence: u64,
        computer: &str,
        tab: &str,
        image: &[u8],
    ) -> Vec<u8> {
        let mut fixed = [0_u8; ENGINE_FRAME_FIXED_HEADER_BYTES];
        fixed[..8].copy_from_slice(ENGINE_FRAME_MAGIC);
        fixed[8..10].copy_from_slice(&ENGINE_PROTOCOL_VERSION.to_le_bytes());
        fixed[10] = 0;
        fixed[11] = 1;
        let header = ENGINE_FRAME_FIXED_HEADER_BYTES + computer.len() + tab.len();
        fixed[12..16].copy_from_slice(&u32::try_from(header).unwrap().to_le_bytes());
        fixed[16..20].copy_from_slice(&u32::try_from(image.len()).unwrap().to_le_bytes());
        fixed[20..28].copy_from_slice(&generation.to_le_bytes());
        fixed[28..36].copy_from_slice(&sequence.to_le_bytes());
        fixed[36..44].copy_from_slice(&1_788_499_200_000_i64.to_le_bytes());
        fixed[44..48].copy_from_slice(&1280_u32.to_le_bytes());
        fixed[48..52].copy_from_slice(&800_u32.to_le_bytes());
        fixed[52..56].copy_from_slice(&2.0_f32.to_le_bytes());
        fixed[56..60].copy_from_slice(&1.0_f32.to_le_bytes());
        fixed[60..64].copy_from_slice(&0.0_f32.to_le_bytes());
        fixed[64..68].copy_from_slice(&20.0_f32.to_le_bytes());
        fixed[68..72].copy_from_slice(&7_u32.to_le_bytes());
        fixed[72..74].copy_from_slice(&u16::try_from(computer.len()).unwrap().to_le_bytes());
        fixed[74..76].copy_from_slice(&u16::try_from(tab.len()).unwrap().to_le_bytes());
        [fixed.as_slice(), computer.as_bytes(), tab.as_bytes(), image].concat()
    }

    #[tokio::test]
    async fn valid_frame_is_accepted_once_and_replay_is_rejected() {
        let mut reader = EngineFrameReader::new(
            EngineRoleKind::BrowserComputer,
            ComputerId::new("computer"),
            ComputerGeneration::new(3),
            TabId::new("tab"),
        );
        let bytes = frame(3, 1, "computer", "tab");
        let accepted = reader.read(&mut bytes.as_slice()).await.expect("frame");
        assert_eq!(accepted.sequence(), 1);
        assert_eq!(accepted.captured_at_ms(), 1_788_499_200_000);
        assert_eq!(accepted.device_scale_factor(), 2.0);
        assert_eq!(accepted.page_scale_factor(), 1.0);
        // The synthetic bitmap is 1×1; input coordinates remain in the CDP metadata's DIP.
        assert_eq!((accepted.width(), accepted.height()), (1280, 800));
        assert_eq!(accepted.bytes(), super::jpeg::test_image());
        assert_eq!((accepted.scroll_x(), accepted.scroll_y()), (0.0, 20.0));
        assert_eq!(
            reader.read(&mut bytes.as_slice()).await,
            Err(EngineFrameError::Sequence)
        );
    }

    #[tokio::test]
    async fn malformed_or_oversized_jpeg_is_never_published_or_used_to_advance_sequence() {
        let mut reader = EngineFrameReader::new(
            EngineRoleKind::BrowserComputer,
            ComputerId::new("computer"),
            ComputerGeneration::new(3),
            TabId::new("tab"),
        );
        let old_marker_only = [0xff, 0xd8, 0xff, 0x01, 0xff, 0xd9];
        let malformed = frame_with_image(3, 1, "computer", "tab", &old_marker_only);
        assert_eq!(
            reader.read(&mut malformed.as_slice()).await,
            Err(EngineFrameError::ImageShape)
        );
        let mut oversized = super::jpeg::test_image();
        oversized[78..80].copy_from_slice(&1281_u16.to_be_bytes());
        let oversized = frame_with_image(3, 1, "computer", "tab", &oversized);
        assert_eq!(
            reader.read(&mut oversized.as_slice()).await,
            Err(EngineFrameError::Dimensions)
        );
        let valid = frame(3, 1, "computer", "tab");
        assert_eq!(
            reader.read(&mut valid.as_slice()).await.unwrap().sequence(),
            1
        );
    }

    #[tokio::test]
    async fn payload_byte_limit_is_rejected_before_reading_or_allocating_an_image() {
        let mut reader = EngineFrameReader::new(
            EngineRoleKind::BrowserComputer,
            ComputerId::new("computer"),
            ComputerGeneration::new(3),
            TabId::new("tab"),
        );
        for length in [
            0,
            u32::try_from(openbot_contracts::engine::MAX_ENGINE_IMAGE_BYTES + 1).unwrap(),
        ] {
            let mut header = frame(3, 1, "computer", "tab");
            header.truncate(ENGINE_FRAME_FIXED_HEADER_BYTES);
            header[16..20].copy_from_slice(&length.to_le_bytes());
            assert_eq!(
                reader.read(&mut header.as_slice()).await,
                Err(EngineFrameError::PayloadBounds)
            );
        }
    }

    #[test]
    fn dimension_limits_match_the_authoritative_screencast_descriptor() {
        let descriptor: serde_json::Value =
            serde_json::from_str(openbot_contracts::engine::ENGINE_PROTOCOL_DESCRIPTOR).unwrap();
        assert_eq!(
            descriptor["screencast"]["max_width"],
            super::MAX_FRAME_WIDTH
        );
        assert_eq!(
            descriptor["screencast"]["max_height"],
            super::MAX_FRAME_HEIGHT
        );
    }

    #[tokio::test]
    async fn stale_generation_wrong_scope_and_bad_magic_are_distinct_rejections() {
        let make_reader = || {
            EngineFrameReader::new(
                EngineRoleKind::BrowserComputer,
                ComputerId::new("computer"),
                ComputerGeneration::new(3),
                TabId::new("tab"),
            )
        };
        let mut reader = make_reader();
        assert_eq!(
            reader
                .read(&mut frame(2, 1, "computer", "tab").as_slice())
                .await,
            Err(EngineFrameError::Generation)
        );
        let mut reader = make_reader();
        assert_eq!(
            reader
                .read(&mut frame(3, 1, "other", "tab").as_slice())
                .await,
            Err(EngineFrameError::Scope)
        );
        let mut bad = frame(3, 1, "computer", "tab");
        bad[0] ^= 1;
        let mut reader = make_reader();
        assert_eq!(
            reader.read(&mut bad.as_slice()).await,
            Err(EngineFrameError::Magic)
        );
    }

    #[tokio::test]
    async fn invalid_timestamp_and_scale_metadata_fail_before_payload_exposure() {
        let make_reader = || {
            EngineFrameReader::new(
                EngineRoleKind::BrowserComputer,
                ComputerId::new("computer"),
                ComputerGeneration::new(3),
                TabId::new("tab"),
            )
        };
        let mut timestamp = frame(3, 1, "computer", "tab");
        timestamp[36..44].copy_from_slice(&0_i64.to_le_bytes());
        let mut reader = make_reader();
        assert_eq!(
            reader.read(&mut timestamp.as_slice()).await,
            Err(EngineFrameError::Metadata)
        );
        let mut scale = frame(3, 1, "computer", "tab");
        scale[52..56].copy_from_slice(&f32::NAN.to_le_bytes());
        let mut reader = make_reader();
        assert_eq!(
            reader.read(&mut scale.as_slice()).await,
            Err(EngineFrameError::Metadata)
        );
    }
}
