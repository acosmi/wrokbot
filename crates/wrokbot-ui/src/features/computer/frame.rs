//! UI boundary for the existing OBSCRN01 v1 ScreenHub binary envelope.
//! The target comes from Rust authority; frame metadata never mints control permission.
#![cfg_attr(not(test), allow(dead_code))]
use openbot_contracts::engine::MAX_ENGINE_IMAGE_BYTES;

const HEADER: usize = 68;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameError {
    Bounds,
    Protocol,
    Generation,
    Sequence,
    Metadata,
    Image,
}
#[derive(Debug)]
pub(crate) struct ScreenFrame<'a> {
    pub sequence: u64,
    pub captured_at_ms: i64,
    pub width: u32,
    pub height: u32,
    pub device_scale: f32,
    pub page_scale: f32,
    pub scroll_x: f32,
    pub scroll_y: f32,
    pub jpeg: &'a [u8],
}

/// Check every byte before exposing a payload to image decoding. Failed frames never advance sequence.
pub(crate) fn decode_frame(
    bytes: &[u8],
    generation: u64,
    last_sequence: u64,
) -> Result<ScreenFrame<'_>, FrameError> {
    if bytes.len() < HEADER || bytes.len() > HEADER + MAX_ENGINE_IMAGE_BYTES {
        return Err(FrameError::Bounds);
    }
    if &bytes[..8] != b"OBSCRN01"
        || bytes[8..12] != [1, 0, 1, 0]
        || u32_at(bytes, 12) != HEADER as u32
    {
        return Err(FrameError::Protocol);
    }
    let payload = u32_at(bytes, 16) as usize;
    if !(4..=MAX_ENGINE_IMAGE_BYTES).contains(&payload) || bytes.len() != HEADER + payload {
        return Err(FrameError::Bounds);
    }
    if generation == 0 || u64_at(bytes, 20) != generation {
        return Err(FrameError::Generation);
    }
    let sequence = u64_at(bytes, 28);
    if sequence <= last_sequence {
        return Err(FrameError::Sequence);
    }
    let captured_at_ms = i64::from_le_bytes(bytes[36..44].try_into().expect("fixed header"));
    let (width, height) = (u32_at(bytes, 44), u32_at(bytes, 48));
    let scale = |offset| f32::from_bits(u32_at(bytes, offset));
    let (device_scale, page_scale, scroll_x, scroll_y) =
        (scale(52), scale(56), scale(60), scale(64));
    if captured_at_ms <= 0
        || width == 0
        || height == 0
        || width > 1280
        || height > 800
        || !device_scale.is_finite()
        || device_scale <= 0.0
        || !page_scale.is_finite()
        || page_scale <= 0.0
        || !scroll_x.is_finite()
        || !scroll_y.is_finite()
    {
        return Err(FrameError::Metadata);
    }
    let jpeg = &bytes[HEADER..];
    let Some((pixel_width, pixel_height)) = jpeg_dimensions(jpeg) else {
        return Err(FrameError::Image);
    };
    if pixel_width == 0 || pixel_height == 0 || pixel_width > 1280 || pixel_height > 800 {
        return Err(FrameError::Image);
    }
    Ok(ScreenFrame {
        sequence,
        captured_at_ms,
        width,
        height,
        device_scale,
        page_scale,
        scroll_x,
        scroll_y,
        jpeg,
    })
}
/// Read a bounded SOF header before browser bitmap allocation; entropy data is never scanned.
fn jpeg_dimensions(bytes: &[u8]) -> Option<(u16, u16)> {
    if !bytes.starts_with(&[0xff, 0xd8]) || !bytes.ends_with(&[0xff, 0xd9]) {
        return None;
    }
    let mut offset = 2;
    for _ in 0..256 {
        if offset > 128 * 1024 || *bytes.get(offset)? != 0xff {
            return None;
        }
        while *bytes.get(offset)? == 0xff {
            offset += 1;
        }
        let marker = *bytes.get(offset)?;
        offset += 1;
        if matches!(marker, 0x00 | 0xd8 | 0xd9 | 0xda) {
            return None;
        }
        if marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
            continue;
        }
        let length = usize::from(u16::from_be_bytes(
            bytes.get(offset..offset + 2)?.try_into().ok()?,
        ));
        if length < 2 {
            return None;
        }
        let segment = bytes.get(offset..offset.checked_add(length)?)?;
        if (0xc0..=0xcf).contains(&marker) && !matches!(marker, 0xc4 | 0xc8 | 0xcc) {
            if segment.len() < 8 {
                return None;
            }
            let height = u16::from_be_bytes([segment[3], segment[4]]);
            let width = u16::from_be_bytes([segment[5], segment[6]]);
            return Some((width, height));
        }
        offset += length;
    }
    None
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed header"))
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("fixed header"))
}

/// A letterboxed display point maps to viewport DIP. DPR cancels; page scale is for document hit-tests.
pub(crate) fn viewport_point(
    frame: &ScreenFrame<'_>,
    display_width: f64,
    display_height: f64,
    x: f64,
    y: f64,
) -> Option<(f64, f64)> {
    if [display_width, display_height, x, y]
        .iter()
        .any(|v| !v.is_finite())
        || display_width <= 0.0
        || display_height <= 0.0
    {
        return None;
    }
    let zoom =
        (display_width / f64::from(frame.width)).min(display_height / f64::from(frame.height));
    let left = (display_width - f64::from(frame.width) * zoom) / 2.0;
    let top = (display_height - f64::from(frame.height) * zoom) / 2.0;
    let (x, y) = ((x - left) / zoom, (y - top) / zoom);
    (x >= 0.0 && y >= 0.0 && x < f64::from(frame.width) && y < f64::from(frame.height))
        .then_some((x, y))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn packet() -> Vec<u8> {
        let mut b = vec![0; HEADER];
        b[..8].copy_from_slice(b"OBSCRN01");
        b[8..12].copy_from_slice(&[1, 0, 1, 0]);
        for (offset, value) in [
            (12, 68u32),
            (16, 4),
            (44, 1280),
            (48, 800),
            (52, 2.0f32.to_bits()),
            (56, 1.5f32.to_bits()),
        ] {
            b[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [(20, 7u64), (28, 9), (36, 123)] {
            b[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        let jpeg = [
            0xff, 0xd8, 0xff, 0xc0, 0, 17, 8, 3, 32, 5, 0, 3, 1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0,
            0xff, 0xd9,
        ];
        b[16..20].copy_from_slice(&(jpeg.len() as u32).to_le_bytes());
        b.extend_from_slice(&jpeg);
        b
    }
    #[test]
    fn bounded_screen_envelope_rejects_old_generations_replays_and_damaged_payloads() {
        let b = packet();
        let frame = decode_frame(&b, 7, 8).unwrap();
        assert_eq!(frame.sequence, 9);
        assert_eq!(frame.captured_at_ms, 123);
        assert_eq!(frame.jpeg.len(), 23);
        assert_eq!(frame.scroll_x, 0.0);
        assert_eq!(frame.scroll_y, 0.0);
        assert_eq!(decode_frame(&b, 6, 8).unwrap_err(), FrameError::Generation);
        assert_eq!(decode_frame(&b, 7, 9).unwrap_err(), FrameError::Sequence);
        for end in 0..b.len() {
            assert!(decode_frame(&b[..end], 7, 8).is_err());
        }
        let mut extra = b.clone();
        extra.push(0);
        assert_eq!(decode_frame(&extra, 7, 8).unwrap_err(), FrameError::Bounds);
        let mut bad = b.clone();
        bad[11] = 1;
        assert_eq!(decode_frame(&bad, 7, 8).unwrap_err(), FrameError::Protocol);
        bad = b.clone();
        bad[52..56].copy_from_slice(&f32::NAN.to_bits().to_le_bytes());
        assert_eq!(decode_frame(&bad, 7, 8).unwrap_err(), FrameError::Metadata);
        bad = b;
        bad[68] = 0;
        assert_eq!(decode_frame(&bad, 7, 8).unwrap_err(), FrameError::Image);
    }
    #[test]
    fn a_small_compressed_packet_cannot_claim_an_unbounded_bitmap() {
        let mut b = packet();
        // SOF width exceeds screen capture pixel budget even with plausible DIP metadata.
        b[HEADER + 9] = 0x7f;
        b[HEADER + 10] = 0xff;
        assert_eq!(decode_frame(&b, 7, 8).unwrap_err(), FrameError::Image);
        let mut b = packet();
        b[HEADER + 3] = 0xda;
        assert_eq!(decode_frame(&b, 7, 8).unwrap_err(), FrameError::Image);
    }

    #[test]
    fn contain_mapping_refuses_black_bars_and_never_multiplies_by_dpr_or_page_scale() {
        let b = packet();
        let frame = decode_frame(&b, 7, 8).unwrap();
        assert_eq!(frame.device_scale, 2.0);
        assert_eq!(frame.page_scale, 1.5);
        assert_eq!(
            viewport_point(&frame, 640.0, 500.0, 320.0, 250.0),
            Some((640.0, 400.0))
        );
        assert_eq!(viewport_point(&frame, 640.0, 500.0, 10.0, 20.0), None);
        assert_eq!(viewport_point(&frame, 640.0, 500.0, 640.0, 250.0), None);
        assert_eq!(viewport_point(&frame, 0.0, 500.0, 0.0, 0.0), None);
    }
}
