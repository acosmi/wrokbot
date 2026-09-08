//! Allocation-free JPEG envelope and physical-dimension guard, before any image decoder.
//!
//! Authored from ITU-T T.81 Annex B (https://www.w3.org/Graphics/JPEG/itu-t81.pdf).
//! The engine emits 8-bit DCT JPEGs. Accept SOF0/1/2 with at most four components; reject
//! arithmetic, lossless, hierarchical and deferred-height (DNL) streams. Traverse every scan,
//! so a later SOF or DNL cannot replace previously checked dimensions. APP/COM/table contents
//! are opaque; Huffman codes, coefficients and scan completeness remain the decoder's job.
//! Work is O(payload bytes), bounded by the caller's 8 MiB ingress limit, with no image allocation.

use super::{EngineFrameError, MAX_FRAME_HEIGHT, MAX_FRAME_WIDTH};

struct FrameInfo {
    progressive: bool,
    components: [u8; 4],
    component_count: usize,
}

pub(super) fn validate(bytes: &[u8]) -> Result<(), EngineFrameError> {
    if !bytes.starts_with(&[0xff, 0xd8]) {
        return Err(EngineFrameError::ImageShape);
    }
    let mut cursor = 2;
    let mut frame = None;
    let mut in_scan = false;
    let mut saw_scan = false;
    let mut scan_has_data = false;
    let mut restart_enabled = false;
    let mut next_restart = 0;
    loop {
        if in_scan {
            while bytes.get(cursor).is_some_and(|byte| *byte != 0xff) {
                cursor += 1;
                scan_has_data = true;
            }
        }
        let (marker, prefixes) = read_marker(bytes, &mut cursor)?;
        if in_scan && marker == 0 && prefixes == 1 {
            // FF00 is a single entropy byte, never a segment boundary.
            scan_has_data = true;
            continue;
        }
        if (0xd0..=0xd7).contains(&marker) {
            if !in_scan || !scan_has_data || !restart_enabled || marker != 0xd0 + next_restart {
                return Err(EngineFrameError::ImageShape);
            }
            next_restart = (next_restart + 1) % 8;
            scan_has_data = false;
            continue;
        }
        if in_scan && !scan_has_data {
            return Err(EngineFrameError::ImageShape);
        }
        in_scan = false;
        match marker {
            0xd9 if frame.is_some() && saw_scan && cursor == bytes.len() => return Ok(()),
            0xc0..=0xc2 if frame.is_none() => {
                frame = Some(read_frame(marker, read_segment(bytes, &mut cursor)?)?);
            }
            0xda => {
                let frame = frame.as_ref().ok_or(EngineFrameError::ImageShape)?;
                read_scan(frame, read_segment(bytes, &mut cursor)?)?;
                in_scan = true;
                saw_scan = true;
                scan_has_data = false;
                next_restart = 0;
            }
            0xdd => {
                let segment = read_segment(bytes, &mut cursor)?;
                let interval: [u8; 2] = segment
                    .try_into()
                    .map_err(|_| EngineFrameError::ImageShape)?;
                restart_enabled = u16::from_be_bytes(interval) != 0;
            }
            // These tables and application metadata cannot redefine frame dimensions.
            0xc4 | 0xdb | 0xe0..=0xef | 0xfe => {
                read_segment(bytes, &mut cursor)?;
            }
            // Includes a second SOI/SOF, early EOI, DNL, TEM, reserved and unsupported SOF.
            _ => return Err(EngineFrameError::ImageShape),
        }
    }
}

fn read_marker(bytes: &[u8], cursor: &mut usize) -> Result<(u8, usize), EngineFrameError> {
    let start = *cursor;
    while bytes.get(*cursor) == Some(&0xff) {
        *cursor += 1;
    }
    let prefixes = *cursor - start;
    if prefixes == 0 {
        return Err(EngineFrameError::ImageShape);
    }
    let marker = *bytes.get(*cursor).ok_or(EngineFrameError::ImageShape)?;
    *cursor += 1;
    Ok((marker, prefixes))
}

fn read_segment<'a>(bytes: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], EngineFrameError> {
    let length_bytes = bytes
        .get(*cursor..*cursor + 2)
        .ok_or(EngineFrameError::ImageShape)?;
    let length = usize::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]));
    if length < 2 {
        return Err(EngineFrameError::ImageShape);
    }
    let end = cursor
        .checked_add(length)
        .ok_or(EngineFrameError::ImageShape)?;
    let segment = bytes
        .get(*cursor + 2..end)
        .ok_or(EngineFrameError::ImageShape)?;
    *cursor = end;
    Ok(segment)
}

fn read_frame(marker: u8, segment: &[u8]) -> Result<FrameInfo, EngineFrameError> {
    if segment.len() < 6 || segment[0] != 8 {
        return Err(EngineFrameError::ImageShape);
    }
    let height = u32::from(u16::from_be_bytes([segment[1], segment[2]]));
    let width = u32::from(u16::from_be_bytes([segment[3], segment[4]]));
    if width == 0 || height == 0 || width > MAX_FRAME_WIDTH || height > MAX_FRAME_HEIGHT {
        return Err(EngineFrameError::Dimensions);
    }
    let component_count = usize::from(segment[5]);
    if !(1..=4).contains(&component_count) || segment.len() != 6 + component_count * 3 {
        return Err(EngineFrameError::ImageShape);
    }
    let mut components = [0; 4];
    for (index, component) in segment[6..].as_chunks::<3>().0.iter().enumerate() {
        if components[..index].contains(&component[0])
            || !(1..=4).contains(&(component[1] >> 4))
            || !(1..=4).contains(&(component[1] & 0x0f))
            || component[2] > 3
        {
            return Err(EngineFrameError::ImageShape);
        }
        components[index] = component[0];
    }
    Ok(FrameInfo {
        progressive: marker == 0xc2,
        components,
        component_count,
    })
}

fn read_scan(frame: &FrameInfo, segment: &[u8]) -> Result<(), EngineFrameError> {
    let count = usize::from(*segment.first().ok_or(EngineFrameError::ImageShape)?);
    if count == 0 || count > frame.component_count || segment.len() != 4 + count * 2 {
        return Err(EngineFrameError::ImageShape);
    }
    let mut selected = [0; 4];
    for (index, component) in segment[1..1 + count * 2]
        .as_chunks::<2>()
        .0
        .iter()
        .enumerate()
    {
        if !frame.components[..frame.component_count].contains(&component[0])
            || selected[..index].contains(&component[0])
            || component[1] >> 4 > 3
            || component[1] & 0x0f > 3
        {
            return Err(EngineFrameError::ImageShape);
        }
        selected[index] = component[0];
    }
    let tail = &segment[1 + count * 2..];
    if !frame.progressive {
        if tail != [0, 63, 0] {
            return Err(EngineFrameError::ImageShape);
        }
    } else {
        let (start, end, high, low) = (tail[0], tail[1], tail[2] >> 4, tail[2] & 0x0f);
        if start > end
            || end > 63
            || (start == 0 && end != 0)
            || (start != 0 && count != 1)
            || high > 13
            || low > 13
            || (high != 0 && high != low + 1)
        {
            return Err(EngineFrameError::ImageShape);
        }
    }
    Ok(())
}

/// Synthetic 1×1 grey baseline image, authored from the format (no captured screen bytes).
#[cfg(any(test, feature = "testkit"))]
pub(super) fn test_image() -> Vec<u8> {
    let mut bytes = vec![0xff, 0xd8, 0xff, 0xdb, 0, 67, 0];
    bytes.extend_from_slice(&[1; 64]);
    bytes.extend_from_slice(&[0xff, 0xc0, 0, 11, 8, 0, 1, 0, 1, 1, 1, 0x11, 0]);
    for table in [0, 0x10] {
        bytes.extend_from_slice(&[0xff, 0xc4, 0, 20, table, 1]);
        bytes.extend_from_slice(&[0; 15]);
        bytes.push(0);
    }
    bytes.extend_from_slice(&[0xff, 0xda, 0, 8, 1, 1, 0, 0, 63, 0, 0x3f, 0xff, 0xd9]);
    bytes
}

#[cfg(test)]
mod tests {
    use super::{test_image, validate};
    use crate::engine::frame::EngineFrameError::{Dimensions, ImageShape};

    const SOF: usize = 71;
    const SOS: usize = 128;

    fn sized_image(width: u16, height: u16) -> Vec<u8> {
        let mut image = test_image();
        image[SOF + 5..SOF + 7].copy_from_slice(&height.to_be_bytes());
        image[SOF + 7..SOF + 9].copy_from_slice(&width.to_be_bytes());
        image
    }

    fn segment(marker: u8, data: &[u8]) -> Vec<u8> {
        let mut segment = vec![0xff, marker];
        segment.extend_from_slice(&u16::try_from(data.len() + 2).unwrap().to_be_bytes());
        segment.extend_from_slice(data);
        segment
    }

    #[test]
    fn baseline_extended_and_progressive_multiple_scans_are_supported() {
        let baseline = test_image();
        assert_eq!(validate(&baseline), Ok(()));
        let mut extended = baseline.clone();
        extended[SOF + 1] = 0xc1;
        assert_eq!(validate(&extended), Ok(()));
        let mut progressive = baseline[..SOS].to_vec();
        progressive[SOF + 1] = 0xc2;
        progressive.extend(segment(0xda, &[1, 1, 0, 0, 0, 0]));
        progressive.push(0x7f); // DC zero followed by padding bits.
        progressive.extend(segment(0xfe, b"between scans"));
        progressive.extend(segment(0xda, &[1, 1, 0, 1, 63, 0]));
        progressive.extend_from_slice(&[0x7f, 0xff, 0xd9]); // AC EOB and EOI.
        assert_eq!(validate(&progressive), Ok(()));
    }

    #[test]
    fn physical_dimensions_are_bounded_independently_of_compressed_size() {
        // Non-1×1 variants exercise the envelope guard only, not entropy completeness.
        assert_eq!(validate(&sized_image(1280, 800)), Ok(()));
        for (width, height) in [(0, 1), (1, 0), (1281, 800), (1280, 801), (65535, 65535)] {
            assert_eq!(validate(&sized_image(width, height)), Err(Dimensions));
        }
    }

    #[test]
    fn marker_bytes_inside_application_segments_cannot_supply_or_replace_sof() {
        let original = test_image();
        let huge = sized_image(65535, 65535);
        let app = segment(0xe1, &huge);
        let mut image = original.clone();
        image.splice(2..2, app.clone());
        assert_eq!(validate(&image), Ok(()));
        let mut missing = original.clone();
        missing.drain(SOF..SOF + 13);
        missing.splice(2..2, app);
        assert_eq!(validate(&missing), Err(ImageShape));
        let mut real_huge = huge;
        real_huge.splice(2..2, segment(0xe2, &original));
        assert_eq!(validate(&real_huge), Err(Dimensions));
    }

    #[test]
    fn stuffed_bytes_fill_and_restart_markers_do_not_desynchronize_scans() {
        let original = test_image();
        let mut image = original[..SOS].to_vec();
        image.extend(segment(0xdd, &[0, 1]));
        image.extend_from_slice(&original[SOS..SOS + 10]);
        // Structural-only entropy: FF00 is data; fill FF before a marker is allowed.
        image.extend_from_slice(&[0xff, 0x00, 0xff, 0xd0, 0x3f, 0xff, 0xff, 0xd1, 0x3f]);
        image.extend_from_slice(&[0xff, 0xff, 0xd9]);
        assert_eq!(validate(&image), Ok(()));
        let mut wrong_order = image.clone();
        let restart = SOS + 6 + 10 + 3;
        assert_eq!(wrong_order[restart], 0xd0);
        wrong_order[restart] = 0xd1;
        assert_eq!(validate(&wrong_order), Err(ImageShape));
        image[SOS + 5] = 0; // Disable restart while retaining a RST marker.
        assert_eq!(validate(&image), Err(ImageShape));
        let mut outside = original.clone();
        outside.splice(2..2, [0xff, 0xd0]);
        assert_eq!(validate(&outside), Err(ImageShape));
        let mut invalid_stuffing = original;
        invalid_stuffing.splice(SOS + 10..SOS + 11, [0xff, 0xff, 0]);
        assert_eq!(validate(&invalid_stuffing), Err(ImageShape));
    }

    #[test]
    fn later_frame_or_deferred_height_cannot_bypass_first_dimensions() {
        let original = test_image();
        for (width, height) in [(1, 1), (0, 0), (65535, 65535)] {
            let extra = sized_image(width, height);
            let mut image = original[..original.len() - 2].to_vec();
            image.extend_from_slice(&extra[SOF..SOF + 13]);
            image.extend_from_slice(&[0xff, 0xd9]);
            assert_eq!(validate(&image), Err(ImageShape));
        }
        for lines in [0_u16, 1, 801, 65535] {
            let mut image = original[..original.len() - 2].to_vec();
            image.extend(segment(0xdc, &lines.to_be_bytes()));
            image.extend_from_slice(&[0xff, 0xd9]);
            assert_eq!(validate(&image), Err(ImageShape));
        }
    }

    #[test]
    fn unsupported_and_malformed_frame_headers_are_rejected() {
        for marker in [
            0xc3, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
        ] {
            let mut image = test_image();
            image[SOF + 1] = marker;
            assert_eq!(validate(&image), Err(ImageShape));
        }
        for (offset, value) in [(4, 12), (9, 0), (9, 5), (11, 0), (11, 0x51), (12, 4)] {
            let mut image = test_image();
            image[SOF + offset] = value;
            assert_eq!(validate(&image), Err(ImageShape));
        }
        let mut duplicate = test_image();
        duplicate[SOF + 3] += 3;
        duplicate[SOF + 9] = 2;
        duplicate.splice(SOF + 13..SOF + 13, [1, 0x11, 0]);
        assert_eq!(validate(&duplicate), Err(ImageShape));
    }

    #[test]
    fn scan_component_and_spectral_structure_are_checked() {
        for (offset, value) in [
            (3, 7),
            (4, 0),
            (4, 2),
            (5, 2),
            (6, 0x40),
            (7, 1),
            (8, 64),
            (9, 1),
        ] {
            let mut image = test_image();
            image[SOS + offset] = value;
            assert_eq!(validate(&image), Err(ImageShape));
        }
        let mut no_scan = test_image()[..SOS].to_vec();
        no_scan.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(validate(&no_scan), Err(ImageShape));
        let mut empty_scan = test_image();
        empty_scan.remove(SOS + 10);
        assert_eq!(validate(&empty_scan), Err(ImageShape));
    }

    #[test]
    fn multiple_components_and_progressive_scan_constraints_are_bounded() {
        for count in [3_u8, 4] {
            let mut image = test_image()[..SOF].to_vec();
            let mut frame = vec![8, 0, 1, 0, 1, count];
            let mut scan = vec![count];
            for id in 1..=count {
                frame.extend_from_slice(&[id, 0x11, 0]);
                scan.extend_from_slice(&[id, 0]);
            }
            scan.extend_from_slice(&[0, 63, 0]);
            image.extend(segment(0xc0, &frame));
            image.extend(segment(0xda, &scan));
            image.extend_from_slice(&[0x3f, 0xff, 0xd9]);
            assert_eq!(validate(&image), Ok(())); // Structure only; coefficients are not decoded.
            scan[3] = scan[1];
            let mut duplicate = image[..SOF].to_vec();
            duplicate.extend(segment(0xc0, &frame));
            duplicate.extend(segment(0xda, &scan));
            duplicate.extend_from_slice(&[0x3f, 0xff, 0xd9]);
            assert_eq!(validate(&duplicate), Err(ImageShape));
        }
        for tail in [[0, 1, 0], [2, 1, 0], [1, 64, 0], [0, 0, 0xee], [0, 0, 0x20]] {
            let mut image = test_image();
            image[SOF + 1] = 0xc2;
            image[SOS + 7..SOS + 10].copy_from_slice(&tail);
            assert_eq!(validate(&image), Err(ImageShape));
        }
    }

    #[test]
    fn every_truncated_prefix_bad_segment_length_and_trailing_image_fail() {
        let original = test_image();
        for length in 0..original.len() {
            assert!(validate(&original[..length]).is_err(), "prefix {length}");
        }
        for length in [0_u16, 1, 65535] {
            let mut image = original.clone();
            image[4..6].copy_from_slice(&length.to_be_bytes());
            assert_eq!(validate(&image), Err(ImageShape));
        }
        let mut joined = original.clone();
        joined.extend_from_slice(&original);
        assert_eq!(validate(&joined), Err(ImageShape));
        for marker in [0, 1, 0x02, 0xbf, 0xd8, 0xde, 0xdf, 0xf0] {
            let mut unknown = original.clone();
            unknown.splice(2..2, [0xff, marker]);
            assert_eq!(validate(&unknown), Err(ImageShape));
        }
    }

    #[test]
    fn maximal_fill_run_is_bounded_and_cannot_panic_or_synthesize_image() {
        let mut image = vec![0xff; openbot_contracts::engine::MAX_ENGINE_IMAGE_BYTES];
        image[1] = 0xd8;
        assert_eq!(validate(&image), Err(ImageShape));
    }
}
