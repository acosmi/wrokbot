//! Pure-Rust RGBA pixel comparison for visual golden tests.
//!
//! This module compares already-decoded RGBA8 buffers. It deliberately does not decode PNGs,
//! capture screenshots, create diff images, or implement the golden gate workflow.

use std::fmt;

/// RGBA channels whose absolute difference is at most this value are considered equal.
pub const CHANNEL_DIFFERENCE_THRESHOLD: u8 = 16;

/// A difference ratio greater than one pixel per thousand comparable pixels fails.
pub const MAX_DIFFERENCE_PER_THOUSAND: usize = 1;

/// A fully different square of this width and height fails independently of the ratio.
pub const FULL_DIFFERENCE_BLOCK_SIZE: usize = 8;

/// A validated borrowed RGBA8 image.
///
/// `stride` is the byte distance between consecutive row starts. Row padding is allowed when
/// `stride >= width * 4`, and the buffer length must be exactly `stride * height`. Comparison reads
/// only the first `width * 4` bytes of every row and never reads padding bytes.
#[derive(Clone, Copy)]
pub struct RgbaImage<'a> {
    width: usize,
    height: usize,
    stride: usize,
    pixels: &'a [u8],
}

impl<'a> RgbaImage<'a> {
    /// Validates and constructs an RGBA8 image view.
    ///
    /// Zero width or height is rejected. All layout arithmetic is checked, and both short and
    /// trailing buffers are rejected rather than silently accepted or clipped.
    pub fn new(
        width: usize,
        height: usize,
        stride: usize,
        pixels: &'a [u8],
    ) -> Result<Self, RgbaImageError> {
        if width == 0 || height == 0 {
            return Err(RgbaImageError::ZeroDimension { width, height });
        }

        let row_bytes = width
            .checked_mul(4)
            .ok_or(RgbaImageError::RowBytesOverflow { width })?;
        if stride < row_bytes {
            return Err(RgbaImageError::StrideTooSmall {
                stride,
                minimum: row_bytes,
            });
        }

        let required_buffer_len = stride
            .checked_mul(height)
            .ok_or(RgbaImageError::BufferLengthOverflow { stride, height })?;
        if pixels.len() != required_buffer_len {
            return Err(RgbaImageError::BufferLengthMismatch {
                expected: required_buffer_len,
                actual: pixels.len(),
            });
        }

        Ok(Self {
            width,
            height,
            stride,
            pixels,
        })
    }

    /// Image width in pixels.
    #[must_use]
    pub const fn width(self) -> usize {
        self.width
    }

    /// Image height in pixels.
    #[must_use]
    pub const fn height(self) -> usize {
        self.height
    }

    /// Byte distance between consecutive row starts.
    #[must_use]
    pub const fn stride(self) -> usize {
        self.stride
    }

    /// Total buffer length, including row padding.
    #[must_use]
    pub fn buffer_len(self) -> usize {
        self.pixels.len()
    }
}

impl fmt::Debug for RgbaImage<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RgbaImage")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("stride", &self.stride)
            .field("buffer_len", &self.pixels.len())
            .field("pixels", &"[redacted]")
            .finish()
    }
}

/// Validation failure for an RGBA image layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RgbaImageError {
    /// Width and height must both be non-zero.
    ZeroDimension { width: usize, height: usize },
    /// `width * 4` overflowed `usize`.
    RowBytesOverflow { width: usize },
    /// The stride cannot hold one complete RGBA row.
    StrideTooSmall { stride: usize, minimum: usize },
    /// `stride * height` overflowed `usize`.
    BufferLengthOverflow { stride: usize, height: usize },
    /// The buffer is not exactly `stride * height` bytes long.
    BufferLengthMismatch { expected: usize, actual: usize },
}

impl fmt::Display for RgbaImageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroDimension { width, height } => {
                write!(
                    formatter,
                    "RGBA dimensions must be non-zero, got {width}x{height}"
                )
            }
            Self::RowBytesOverflow { width } => {
                write!(formatter, "RGBA row byte count overflows for width {width}")
            }
            Self::StrideTooSmall { stride, minimum } => write!(
                formatter,
                "RGBA stride {stride} is smaller than the required row size {minimum}"
            ),
            Self::BufferLengthOverflow { stride, height } => write!(
                formatter,
                "RGBA buffer length overflows for stride {stride} and height {height}"
            ),
            Self::BufferLengthMismatch { expected, actual } => write!(
                formatter,
                "RGBA buffer length mismatch: expected {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for RgbaImageError {}

/// An explicit axis-aligned mask rectangle in pixel coordinates.
///
/// The rectangle covers the half-open range `[x, x + width) × [y, y + height)`. Width and height
/// must both be non-zero. Coordinate addition must not overflow, and the complete rectangle must be
/// inside the compared image; invalid rectangles are rejected instead of clipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaskRect {
    pub x: usize,
    pub y: usize,
    pub width: usize,
    pub height: usize,
}

/// The checked result of one RGBA comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoldenComparison {
    comparable_pixels: usize,
    different_pixels: usize,
    difference_ratio_exceeded: bool,
    full_difference_block: bool,
}

impl GoldenComparison {
    /// Number of unmasked pixels included in the comparison.
    #[must_use]
    pub const fn comparable_pixels(self) -> usize {
        self.comparable_pixels
    }

    /// Number of unmasked pixels where at least one RGBA channel differs by more than 16.
    #[must_use]
    pub const fn different_pixels(self) -> usize {
        self.different_pixels
    }

    /// Whether the difference ratio is strictly greater than 0.1%.
    #[must_use]
    pub const fn difference_ratio_exceeded(self) -> bool {
        self.difference_ratio_exceeded
    }

    /// Whether any complete 8×8 region consists entirely of unmasked different pixels.
    #[must_use]
    pub const fn has_full_difference_block(self) -> bool {
        self.full_difference_block
    }

    /// Returns `true` only when neither independent failure condition is present.
    #[must_use]
    pub const fn is_match(self) -> bool {
        !self.difference_ratio_exceeded && !self.full_difference_block
    }
}

/// Failure to validate or safely execute an RGBA comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GoldenCompareError {
    /// Expected and actual images must have exactly the same pixel dimensions.
    DimensionMismatch {
        expected_width: usize,
        expected_height: usize,
        actual_width: usize,
        actual_height: usize,
    },
    /// Empty mask rectangles are rejected rather than treated as silent no-ops.
    EmptyMask { index: usize },
    /// A mask's `x + width` or `y + height` calculation overflowed.
    MaskCoordinateOverflow { index: usize },
    /// A complete mask rectangle does not fit inside the image.
    MaskOutOfBounds {
        index: usize,
        image_width: usize,
        image_height: usize,
    },
    /// Every pixel was masked, so no ratio or block comparison can be made.
    NoComparablePixels,
    /// Checked comparison arithmetic overflowed.
    ArithmeticOverflow { operation: &'static str },
    /// A validated image could not provide a requested four-byte pixel.
    PixelAccessOutOfBounds,
    /// Working memory for block detection could not be reserved.
    WorkingMemoryUnavailable,
}

impl fmt::Display for GoldenCompareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DimensionMismatch {
                expected_width,
                expected_height,
                actual_width,
                actual_height,
            } => write!(
                formatter,
                "RGBA dimensions differ: expected {expected_width}x{expected_height}, got {actual_width}x{actual_height}"
            ),
            Self::EmptyMask { index } => {
                write!(formatter, "mask rectangle {index} must be non-empty")
            }
            Self::MaskCoordinateOverflow { index } => {
                write!(
                    formatter,
                    "mask rectangle {index} coordinate arithmetic overflowed"
                )
            }
            Self::MaskOutOfBounds {
                index,
                image_width,
                image_height,
            } => write!(
                formatter,
                "mask rectangle {index} is outside the {image_width}x{image_height} image"
            ),
            Self::NoComparablePixels => formatter.write_str("all RGBA pixels are masked"),
            Self::ArithmeticOverflow { operation } => {
                write!(
                    formatter,
                    "RGBA comparison arithmetic overflowed during {operation}"
                )
            }
            Self::PixelAccessOutOfBounds => {
                formatter.write_str("RGBA comparison pixel access was out of bounds")
            }
            Self::WorkingMemoryUnavailable => {
                formatter.write_str("RGBA comparison working memory is unavailable")
            }
        }
    }
}

impl std::error::Error for GoldenCompareError {}

#[derive(Clone, Copy)]
struct ValidatedMask {
    x: usize,
    y: usize,
    end_x: usize,
    end_y: usize,
}

/// Compares two validated RGBA8 images using the visual golden thresholds.
///
/// A pixel differs when any one of its four channels has an absolute difference strictly greater
/// than [`CHANNEL_DIFFERENCE_THRESHOLD`]. Masked pixels contribute neither to the ratio denominator
/// nor to 8×8 block membership. The ratio fails only when
/// `different_pixels * 1000 > comparable_pixels`, evaluated with checked integer arithmetic, so
/// exactly 0.1% passes.
pub fn compare_rgba(
    expected: RgbaImage<'_>,
    actual: RgbaImage<'_>,
    masks: &[MaskRect],
) -> Result<GoldenComparison, GoldenCompareError> {
    if expected.width != actual.width || expected.height != actual.height {
        return Err(GoldenCompareError::DimensionMismatch {
            expected_width: expected.width,
            expected_height: expected.height,
            actual_width: actual.width,
            actual_height: actual.height,
        });
    }

    let validated_masks = validate_masks(masks, expected.width, expected.height)?;
    let row_bytes =
        expected
            .width
            .checked_mul(4)
            .ok_or(GoldenCompareError::ArithmeticOverflow {
                operation: "row byte multiplication",
            })?;

    let mut vertical_difference_runs = Vec::new();
    vertical_difference_runs
        .try_reserve_exact(expected.width)
        .map_err(|_| GoldenCompareError::WorkingMemoryUnavailable)?;
    vertical_difference_runs.resize(expected.width, 0_usize);

    let mut row_masks = Vec::new();
    row_masks
        .try_reserve_exact(validated_masks.len())
        .map_err(|_| GoldenCompareError::WorkingMemoryUnavailable)?;

    let mut comparable_pixels = 0_usize;
    let mut different_pixels = 0_usize;
    let mut full_difference_block = false;

    for y in 0..expected.height {
        let expected_row = image_row(expected, y, row_bytes)?;
        let actual_row = image_row(actual, y, row_bytes)?;

        row_masks.clear();
        row_masks.extend(
            validated_masks
                .iter()
                .filter(|mask| mask.y <= y && y < mask.end_y)
                .map(|mask| (mask.x, mask.end_x)),
        );
        row_masks.sort_unstable_by_key(|&(start, _)| start);

        let (expected_pixels, expected_remainder) = expected_row.as_chunks::<4>();
        let (actual_pixels, actual_remainder) = actual_row.as_chunks::<4>();
        if !expected_remainder.is_empty()
            || !actual_remainder.is_empty()
            || expected_pixels.len() != expected.width
            || actual_pixels.len() != actual.width
        {
            return Err(GoldenCompareError::PixelAccessOutOfBounds);
        }

        let mut mask_index = 0_usize;
        let mut consecutive_block_columns = 0_usize;
        for (x, (expected_pixel, actual_pixel)) in
            expected_pixels.iter().zip(actual_pixels).enumerate()
        {
            while row_masks.get(mask_index).is_some_and(|&(_, end)| end <= x) {
                mask_index = checked_add(mask_index, 1, "mask interval index")?;
            }
            let masked = row_masks
                .get(mask_index)
                .is_some_and(|&(start, end)| start <= x && x < end);
            let differs = if masked {
                false
            } else {
                comparable_pixels = checked_add(comparable_pixels, 1, "comparable pixel count")?;
                let differs = expected_pixel.iter().zip(actual_pixel).any(
                    |(expected_channel, actual_channel)| {
                        expected_channel.abs_diff(*actual_channel) > CHANNEL_DIFFERENCE_THRESHOLD
                    },
                );
                if differs {
                    different_pixels = checked_add(different_pixels, 1, "different pixel count")?;
                }
                differs
            };

            let vertical_run = vertical_difference_runs
                .get_mut(x)
                .ok_or(GoldenCompareError::PixelAccessOutOfBounds)?;
            if differs {
                *vertical_run = checked_add(*vertical_run, 1, "vertical difference run")?;
            } else {
                *vertical_run = 0;
            }

            if *vertical_run >= FULL_DIFFERENCE_BLOCK_SIZE {
                consecutive_block_columns =
                    checked_add(consecutive_block_columns, 1, "horizontal difference run")?;
                if consecutive_block_columns >= FULL_DIFFERENCE_BLOCK_SIZE {
                    full_difference_block = true;
                }
            } else {
                consecutive_block_columns = 0;
            }
        }
    }

    if comparable_pixels == 0 {
        return Err(GoldenCompareError::NoComparablePixels);
    }

    let difference_ratio_exceeded = difference_ratio_exceeded(different_pixels, comparable_pixels)?;

    Ok(GoldenComparison {
        comparable_pixels,
        different_pixels,
        difference_ratio_exceeded,
        full_difference_block,
    })
}

fn validate_masks(
    masks: &[MaskRect],
    image_width: usize,
    image_height: usize,
) -> Result<Vec<ValidatedMask>, GoldenCompareError> {
    let mut validated = Vec::new();
    validated
        .try_reserve_exact(masks.len())
        .map_err(|_| GoldenCompareError::WorkingMemoryUnavailable)?;

    for (index, mask) in masks.iter().copied().enumerate() {
        if mask.width == 0 || mask.height == 0 {
            return Err(GoldenCompareError::EmptyMask { index });
        }
        let end_x = mask
            .x
            .checked_add(mask.width)
            .ok_or(GoldenCompareError::MaskCoordinateOverflow { index })?;
        let end_y = mask
            .y
            .checked_add(mask.height)
            .ok_or(GoldenCompareError::MaskCoordinateOverflow { index })?;
        if end_x > image_width || end_y > image_height {
            return Err(GoldenCompareError::MaskOutOfBounds {
                index,
                image_width,
                image_height,
            });
        }
        validated.push(ValidatedMask {
            x: mask.x,
            y: mask.y,
            end_x,
            end_y,
        });
    }

    Ok(validated)
}

fn image_row(
    image: RgbaImage<'_>,
    y: usize,
    row_bytes: usize,
) -> Result<&[u8], GoldenCompareError> {
    let row_offset = y
        .checked_mul(image.stride)
        .ok_or(GoldenCompareError::ArithmeticOverflow {
            operation: "row offset multiplication",
        })?;
    let row_end =
        row_offset
            .checked_add(row_bytes)
            .ok_or(GoldenCompareError::ArithmeticOverflow {
                operation: "row end addition",
            })?;

    image
        .pixels
        .get(row_offset..row_end)
        .ok_or(GoldenCompareError::PixelAccessOutOfBounds)
}

fn difference_ratio_exceeded(
    different_pixels: usize,
    comparable_pixels: usize,
) -> Result<bool, GoldenCompareError> {
    let scaled_differences =
        different_pixels
            .checked_mul(1000)
            .ok_or(GoldenCompareError::ArithmeticOverflow {
                operation: "difference ratio scaling",
            })?;
    let allowed_scaled_differences = comparable_pixels
        .checked_mul(MAX_DIFFERENCE_PER_THOUSAND)
        .ok_or(GoldenCompareError::ArithmeticOverflow {
            operation: "difference ratio allowance",
        })?;
    Ok(scaled_differences > allowed_scaled_differences)
}

fn checked_add(
    left: usize,
    right: usize,
    operation: &'static str,
) -> Result<usize, GoldenCompareError> {
    left.checked_add(right)
        .ok_or(GoldenCompareError::ArithmeticOverflow { operation })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packed_pixels(width: usize, height: usize) -> Vec<u8> {
        vec![0; width * height * 4]
    }

    fn packed_image<'a>(width: usize, height: usize, pixels: &'a [u8]) -> RgbaImage<'a> {
        RgbaImage::new(width, height, width * 4, pixels).expect("packed test image is valid")
    }

    fn set_pixel(pixels: &mut [u8], width: usize, x: usize, y: usize, rgba: [u8; 4]) {
        let start = (y * width + x) * 4;
        pixels[start..start + 4].copy_from_slice(&rgba);
    }

    fn set_different_pixel(pixels: &mut [u8], width: usize, x: usize, y: usize) {
        set_pixel(pixels, width, x, y, [17, 0, 0, 0]);
    }

    #[test]
    fn channel_threshold_is_strict_for_every_rgba_channel() {
        let expected_pixels = [0_u8; 4];

        for channel in 0..4 {
            let mut equal_at_threshold = [0_u8; 4];
            equal_at_threshold[channel] = CHANNEL_DIFFERENCE_THRESHOLD;
            let comparison = compare_rgba(
                packed_image(1, 1, &expected_pixels),
                packed_image(1, 1, &equal_at_threshold),
                &[],
            )
            .expect("threshold comparison succeeds");
            assert_eq!(comparison.different_pixels(), 0);
            assert!(comparison.is_match());

            let mut over_threshold = [0_u8; 4];
            over_threshold[channel] = CHANNEL_DIFFERENCE_THRESHOLD + 1;
            let comparison = compare_rgba(
                packed_image(1, 1, &expected_pixels),
                packed_image(1, 1, &over_threshold),
                &[],
            )
            .expect("over-threshold comparison succeeds");
            assert_eq!(comparison.different_pixels(), 1);
            assert!(comparison.difference_ratio_exceeded());
            assert!(!comparison.has_full_difference_block());
            assert!(!comparison.is_match());
        }
    }

    #[test]
    fn ratio_allows_exactly_point_one_percent_and_rejects_more() {
        let width = 1000;
        let expected_pixels = packed_pixels(width, 1);
        let mut actual_pixels = expected_pixels.clone();
        set_different_pixel(&mut actual_pixels, width, 0, 0);

        let exact_boundary = compare_rgba(
            packed_image(width, 1, &expected_pixels),
            packed_image(width, 1, &actual_pixels),
            &[],
        )
        .expect("exact boundary comparison succeeds");
        assert_eq!(exact_boundary.comparable_pixels(), 1000);
        assert_eq!(exact_boundary.different_pixels(), 1);
        assert!(!exact_boundary.difference_ratio_exceeded());
        assert!(exact_boundary.is_match());

        set_different_pixel(&mut actual_pixels, width, 1, 0);
        let above_boundary = compare_rgba(
            packed_image(width, 1, &expected_pixels),
            packed_image(width, 1, &actual_pixels),
            &[],
        )
        .expect("above-boundary comparison succeeds");
        assert_eq!(above_boundary.different_pixels(), 2);
        assert!(above_boundary.difference_ratio_exceeded());
        assert!(!above_boundary.is_match());
    }

    #[test]
    fn complete_eight_by_eight_block_fails_independently_at_ratio_boundary() {
        let width = 1000;
        let height = 64;
        let expected_pixels = packed_pixels(width, height);
        let mut actual_pixels = expected_pixels.clone();
        for y in 5..(5 + FULL_DIFFERENCE_BLOCK_SIZE) {
            for x in 3..(3 + FULL_DIFFERENCE_BLOCK_SIZE) {
                set_different_pixel(&mut actual_pixels, width, x, y);
            }
        }

        let comparison = compare_rgba(
            packed_image(width, height, &expected_pixels),
            packed_image(width, height, &actual_pixels),
            &[],
        )
        .expect("block comparison succeeds");
        assert_eq!(comparison.comparable_pixels(), 64_000);
        assert_eq!(comparison.different_pixels(), 64);
        assert!(!comparison.difference_ratio_exceeded());
        assert!(comparison.has_full_difference_block());
        assert!(!comparison.is_match());
    }

    #[test]
    fn edge_regions_shorter_than_eight_do_not_form_a_full_block() {
        let width = 1000;
        let height = 56;
        let expected_pixels = packed_pixels(width, height);

        let mut horizontally_short = expected_pixels.clone();
        for y in 0..FULL_DIFFERENCE_BLOCK_SIZE {
            for x in (width - 7)..width {
                set_different_pixel(&mut horizontally_short, width, x, y);
            }
        }
        let horizontal_comparison = compare_rgba(
            packed_image(width, height, &expected_pixels),
            packed_image(width, height, &horizontally_short),
            &[],
        )
        .expect("horizontally short edge comparison succeeds");
        assert_eq!(horizontal_comparison.comparable_pixels(), 56_000);
        assert_eq!(horizontal_comparison.different_pixels(), 56);
        assert!(!horizontal_comparison.difference_ratio_exceeded());
        assert!(!horizontal_comparison.has_full_difference_block());
        assert!(horizontal_comparison.is_match());

        let mut vertically_short = expected_pixels.clone();
        for y in (height - 7)..height {
            for x in 0..FULL_DIFFERENCE_BLOCK_SIZE {
                set_different_pixel(&mut vertically_short, width, x, y);
            }
        }
        let vertical_comparison = compare_rgba(
            packed_image(width, height, &expected_pixels),
            packed_image(width, height, &vertically_short),
            &[],
        )
        .expect("vertically short edge comparison succeeds");
        assert_eq!(vertical_comparison.comparable_pixels(), 56_000);
        assert_eq!(vertical_comparison.different_pixels(), 56);
        assert!(!vertical_comparison.difference_ratio_exceeded());
        assert!(!vertical_comparison.has_full_difference_block());
        assert!(vertical_comparison.is_match());
    }

    #[test]
    fn mask_removes_pixels_from_both_ratio_counts() {
        let width = 1001;
        let expected_pixels = packed_pixels(width, 1);
        let mut actual_pixels = expected_pixels.clone();
        set_different_pixel(&mut actual_pixels, width, 0, 0);
        set_different_pixel(&mut actual_pixels, width, 1, 0);

        let without_mask = compare_rgba(
            packed_image(width, 1, &expected_pixels),
            packed_image(width, 1, &actual_pixels),
            &[],
        )
        .expect("unmasked comparison succeeds");
        assert!(without_mask.difference_ratio_exceeded());

        let with_mask = compare_rgba(
            packed_image(width, 1, &expected_pixels),
            packed_image(width, 1, &actual_pixels),
            &[MaskRect {
                x: 1,
                y: 0,
                width: 1,
                height: 1,
            }],
        )
        .expect("masked comparison succeeds");
        assert_eq!(with_mask.comparable_pixels(), 1000);
        assert_eq!(with_mask.different_pixels(), 1);
        assert!(!with_mask.difference_ratio_exceeded());
        assert!(with_mask.is_match());
    }

    #[test]
    fn overlapping_masks_are_merged_by_row_without_double_counting() {
        let width = 6;
        let expected_pixels = packed_pixels(width, 1);
        let actual_pixels = expected_pixels.clone();
        let comparison = compare_rgba(
            packed_image(width, 1, &expected_pixels),
            packed_image(width, 1, &actual_pixels),
            &[
                MaskRect {
                    x: 1,
                    y: 0,
                    width: 3,
                    height: 1,
                },
                MaskRect {
                    x: 3,
                    y: 0,
                    width: 2,
                    height: 1,
                },
            ],
        )
        .expect("overlapping masks compare successfully");

        assert_eq!(comparison.comparable_pixels(), 2);
        assert_eq!(comparison.different_pixels(), 0);
        assert!(comparison.is_match());
    }

    #[test]
    fn one_masked_pixel_breaks_an_eight_by_eight_block() {
        let width = 1000;
        let height = 64;
        let expected_pixels = packed_pixels(width, height);
        let mut actual_pixels = expected_pixels.clone();
        for y in 0..FULL_DIFFERENCE_BLOCK_SIZE {
            for x in 0..FULL_DIFFERENCE_BLOCK_SIZE {
                set_different_pixel(&mut actual_pixels, width, x, y);
            }
        }

        let comparison = compare_rgba(
            packed_image(width, height, &expected_pixels),
            packed_image(width, height, &actual_pixels),
            &[MaskRect {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            }],
        )
        .expect("masked block comparison succeeds");
        assert_eq!(comparison.comparable_pixels(), 63_999);
        assert_eq!(comparison.different_pixels(), 63);
        assert!(!comparison.difference_ratio_exceeded());
        assert!(!comparison.has_full_difference_block());
        assert!(comparison.is_match());
    }

    #[test]
    fn dimension_mismatch_is_rejected() {
        let expected_pixels = packed_pixels(2, 2);
        let actual_pixels = packed_pixels(1, 4);
        let error = compare_rgba(
            packed_image(2, 2, &expected_pixels),
            packed_image(1, 4, &actual_pixels),
            &[],
        )
        .expect_err("different dimensions must fail");
        assert_eq!(
            error,
            GoldenCompareError::DimensionMismatch {
                expected_width: 2,
                expected_height: 2,
                actual_width: 1,
                actual_height: 4,
            }
        );
    }

    #[test]
    fn stride_must_hold_a_complete_rgba_row() {
        let error =
            RgbaImage::new(2, 1, 7, &[0; 7]).expect_err("stride below width times four must fail");
        assert_eq!(
            error,
            RgbaImageError::StrideTooSmall {
                stride: 7,
                minimum: 8,
            }
        );
    }

    #[test]
    fn buffer_length_must_equal_stride_times_height() {
        let short = RgbaImage::new(1, 2, 4, &[0; 7]).expect_err("short RGBA buffer must fail");
        assert_eq!(
            short,
            RgbaImageError::BufferLengthMismatch {
                expected: 8,
                actual: 7,
            }
        );

        let trailing = RgbaImage::new(1, 2, 4, &[0; 9]).expect_err("trailing RGBA bytes must fail");
        assert_eq!(
            trailing,
            RgbaImageError::BufferLengthMismatch {
                expected: 8,
                actual: 9,
            }
        );
    }

    #[test]
    fn row_padding_and_different_valid_strides_are_allowed_but_never_compared() {
        let width = 2;
        let height = 2;
        let expected_pixels = [0_u8; 16];
        let mut actual_pixels = [0_u8; 24];
        actual_pixels[8..12].fill(255);
        actual_pixels[20..24].fill(127);

        let comparison = compare_rgba(
            RgbaImage::new(width, height, 8, &expected_pixels)
                .expect("packed expected image is valid"),
            RgbaImage::new(width, height, 12, &actual_pixels)
                .expect("padded actual image is valid"),
            &[],
        )
        .expect("padding comparison succeeds");
        assert_eq!(comparison.comparable_pixels(), 4);
        assert_eq!(comparison.different_pixels(), 0);
        assert!(comparison.is_match());
    }

    #[test]
    fn zero_dimensions_are_rejected() {
        assert_eq!(
            RgbaImage::new(0, 1, 0, &[]).expect_err("zero width must fail"),
            RgbaImageError::ZeroDimension {
                width: 0,
                height: 1,
            }
        );
        assert_eq!(
            RgbaImage::new(1, 0, 4, &[]).expect_err("zero height must fail"),
            RgbaImageError::ZeroDimension {
                width: 1,
                height: 0,
            }
        );
    }

    #[test]
    fn fully_masked_image_has_no_comparable_pixels() {
        let pixels = packed_pixels(2, 2);
        let error = compare_rgba(
            packed_image(2, 2, &pixels),
            packed_image(2, 2, &pixels),
            &[MaskRect {
                x: 0,
                y: 0,
                width: 2,
                height: 2,
            }],
        )
        .expect_err("fully masked image must fail closed");
        assert_eq!(error, GoldenCompareError::NoComparablePixels);
    }

    #[test]
    fn empty_and_out_of_bounds_masks_are_rejected_without_clipping() {
        let pixels = packed_pixels(2, 2);
        let image = packed_image(2, 2, &pixels);

        let empty = compare_rgba(
            image,
            image,
            &[MaskRect {
                x: 0,
                y: 0,
                width: 0,
                height: 1,
            }],
        )
        .expect_err("empty mask must fail");
        assert_eq!(empty, GoldenCompareError::EmptyMask { index: 0 });

        let out_of_bounds = compare_rgba(
            image,
            image,
            &[MaskRect {
                x: 1,
                y: 0,
                width: 2,
                height: 1,
            }],
        )
        .expect_err("out-of-bounds mask must fail rather than clip");
        assert_eq!(
            out_of_bounds,
            GoldenCompareError::MaskOutOfBounds {
                index: 0,
                image_width: 2,
                image_height: 2,
            }
        );
    }

    #[test]
    fn mask_coordinate_overflow_is_rejected() {
        let pixels = packed_pixels(2, 2);
        let image = packed_image(2, 2, &pixels);
        let error = compare_rgba(
            image,
            image,
            &[MaskRect {
                x: usize::MAX,
                y: 0,
                width: 2,
                height: 1,
            }],
        )
        .expect_err("overflowing mask must fail");
        assert_eq!(
            error,
            GoldenCompareError::MaskCoordinateOverflow { index: 0 }
        );
    }

    #[test]
    fn image_layout_arithmetic_overflow_is_rejected() {
        let row_bytes = RgbaImage::new(usize::MAX, 1, usize::MAX, &[])
            .expect_err("width times four overflow must fail");
        assert_eq!(
            row_bytes,
            RgbaImageError::RowBytesOverflow { width: usize::MAX }
        );

        let buffer_len = RgbaImage::new(1, 2, usize::MAX, &[])
            .expect_err("stride times height overflow must fail");
        assert_eq!(
            buffer_len,
            RgbaImageError::BufferLengthOverflow {
                stride: usize::MAX,
                height: 2,
            }
        );
    }

    #[test]
    fn comparison_arithmetic_helpers_fail_closed_on_usize_overflow() {
        assert_eq!(
            difference_ratio_exceeded(usize::MAX, usize::MAX)
                .expect_err("ratio multiplication overflow must fail"),
            GoldenCompareError::ArithmeticOverflow {
                operation: "difference ratio scaling",
            }
        );
        assert_eq!(
            checked_add(usize::MAX, 1, "test addition")
                .expect_err("counter addition overflow must fail"),
            GoldenCompareError::ArithmeticOverflow {
                operation: "test addition",
            }
        );

        let invalid_image = RgbaImage {
            width: 1,
            height: 1,
            stride: usize::MAX,
            pixels: &[0; 4],
        };
        assert_eq!(
            image_row(invalid_image, 2, 4)
                .expect_err("row offset multiplication overflow must fail"),
            GoldenCompareError::ArithmeticOverflow {
                operation: "row offset multiplication",
            }
        );
        assert_eq!(
            image_row(invalid_image, 1, 4).expect_err("row end addition overflow must fail"),
            GoldenCompareError::ArithmeticOverflow {
                operation: "row end addition",
            }
        );
    }

    #[test]
    fn debug_output_redacts_pixel_bytes_and_text() {
        let pixels = *b"password";
        let image = RgbaImage::new(2, 1, 8, &pixels).expect("debug image is valid");
        let debug = format!("{image:?}");

        assert!(debug.contains("pixels: \"[redacted]\""));
        assert!(debug.contains("buffer_len: 8"));
        assert!(!debug.contains("password"));
        assert!(!debug.contains("112, 97, 115"));
    }
}
