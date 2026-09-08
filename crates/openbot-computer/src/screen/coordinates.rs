//! Fail-closed viewer-canvas to CDP viewport coordinate mapping (v4 §12.5–§12.6).
//!
//! CDP defines screencast `deviceWidth`/`deviceHeight` in device-independent pixels (DIP),
//! `pageScaleFactor` separately, and scroll offsets in CSS pixels. `Input.dispatchMouseEvent`
//! accepts coordinates relative to the main-frame viewport in CSS pixels. This module keeps those
//! units explicit and rejects pointer events in `object-fit: contain` letterbox bars.

use super::ScreenViewerFrame;

const MAX_CANVAS_AXIS: f64 = 1_000_000.0;
const MIN_DECODED_AXIS: u32 = 16;
const MAX_DECODED_AXIS: u32 = 16_384;

/// CSS content box occupied by the canvas element.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CanvasRect {
    left: f64,
    top: f64,
    width: f64,
    height: f64,
}

impl CanvasRect {
    /// Construct one finite, non-empty, bounded canvas content box.
    pub fn new(left: f64, top: f64, width: f64, height: f64) -> Result<Self, CoordinateError> {
        if ![left, top, width, height]
            .iter()
            .all(|value| value.is_finite())
            || left.abs() > MAX_CANVAS_AXIS
            || top.abs() > MAX_CANVAS_AXIS
            || width <= 0.0
            || height <= 0.0
            || width > MAX_CANVAS_AXIS
            || height > MAX_CANVAS_AXIS
        {
            return Err(CoordinateError::InvalidCanvas);
        }
        Ok(Self {
            left,
            top,
            width,
            height,
        })
    }
}

/// Intrinsic dimensions reported by `createImageBitmap`, in decoded image pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedFrameSize {
    width: u32,
    height: u32,
}

impl DecodedFrameSize {
    /// Reject zero or unexpectedly large decoded surfaces before coordinate arithmetic.
    pub const fn new(width: u32, height: u32) -> Result<Self, CoordinateError> {
        if width < MIN_DECODED_AXIS
            || height < MIN_DECODED_AXIS
            || width > MAX_DECODED_AXIS
            || height > MAX_DECODED_AXIS
        {
            Err(CoordinateError::InvalidDecodedFrame)
        } else {
            Ok(Self { width, height })
        }
    }
}

/// One immutable mapping bound to the exact frame sequence displayed by a viewer.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ScreenCoordinateMap {
    frame_sequence: u64,
    image_left: f64,
    image_top: f64,
    image_width: f64,
    image_height: f64,
    viewport_css_per_canvas_x: f64,
    viewport_css_per_canvas_y: f64,
    page_scale: f64,
    scroll_x: f64,
    scroll_y: f64,
}

impl ScreenCoordinateMap {
    /// Build an `object-fit: contain` mapping for one decoded, displayed frame.
    pub fn new(
        frame: &ScreenViewerFrame,
        decoded: DecodedFrameSize,
        canvas: CanvasRect,
    ) -> Result<Self, CoordinateError> {
        validate_frame_geometry(frame)?;
        validate_aspect(frame, decoded)?;

        let decoded_width = f64::from(decoded.width);
        let decoded_height = f64::from(decoded.height);
        let contain_scale = (canvas.width / decoded_width).min(canvas.height / decoded_height);
        let image_width = decoded_width * contain_scale;
        let image_height = decoded_height * contain_scale;
        let image_left = canvas.left + (canvas.width - image_width) / 2.0;
        let image_top = canvas.top + (canvas.height - image_height) / 2.0;

        // The intermediate physical-pixel terms deliberately retain device scale. It cancels when
        // converting to CDP viewport CSS pixels, which is exactly why a Retina display must not
        // move a DOM target. Chromium DevTools applies pageScale only when it derives a document
        // hit-test point; dispatchMouseEvent and wheel deltas use viewport CSS directly.
        let device_scale = f64::from(frame.device_scale_factor());
        let page_scale = f64::from(frame.page_scale_factor());
        let physical_width = f64::from(frame.width()) * device_scale;
        let physical_height = f64::from(frame.height()) * device_scale;
        let viewport_css_per_canvas_x = physical_width / image_width / device_scale;
        let viewport_css_per_canvas_y = physical_height / image_height / device_scale;
        if !image_left.is_finite()
            || !image_top.is_finite()
            || ![
                image_width,
                image_height,
                viewport_css_per_canvas_x,
                viewport_css_per_canvas_y,
            ]
            .iter()
            .all(|value| value.is_finite() && *value > 0.0)
        {
            return Err(CoordinateError::InvalidFrameGeometry);
        }

        Ok(Self {
            frame_sequence: frame.sequence(),
            image_left,
            image_top,
            image_width,
            image_height,
            viewport_css_per_canvas_x,
            viewport_css_per_canvas_y,
            page_scale,
            scroll_x: f64::from(frame.scroll_x()),
            scroll_y: f64::from(frame.scroll_y()),
        })
    }

    /// Exact viewer frame sequence from which this geometry was derived.
    #[must_use]
    pub const fn frame_sequence(self) -> u64 {
        self.frame_sequence
    }

    /// Map one client-space pointer. Letterbox bars and the exclusive right/bottom edge reject.
    pub fn map_point(
        self,
        client_x: f64,
        client_y: f64,
    ) -> Result<MappedScreenPoint, CoordinateError> {
        if !client_x.is_finite() || !client_y.is_finite() {
            return Err(CoordinateError::NonFiniteInput);
        }
        let right = self.image_left + self.image_width;
        let bottom = self.image_top + self.image_height;
        if client_x < self.image_left
            || client_x >= right
            || client_y < self.image_top
            || client_y >= bottom
        {
            return Err(CoordinateError::OutsideDisplayedFrame);
        }
        let viewport_x = (client_x - self.image_left) * self.viewport_css_per_canvas_x;
        let viewport_y = (client_y - self.image_top) * self.viewport_css_per_canvas_y;
        let document_x = viewport_x / self.page_scale + self.scroll_x;
        let document_y = viewport_y / self.page_scale + self.scroll_y;
        if ![viewport_x, viewport_y, document_x, document_y]
            .iter()
            .all(|value| value.is_finite())
        {
            return Err(CoordinateError::InvalidFrameGeometry);
        }
        Ok(MappedScreenPoint {
            frame_sequence: self.frame_sequence,
            viewport_x,
            viewport_y,
            document_x,
            document_y,
        })
    }

    /// Convert viewer wheel movement into the CSS-pixel deltas required by CDP.
    pub fn map_delta(
        self,
        delta_x: f64,
        delta_y: f64,
    ) -> Result<MappedScreenDelta, CoordinateError> {
        if !delta_x.is_finite() || !delta_y.is_finite() {
            return Err(CoordinateError::NonFiniteInput);
        }
        let delta_x = delta_x * self.viewport_css_per_canvas_x;
        let delta_y = delta_y * self.viewport_css_per_canvas_y;
        if !delta_x.is_finite() || !delta_y.is_finite() {
            return Err(CoordinateError::InvalidFrameGeometry);
        }
        Ok(MappedScreenDelta { delta_x, delta_y })
    }
}

/// Pointer coordinates in the two explicit CDP-relevant spaces.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MappedScreenPoint {
    frame_sequence: u64,
    viewport_x: f64,
    viewport_y: f64,
    document_x: f64,
    document_y: f64,
}

impl MappedScreenPoint {
    /// Frame sequence whose metadata produced this point.
    #[must_use]
    pub const fn frame_sequence(self) -> u64 {
        self.frame_sequence
    }

    /// Main-frame viewport x in CSS pixels, for `Input.dispatchMouseEvent`.
    #[must_use]
    pub const fn viewport_x(self) -> f64 {
        self.viewport_x
    }

    /// Main-frame viewport y in CSS pixels, for `Input.dispatchMouseEvent`.
    #[must_use]
    pub const fn viewport_y(self) -> f64 {
        self.viewport_y
    }

    /// Document x in CSS pixels, for exact target/ref hit-test validation.
    #[must_use]
    pub const fn document_x(self) -> f64 {
        self.document_x
    }

    /// Document y in CSS pixels, for exact target/ref hit-test validation.
    #[must_use]
    pub const fn document_y(self) -> f64 {
        self.document_y
    }
}

/// Wheel delta in viewport CSS pixels.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MappedScreenDelta {
    delta_x: f64,
    delta_y: f64,
}

impl MappedScreenDelta {
    /// Horizontal wheel delta in viewport CSS pixels.
    #[must_use]
    pub const fn delta_x(self) -> f64 {
        self.delta_x
    }

    /// Vertical wheel delta in viewport CSS pixels.
    #[must_use]
    pub const fn delta_y(self) -> f64 {
        self.delta_y
    }
}

/// Stable coordinate failures; no client coordinates or frame metadata enter Display.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CoordinateError {
    /// Canvas geometry was non-finite, empty, or outside the closed bound.
    #[error("screen_coordinate_canvas_invalid")]
    InvalidCanvas,
    /// Decoded image dimensions were empty or outside the closed bound.
    #[error("screen_coordinate_decoded_frame_invalid")]
    InvalidDecodedFrame,
    /// Authenticated frame metadata could not produce finite positive mapping factors.
    #[error("screen_coordinate_frame_geometry_invalid")]
    InvalidFrameGeometry,
    /// Decoded pixels did not preserve the authenticated device aspect ratio.
    #[error("screen_coordinate_aspect_mismatch")]
    FrameAspectMismatch,
    /// Pointer or wheel input contained NaN or infinity.
    #[error("screen_coordinate_input_non_finite")]
    NonFiniteInput,
    /// Pointer was in a letterbox bar or on the exclusive right/bottom edge.
    #[error("screen_coordinate_outside_frame")]
    OutsideDisplayedFrame,
}

fn validate_frame_geometry(frame: &ScreenViewerFrame) -> Result<(), CoordinateError> {
    if frame.width() == 0
        || frame.height() == 0
        || !frame.device_scale_factor().is_finite()
        || frame.device_scale_factor() <= 0.0
        || !frame.page_scale_factor().is_finite()
        || frame.page_scale_factor() <= 0.0
        || !frame.scroll_x().is_finite()
        || !frame.scroll_y().is_finite()
    {
        Err(CoordinateError::InvalidFrameGeometry)
    } else {
        Ok(())
    }
}

fn validate_aspect(
    frame: &ScreenViewerFrame,
    decoded: DecodedFrameSize,
) -> Result<(), CoordinateError> {
    let left = u64::from(decoded.width) * u64::from(frame.height());
    let right = u64::from(decoded.height) * u64::from(frame.width());
    let difference = left.abs_diff(right);
    let one_decoded_pixel = u64::from(frame.width().max(frame.height()));
    if difference <= one_decoded_pixel {
        Ok(())
    } else {
        Err(CoordinateError::FrameAspectMismatch)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn frame(
        device_scale_factor: f32,
        page_scale_factor: f32,
        scroll_x: f32,
        scroll_y: f32,
    ) -> ScreenViewerFrame {
        ScreenViewerFrame {
            sequence: 17,
            captured_at_ms: 1_788_499_200_000,
            width: 1280,
            height: 800,
            device_scale_factor,
            page_scale_factor,
            scroll_x,
            scroll_y,
            bytes: Arc::from(&b"OBSCRN01"[..]),
        }
    }

    #[test]
    fn contain_letterbox_maps_to_viewport_and_document_css_pixels() {
        let map = ScreenCoordinateMap::new(
            &frame(1.0, 1.0, 10.0, 20.0),
            DecodedFrameSize::new(1280, 800).expect("decoded"),
            CanvasRect::new(100.0, 50.0, 640.0, 500.0).expect("canvas"),
        )
        .expect("map");
        // The image renders at x=100..740 and y=100..500, leaving 50px bars above and below.
        let point = map.map_point(140.0, 184.0).expect("inside image");
        assert_eq!(point.frame_sequence(), 17);
        assert_eq!((point.viewport_x(), point.viewport_y()), (80.0, 168.0));
        assert_eq!((point.document_x(), point.document_y()), (90.0, 188.0));
        assert_eq!(
            map.map_point(140.0, 99.999),
            Err(CoordinateError::OutsideDisplayedFrame)
        );
        assert_eq!(
            map.map_point(740.0, 200.0),
            Err(CoordinateError::OutsideDisplayedFrame)
        );
    }

    #[test]
    fn device_scale_cancels_and_page_scale_only_changes_document_coordinates() {
        let decoded = DecodedFrameSize::new(1280, 800).expect("decoded");
        let canvas = CanvasRect::new(0.0, 0.0, 1280.0, 800.0).expect("canvas");
        let normal = ScreenCoordinateMap::new(&frame(1.0, 2.0, 30.0, 40.0), decoded, canvas)
            .expect("normal");
        let retina = ScreenCoordinateMap::new(&frame(2.0, 2.0, 30.0, 40.0), decoded, canvas)
            .expect("retina");
        let normal = normal.map_point(640.0, 400.0).expect("normal point");
        let retina = retina.map_point(640.0, 400.0).expect("retina point");
        assert_eq!(normal, retina);
        assert_eq!((normal.viewport_x(), normal.viewport_y()), (640.0, 400.0));
        assert_eq!((normal.document_x(), normal.document_y()), (350.0, 240.0));
    }

    #[test]
    fn wheel_delta_uses_the_same_css_scale_without_scroll_offset() {
        let map = ScreenCoordinateMap::new(
            &frame(2.0, 2.0, 300.0, 400.0),
            DecodedFrameSize::new(1280, 800).expect("decoded"),
            CanvasRect::new(0.0, 0.0, 640.0, 400.0).expect("canvas"),
        )
        .expect("map");
        let delta = map.map_delta(-10.0, 25.0).expect("delta");
        assert_eq!((delta.delta_x(), delta.delta_y()), (-20.0, 50.0));
    }

    #[test]
    fn invalid_geometry_aspect_edges_and_numbers_fail_closed() {
        assert_eq!(
            CanvasRect::new(0.0, 0.0, 0.0, 1.0),
            Err(CoordinateError::InvalidCanvas)
        );
        assert_eq!(
            CanvasRect::new(f64::MAX, 0.0, 1.0, 1.0),
            Err(CoordinateError::InvalidCanvas)
        );
        assert_eq!(
            DecodedFrameSize::new(0, 800),
            Err(CoordinateError::InvalidDecodedFrame)
        );
        assert_eq!(
            DecodedFrameSize::new(1, 1),
            Err(CoordinateError::InvalidDecodedFrame)
        );
        assert_eq!(
            ScreenCoordinateMap::new(
                &frame(1.0, 1.0, 0.0, 0.0),
                DecodedFrameSize::new(1280, 700).expect("decoded"),
                CanvasRect::new(0.0, 0.0, 1280.0, 800.0).expect("canvas"),
            ),
            Err(CoordinateError::FrameAspectMismatch)
        );
        let map = ScreenCoordinateMap::new(
            &frame(1.0, 1.0, 0.0, 0.0),
            DecodedFrameSize::new(1280, 800).expect("decoded"),
            CanvasRect::new(0.0, 0.0, 1280.0, 800.0).expect("canvas"),
        )
        .expect("map");
        assert_eq!(
            map.map_point(f64::NAN, 0.0),
            Err(CoordinateError::NonFiniteInput)
        );
        assert_eq!(
            map.map_delta(0.0, f64::INFINITY),
            Err(CoordinateError::NonFiniteInput)
        );
    }
}
