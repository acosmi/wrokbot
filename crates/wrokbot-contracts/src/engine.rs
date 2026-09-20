//! Closed Rust↔Electron engine protocol constants (v4 §11.2, R118/R119).
//!
//! The JSON descriptor is the language-neutral source consumed by the Rust host and by the
//! mechanically generated `engine-shim/generated/protocol.mjs`. It contains only framing limits
//! and closed tags—never actor, policy, intent, secret, free CDP method, or free URL fields.

/// Canonical language-neutral protocol descriptor committed beside this crate.
pub const ENGINE_PROTOCOL_DESCRIPTOR: &str = include_str!("../engine-protocol-v4.json");

/// Current typed framing version.
pub const ENGINE_PROTOCOL_VERSION: u16 = 4;

/// Current accepted packaging epoch for the dual-role Electron engine.
pub const ENGINE_RELEASE_EPOCH: u64 = 5;

/// Boot capability is exactly one bounded line on stdin.
pub const MAX_ENGINE_BOOT_BYTES: usize = 4 * 1024;

/// Control NDJSON frame limit.
pub const MAX_ENGINE_CONTROL_FRAME_BYTES: usize = 64 * 1024;

/// Independent binary image payload limit.
pub const MAX_ENGINE_IMAGE_BYTES: usize = 8 * 1024 * 1024;

/// Binary image-frame magic.
pub const ENGINE_FRAME_MAGIC: &[u8; 8] = b"OBFRAME2";

/// Binary ingress token preface magic.
pub const ENGINE_FRAME_HELLO_MAGIC: &[u8; 8] = b"OBFHELLO";

/// Fixed bytes before variable computer/tab IDs in a binary frame.
pub const ENGINE_FRAME_FIXED_HEADER_BYTES: usize = 76;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_and_rust_constants_are_exactly_joined() {
        let descriptor: serde_json::Value =
            serde_json::from_str(ENGINE_PROTOCOL_DESCRIPTOR).expect("descriptor JSON");
        assert_eq!(descriptor["schema"], "openbot-engine-protocol");
        assert_eq!(descriptor["version"], u64::from(ENGINE_PROTOCOL_VERSION));
        assert_eq!(descriptor["release_epoch"], ENGINE_RELEASE_EPOCH);
        assert_eq!(descriptor["max_boot_bytes"], MAX_ENGINE_BOOT_BYTES);
        assert_eq!(
            descriptor["max_control_frame_bytes"],
            MAX_ENGINE_CONTROL_FRAME_BYTES
        );
        assert_eq!(descriptor["max_image_bytes"], MAX_ENGINE_IMAGE_BYTES);
        assert_eq!(descriptor["frame_magic"], "OBFRAME2");
        assert_eq!(descriptor["frame_hello_magic"], "OBFHELLO");
        assert_eq!(
            descriptor["frame_fixed_header_bytes"],
            ENGINE_FRAME_FIXED_HEADER_BYTES
        );
    }
}
