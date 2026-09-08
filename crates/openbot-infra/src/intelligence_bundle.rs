//! Encrypted/signed Intelligence neutral bundle verifier（v3 §20.3）。

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, VerifyingKey};
use hkdf::Hkdf;
use openbot_application::{IntelligenceImportError, VerifiedIntelligenceBundle};
use openbot_contracts::intelligence::{
    INTELLIGENCE_BUNDLE_FORMAT, IntelligenceBundleEnvelope, IntelligenceBundlePayload,
};
use openbot_domain::vault::SecretBytes;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// 外信封 JSON 上限；ciphertext 的解密后 payload 同受该数量级约束。
pub const MAX_INTELLIGENCE_BUNDLE_BYTES: usize = 512 * 1024 * 1024;

/// AES-256-GCM bundle key；Debug/Drop 均不泄漏材料。
pub struct IntelligenceBundleDecryptionKey(SecretBytes);

impl IntelligenceBundleDecryptionKey {
    /// 接管精确 32 bytes；不截断/补零。
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, IntelligenceImportError> {
        if bytes.len() != 32 {
            drop(SecretBytes::new(bytes));
            return Err(IntelligenceImportError::Invalid {
                field: "bundle_decryption_key",
            });
        }
        Ok(Self(SecretBytes::new(bytes)))
    }
}

impl core::fmt::Debug for IntelligenceBundleDecryptionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IntelligenceBundleDecryptionKey([redacted])")
    }
}

/// Ed25519 verification key 与非 secret key id。
#[derive(Clone)]
pub struct IntelligenceBundleVerificationKey {
    key_id: String,
    key: VerifyingKey,
}

impl IntelligenceBundleVerificationKey {
    /// 由 32-byte Ed25519 public key 构造。
    pub fn from_bytes(key_id: String, bytes: &[u8]) -> Result<Self, IntelligenceImportError> {
        if key_id.is_empty() || key_id.len() > 512 || key_id.as_bytes().contains(&0) {
            return Err(IntelligenceImportError::Invalid {
                field: "signing_key_id",
            });
        }
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| IntelligenceImportError::Invalid {
                field: "bundle_verification_key",
            })?;
        let key =
            VerifyingKey::from_bytes(&bytes).map_err(|_| IntelligenceImportError::Invalid {
                field: "bundle_verification_key",
            })?;
        Ok(Self { key_id, key })
    }
}

impl core::fmt::Debug for IntelligenceBundleVerificationKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IntelligenceBundleVerificationKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// 严格 parse → signature → AEAD → plaintext hash → payload binding。
pub fn verify_intelligence_bundle(
    envelope_bytes: &[u8],
    decryption_key: &IntelligenceBundleDecryptionKey,
    verification_key: &IntelligenceBundleVerificationKey,
) -> Result<VerifiedIntelligenceBundle, IntelligenceImportError> {
    if envelope_bytes.is_empty() || envelope_bytes.len() > MAX_INTELLIGENCE_BUNDLE_BYTES {
        return Err(IntelligenceImportError::Invalid {
            field: "bundle_size",
        });
    }
    let envelope: IntelligenceBundleEnvelope =
        serde_json::from_slice(envelope_bytes).map_err(|_| IntelligenceImportError::Invalid {
            field: "bundle_envelope",
        })?;
    if envelope.format != INTELLIGENCE_BUNDLE_FORMAT {
        return Err(IntelligenceImportError::Invalid {
            field: "bundle_format",
        });
    }
    validate_id(&envelope.bundle_id, "bundle_id")?;
    validate_id(&envelope.source_deployment_id, "source_deployment_id")?;
    if envelope.signing_key_id != verification_key.key_id {
        return Err(IntelligenceImportError::Invalid {
            field: "signing_key_id",
        });
    }
    let hash = decode_lower_hex_32(&envelope.payload_sha256)?;
    let nonce = decode_base64(&envelope.nonce, "bundle_nonce")?;
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| IntelligenceImportError::Invalid {
            field: "bundle_nonce",
        })?;
    let ciphertext = decode_base64(&envelope.ciphertext, "bundle_ciphertext")?;
    if ciphertext.len() < 16 || ciphertext.len() > MAX_INTELLIGENCE_BUNDLE_BYTES {
        return Err(IntelligenceImportError::Invalid {
            field: "bundle_ciphertext",
        });
    }
    let signature = decode_base64(&envelope.signature, "bundle_signature")?;
    let signature =
        Signature::from_slice(&signature).map_err(|_| IntelligenceImportError::Invalid {
            field: "bundle_signature",
        })?;
    let signed = signature_input(
        &envelope.bundle_id,
        &envelope.source_deployment_id,
        &verification_key.key_id,
        &nonce,
        &hash,
        &ciphertext,
    )?;
    verification_key
        .key
        .verify_strict(&signed, &signature)
        .map_err(|_| IntelligenceImportError::Invalid {
            field: "bundle_signature",
        })?;
    let aad = bundle_aad(
        &envelope.bundle_id,
        &envelope.source_deployment_id,
        &verification_key.key_id,
        &hash,
    )?;
    let derived = derive_bundle_key(
        decryption_key.0.expose(),
        &hash,
        &envelope.bundle_id,
        &envelope.source_deployment_id,
        &verification_key.key_id,
    )?;
    let cipher = Aes256Gcm::new_from_slice(derived.as_ref()).map_err(|_| {
        IntelligenceImportError::Invalid {
            field: "bundle_decryption_key",
        }
    })?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| IntelligenceImportError::Invalid {
            field: "bundle_ciphertext",
        })?;
    if Sha256::digest(&plaintext).as_slice() != hash {
        return Err(IntelligenceImportError::Invalid {
            field: "payload_sha256",
        });
    }
    let payload: IntelligenceBundlePayload =
        serde_json::from_slice(&plaintext).map_err(|_| IntelligenceImportError::Invalid {
            field: "bundle_payload",
        })?;
    if payload.bundle_id != envelope.bundle_id
        || payload.source_deployment_id != envelope.source_deployment_id
    {
        return Err(IntelligenceImportError::Invalid {
            field: "payload_envelope_binding",
        });
    }
    VerifiedIntelligenceBundle::new(
        payload,
        envelope.payload_sha256,
        verification_key.key_id.clone(),
    )
}

fn derive_bundle_key(
    master: &[u8],
    payload_hash: &[u8; 32],
    bundle_id: &str,
    source_deployment_id: &str,
    signing_key_id: &str,
) -> Result<Zeroizing<[u8; 32]>, IntelligenceImportError> {
    let info = bundle_aad(
        bundle_id,
        source_deployment_id,
        signing_key_id,
        payload_hash,
    )?;
    let mut derived = Zeroizing::new([0_u8; 32]);
    Hkdf::<Sha256>::new(Some(payload_hash), master)
        .expand(&info, derived.as_mut())
        .map_err(|_| IntelligenceImportError::Invalid {
            field: "bundle_key_derivation",
        })?;
    Ok(derived)
}

fn signature_input(
    bundle_id: &str,
    source_deployment_id: &str,
    signing_key_id: &str,
    nonce: &[u8; 12],
    payload_hash: &[u8; 32],
    ciphertext: &[u8],
) -> Result<Vec<u8>, IntelligenceImportError> {
    let mut output = bundle_aad(
        bundle_id,
        source_deployment_id,
        signing_key_id,
        payload_hash,
    )?;
    push_framed(&mut output, nonce)?;
    push_framed(&mut output, ciphertext)?;
    Ok(output)
}

fn bundle_aad(
    bundle_id: &str,
    source_deployment_id: &str,
    signing_key_id: &str,
    payload_hash: &[u8; 32],
) -> Result<Vec<u8>, IntelligenceImportError> {
    let mut output = Vec::new();
    for bytes in [
        INTELLIGENCE_BUNDLE_FORMAT.as_bytes(),
        bundle_id.as_bytes(),
        source_deployment_id.as_bytes(),
        signing_key_id.as_bytes(),
        payload_hash,
    ] {
        push_framed(&mut output, bytes)?;
    }
    Ok(output)
}

fn push_framed(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), IntelligenceImportError> {
    output.extend(
        u64::try_from(bytes.len())
            .map_err(|_| IntelligenceImportError::Invalid {
                field: "bundle_framing",
            })?
            .to_be_bytes(),
    );
    output.extend(bytes);
    Ok(())
}

fn decode_base64(value: &str, field: &'static str) -> Result<Vec<u8>, IntelligenceImportError> {
    BASE64
        .decode(value)
        .map_err(|_| IntelligenceImportError::Invalid { field })
}

fn decode_lower_hex_32(value: &str) -> Result<[u8; 32], IntelligenceImportError> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(IntelligenceImportError::Invalid {
            field: "payload_sha256",
        });
    }
    let bytes = value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16).map_err(|_| {
                IntelligenceImportError::Invalid {
                    field: "payload_sha256",
                }
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    bytes
        .try_into()
        .map_err(|_| IntelligenceImportError::Invalid {
            field: "payload_sha256",
        })
}

fn validate_id(value: &str, field: &'static str) -> Result<(), IntelligenceImportError> {
    if value.is_empty() || value.len() > 512 || value.as_bytes().contains(&0) {
        Err(IntelligenceImportError::Invalid { field })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use openbot_contracts::intelligence::{
        INTELLIGENCE_BUNDLE_SCHEMA_VERSION, IntelligenceBundleProvenance,
    };
    use time::macros::datetime;

    use super::*;

    fn fixture() -> (
        Vec<u8>,
        IntelligenceBundleDecryptionKey,
        IntelligenceBundleVerificationKey,
    ) {
        let payload = IntelligenceBundlePayload {
            schema_version: INTELLIGENCE_BUNDLE_SCHEMA_VERSION,
            bundle_id: "bundle-1".to_owned(),
            source_deployment_id: "dep-a".to_owned(),
            exported_at: datetime!(2026-08-24 00:00 UTC),
            provenance: IntelligenceBundleProvenance {
                upstream_commit: openbot_application::INTELLIGENCE_SOURCE_COMMIT.to_owned(),
                exporter_version: "legacy-exporter-v1".to_owned(),
                project_id: "project-1".to_owned(),
            },
            threads: Vec::new(),
        };
        let plaintext = serde_json::to_vec(&payload).unwrap();
        let hash: [u8; 32] = Sha256::digest(&plaintext).into();
        let hash_hex = format!("{:x}", Sha256::digest(&plaintext));
        let nonce = [7_u8; 12];
        let key = [3_u8; 32];
        let signing = SigningKey::from_bytes(&[9_u8; 32]);
        let aad = bundle_aad("bundle-1", "dep-a", "key-1", &hash).unwrap();
        let derived = derive_bundle_key(&key, &hash, "bundle-1", "dep-a", "key-1").unwrap();
        let cipher = Aes256Gcm::new_from_slice(derived.as_ref()).unwrap();
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .unwrap();
        let signed =
            signature_input("bundle-1", "dep-a", "key-1", &nonce, &hash, &ciphertext).unwrap();
        let envelope = IntelligenceBundleEnvelope {
            format: INTELLIGENCE_BUNDLE_FORMAT.to_owned(),
            bundle_id: "bundle-1".to_owned(),
            source_deployment_id: "dep-a".to_owned(),
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
            payload_sha256: hash_hex,
            signing_key_id: "key-1".to_owned(),
            signature: BASE64.encode(signing.sign(&signed).to_bytes()),
        };
        (
            serde_json::to_vec(&envelope).unwrap(),
            IntelligenceBundleDecryptionKey::from_bytes(key.to_vec()).unwrap(),
            IntelligenceBundleVerificationKey::from_bytes(
                "key-1".to_owned(),
                signing.verifying_key().as_bytes(),
            )
            .unwrap(),
        )
    }

    #[test]
    fn signed_encrypted_bundle_opens_and_every_tamper_fails_closed() {
        let (bytes, key, verify) = fixture();
        let opened = verify_intelligence_bundle(&bytes, &key, &verify).unwrap();
        assert_eq!(opened.payload().bundle_id, "bundle-1");

        let mut envelope: IntelligenceBundleEnvelope = serde_json::from_slice(&bytes).unwrap();
        envelope.bundle_id = "bundle-2".to_owned();
        assert!(
            verify_intelligence_bundle(&serde_json::to_vec(&envelope).unwrap(), &key, &verify)
                .is_err()
        );
        let mut envelope: IntelligenceBundleEnvelope = serde_json::from_slice(&bytes).unwrap();
        let mut signature = BASE64.decode(&envelope.signature).unwrap();
        signature[0] ^= 1;
        envelope.signature = BASE64.encode(signature);
        assert!(
            verify_intelligence_bundle(&serde_json::to_vec(&envelope).unwrap(), &key, &verify)
                .is_err()
        );
        let wrong_key = IntelligenceBundleDecryptionKey::from_bytes(vec![4; 32]).unwrap();
        assert!(verify_intelligence_bundle(&bytes, &wrong_key, &verify).is_err());
    }
}
