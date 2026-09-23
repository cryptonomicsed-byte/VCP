use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use vcp_types::VcpError;

/// Returns `Err` when `VCP_REQUIRE_PUBKEY=true` and `public_key_hex` is empty.
///
/// Use this at the auth/verify callsite to enforce that no device can claim
/// an identity without supplying a real Ed25519 public key in production.
/// When the env var is absent or not `"true"` the function is a no-op (dev
/// mode) and logs a warning so the bypass is visible in server output.
pub fn require_pubkey_in_production(
    device_id: &str,
    public_key_hex: &str,
) -> Result<(), VcpError> {
    if public_key_hex.is_empty() {
        if std::env::var("VCP_REQUIRE_PUBKEY").unwrap_or_default() == "true" {
            return Err(VcpError::ChallengeFailed {
                reason: format!(
                    "device '{}' has no public_key — device public key required in production mode \
                     (VCP_REQUIRE_PUBKEY=true). Supply an Ed25519 public key or unset VCP_REQUIRE_PUBKEY.",
                    device_id
                ),
            });
        }
        tracing::warn!(
            device_id,
            "VCP: empty public_key — skipping Ed25519 verification (dev mode)"
        );
    }
    Ok(())
}

/// Verify an Ed25519 signature over the canonical auth message.
///
/// Auth message = SHA-256(challenge_id || ":" || nonce)
/// The device signs this during step 3 of the 7-step handshake.
///
/// public_key_hex: 32-byte Ed25519 public key as lowercase hex (64 chars)
/// signature_hex:  64-byte signature as lowercase hex (128 chars)
pub fn verify_auth_signature(
    challenge_id: &str,
    nonce: &str,
    public_key_hex: &str,
    signature_hex: &str,
) -> Result<(), VcpError> {
    // Build the message that was signed
    let message = Sha256::digest(format!("{challenge_id}:{nonce}").as_bytes());

    // Decode public key
    let pk_bytes = hex::decode(public_key_hex).map_err(|e| VcpError::ChallengeFailed {
        reason: format!("invalid public key hex: {e}"),
    })?;
    let pk_arr: [u8; 32] = pk_bytes.try_into().map_err(|_| VcpError::ChallengeFailed {
        reason: "public key must be 32 bytes".into(),
    })?;
    let verifying_key = VerifyingKey::from_bytes(&pk_arr).map_err(|e| VcpError::ChallengeFailed {
        reason: format!("invalid Ed25519 public key: {e}"),
    })?;

    // Decode signature
    let sig_bytes = hex::decode(signature_hex).map_err(|e| VcpError::ChallengeFailed {
        reason: format!("invalid signature hex: {e}"),
    })?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| VcpError::ChallengeFailed {
        reason: "signature must be 64 bytes".into(),
    })?;
    let signature = Signature::from_bytes(&sig_arr);

    // Verify
    use ed25519_dalek::Verifier;
    verifying_key
        .verify(&message, &signature)
        .map_err(|_| VcpError::SignatureInvalid)
}
