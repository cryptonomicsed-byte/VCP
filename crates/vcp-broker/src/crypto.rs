use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use vcp_types::VcpError;

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
