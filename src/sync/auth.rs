//! Auth helpers — Ed25519 signature verification, Bearer token extraction, and DID utilities.

use axum::http::{HeaderMap, StatusCode};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Extract a Bearer token from the Authorization header.
pub fn extract_bearer_token(headers: &HeaderMap) -> Result<String, (StatusCode, &'static str)> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header"))?;

    if !auth.starts_with("Bearer ") {
        return Err((StatusCode::UNAUTHORIZED, "Invalid Authorization format"));
    }

    Ok(auth[7..].to_string())
}

/// Verify an Ed25519 signature over a nonce.
/// `public_key_b64` and `signature_b64` are base64-encoded.
/// Returns `true` if the signature is valid.
pub fn verify_ed25519_signature(
    nonce: &str,
    public_key_b64: &str,
    signature_b64: &str,
) -> Result<bool, String> {
    let b64 = base64::engine::general_purpose::STANDARD;

    let pk_bytes = b64
        .decode(public_key_b64)
        .map_err(|e| format!("Invalid public key encoding: {}", e))?;

    let sig_bytes = b64
        .decode(signature_b64)
        .map_err(|e| format!("Invalid signature encoding: {}", e))?;

    let pk_array: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| "Public key must be 32 bytes".to_string())?;

    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "Signature must be 64 bytes".to_string())?;

    let verifying_key =
        VerifyingKey::from_bytes(&pk_array).map_err(|e| format!("Invalid public key: {}", e))?;

    let signature = Signature::from_bytes(&sig_array);

    Ok(verifying_key.verify(nonce.as_bytes(), &signature).is_ok())
}

/// Maximum allowed age for a signed username payload (5 minutes).
const USERNAME_SIGNATURE_MAX_AGE_SECS: i64 = 300;

/// Extract a 32-byte Ed25519 public key from a `did:key:z6Mk...` DID.
///
/// The format is:
///   did:key:<multibase-base58btc(multicodec-ed25519-pub ++ raw-32-bytes)>
///
/// - Multibase prefix: `z` (base58btc)
/// - Multicodec prefix for Ed25519 pub key: `0xed01` (two bytes)
/// - Remaining 32 bytes: the raw public key
pub fn did_to_public_key(did: &str) -> Result<[u8; 32], String> {
    let key_part = did
        .strip_prefix("did:key:")
        .ok_or_else(|| format!("Not a did:key DID: {}", did))?;

    // Strip the multibase prefix 'z' (base58btc)
    let b58_str = key_part
        .strip_prefix('z')
        .ok_or_else(|| "Expected base58btc multibase prefix 'z'".to_string())?;

    let decoded = bs58::decode(b58_str)
        .into_vec()
        .map_err(|e| format!("Base58 decode failed: {}", e))?;

    // First two bytes should be the Ed25519 multicodec prefix: 0xed 0x01
    if decoded.len() < 2 {
        return Err("Decoded key too short".to_string());
    }
    if decoded[0] != 0xed || decoded[1] != 0x01 {
        return Err(format!(
            "Expected Ed25519 multicodec prefix (0xed01), got: 0x{:02x}{:02x}",
            decoded[0], decoded[1]
        ));
    }

    let key_bytes = &decoded[2..];
    let pk_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| format!("Expected 32 key bytes, got {}", key_bytes.len()))?;

    Ok(pk_array)
}

/// Verify a signed username operation.
///
/// The canonical payload format is: `umbra:username:{did}:{name}:{timestamp}`
/// For release operations, `name` is "release".
///
/// Verifies:
/// 1. The signature is valid Ed25519 over the canonical payload
/// 2. The public key in the request matches the DID
/// 3. The timestamp is within the allowed window (5 minutes)
pub fn verify_username_signature(
    did: &str,
    name: &str,
    signature_b64: &str,
    public_key_b64: &str,
    timestamp: i64,
) -> Result<(), String> {
    // 1. Check timestamp freshness
    let now = chrono::Utc::now().timestamp();
    let age = now - timestamp;
    if age > USERNAME_SIGNATURE_MAX_AGE_SECS {
        return Err(format!(
            "Signature expired: {} seconds old (max {})",
            age, USERNAME_SIGNATURE_MAX_AGE_SECS
        ));
    }
    if age < -60 {
        return Err("Signature timestamp is in the future".to_string());
    }

    // 2. Verify the public key matches the DID
    let did_pk = did_to_public_key(did)?;
    let b64 = base64::engine::general_purpose::STANDARD;
    let req_pk_bytes = b64
        .decode(public_key_b64)
        .map_err(|e| format!("Invalid public key encoding: {}", e))?;
    let req_pk: [u8; 32] = req_pk_bytes
        .try_into()
        .map_err(|_| "Public key must be 32 bytes".to_string())?;
    if did_pk != req_pk {
        return Err("Public key does not match DID".to_string());
    }

    // 3. Reconstruct canonical payload and verify signature
    let payload = format!("umbra:username:{}:{}:{}", did, name, timestamp);
    let valid = verify_ed25519_signature(&payload, public_key_b64, signature_b64)?;
    if !valid {
        return Err("Invalid signature".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_to_public_key_valid() {
        // A known did:key for Ed25519
        // did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
        // This encodes the Ed25519 public key from the example in the did:key spec
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let result = did_to_public_key(did);
        assert!(result.is_ok());
        let pk = result.unwrap();
        assert_eq!(pk.len(), 32);
    }

    #[test]
    fn test_did_to_public_key_invalid_prefix() {
        let result = did_to_public_key("did:web:example.com");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Not a did:key"));
    }

    #[test]
    fn test_did_to_public_key_invalid_multibase() {
        let result = did_to_public_key("did:key:m6MkhaXg");
        assert!(result.is_err());
    }
}
