//! REST handlers for sync blob CRUD and challenge-response auth.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde_json::json;

use super::auth::{extract_bearer_token, verify_ed25519_signature};
use super::blob_store::SyncBlobStore;

/// Shared state for sync endpoints.
pub type SyncState = Arc<SyncBlobStore>;

// ── Auth Endpoints ──────────────────────────────────────────────────────────

/// POST /api/sync/:did/auth — Request an auth challenge nonce.
pub async fn create_challenge(
    Path(did): Path<String>,
    State(store): State<SyncState>,
) -> impl IntoResponse {
    match store.create_challenge(&did) {
        Ok(nonce) => (StatusCode::OK, Json(json!({ "nonce": nonce }))).into_response(),
        Err(e) => {
            tracing::error!("Failed to create challenge for {}: {}", did, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal_error" })),
            )
                .into_response()
        }
    }
}

/// Verify request — nonce + Ed25519 signature + public key.
#[derive(Debug, serde::Deserialize)]
pub struct AuthVerifyWithNonce {
    pub nonce: String,
    pub signature: String,
    pub public_key: String,
}

/// POST /api/sync/:did/verify — Verify Ed25519 signature over nonce.
pub async fn verify_with_nonce(
    Path(did): Path<String>,
    State(store): State<SyncState>,
    Json(body): Json<AuthVerifyWithNonce>,
) -> impl IntoResponse {
    // 1. Verify the challenge nonce exists and belongs to this DID
    let challenge_did = match store.verify_challenge(&body.nonce) {
        Ok(Some(d)) => d,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid_or_expired_nonce" })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Challenge verification error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal_error" })),
            )
                .into_response();
        }
    };

    // 2. Verify the challenge was issued for this DID
    if challenge_did != did {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "nonce_did_mismatch" })),
        )
            .into_response();
    }

    // 3. Verify the Ed25519 signature over the nonce
    match verify_ed25519_signature(&body.nonce, &body.public_key, &body.signature) {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid_signature" })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::warn!("Signature verification error for {}: {}", did, e);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "malformed_signature", "detail": e })),
            )
                .into_response();
        }
    }

    // 4. Issue a Bearer token
    match store.create_token(&did) {
        Ok((token, expires_at)) => {
            tracing::info!("Sync auth: issued token for {}", did);
            (
                StatusCode::OK,
                Json(json!({ "token": token, "expires_at": expires_at })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Failed to create token for {}: {}", did, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal_error" })),
            )
                .into_response()
        }
    }
}

// ── Blob Endpoints ──────────────────────────────────────────────────────────

/// Helper: validate Bearer token and check DID matches.
fn validate_auth(
    store: &SyncBlobStore,
    headers: &HeaderMap,
    did: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let token = extract_bearer_token(headers).map_err(|(status, msg)| {
        (status, Json(json!({ "error": msg })))
    })?;

    match store.validate_token(&token) {
        Ok(Some(token_did)) if token_did == did => Ok(()),
        Ok(Some(_)) => Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "token_did_mismatch" })),
        )),
        Ok(None) => Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid_or_expired_token" })),
        )),
        Err(e) => {
            tracing::error!("Token validation error: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal_error" })),
            ))
        }
    }
}

/// PUT /api/sync/:did — Upload an encrypted sync blob.
pub async fn put_blob(
    Path(did): Path<String>,
    State(store): State<SyncState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if let Err(resp) = validate_auth(&store, &headers, &did) {
        return resp.into_response();
    }

    match store.put_blob(&did, &body) {
        Ok(()) => {
            tracing::debug!("Sync blob stored for {} ({} bytes)", did, body.len());
            (StatusCode::NO_CONTENT, Json(json!({}))).into_response()
        }
        Err(e) if e.contains("exceeds maximum") => (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({ "error": "blob_too_large", "detail": e })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to store blob for {}: {}", did, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal_error" })),
            )
                .into_response()
        }
    }
}

/// GET /api/sync/:did — Download an encrypted sync blob.
pub async fn get_blob(
    Path(did): Path<String>,
    State(store): State<SyncState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = validate_auth(&store, &headers, &did) {
        return resp.into_response();
    }

    match store.get_blob(&did) {
        Ok(Some(blob)) => {
            tracing::debug!("Sync blob retrieved for {} ({} bytes)", did, blob.len());
            (
                StatusCode::OK,
                [("content-type", "application/octet-stream")],
                blob,
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no_blob_found" })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to get blob for {}: {}", did, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal_error" })),
            )
                .into_response()
        }
    }
}

/// GET /api/sync/:did/meta — Get metadata about a sync blob without downloading.
pub async fn get_blob_meta(
    Path(did): Path<String>,
    State(store): State<SyncState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = validate_auth(&store, &headers, &did) {
        return resp.into_response();
    }

    match store.get_blob_meta(&did) {
        Ok(Some(meta)) => (StatusCode::OK, Json(json!(meta))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no_blob_found" })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to get blob meta for {}: {}", did, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal_error" })),
            )
                .into_response()
        }
    }
}

/// DELETE /api/sync/:did — Delete a sync blob.
pub async fn delete_blob(
    Path(did): Path<String>,
    State(store): State<SyncState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = validate_auth(&store, &headers, &did) {
        return resp.into_response();
    }

    match store.delete_blob(&did) {
        Ok(true) => {
            tracing::info!("Sync blob deleted for {}", did);
            (StatusCode::NO_CONTENT, Json(json!({}))).into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no_blob_found" })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to delete blob for {}: {}", did, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal_error" })),
            )
                .into_response()
        }
    }
}
