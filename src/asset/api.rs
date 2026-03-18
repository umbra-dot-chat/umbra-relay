//! Community asset upload/serve API handlers.
//!
//! Endpoints for uploading and serving community emoji, stickers, and other
//! media assets. Assets are stored on disk and served with proper caching headers.
//!
//! - `POST /api/community/:communityId/assets/upload` — Upload an asset
//! - `GET  /api/community/:communityId/assets/:filename`  — Serve an asset

use axum::{
    body::Body,
    extract::{Multipart, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Serialize;

use super::store::AssetStore;

// ── Response Types ───────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadResponse {
    pub url: String,
    pub hash: String,
    pub size: u64,
    pub content_type: String,
}

fn error_response<T: Serialize>(
    status: StatusCode,
    msg: &str,
) -> (StatusCode, Json<ApiResponse<T>>) {
    (
        status,
        Json(ApiResponse {
            ok: false,
            data: None,
            error: Some(msg.to_string()),
        }),
    )
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// POST /api/community/:communityId/assets/upload
///
/// Upload a community asset (emoji or sticker image).
///
/// Multipart form fields:
/// - `file`: The binary image data
/// - `type`: Asset type — "emoji" (max 256KB) or "sticker" (max 2MB)
/// - `did`: The uploader's DID (for rate limiting and audit)
///
/// Returns the asset URL and hash for deduplication.
pub async fn upload_asset(
    State(store): State<AssetStore>,
    Path(community_id): Path<String>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let mut file_data: Option<Vec<u8>> = None;
    let mut file_content_type: Option<String> = None;
    let mut asset_type = String::from("emoji");
    let mut uploader_did = String::new();

    // Parse multipart fields
    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();

        match name.as_str() {
            "file" => {
                // Get content type from the file field
                let ct = field
                    .content_type()
                    .unwrap_or("application/octet-stream")
                    .to_string();
                file_content_type = Some(ct);

                match field.bytes().await {
                    Ok(bytes) => file_data = Some(bytes.to_vec()),
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to read upload file bytes");
                        return error_response(StatusCode::BAD_REQUEST, "Failed to read file data");
                    }
                }
            }
            "type" => {
                if let Ok(text) = field.text().await {
                    asset_type = text;
                }
            }
            "did" => {
                if let Ok(text) = field.text().await {
                    uploader_did = text;
                }
            }
            _ => {
                // Skip unknown fields
            }
        }
    }

    // Validate required fields
    let data = match file_data {
        Some(d) => d,
        None => {
            return error_response(StatusCode::BAD_REQUEST, "No file data provided");
        }
    };

    let content_type = match file_content_type {
        Some(ct) => ct,
        None => {
            return error_response(StatusCode::BAD_REQUEST, "No content type provided");
        }
    };

    if uploader_did.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "DID is required");
    }

    if community_id.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "Community ID is required");
    }

    // Validate content type
    if !AssetStore::is_valid_content_type(&content_type) {
        return error_response(
            StatusCode::BAD_REQUEST,
            &format!(
                "Invalid content type '{}'. Allowed: PNG, GIF, WEBP, APNG, JPEG, JSON (Lottie)",
                content_type
            ),
        );
    }

    // Validate file size
    let max_size = AssetStore::max_size_for_type(&asset_type);
    if data.len() > max_size {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            &format!(
                "File too large ({} bytes). Max for {}: {} bytes",
                data.len(),
                asset_type,
                max_size
            ),
        );
    }

    // Rate limit check
    if !store.check_rate_limit(&uploader_did) {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Upload rate limit exceeded. Try again in a minute.",
        );
    }

    // Check community storage quota
    let used = store.community_storage_used(&community_id);
    if used + data.len() as u64 > super::store::MAX_COMMUNITY_STORAGE {
        return error_response(
            StatusCode::INSUFFICIENT_STORAGE,
            "Community storage quota exceeded (500 MB limit)",
        );
    }

    // Store the asset
    match store.store_asset(&community_id, &data, &content_type, &uploader_did) {
        Ok(meta) => {
            let url = format!("/api/community/{}/assets/{}", community_id, meta.filename);
            (
                StatusCode::CREATED,
                Json(ApiResponse {
                    ok: true,
                    data: Some(UploadResponse {
                        url,
                        hash: meta.hash,
                        size: meta.size,
                        content_type: meta.content_type,
                    }),
                    error: None,
                }),
            )
        }
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

/// GET /api/community/:communityId/assets/:filename
///
/// Serve a stored asset file with proper Content-Type and cache headers.
/// No auth required — URLs use content-hash filenames which are unguessable.
pub async fn get_asset(
    State(store): State<AssetStore>,
    Path((community_id, filename)): Path<(String, String)>,
) -> impl IntoResponse {
    match store.get_asset(&community_id, &filename) {
        Some((data, content_type)) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                content_type
                    .parse()
                    .unwrap_or_else(|_| "application/octet-stream".parse().unwrap()),
            );
            // Cache for 1 year — content-hash filenames never change
            headers.insert(
                header::CACHE_CONTROL,
                "public, max-age=31536000, immutable".parse().unwrap(),
            );

            (StatusCode::OK, headers, Body::from(data)).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
