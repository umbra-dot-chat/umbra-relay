//! GIF proxy API handlers.
//!
//! Proxies search and trending requests to the Tenor API v2.
//! The API key is injected server-side so clients never see it.
//!
//! - `GET /api/gif/search?q=QUERY&limit=20&pos=TOKEN`   — Search GIFs
//! - `GET /api/gif/trending?limit=20&pos=TOKEN`          — Trending GIFs

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

use super::config::GifConfig;

// ── Query Parameters ─────────────────────────────────────────────────────────

/// Query parameters for GIF search.
#[derive(Debug, Deserialize)]
pub struct GifSearchQuery {
    /// Search query string.
    pub q: String,
    /// Maximum number of results (default 20, max 50).
    pub limit: Option<u32>,
    /// Pagination token from previous response.
    pub pos: Option<String>,
}

/// Query parameters for trending GIFs.
#[derive(Debug, Deserialize)]
pub struct GifTrendingQuery {
    /// Maximum number of results (default 20, max 50).
    pub limit: Option<u32>,
    /// Pagination token from previous response.
    pub pos: Option<String>,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// Search GIFs via Tenor.
///
/// GET /api/gif/search?q=hello&limit=20&pos=...
pub async fn search(
    State(config): State<GifConfig>,
    Query(query): Query<GifSearchQuery>,
) -> impl IntoResponse {
    let api_key = match &config.tenor_api_key {
        Some(key) => key,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "GIF service not configured" })),
            )
                .into_response();
        }
    };

    let limit = query.limit.unwrap_or(20).min(50);

    let client = reqwest::Client::new();
    let mut request = client
        .get(format!("{}/search", config.tenor_base_url()))
        .query(&[
            ("q", query.q.as_str()),
            ("key", api_key.as_str()),
            ("limit", &limit.to_string()),
            ("media_filter", "gif,tinygif"),
            ("client_key", "umbra"),
        ]);

    if let Some(ref pos) = query.pos {
        request = request.query(&[("pos", pos.as_str())]);
    }

    match request.send().await {
        Ok(response) => match response.json::<serde_json::Value>().await {
            Ok(json) => Json(json).into_response(),
            Err(e) => {
                tracing::error!("Failed to parse Tenor response: {}", e);
                (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({ "error": "Failed to parse GIF response" })),
                )
                    .into_response()
            }
        },
        Err(e) => {
            tracing::error!("Failed to fetch from Tenor: {}", e);
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": "Failed to fetch GIFs" })),
            )
                .into_response()
        }
    }
}

/// Get trending/featured GIFs via Tenor.
///
/// GET /api/gif/trending?limit=20&pos=...
pub async fn trending(
    State(config): State<GifConfig>,
    Query(query): Query<GifTrendingQuery>,
) -> impl IntoResponse {
    let api_key = match &config.tenor_api_key {
        Some(key) => key,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "GIF service not configured" })),
            )
                .into_response();
        }
    };

    let limit = query.limit.unwrap_or(20).min(50);

    let client = reqwest::Client::new();
    let mut request = client
        .get(format!("{}/featured", config.tenor_base_url()))
        .query(&[
            ("key", api_key.as_str()),
            ("limit", &limit.to_string()),
            ("media_filter", "gif,tinygif"),
            ("client_key", "umbra"),
        ]);

    if let Some(ref pos) = query.pos {
        request = request.query(&[("pos", pos.as_str())]);
    }

    match request.send().await {
        Ok(response) => match response.json::<serde_json::Value>().await {
            Ok(json) => Json(json).into_response(),
            Err(e) => {
                tracing::error!("Failed to parse Tenor response: {}", e);
                (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({ "error": "Failed to parse GIF response" })),
                )
                    .into_response()
            }
        },
        Err(e) => {
            tracing::error!("Failed to fetch from Tenor: {}", e);
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": "Failed to fetch GIFs" })),
            )
                .into_response()
        }
    }
}
