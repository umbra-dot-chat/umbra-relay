//! Bridge config REST API handlers.
//!
//! Endpoints for managing Discord ↔ Umbra bridge configurations.
//! These are called by the Umbra client during import and by the bridge bot
//! to discover which communities to bridge.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use super::store::{BridgeChannel, BridgeConfig, BridgeSeat, BridgeStore};

// ── Request / Response Types ─────────────────────────────────────────────────

/// POST /api/bridge/register
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterBridgeRequest {
    pub community_id: String,
    pub guild_id: String,
    pub channels: Vec<BridgeChannel>,
    pub seats: Vec<BridgeSeat>,
    pub member_dids: Vec<String>,
    /// Optional: the DID the bridge bot will use for this community.
    pub bridge_did: Option<String>,
}

/// PUT /api/bridge/:id/members
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateMembersRequest {
    pub member_dids: Vec<String>,
}

/// PUT /api/bridge/:id/enabled
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetEnabledRequest {
    pub enabled: bool,
}

/// Generic success response.
#[derive(Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    fn success(data: T) -> Json<Self> {
        Json(Self {
            ok: true,
            data: Some(data),
            error: None,
        })
    }
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

/// POST /api/bridge/register — Register a new bridge configuration.
///
/// Called by the Umbra client during/after Discord import when the user
/// enables bridging. Creates or overwrites the config for a community.
pub async fn register_bridge(
    State(store): State<BridgeStore>,
    Json(req): Json<RegisterBridgeRequest>,
) -> impl IntoResponse {
    if req.community_id.is_empty() || req.guild_id.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "communityId and guildId are required",
        );
    }

    if req.channels.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "At least one channel mapping is required",
        );
    }

    let now = chrono::Utc::now().timestamp_millis();
    let config = BridgeConfig {
        community_id: req.community_id.clone(),
        guild_id: req.guild_id,
        enabled: true,
        bridge_did: req.bridge_did,
        channels: req.channels,
        seats: req.seats,
        member_dids: req.member_dids,
        created_at: now,
        updated_at: now,
    };

    store.register(config.clone());

    (
        StatusCode::CREATED,
        Json(ApiResponse {
            ok: true,
            data: Some(config),
            error: None,
        }),
    )
}

/// GET /api/bridge/list — List all bridge configs (summaries).
///
/// Used by the bridge bot on startup to discover which communities
/// to bridge, and by the client for settings UI.
pub async fn list_bridges(State(store): State<BridgeStore>) -> impl IntoResponse {
    let bridges = store.list();
    ApiResponse::success(bridges)
}

/// GET /api/bridge/:id — Get full bridge config for a community.
///
/// Used by the bridge bot to get channel mappings, seats, and member
/// lists for a specific community.
pub async fn get_bridge(
    State(store): State<BridgeStore>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match store.get(&id) {
        Some(config) => (
            StatusCode::OK,
            Json(ApiResponse {
                ok: true,
                data: Some(config),
                error: None,
            }),
        ),
        None => error_response(StatusCode::NOT_FOUND, "Bridge config not found"),
    }
}

/// DELETE /api/bridge/:id — Delete a bridge config.
///
/// Disables and removes the bridge for a community.
pub async fn delete_bridge(
    State(store): State<BridgeStore>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if store.delete(&id) {
        (
            StatusCode::OK,
            Json(ApiResponse::<()> {
                ok: true,
                data: None,
                error: None,
            }),
        )
    } else {
        error_response(StatusCode::NOT_FOUND, "Bridge config not found")
    }
}

/// PUT /api/bridge/:id/members — Update member DID list for a bridge.
///
/// Called when community membership changes so the bridge bot knows
/// which DIDs to fan out messages to.
pub async fn update_members(
    State(store): State<BridgeStore>,
    Path(id): Path<String>,
    Json(req): Json<UpdateMembersRequest>,
) -> impl IntoResponse {
    if store.update_members(&id, req.member_dids) {
        let config = store.get(&id);
        (
            StatusCode::OK,
            Json(ApiResponse {
                ok: true,
                data: config,
                error: None,
            }),
        )
    } else {
        error_response(StatusCode::NOT_FOUND, "Bridge config not found")
    }
}

/// PUT /api/bridge/:id/enabled — Enable or disable a bridge.
///
/// Allows toggling the bridge without deleting the config.
pub async fn set_enabled(
    State(store): State<BridgeStore>,
    Path(id): Path<String>,
    Json(req): Json<SetEnabledRequest>,
) -> impl IntoResponse {
    if store.set_enabled(&id, req.enabled) {
        let config = store.get(&id);
        (
            StatusCode::OK,
            Json(ApiResponse {
                ok: true,
                data: config,
                error: None,
            }),
        )
    } else {
        error_response(StatusCode::NOT_FOUND, "Bridge config not found")
    }
}
