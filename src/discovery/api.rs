//! Discovery API endpoints.
//!
//! REST API for managing linked accounts and performing lookups.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use super::config::DiscoveryConfig;
use super::store::DiscoveryStore;
use chrono::Utc;

use super::types::{
    BatchLookupRequest, BatchLookupResponse, ChangeUsernameRequest, DiscoveryStatusResponse,
    LinkAccountRequest, LinkedAccount, LinkedAccountInfo, Platform, RegisterUsernameRequest,
    ReleaseUsernameRequest, UnlinkRequest, UpdateSettingsRequest, UsernameForDidQuery,
    UsernameLookupQuery, UsernameResponse, UsernameSearchQuery, UsernameSearchResultItem,
};

use crate::sync::auth::verify_username_signature;

/// Type alias for the discovery state.
pub type DiscoveryState = (DiscoveryStore, DiscoveryConfig);

/// Query parameters for status endpoint.
#[derive(Debug, Deserialize)]
pub struct StatusQuery {
    /// The user's Umbra DID.
    pub did: String,
}

/// Get discovery status for a DID.
///
/// Returns linked accounts and discoverability status.
///
/// GET /discovery/status?did=did:key:z6Mk...
pub async fn get_status(
    State((store, _config)): State<DiscoveryState>,
    Query(query): Query<StatusQuery>,
) -> impl IntoResponse {
    let entry = store.get_or_create_entry(&query.did);

    Json(DiscoveryStatusResponse {
        did: entry.did,
        discoverable: entry.discoverable,
        accounts: entry.accounts.iter().map(LinkedAccountInfo::from).collect(),
    })
}

/// Update discovery settings.
///
/// POST /discovery/settings
/// Body: { "did": "...", "discoverable": true }
pub async fn update_settings(
    State((store, _config)): State<DiscoveryState>,
    Json(request): Json<UpdateSettingsRequest>,
) -> impl IntoResponse {
    store.set_discoverable(&request.did, request.discoverable);

    let entry = store.get_entry(&request.did).unwrap();

    Json(DiscoveryStatusResponse {
        did: entry.did,
        discoverable: entry.discoverable,
        accounts: entry.accounts.iter().map(LinkedAccountInfo::from).collect(),
    })
}

/// Batch lookup hashed platform IDs.
///
/// For privacy-preserving friend discovery. Clients hash platform IDs
/// locally before sending.
///
/// POST /discovery/lookup
/// Body: { "lookups": [{ "platform": "discord", "id_hash": "abc123..." }] }
pub async fn batch_lookup(
    State((store, _config)): State<DiscoveryState>,
    Json(request): Json<BatchLookupRequest>,
) -> impl IntoResponse {
    // Rate limit check could go here

    let results = store.batch_lookup(&request.lookups);

    Json(BatchLookupResponse { results })
}

/// Link a platform account directly.
///
/// Used after profile import OAuth — the client already has verified
/// platform credentials from the profile import flow, so we accept
/// a direct link request with the platform ID and username.
///
/// POST /discovery/link
/// Body: { "did": "...", "platform": "discord", "platform_id": "123", "username": "user" }
pub async fn link_account(
    State((store, _config)): State<DiscoveryState>,
    Json(request): Json<LinkAccountRequest>,
) -> impl IntoResponse {
    if request.did.is_empty() || request.platform_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Missing required fields" })),
        )
            .into_response();
    }

    let account = LinkedAccount {
        platform: request.platform,
        platform_id: request.platform_id,
        platform_username: request.username,
        linked_at: Utc::now(),
        verified: true,
    };

    store.link_account(&request.did, account);

    let entry = store.get_entry(&request.did).unwrap();
    (
        StatusCode::OK,
        Json(DiscoveryStatusResponse {
            did: entry.did,
            discoverable: entry.discoverable,
            accounts: entry.accounts.iter().map(LinkedAccountInfo::from).collect(),
        }),
    )
        .into_response()
}

/// Unlink a platform account.
///
/// DELETE /discovery/unlink
/// Body: { "did": "...", "platform": "discord" }
pub async fn unlink(
    State((store, _config)): State<DiscoveryState>,
    Json(request): Json<UnlinkRequest>,
) -> impl IntoResponse {
    if store.unlink_account(&request.did, request.platform) {
        let entry = store.get_entry(&request.did).unwrap();
        (
            StatusCode::OK,
            Json(DiscoveryStatusResponse {
                did: entry.did,
                discoverable: entry.discoverable,
                accounts: entry.accounts.iter().map(LinkedAccountInfo::from).collect(),
            }),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(DiscoveryStatusResponse {
                did: request.did,
                discoverable: false,
                accounts: vec![],
            }),
        )
    }
}

/// Get discovery service stats (for monitoring).
///
/// GET /discovery/stats
pub async fn stats(State((store, _config)): State<DiscoveryState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "users": store.user_count(),
        "indexed_accounts": store.index_size(),
        "pending_oauth": store.pending_oauth_count(),
        "registered_usernames": store.username_count(),
    }))
}

/// Create a hash for client-side lookup preparation.
///
/// This endpoint allows clients to hash a platform ID using the server's salt.
/// Useful for GDPR data exports where the client has raw platform IDs.
///
/// GET /discovery/hash?platform=discord&platform_id=123456789
#[derive(Debug, Deserialize)]
pub struct HashQuery {
    pub platform: Platform,
    pub platform_id: String,
}

pub async fn create_hash(
    State((store, _config)): State<DiscoveryState>,
    Query(query): Query<HashQuery>,
) -> impl IntoResponse {
    let hash = store.create_lookup_hash(query.platform, &query.platform_id);

    Json(serde_json::json!({
        "platform": query.platform,
        "id_hash": hash,
    }))
}

/// Search for discoverable users by platform username.
///
/// Returns users whose platform username contains the query string
/// (case-insensitive). Only returns users who have opted into discovery.
///
/// GET /discovery/search?platform=discord&username=Matt
#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub platform: Platform,
    pub username: String,
}

#[derive(Debug, Serialize)]
pub struct SearchResultItem {
    pub did: String,
    pub platform: Platform,
    pub username: String,
}

pub async fn search_by_username(
    State((store, _config)): State<DiscoveryState>,
    Query(query): Query<SearchQuery>,
) -> impl IntoResponse {
    if query.username.len() < 2 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Username query must be at least 2 characters" })),
        )
            .into_response();
    }

    let results = store.search_by_username(query.platform, &query.username, 10);

    let items: Vec<SearchResultItem> = results
        .into_iter()
        .map(|(did, info)| SearchResultItem {
            did,
            platform: info.platform,
            username: info.username,
        })
        .collect();

    Json(serde_json::json!({ "results": items })).into_response()
}

// ── Username Endpoints ──────────────────────────────────────────────────────

/// Register a username for a DID.
///
/// The relay auto-assigns a 5-digit numeric tag for uniqueness.
/// If the DID already has a username, the old one is released first.
///
/// POST /discovery/username/register
/// Body: { "did": "...", "name": "Matt" }
pub async fn register_username(
    State((store, _config)): State<DiscoveryState>,
    Json(request): Json<RegisterUsernameRequest>,
) -> impl IntoResponse {
    if request.did.is_empty() || request.name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Missing required fields" })),
        )
            .into_response();
    }

    // Verify Ed25519 signature (required)
    match (&request.signature, &request.public_key, request.timestamp) {
        (Some(sig), Some(pk), Some(ts)) => {
            if let Err(e) = verify_username_signature(&request.did, &request.name, sig, pk, ts) {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": format!("Signature verification failed: {}", e) })),
                )
                    .into_response();
            }
        }
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "Missing signature fields (signature, public_key, timestamp required)" })),
            )
                .into_response();
        }
    }

    match store.register_username(&request.did, &request.name) {
        Ok(entry) => (
            StatusCode::OK,
            Json(UsernameResponse {
                did: request.did,
                username: Some(entry.full_username()),
                name: Some(entry.name),
                tag: Some(entry.tag),
                registered_at: Some(entry.registered_at),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

/// Get the username for a DID.
///
/// GET /discovery/username?did=did:key:z6Mk...
pub async fn get_username(
    State((store, _config)): State<DiscoveryState>,
    Query(query): Query<UsernameForDidQuery>,
) -> impl IntoResponse {
    match store.get_username(&query.did) {
        Some(entry) => Json(UsernameResponse {
            did: query.did,
            username: Some(entry.full_username()),
            name: Some(entry.name),
            tag: Some(entry.tag),
            registered_at: Some(entry.registered_at),
        }),
        None => Json(UsernameResponse {
            did: query.did,
            username: None,
            name: None,
            tag: None,
            registered_at: None,
        }),
    }
}

/// Look up a user by exact username (Name#Tag).
///
/// Returns the DID if found. Case-insensitive.
///
/// GET /discovery/username/lookup?username=Matt%2301283
pub async fn lookup_username(
    State((store, _config)): State<DiscoveryState>,
    Query(query): Query<UsernameLookupQuery>,
) -> impl IntoResponse {
    match store.lookup_username(&query.username) {
        Some(did) => {
            let uname = store.get_username(&did);
            Json(serde_json::json!({
                "found": true,
                "did": did,
                "username": uname.as_ref().map(|u| u.full_username()),
            }))
        }
        None => Json(serde_json::json!({
            "found": false,
            "did": null,
            "username": null,
        })),
    }
}

/// Search for users by partial name.
///
/// Case-insensitive substring match on the name portion.
/// Minimum 2 characters, max 50 results.
///
/// GET /discovery/username/search?name=Matt&limit=20
pub async fn search_usernames(
    State((store, _config)): State<DiscoveryState>,
    Query(query): Query<UsernameSearchQuery>,
) -> impl IntoResponse {
    if query.name.len() < 2 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Search query must be at least 2 characters" })),
        )
            .into_response();
    }

    let limit = query.limit.unwrap_or(20).min(50);
    let results = store.search_usernames(&query.name, limit);

    let items: Vec<UsernameSearchResultItem> = results
        .into_iter()
        .map(|(did, username)| UsernameSearchResultItem { did, username })
        .collect();

    Json(serde_json::json!({ "results": items })).into_response()
}

/// Change username (releases old, registers new with fresh tag).
///
/// POST /discovery/username/change
/// Body: { "did": "...", "name": "NewName" }
pub async fn change_username(
    State((store, _config)): State<DiscoveryState>,
    Json(request): Json<ChangeUsernameRequest>,
) -> impl IntoResponse {
    if request.did.is_empty() || request.name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Missing required fields" })),
        )
            .into_response();
    }

    // Verify Ed25519 signature (required)
    match (&request.signature, &request.public_key, request.timestamp) {
        (Some(sig), Some(pk), Some(ts)) => {
            if let Err(e) = verify_username_signature(&request.did, &request.name, sig, pk, ts) {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": format!("Signature verification failed: {}", e) })),
                )
                    .into_response();
            }
        }
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "Missing signature fields (signature, public_key, timestamp required)" })),
            )
                .into_response();
        }
    }

    // register_username already handles releasing the old one
    match store.register_username(&request.did, &request.name) {
        Ok(entry) => Json(UsernameResponse {
            did: request.did,
            username: Some(entry.full_username()),
            name: Some(entry.name),
            tag: Some(entry.tag),
            registered_at: Some(entry.registered_at),
        })
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

/// Release (delete) a username.
///
/// DELETE /discovery/username/release
/// Body: { "did": "..." }
pub async fn release_username(
    State((store, _config)): State<DiscoveryState>,
    Json(request): Json<ReleaseUsernameRequest>,
) -> impl IntoResponse {
    // Verify Ed25519 signature (required) — for release, name = "release"
    match (&request.signature, &request.public_key, request.timestamp) {
        (Some(sig), Some(pk), Some(ts)) => {
            if let Err(e) = verify_username_signature(&request.did, "release", sig, pk, ts) {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": format!("Signature verification failed: {}", e) })),
                )
                    .into_response();
            }
        }
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "Missing signature fields (signature, public_key, timestamp required)" })),
            )
                .into_response();
        }
    }

    if store.release_username(&request.did) {
        Json(serde_json::json!({ "success": true })).into_response()
    } else {
        Json(serde_json::json!({ "success": false, "error": "No username found" })).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::config::DiscoveryConfig;

    fn test_store() -> DiscoveryStore {
        DiscoveryStore::new(DiscoveryConfig {
            discord_client_id: None,
            discord_client_secret: None,
            discord_redirect_uri: None,
            discord_profile_import_redirect_uri: None,
            discord_community_import_redirect_uri: None,
            discord_bot_token: None,
            github_client_id: None,
            github_client_secret: None,
            github_redirect_uri: None,
            github_profile_import_redirect_uri: None,
            steam_api_key: None,
            steam_profile_import_redirect_uri: None,
            bluesky_client_id: None,
            bluesky_client_secret: None,
            bluesky_profile_import_redirect_uri: None,
            xbox_client_id: None,
            xbox_client_secret: None,
            xbox_profile_import_redirect_uri: None,
            discovery_salt: "test-salt".to_string(),
            relay_base_url: "http://localhost:8080".to_string(),
            data_dir: None,
        })
    }

    #[test]
    fn test_batch_lookup_request_deserialization() {
        let json = r#"{
            "lookups": [
                {"platform": "discord", "id_hash": "abc123"},
                {"platform": "github", "id_hash": "def456"}
            ]
        }"#;

        let request: BatchLookupRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.lookups.len(), 2);
        assert_eq!(request.lookups[0].platform, Platform::Discord);
        assert_eq!(request.lookups[1].platform, Platform::GitHub);
    }

    #[test]
    fn test_update_settings_request_deserialization() {
        let json = r#"{
            "did": "did:key:z6MkTest",
            "discoverable": true
        }"#;

        let request: UpdateSettingsRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.did, "did:key:z6MkTest");
        assert!(request.discoverable);
    }
}
