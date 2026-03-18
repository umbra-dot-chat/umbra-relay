//! Umbra Relay Server
//!
//! A lightweight WebSocket relay server that provides:
//!
//! 1. **Signaling relay**: Forward SDP offers/answers between peers for WebRTC
//!    connection establishment when direct exchange isn't possible.
//!
//! 2. **Single-scan friend adding**: Alice creates a session with her offer,
//!    gets a link/QR code. Bob scans it, the relay forwards the SDP exchange
//!    automatically. No second scan needed.
//!
//! 3. **Offline message queue**: If a recipient is offline, the relay stores
//!    encrypted message blobs and delivers them when the peer reconnects.
//!
//! **Privacy**: The relay never sees plaintext content. All E2E encryption
//! happens client-side — the relay only handles opaque encrypted blobs.

mod asset;
mod bridge;
mod debug;
mod discovery;
mod gif;
mod federation;
mod handler;
mod protocol;
mod state;
mod sync;

use std::time::Duration;

use axum::{
    extract::{Path, State, WebSocketUpgrade},
    http::{Method, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use clap::Parser;
use serde_json::json;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use bridge::BridgeStore;
use debug::DebugState;
use discovery::{DiscoveryConfig, DiscoveryStore};
use federation::Federation;
use state::{RelayConfig, RelayState};

// ── CLI Arguments ─────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "umbra-relay", version, about = "Umbra P2P relay server")]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value_t = 8080, env = "RELAY_PORT")]
    port: u16,

    /// Maximum offline messages per DID
    #[arg(long, default_value_t = 1000, env = "MAX_OFFLINE_MESSAGES")]
    max_offline_messages: usize,

    /// Offline message TTL in days
    #[arg(long, default_value_t = 7, env = "OFFLINE_TTL_DAYS")]
    offline_ttl_days: i64,

    /// Session TTL in seconds
    #[arg(long, default_value_t = 3600, env = "SESSION_TTL_SECS")]
    session_ttl_secs: i64,

    /// Cleanup interval in seconds
    #[arg(long, default_value_t = 300, env = "CLEANUP_INTERVAL_SECS")]
    cleanup_interval_secs: u64,

    /// Server region label (e.g. "US East", "EU West")
    #[arg(long, default_value = "US East", env = "RELAY_REGION")]
    region: String,

    /// Server location / city (e.g. "New York", "Frankfurt")
    #[arg(long, default_value = "New York", env = "RELAY_LOCATION")]
    location: String,

    /// This relay's public WebSocket URL (for federation identity).
    /// Required when peers are configured.
    #[arg(long, env = "RELAY_PUBLIC_URL")]
    public_url: Option<String>,

    /// Peer relay WebSocket URLs to form a mesh with (comma-separated).
    /// Example: wss://relay2.example.com/ws,wss://relay3.example.com/ws
    #[arg(long, env = "RELAY_PEERS", value_delimiter = ',')]
    peers: Vec<String>,

    /// Relay ID — unique identifier for this relay instance.
    /// Defaults to a random UUID if not set.
    #[arg(long, env = "RELAY_ID")]
    relay_id: Option<String>,

    /// Presence heartbeat interval in seconds (how often to sync full
    /// presence with peers).
    #[arg(long, default_value_t = 30, env = "PRESENCE_HEARTBEAT_SECS")]
    presence_heartbeat_secs: u64,
}

// ── Entry Point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // Install rustls crypto provider for federation TLS connections
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "umbra_relay=info,tower_http=info".into()),
        )
        .init();

    let args = Args::parse();

    let config = RelayConfig {
        port: args.port,
        max_offline_per_did: args.max_offline_messages,
        session_ttl_secs: args.session_ttl_secs,
        offline_ttl_secs: args.offline_ttl_days * 24 * 3600,
        region: args.region,
        location: args.location,
    };

    // ── Federation Setup ──────────────────────────────────────────────────

    let peer_urls: Vec<String> = args
        .peers
        .into_iter()
        .filter(|url| !url.trim().is_empty())
        .collect();

    let mut state = if !peer_urls.is_empty() {
        let relay_id = args
            .relay_id
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let public_url = args
            .public_url
            .unwrap_or_else(|| format!("ws://0.0.0.0:{}/ws", args.port));

        tracing::info!(
            relay_id = relay_id.as_str(),
            public_url = public_url.as_str(),
            peer_count = peer_urls.len(),
            "Federation enabled"
        );

        for peer in &peer_urls {
            tracing::info!(peer = peer.as_str(), "Configured peer relay");
        }

        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::unbounded_channel();

        let federation = Federation::new(
            relay_id,
            public_url,
            config.region.clone(),
            config.location.clone(),
            peer_urls,
            inbound_tx,
        );

        let state = RelayState::with_federation(config, federation.clone());

        // Start federation connections
        federation.start();

        // Spawn federation inbound message handler
        let fed_state = state.clone();
        tokio::spawn(async move {
            handler::handle_federation_inbound(fed_state, inbound_rx).await;
        });

        // Spawn periodic presence heartbeat
        let heartbeat_state = state.clone();
        let heartbeat_interval = args.presence_heartbeat_secs;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(heartbeat_interval));
            loop {
                interval.tick().await;
                let dids = heartbeat_state.local_online_dids();
                if let Some(ref fed) = heartbeat_state.federation {
                    fed.broadcast_full_presence(dids);
                }
            }
        });

        state
    } else {
        tracing::info!("Federation disabled (no peers configured)");
        RelayState::new(config)
    };

    // Spawn periodic cleanup task
    let cleanup_state = state.clone();
    let cleanup_interval = args.cleanup_interval_secs;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(cleanup_interval));
        loop {
            interval.tick().await;
            cleanup_state.cleanup_expired();
        }
    });

    // ── Discovery Service Setup ─────────────────────────────────────────────
    let discovery_config = DiscoveryConfig::from_env();
    let discovery_store = DiscoveryStore::new(discovery_config.clone());

    // Load persisted discovery data from disk
    let loaded = discovery_store.load_from_disk();
    if loaded > 0 {
        tracing::info!(entries = loaded, "Loaded discovery data from disk");
    }

    // Log discovery service status
    if discovery_config.discord_enabled() {
        tracing::info!("Discord OAuth enabled");
    }
    if discovery_config.github_enabled() {
        tracing::info!("GitHub OAuth enabled");
    }
    if discovery_config.steam_enabled() {
        tracing::info!("Steam OpenID enabled");
    }
    tracing::info!("Bluesky handle verification enabled (public API)");
    if discovery_config.xbox_enabled() {
        tracing::info!("Xbox OAuth enabled");
    }

    // Spawn discovery cleanup task
    let discovery_cleanup = discovery_store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            discovery_cleanup.cleanup_expired_states();
        }
    });

    // ── Bridge Config Store Setup ──────────────────────────────────────────
    let data_dir = std::env::var("DATA_DIR").ok();
    let bridge_store = BridgeStore::new(data_dir.as_deref());
    let bridge_loaded = bridge_store.load_from_disk();
    if bridge_loaded > 0 {
        tracing::info!(bridges = bridge_loaded, "Loaded bridge configs from disk");
    }

    // ── Debug Endpoint Setup ──────────────────────────────────────────────
    let debug_state = DebugState::new();
    if debug_state.is_enabled() {
        state.set_debug(debug_state.clone());
    }

    // ── Sync Blob Store Setup ──────────────────────────────────────────────
    let sync_store = match sync::blob_store::SyncBlobStore::new(data_dir.as_deref()) {
        Ok(store) => {
            tracing::info!("Sync blob store initialized");
            std::sync::Arc::new(store)
        }
        Err(e) => {
            tracing::error!("Failed to initialize sync blob store: {}", e);
            std::process::exit(1);
        }
    };

    // Spawn sync cleanup task
    let sync_cleanup = sync_store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600)); // hourly
        loop {
            interval.tick().await;
            let (blobs, challenges, tokens) = sync_cleanup.cleanup_expired();
            if blobs + challenges + tokens > 0 {
                tracing::info!(
                    blobs = blobs,
                    challenges = challenges,
                    tokens = tokens,
                    "Sync store cleanup completed"
                );
            }
        }
    });

    // Build sync router
    let sync_router = sync::router(sync_store);

    // ── Asset Store Setup ────────────────────────────────────────────────
    let asset_store = asset::store::AssetStore::new(data_dir.as_deref());
    let assets_loaded = asset_store.load_from_disk();
    if assets_loaded > 0 {
        tracing::info!(assets = assets_loaded, "Loaded community assets from disk");
    }

    // Build asset router
    let asset_router = Router::new()
        .route(
            "/api/community/:communityId/assets/upload",
            post(asset::api::upload_asset),
        )
        .route(
            "/api/community/:communityId/assets/:filename",
            get(asset::api::get_asset),
        )
        .with_state(asset_store);

    // Build bridge router
    let bridge_router = Router::new()
        .route("/api/bridge/register", post(bridge::api::register_bridge))
        .route("/api/bridge/list", get(bridge::api::list_bridges))
        .route("/api/bridge/:id", get(bridge::api::get_bridge))
        .route("/api/bridge/:id", delete(bridge::api::delete_bridge))
        .route("/api/bridge/:id/members", put(bridge::api::update_members))
        .route("/api/bridge/:id/enabled", put(bridge::api::set_enabled))
        .with_state(bridge_store);

    // Build discovery router with its own state
    let discovery_router = Router::new()
        // OAuth routes (account linking)
        .route("/auth/discord/start", get(discovery::oauth::discord::start))
        .route(
            "/auth/discord/callback",
            get(discovery::oauth::discord::callback),
        )
        .route("/auth/github/start", get(discovery::oauth::github::start))
        .route(
            "/auth/github/callback",
            get(discovery::oauth::github::callback),
        )
        .route("/auth/steam/start", get(discovery::oauth::steam::start))
        .route(
            "/auth/steam/callback",
            get(discovery::oauth::steam::callback),
        )
        .route("/auth/bluesky/start", get(discovery::oauth::bluesky::start))
        .route(
            "/auth/bluesky/callback",
            get(discovery::oauth::bluesky::callback),
        )
        .route("/auth/xbox/start", get(discovery::oauth::xbox::start))
        .route("/auth/xbox/callback", get(discovery::oauth::xbox::callback))
        // Profile import OAuth routes (returns JSON with profile data)
        .route(
            "/profile/import/discord/start",
            post(discovery::oauth::profile_import::start_discord),
        )
        .route(
            "/profile/import/discord/callback",
            get(discovery::oauth::profile_import::callback_discord),
        )
        .route(
            "/profile/import/github/start",
            post(discovery::oauth::profile_import::start_github),
        )
        .route(
            "/profile/import/github/callback",
            get(discovery::oauth::profile_import::callback_github),
        )
        .route(
            "/profile/import/steam/start",
            post(discovery::oauth::profile_import::start_steam),
        )
        .route(
            "/profile/import/steam/callback",
            get(discovery::oauth::profile_import::callback_steam),
        )
        .route(
            "/profile/import/bluesky/start",
            post(discovery::oauth::profile_import::start_bluesky),
        )
        .route(
            "/profile/import/bluesky/verify",
            get(discovery::oauth::profile_import::verify_bluesky_page),
        )
        .route(
            "/profile/import/bluesky/callback",
            get(discovery::oauth::profile_import::callback_bluesky),
        )
        .route(
            "/profile/import/xbox/start",
            post(discovery::oauth::profile_import::start_xbox),
        )
        .route(
            "/profile/import/xbox/callback",
            get(discovery::oauth::profile_import::callback_xbox),
        )
        // Profile import result polling (for mobile clients)
        .route(
            "/profile/import/result/:state",
            get(discovery::oauth::profile_import::get_profile_result),
        )
        // Community import OAuth routes (for importing Discord server structure)
        .route(
            "/community/import/discord/start",
            post(discovery::oauth::community_import::start_discord_community_import),
        )
        .route(
            "/community/import/discord/callback",
            get(discovery::oauth::community_import::callback_discord_community_import),
        )
        // Community import result polling (for Tauri/mobile clients)
        .route(
            "/community/import/discord/result/:state",
            get(discovery::oauth::community_import::get_community_import_result),
        )
        .route(
            "/community/import/discord/guilds",
            get(discovery::oauth::community_import::get_discord_guilds),
        )
        .route(
            "/community/import/discord/guild/:id/structure",
            get(discovery::oauth::community_import::get_discord_guild_structure),
        )
        .route(
            "/community/import/discord/bot-invite",
            get(discovery::oauth::community_import::get_bot_invite_url),
        )
        .route(
            "/community/import/discord/bot-status",
            get(discovery::oauth::community_import::check_bot_in_guild),
        )
        .route(
            "/community/import/discord/guild/:id/members",
            get(discovery::oauth::community_import::get_discord_guild_members),
        )
        .route(
            "/community/import/discord/channel/:id/pins",
            get(discovery::oauth::community_import::get_discord_channel_pins),
        )
        .route(
            "/community/import/discord/guild/:id/audit-log",
            get(discovery::oauth::community_import::get_discord_guild_audit_log),
        )
        // API routes
        .route("/discovery/status", get(discovery::api::get_status))
        .route("/discovery/settings", post(discovery::api::update_settings))
        .route("/discovery/lookup", post(discovery::api::batch_lookup))
        .route("/discovery/link", post(discovery::api::link_account))
        .route("/discovery/unlink", delete(discovery::api::unlink))
        .route("/discovery/stats", get(discovery::api::stats))
        .route("/discovery/hash", get(discovery::api::create_hash))
        .route("/discovery/search", get(discovery::api::search_by_username))
        // Username routes
        .route("/discovery/username", get(discovery::api::get_username))
        .route(
            "/discovery/username/register",
            post(discovery::api::register_username),
        )
        .route(
            "/discovery/username/lookup",
            get(discovery::api::lookup_username),
        )
        .route(
            "/discovery/username/search",
            get(discovery::api::search_usernames),
        )
        .route(
            "/discovery/username/change",
            post(discovery::api::change_username),
        )
        .route(
            "/discovery/username/release",
            delete(discovery::api::release_username),
        )
        .with_state((discovery_store, discovery_config));

    // GIF proxy (Tenor)
    let gif_config = gif::config::GifConfig::from_env();
    if gif_config.enabled() {
        tracing::info!("Tenor GIF proxy enabled");
    } else {
        tracing::warn!("Tenor GIF proxy disabled (set TENOR_API_KEY to enable)");
    }

    let gif_router = Router::new()
        .route("/api/gif/search", get(gif::api::search))
        .route("/api/gif/trending", get(gif::api::trending))
        .with_state(gif_config);

    // Build debug router
    let debug_router = Router::new()
        .route("/debug", get(debug::debug_ws_handler))
        .with_state(debug_state.clone());

    // Spawn periodic debug queue_size snapshot (every 5s)
    if debug_state.is_enabled() {
        let debug_periodic = debug_state.clone();
        let state_periodic = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                if debug_periodic.client_count().await == 0 {
                    continue; // Skip if no debug clients
                }
                let total = state_periodic.offline_queue_size();
                debug_periodic.emit(
                    "queue_size",
                    0,
                    0.0,
                    serde_json::json!({ "total_queued": total }),
                );
            }
        });
    }

    // Build main router
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers(Any);

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/federation", get(federation_ws_handler))
        .route("/health", get(health_handler))
        .route("/stats", get(stats_handler))
        .route("/info", get(info_handler))
        .route("/api/invite/:code", get(invite_resolve_handler))
        .with_state(state)
        .merge(discovery_router)
        .merge(bridge_router)
        .merge(asset_router)
        .merge(gif_router)
        .merge(sync_router)
        .merge(debug_router)
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    let addr = format!("0.0.0.0:{}", args.port);
    tracing::info!("Umbra relay server starting on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind address");

    axum::serve(listener, app).await.expect("Server error");
}

// ── Route Handlers ────────────────────────────────────────────────────────────

/// WebSocket upgrade handler for client connections.
async fn ws_handler(ws: WebSocketUpgrade, State(state): State<RelayState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handler::handle_websocket(socket, state))
}

/// WebSocket upgrade handler for federation (relay-to-relay) connections.
async fn federation_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<RelayState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handler::handle_federation_peer(socket, state))
}

/// Health check endpoint.
async fn health_handler() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "umbra-relay",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// Statistics endpoint.
async fn stats_handler(State(state): State<RelayState>) -> impl IntoResponse {
    let queue_details: Vec<serde_json::Value> = state
        .offline_queue_details()
        .into_iter()
        .map(|(did_suffix, count)| {
            json!({ "did_suffix": did_suffix, "count": count })
        })
        .collect();

    Json(json!({
        "online_clients": state.online_count(),
        "mesh_online_clients": state.mesh_online_count(),
        "offline_queue_size": state.offline_queue_size(),
        "offline_queue_details": queue_details,
        "active_sessions": state.sessions.len(),
        "published_invites": state.published_invites.len(),
        "connected_peers": state.connected_peers(),
        "federation_enabled": state.federation.is_some(),
    }))
}

/// Server info endpoint — returns metadata including region and location.
/// Also useful for client-side ping measurement (time the round-trip).
async fn info_handler(State(state): State<RelayState>) -> impl IntoResponse {
    Json(json!({
        "service": "umbra-relay",
        "version": env!("CARGO_PKG_VERSION"),
        "region": state.config.region,
        "location": state.config.location,
        "online_clients": state.online_count(),
        "mesh_online_clients": state.mesh_online_count(),
        "connected_peers": state.connected_peers(),
        "federation_enabled": state.federation.is_some(),
        "timestamp": chrono::Utc::now().timestamp_millis(),
    }))
}

/// HTTP invite resolution endpoint.
/// Allows clients to resolve an invite code without a WebSocket connection.
/// Returns invite preview metadata (community name, member count, etc.)
/// and the invite payload needed to bootstrap the joiner's local DB.
async fn invite_resolve_handler(
    Path(code): Path<String>,
    State(state): State<RelayState>,
) -> impl IntoResponse {
    match state.resolve_invite(&code) {
        Some(invite) => {
            let body = json!({
                "code": invite.code,
                "community_id": invite.community_id,
                "community_name": invite.community_name,
                "community_description": invite.community_description,
                "community_icon": invite.community_icon,
                "member_count": invite.member_count,
                "max_uses": invite.max_uses,
                "expires_at": invite.expires_at,
                "invite_payload": invite.invite_payload,
            });
            (StatusCode::OK, Json(body)).into_response()
        }
        None => {
            let body = json!({
                "error": "invite_not_found",
                "message": format!("Invite code '{}' not found or has expired", code),
            });
            (StatusCode::NOT_FOUND, Json(body)).into_response()
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_json_structure() {
        let json_val = json!({
            "status": "ok",
            "service": "umbra-relay",
            "version": env!("CARGO_PKG_VERSION"),
        });
        assert_eq!(json_val["status"], "ok");
        assert_eq!(json_val["service"], "umbra-relay");
    }

    #[test]
    fn test_default_config() {
        let config = RelayConfig::default();
        assert_eq!(config.port, 8080);
        assert_eq!(config.max_offline_per_did, 1000);
        assert_eq!(config.session_ttl_secs, 3600);
        assert_eq!(config.offline_ttl_secs, 7 * 24 * 3600);
        assert_eq!(config.region, "US East");
        assert_eq!(config.location, "New York");
    }

    #[tokio::test]
    async fn test_state_creation() {
        let state = RelayState::new(RelayConfig::default());
        assert_eq!(state.online_count(), 0);
        assert_eq!(state.offline_queue_size(), 0);
    }
}
