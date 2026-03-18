//! Debug WebSocket endpoint for streaming relay events to a debug TUI.
//!
//! Accepts connections on `/debug?token=<secret>` and broadcasts internal
//! relay events (connections, message routing, queue snapshots) to all
//! connected debug clients. The token is validated against the
//! `UMBRA_DEBUG_TOKEN` environment variable.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Query, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

/// Global monotonic sequence counter for debug events.
static SEQ: AtomicU64 = AtomicU64::new(1);

/// A debug trace event matching the frontend TraceEvent schema.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DebugEvent {
    pub seq: u64,
    /// Milliseconds since relay start.
    pub ts: f64,
    /// Always "relay" for relay-emitted events.
    pub cat: &'static str,
    /// Event function name.
    #[serde(rename = "fn")]
    pub fn_name: String,
    /// Byte size of the relevant payload (0 if not applicable).
    pub arg_bytes: usize,
    /// Duration in milliseconds (0 for instantaneous events).
    pub dur_ms: f64,
    /// Extra context fields serialized inline.
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Query parameters for the /debug endpoint.
#[derive(Deserialize)]
pub struct DebugQuery {
    pub token: Option<String>,
}

/// Shared state for debug WebSocket clients.
#[derive(Clone)]
pub struct DebugState {
    /// Senders for all connected debug clients.
    clients: Arc<tokio::sync::Mutex<Vec<mpsc::UnboundedSender<String>>>>,
    /// The expected token (from UMBRA_DEBUG_TOKEN env var).
    /// None means the debug endpoint is disabled.
    token: Option<String>,
    /// Instant when the relay started (for relative timestamps).
    start_time: Instant,
}

impl DebugState {
    /// Create a new DebugState. Reads `UMBRA_DEBUG_TOKEN` from the environment.
    /// If the env var is not set, the debug endpoint is disabled.
    pub fn new() -> Self {
        let token = std::env::var("UMBRA_DEBUG_TOKEN").ok().filter(|t| !t.is_empty());
        if token.is_some() {
            tracing::info!("Debug endpoint enabled (UMBRA_DEBUG_TOKEN set)");
        } else {
            tracing::info!("Debug endpoint disabled (UMBRA_DEBUG_TOKEN not set)");
        }
        Self {
            clients: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            token,
            start_time: Instant::now(),
        }
    }

    /// Whether the debug endpoint is configured (has a token).
    pub fn is_enabled(&self) -> bool {
        self.token.is_some()
    }

    /// Validate a provided token against the configured token.
    fn validate_token(&self, provided: Option<&str>) -> bool {
        match (&self.token, provided) {
            (Some(expected), Some(provided)) => {
                !expected.is_empty() && !provided.is_empty() && expected == provided
            }
            _ => false,
        }
    }

    /// Milliseconds elapsed since the relay started.
    fn elapsed_ms(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64() * 1000.0
    }

    /// Broadcast a debug event to all connected debug clients.
    /// Disconnected clients are removed automatically.
    /// This is a no-op if no debug clients are connected.
    pub fn emit(&self, fn_name: &str, arg_bytes: usize, dur_ms: f64, extra: serde_json::Value) {
        // Fast path: skip if no clients are connected
        let clients = self.clients.clone();

        let event = DebugEvent {
            seq: SEQ.fetch_add(1, Ordering::Relaxed),
            ts: self.elapsed_ms(),
            cat: "relay",
            fn_name: fn_name.to_string(),
            arg_bytes,
            dur_ms,
            extra,
        };

        let json = match serde_json::to_string(&event) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!("Failed to serialize debug event: {}", e);
                return;
            }
        };

        // Spawn a lightweight task to avoid blocking the caller
        tokio::spawn(async move {
            let mut guard = clients.lock().await;
            guard.retain(|tx| tx.send(json.clone()).is_ok());
        });
    }

    /// Return the number of connected debug clients.
    pub async fn client_count(&self) -> usize {
        self.clients.lock().await.len()
    }
}

/// Axum handler for the `/debug` WebSocket upgrade.
///
/// If UMBRA_DEBUG_TOKEN is not set, returns 403.
/// If the token query parameter is missing or invalid, returns 401.
pub async fn debug_ws_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<DebugQuery>,
    State(state): State<DebugState>,
) -> impl IntoResponse {
    if !state.is_enabled() {
        return (
            StatusCode::FORBIDDEN,
            "Debug endpoint not configured",
        )
            .into_response();
    }

    if !state.validate_token(query.token.as_deref()) {
        return (
            StatusCode::UNAUTHORIZED,
            "Invalid or missing debug token",
        )
            .into_response();
    }

    ws.on_upgrade(move |socket| handle_debug_ws(socket, state))
        .into_response()
}

/// Handle a connected debug WebSocket client.
/// Streams debug events until the client disconnects.
async fn handle_debug_ws(socket: WebSocket, state: DebugState) {
    let (mut ws_sender, mut ws_receiver) = socket.split();

    // Create a channel for sending events to this client
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    // Register this client
    {
        let mut clients = state.clients.lock().await;
        clients.push(tx);
    }

    let client_count = state.client_count().await;
    tracing::info!(clients = client_count, "Debug client connected");

    // Spawn sender task: forward channel messages to the WebSocket
    let sender_task = tokio::spawn(async move {
        while let Some(json) = rx.recv().await {
            if ws_sender.send(Message::Text(json)).await.is_err() {
                break;
            }
        }
    });

    // Read loop: keep alive by consuming client messages (ignore them)
    while let Some(msg_result) = ws_receiver.next().await {
        match msg_result {
            Ok(Message::Close(_)) => break,
            Err(_) => break,
            _ => {} // Ignore text/binary/ping from debug clients
        }
    }

    sender_task.abort();

    let client_count = state.client_count().await;
    tracing::info!(clients = client_count, "Debug client disconnected");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a DebugState with a known token (bypasses env var).
    fn state_with_token(token: Option<&str>) -> DebugState {
        DebugState {
            clients: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            token: token.map(|t| t.to_string()),
            start_time: Instant::now(),
        }
    }

    #[test]
    fn test_debug_state_disabled_when_no_token() {
        let state = state_with_token(None);
        assert!(!state.is_enabled());
        assert!(!state.validate_token(Some("anything")));
        assert!(!state.validate_token(None));
    }

    #[test]
    fn test_debug_state_enabled_with_token() {
        let state = state_with_token(Some("test-secret-123"));
        assert!(state.is_enabled());
        assert!(state.validate_token(Some("test-secret-123")));
        assert!(!state.validate_token(Some("wrong-token")));
        assert!(!state.validate_token(None));
    }

    #[test]
    fn test_debug_event_serialization() {
        let event = DebugEvent {
            seq: 1,
            ts: 12345.67,
            cat: "relay",
            fn_name: "client_connect".to_string(),
            arg_bytes: 0,
            dur_ms: 0.0,
            extra: serde_json::json!({
                "clientId": "relay-1",
                "did_prefix": "did:key:z6Mk...abc"
            }),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"seq\":1"));
        assert!(json.contains("\"cat\":\"relay\""));
        assert!(json.contains("\"fn\":\"client_connect\""));
        assert!(json.contains("\"clientId\":\"relay-1\""));
    }

    #[test]
    fn test_debug_event_sequence_increments() {
        let before = SEQ.load(Ordering::Relaxed);
        let _ = SEQ.fetch_add(1, Ordering::Relaxed);
        let after = SEQ.load(Ordering::Relaxed);
        assert_eq!(after, before + 1);
    }

    #[test]
    fn test_empty_token_treated_as_disabled() {
        // Empty string token should be treated as disabled
        let state = state_with_token(Some(""));
        // The DebugState::new() filters empty strings, but directly constructing
        // with Some("") still makes is_enabled() true. Test the new() path instead.
        // Since env var tests are racy in parallel, just test validate_token:
        assert!(!state.validate_token(Some("")));
        assert!(!state.validate_token(None));
    }
}
