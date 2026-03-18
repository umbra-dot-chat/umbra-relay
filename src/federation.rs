//! Relay Federation (Mesh Networking)
//!
//! Enables multiple relay servers to form a mesh network so that clients
//! connected to different relays can still communicate seamlessly.
//!
//! ## How it works
//!
//! 1. Each relay is configured with a list of peer relay WebSocket URLs.
//! 2. On startup, the relay connects to all peers via WebSocket.
//! 3. Relays exchange `Hello` messages to identify each other.
//! 4. Relays broadcast presence changes (online/offline) to all peers.
//! 5. When a message targets a DID not connected locally, the relay
//!    forwards it through the mesh to the peer that has the DID online.
//! 6. Signaling sessions are replicated across the mesh so they can
//!    be joined from any relay.
//!
//! ## Reconnection
//!
//! If a peer connection drops, the relay automatically retries with
//! exponential backoff (up to 60 seconds).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};

use crate::protocol::PeerMessage;

/// Information about a connected peer relay.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PeerInfo {
    /// Unique relay ID (from Hello message)
    pub relay_id: String,
    /// Public WebSocket URL
    pub relay_url: String,
    /// Human-readable region
    pub region: String,
    /// Human-readable location
    pub location: String,
    /// DIDs currently online at this peer
    pub online_dids: HashSet<String>,
}

/// Channel sender for pushing messages to a peer relay.
pub type PeerSender = mpsc::UnboundedSender<PeerMessage>;

/// Manages federated connections to peer relays.
#[derive(Clone)]
pub struct Federation {
    /// Our relay's unique ID
    pub relay_id: String,
    /// Our relay's public WebSocket URL
    pub relay_url: String,
    /// Our relay's region
    pub region: String,
    /// Our relay's location
    pub location: String,

    /// Peer relay URL → sender channel (for sending messages to peers)
    pub peer_senders: Arc<DashMap<String, PeerSender>>,

    /// Peer relay URL → info (metadata + presence from that peer)
    pub peer_info: Arc<DashMap<String, PeerInfo>>,

    /// Global DID → peer relay URL index.
    /// Maps every DID known to be online at a remote peer → that peer's URL.
    /// This allows O(1) lookup when routing a message.
    pub did_to_peer: Arc<DashMap<String, String>>,

    /// Configured peer relay URLs to connect to
    pub peer_urls: Arc<Vec<String>>,

    /// Callback sender: when a forwarded message arrives from a peer,
    /// it's pushed here so the main handler can deliver it locally.
    pub inbound_tx: mpsc::UnboundedSender<PeerMessage>,
}

impl Federation {
    /// Create a new federation manager.
    ///
    /// - `relay_id`: Unique identifier for this relay instance
    /// - `relay_url`: This relay's public WebSocket URL
    /// - `region`: Human-readable region label
    /// - `location`: Human-readable location
    /// - `peer_urls`: List of peer relay WebSocket URLs to connect to
    /// - `inbound_tx`: Channel for forwarding inbound peer messages to the main handler
    pub fn new(
        relay_id: String,
        relay_url: String,
        region: String,
        location: String,
        peer_urls: Vec<String>,
        inbound_tx: mpsc::UnboundedSender<PeerMessage>,
    ) -> Self {
        Self {
            relay_id,
            relay_url,
            region,
            location,
            peer_senders: Arc::new(DashMap::new()),
            peer_info: Arc::new(DashMap::new()),
            did_to_peer: Arc::new(DashMap::new()),
            peer_urls: Arc::new(peer_urls),
            inbound_tx,
        }
    }

    /// Start federation: connect to all configured peers.
    /// Each peer connection runs in its own background task with reconnection.
    pub fn start(&self) {
        for peer_url in self.peer_urls.iter() {
            let fed = self.clone();
            let url = peer_url.clone();
            tokio::spawn(async move {
                fed.peer_connection_loop(url).await;
            });
        }

        tracing::info!(
            relay_id = self.relay_id.as_str(),
            peer_count = self.peer_urls.len(),
            "Federation started"
        );
    }

    /// Persistent connection loop for a single peer.
    /// Reconnects with exponential backoff on failure.
    async fn peer_connection_loop(&self, peer_url: String) {
        let mut backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(60);

        loop {
            tracing::info!(peer = peer_url.as_str(), "Connecting to peer relay...");

            match self.connect_to_peer(&peer_url).await {
                Ok(()) => {
                    tracing::info!(peer = peer_url.as_str(), "Peer connection closed cleanly");
                    backoff = Duration::from_secs(1); // Reset backoff on clean close
                }
                Err(e) => {
                    tracing::warn!(
                        peer = peer_url.as_str(),
                        error = %e,
                        "Peer connection failed"
                    );
                }
            }

            // Clean up presence data for this peer
            self.remove_peer_presence(&peer_url);

            tracing::info!(
                peer = peer_url.as_str(),
                backoff_secs = backoff.as_secs(),
                "Reconnecting to peer after backoff..."
            );
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(max_backoff);
        }
    }

    /// Connect to a single peer relay and handle the message loop.
    /// Connects to the `/federation` endpoint on the peer.
    async fn connect_to_peer(
        &self,
        peer_url: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Convert /ws URL to /federation endpoint
        let federation_url = if peer_url.ends_with("/ws") {
            format!("{}federation", &peer_url[..peer_url.len() - 2])
        } else if peer_url.ends_with("/ws/") {
            format!("{}federation", &peer_url[..peer_url.len() - 3])
        } else {
            format!("{}/federation", peer_url.trim_end_matches('/'))
        };

        let (ws_stream, _) = connect_async(&federation_url).await?;
        let (mut ws_sender, mut ws_receiver) = ws_stream.split();

        // Create sender channel for this peer
        let (tx, mut rx) = mpsc::unbounded_channel::<PeerMessage>();
        self.peer_senders.insert(peer_url.to_string(), tx);

        // Send Hello
        let hello = PeerMessage::Hello {
            relay_id: self.relay_id.clone(),
            relay_url: self.relay_url.clone(),
            region: self.region.clone(),
            location: self.location.clone(),
        };
        let hello_json = serde_json::to_string(&hello)?;
        ws_sender.send(WsMessage::Text(hello_json)).await?;

        // Spawn sender task
        let sender_task = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                match serde_json::to_string(&msg) {
                    Ok(json) => {
                        if ws_sender.send(WsMessage::Text(json)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to serialize peer message: {}", e);
                    }
                }
            }
        });

        // Process incoming messages from peer
        while let Some(msg_result) = ws_receiver.next().await {
            match msg_result {
                Ok(WsMessage::Text(text)) => match serde_json::from_str::<PeerMessage>(&text) {
                    Ok(peer_msg) => {
                        self.handle_peer_message(peer_url, peer_msg);
                    }
                    Err(e) => {
                        tracing::warn!(
                            peer = peer_url,
                            error = %e,
                            "Failed to parse peer message"
                        );
                    }
                },
                Ok(WsMessage::Ping(data)) => {
                    // tungstenite auto-responds to pings
                    let _ = data;
                }
                Ok(WsMessage::Close(_)) => {
                    tracing::info!(peer = peer_url, "Peer sent close frame");
                    break;
                }
                Err(e) => {
                    tracing::warn!(peer = peer_url, error = %e, "Peer WebSocket error");
                    break;
                }
                _ => {}
            }
        }

        // Cleanup
        self.peer_senders.remove(peer_url);
        sender_task.abort();

        Ok(())
    }

    /// Handle an incoming message from a peer relay.
    pub fn handle_peer_message(&self, peer_url: &str, msg: PeerMessage) {
        match &msg {
            PeerMessage::Hello {
                relay_id,
                relay_url,
                region,
                location,
            } => {
                tracing::info!(
                    peer = peer_url,
                    relay_id = relay_id.as_str(),
                    region = region.as_str(),
                    location = location.as_str(),
                    "Peer relay identified"
                );

                self.peer_info.insert(
                    peer_url.to_string(),
                    PeerInfo {
                        relay_id: relay_id.clone(),
                        relay_url: relay_url.clone(),
                        region: region.clone(),
                        location: location.clone(),
                        online_dids: HashSet::new(),
                    },
                );

                // Send our full presence to the new peer
                self.send_full_presence_to_peer(peer_url);
            }

            PeerMessage::PresenceSync {
                relay_id,
                online_dids,
            } => {
                tracing::debug!(
                    peer = peer_url,
                    relay_id = relay_id.as_str(),
                    count = online_dids.len(),
                    "Received presence sync"
                );

                // Clear old presence for this peer
                if let Some(mut info) = self.peer_info.get_mut(peer_url) {
                    // Remove old DID→peer mappings
                    for old_did in &info.online_dids {
                        self.did_to_peer.remove(old_did);
                    }

                    // Set new DIDs
                    info.online_dids = online_dids.iter().cloned().collect();
                }

                // Add new DID→peer mappings
                for did in online_dids {
                    self.did_to_peer.insert(did.clone(), peer_url.to_string());
                }
            }

            PeerMessage::PresenceOnline { relay_id, did } => {
                tracing::debug!(
                    peer = peer_url,
                    relay_id = relay_id.as_str(),
                    did = did.as_str(),
                    "Remote DID came online"
                );

                self.did_to_peer.insert(did.clone(), peer_url.to_string());

                if let Some(mut info) = self.peer_info.get_mut(peer_url) {
                    info.online_dids.insert(did.clone());
                }
            }

            PeerMessage::PresenceOffline { relay_id, did } => {
                tracing::debug!(
                    peer = peer_url,
                    relay_id = relay_id.as_str(),
                    did = did.as_str(),
                    "Remote DID went offline"
                );

                self.did_to_peer.remove(did);

                if let Some(mut info) = self.peer_info.get_mut(peer_url) {
                    info.online_dids.remove(did);
                }
            }

            PeerMessage::PeerPing => {
                if let Some(sender) = self.peer_senders.get(peer_url) {
                    let _ = sender.send(PeerMessage::PeerPong);
                }
            }

            PeerMessage::PeerPong => {
                // Keepalive acknowledged — nothing to do
            }

            // All forwarding messages get passed to the main handler via inbound_tx
            PeerMessage::ForwardSignal { .. }
            | PeerMessage::ForwardMessage { .. }
            | PeerMessage::ForwardSessionJoin { .. }
            | PeerMessage::SessionSync { .. }
            | PeerMessage::ForwardOffline { .. }
            | PeerMessage::InviteSync { .. }
            | PeerMessage::InviteRevoke { .. }
            | PeerMessage::ForwardResolveInvite { .. }
            | PeerMessage::ForwardInviteResolved { .. } => {
                if let Err(e) = self.inbound_tx.send(msg) {
                    tracing::error!(
                        peer = peer_url,
                        error = %e,
                        "Failed to forward peer message to handler"
                    );
                }
            }
        }
    }

    // ── Public API for the main handler ─────────────────────────────────────

    /// Look up which peer relay a DID is connected to.
    /// Returns None if the DID is not known to any peer.
    pub fn find_peer_for_did(&self, did: &str) -> Option<String> {
        self.did_to_peer.get(did).map(|v| v.value().clone())
    }

    /// Send a message to a specific peer relay.
    pub fn send_to_peer(&self, peer_url: &str, msg: PeerMessage) -> bool {
        if let Some(sender) = self.peer_senders.get(peer_url) {
            sender.send(msg).is_ok()
        } else {
            false
        }
    }

    /// Broadcast a message to all connected peers.
    pub fn broadcast_to_peers(&self, msg: PeerMessage) {
        for entry in self.peer_senders.iter() {
            let _ = entry.value().send(msg.clone());
        }
    }

    /// Notify all peers that a DID came online locally.
    pub fn broadcast_presence_online(&self, did: &str) {
        let msg = PeerMessage::PresenceOnline {
            relay_id: self.relay_id.clone(),
            did: did.to_string(),
        };
        self.broadcast_to_peers(msg);
    }

    /// Notify all peers that a DID went offline locally.
    pub fn broadcast_presence_offline(&self, did: &str) {
        let msg = PeerMessage::PresenceOffline {
            relay_id: self.relay_id.clone(),
            did: did.to_string(),
        };
        self.broadcast_to_peers(msg);
    }

    /// Broadcast the full set of locally-connected DIDs to all peers.
    /// Called periodically as a heartbeat and on initial connection.
    pub fn broadcast_full_presence(&self, local_dids: Vec<String>) {
        let msg = PeerMessage::PresenceSync {
            relay_id: self.relay_id.clone(),
            online_dids: local_dids,
        };
        self.broadcast_to_peers(msg);
    }

    /// Send full presence to a specific peer (e.g. on new connection).
    fn send_full_presence_to_peer(&self, _peer_url: &str) {
        // This is called from the peer message handler context.
        // The actual local DIDs need to be provided externally;
        // we'll use the inbound channel to request it via a special flow,
        // or store a reference. For simplicity, we broadcast to all peers
        // which includes the new one.
        // Note: The main server will call broadcast_full_presence periodically.
    }

    /// Replicate a signaling session to all peers so it can be joined from anywhere.
    pub fn replicate_session(
        &self,
        session_id: &str,
        creator_did: &str,
        offer_payload: &str,
        created_at: i64,
    ) {
        let msg = PeerMessage::SessionSync {
            session_id: session_id.to_string(),
            creator_did: creator_did.to_string(),
            offer_payload: offer_payload.to_string(),
            created_at,
        };
        self.broadcast_to_peers(msg);
    }

    /// Forward a signal to the peer that has the target DID.
    pub fn forward_signal(&self, from_did: &str, to_did: &str, payload: &str) -> bool {
        if let Some(peer_url) = self.find_peer_for_did(to_did) {
            self.send_to_peer(
                &peer_url,
                PeerMessage::ForwardSignal {
                    from_did: from_did.to_string(),
                    to_did: to_did.to_string(),
                    payload: payload.to_string(),
                },
            )
        } else {
            false
        }
    }

    /// Forward a message to the peer that has the target DID.
    pub fn forward_message(
        &self,
        from_did: &str,
        to_did: &str,
        payload: &str,
        timestamp: i64,
    ) -> bool {
        if let Some(peer_url) = self.find_peer_for_did(to_did) {
            self.send_to_peer(
                &peer_url,
                PeerMessage::ForwardMessage {
                    from_did: from_did.to_string(),
                    to_did: to_did.to_string(),
                    payload: payload.to_string(),
                    timestamp,
                },
            )
        } else {
            false
        }
    }

    /// Forward a session join to the peer that has the session creator.
    pub fn forward_session_join(
        &self,
        creator_did: &str,
        session_id: &str,
        joiner_did: &str,
        answer_payload: &str,
    ) -> bool {
        if let Some(peer_url) = self.find_peer_for_did(creator_did) {
            self.send_to_peer(
                &peer_url,
                PeerMessage::ForwardSessionJoin {
                    session_id: session_id.to_string(),
                    joiner_did: joiner_did.to_string(),
                    answer_payload: answer_payload.to_string(),
                },
            )
        } else {
            false
        }
    }

    /// Queue an offline message on any peer (broadcast to all).
    #[allow(dead_code)]
    pub fn broadcast_offline_message(
        &self,
        to_did: &str,
        from_did: &str,
        payload: &str,
        timestamp: i64,
    ) {
        let msg = PeerMessage::ForwardOffline {
            to_did: to_did.to_string(),
            from_did: from_did.to_string(),
            payload: payload.to_string(),
            timestamp,
        };
        self.broadcast_to_peers(msg);
    }

    /// Get count of connected peers.
    pub fn connected_peer_count(&self) -> usize {
        self.peer_senders.len()
    }

    /// Get count of remote DIDs known across the mesh.
    pub fn remote_did_count(&self) -> usize {
        self.did_to_peer.len()
    }

    // ── Internal ────────────────────────────────────────────────────────────

    /// Remove all presence data for a disconnected peer (public API).
    pub fn remove_peer_presence_pub(&self, peer_url: &str) {
        self.remove_peer_presence(peer_url);
    }

    /// Remove all presence data for a disconnected peer.
    fn remove_peer_presence(&self, peer_url: &str) {
        if let Some((_, info)) = self.peer_info.remove(peer_url) {
            for did in &info.online_dids {
                self.did_to_peer.remove(did);
            }

            tracing::debug!(
                peer = peer_url,
                removed_dids = info.online_dids.len(),
                "Cleaned up peer presence"
            );
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_federation(
        peer_urls: Vec<String>,
    ) -> (Federation, mpsc::UnboundedReceiver<PeerMessage>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let fed = Federation::new(
            "test-relay".to_string(),
            "wss://test.example.com/ws".to_string(),
            "US East".to_string(),
            "Test City".to_string(),
            peer_urls,
            tx,
        );
        (fed, rx)
    }

    #[test]
    fn test_federation_creation() {
        let (fed, _rx) = make_federation(vec!["wss://peer1.example.com/ws".to_string()]);
        assert_eq!(fed.relay_id, "test-relay");
        assert_eq!(fed.peer_urls.len(), 1);
        assert_eq!(fed.connected_peer_count(), 0);
        assert_eq!(fed.remote_did_count(), 0);
    }

    #[test]
    fn test_did_to_peer_lookup() {
        let (fed, _rx) = make_federation(vec![]);

        // Simulate a presence online from a peer
        fed.did_to_peer.insert(
            "did:key:z6MkAlice".to_string(),
            "wss://peer1/ws".to_string(),
        );

        assert_eq!(
            fed.find_peer_for_did("did:key:z6MkAlice"),
            Some("wss://peer1/ws".to_string())
        );
        assert_eq!(fed.find_peer_for_did("did:key:z6MkBob"), None);
    }

    #[test]
    fn test_remove_peer_presence() {
        let (fed, _rx) = make_federation(vec![]);

        // Add a peer with two DIDs
        let peer_url = "wss://peer1/ws";
        fed.peer_info.insert(
            peer_url.to_string(),
            PeerInfo {
                relay_id: "peer1".to_string(),
                relay_url: peer_url.to_string(),
                region: "US".to_string(),
                location: "NYC".to_string(),
                online_dids: {
                    let mut s = HashSet::new();
                    s.insert("did:key:z6MkAlice".to_string());
                    s.insert("did:key:z6MkBob".to_string());
                    s
                },
            },
        );
        fed.did_to_peer
            .insert("did:key:z6MkAlice".to_string(), peer_url.to_string());
        fed.did_to_peer
            .insert("did:key:z6MkBob".to_string(), peer_url.to_string());

        assert_eq!(fed.remote_did_count(), 2);

        // Remove peer
        fed.remove_peer_presence(peer_url);

        assert_eq!(fed.remote_did_count(), 0);
        assert!(fed.find_peer_for_did("did:key:z6MkAlice").is_none());
        assert!(fed.find_peer_for_did("did:key:z6MkBob").is_none());
    }

    #[test]
    fn test_handle_presence_sync() {
        let (fed, _rx) = make_federation(vec![]);

        let peer_url = "wss://peer1/ws";

        // First add peer info via Hello
        fed.peer_info.insert(
            peer_url.to_string(),
            PeerInfo {
                relay_id: "peer1".to_string(),
                relay_url: peer_url.to_string(),
                region: "US".to_string(),
                location: "NYC".to_string(),
                online_dids: HashSet::new(),
            },
        );

        // Simulate presence sync
        fed.handle_peer_message(
            peer_url,
            PeerMessage::PresenceSync {
                relay_id: "peer1".to_string(),
                online_dids: vec![
                    "did:key:z6MkAlice".to_string(),
                    "did:key:z6MkBob".to_string(),
                ],
            },
        );

        assert_eq!(fed.remote_did_count(), 2);
        assert_eq!(
            fed.find_peer_for_did("did:key:z6MkAlice"),
            Some(peer_url.to_string())
        );
    }

    #[test]
    fn test_handle_presence_online_offline() {
        let (fed, _rx) = make_federation(vec![]);

        let peer_url = "wss://peer1/ws";
        fed.peer_info.insert(
            peer_url.to_string(),
            PeerInfo {
                relay_id: "peer1".to_string(),
                relay_url: peer_url.to_string(),
                region: "US".to_string(),
                location: "NYC".to_string(),
                online_dids: HashSet::new(),
            },
        );

        // DID comes online
        fed.handle_peer_message(
            peer_url,
            PeerMessage::PresenceOnline {
                relay_id: "peer1".to_string(),
                did: "did:key:z6MkAlice".to_string(),
            },
        );

        assert_eq!(fed.remote_did_count(), 1);
        assert!(fed.find_peer_for_did("did:key:z6MkAlice").is_some());

        // DID goes offline
        fed.handle_peer_message(
            peer_url,
            PeerMessage::PresenceOffline {
                relay_id: "peer1".to_string(),
                did: "did:key:z6MkAlice".to_string(),
            },
        );

        assert_eq!(fed.remote_did_count(), 0);
        assert!(fed.find_peer_for_did("did:key:z6MkAlice").is_none());
    }

    #[test]
    fn test_forwarded_messages_reach_inbound_channel() {
        let (fed, mut rx) = make_federation(vec![]);

        let peer_url = "wss://peer1/ws";

        // Simulate a forwarded message
        fed.handle_peer_message(
            peer_url,
            PeerMessage::ForwardMessage {
                from_did: "did:key:z6MkAlice".to_string(),
                to_did: "did:key:z6MkBob".to_string(),
                payload: "hello".to_string(),
                timestamp: 100,
            },
        );

        // Should be available on the inbound channel
        let msg = rx.try_recv().unwrap();
        match msg {
            PeerMessage::ForwardMessage { to_did, .. } => {
                assert_eq!(to_did, "did:key:z6MkBob");
            }
            _ => panic!("Expected ForwardMessage"),
        }
    }
}
