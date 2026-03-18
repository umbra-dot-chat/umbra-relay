//! Server state management.
//!
//! Tracks online clients, offline message queues, and signaling sessions.
//! All data structures are concurrent (DashMap) for lock-free access.

use std::sync::Arc;

use chrono::Utc;
use dashmap::DashMap;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::debug::DebugState;
use crate::federation::Federation;
use crate::protocol::{CallRoom, OfflineMessage, PublishedInvite, ServerMessage, SignalingSession};

/// Result of attempting to route a message to a DID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteResult {
    /// Delivered directly to a locally-connected client.
    DeliveredLocally,
    /// Forwarded to a federated peer relay (delivery NOT guaranteed).
    ForwardedToPeer,
    /// Recipient is unreachable — not local or on any federated peer.
    Unreachable,
}

/// Maximum number of offline messages to store per DID.
const DEFAULT_MAX_OFFLINE_PER_DID: usize = 1000;

/// Default session TTL in seconds (1 hour).
const DEFAULT_SESSION_TTL_SECS: i64 = 3600;

/// Default offline message TTL in seconds (7 days).
const DEFAULT_OFFLINE_TTL_SECS: i64 = 7 * 24 * 3600;

/// Default maximum participants per call room.
const DEFAULT_MAX_CALL_PARTICIPANTS: usize = 50;

/// Default call room TTL in seconds (4 hours).
const DEFAULT_CALL_ROOM_TTL_SECS: i64 = 4 * 3600;

/// Default invite TTL in seconds (7 days).
const DEFAULT_INVITE_TTL_SECS: i64 = 7 * 24 * 3600;

/// Server configuration.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RelayConfig {
    pub port: u16,
    pub max_offline_per_did: usize,
    pub session_ttl_secs: i64,
    pub offline_ttl_secs: i64,
    /// Human-readable region label (e.g. "US East", "EU West")
    pub region: String,
    /// City or location description (e.g. "New York", "Frankfurt")
    pub location: String,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            port: 8080,
            max_offline_per_did: DEFAULT_MAX_OFFLINE_PER_DID,
            session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
            offline_ttl_secs: DEFAULT_OFFLINE_TTL_SECS,
            region: "US East".to_string(),
            location: "New York".to_string(),
        }
    }
}

/// A connected client's sender channel.
pub type ClientSender = mpsc::UnboundedSender<ServerMessage>;

/// A unique identifier for a WebSocket session (one per connection).
pub type SessionId = String;

/// Shared server state.
#[derive(Clone)]
pub struct RelayState {
    /// DID → list of active sessions (session_id, sender channel).
    /// A single DID can have multiple concurrent sessions (multi-device).
    /// When a client connects and registers, their session is appended.
    /// When they disconnect, their specific session is removed.
    pub online_clients: Arc<DashMap<String, Vec<(SessionId, ClientSender)>>>,

    /// DID → queued offline messages.
    /// Messages sent to offline peers are stored here until they reconnect
    /// and call FetchOffline.
    pub offline_queue: Arc<DashMap<String, Vec<OfflineMessage>>>,

    /// Session ID → signaling session.
    /// Used for single-scan friend adding flow.
    pub sessions: Arc<DashMap<String, SignalingSession>>,

    /// Room ID → call room.
    /// Tracks active group call rooms and their participants.
    pub call_rooms: Arc<DashMap<String, CallRoom>>,

    /// Invite code → published invite.
    /// Community owners publish invites here so they can be resolved by
    /// anyone on the network, even if the owner is offline.
    pub published_invites: Arc<DashMap<String, PublishedInvite>>,

    /// Server configuration.
    pub config: RelayConfig,

    /// Federation manager for relay-to-relay mesh networking.
    /// None if federation is disabled (no peer URLs configured).
    pub federation: Option<Federation>,

    /// Debug event emitter. None if debug endpoint is not configured.
    pub debug: Option<DebugState>,
}

impl RelayState {
    /// Create a new relay state with the given configuration.
    pub fn new(config: RelayConfig) -> Self {
        Self {
            online_clients: Arc::new(DashMap::new()),
            offline_queue: Arc::new(DashMap::new()),
            sessions: Arc::new(DashMap::new()),
            call_rooms: Arc::new(DashMap::new()),
            published_invites: Arc::new(DashMap::new()),
            config,
            federation: None,
            debug: None,
        }
    }

    /// Create a new relay state with federation enabled.
    pub fn with_federation(config: RelayConfig, federation: Federation) -> Self {
        Self {
            online_clients: Arc::new(DashMap::new()),
            offline_queue: Arc::new(DashMap::new()),
            sessions: Arc::new(DashMap::new()),
            call_rooms: Arc::new(DashMap::new()),
            published_invites: Arc::new(DashMap::new()),
            config,
            federation: Some(federation),
            debug: None,
        }
    }

    /// Attach a debug state for event emission.
    pub fn set_debug(&mut self, debug_state: DebugState) {
        self.debug = Some(debug_state);
    }

    /// Emit a debug event if the debug endpoint is configured.
    pub fn emit_debug(&self, fn_name: &str, arg_bytes: usize, extra: serde_json::Value) {
        if let Some(ref debug) = self.debug {
            debug.emit(fn_name, arg_bytes, 0.0, extra);
        }
    }

    // ── Client Management ─────────────────────────────────────────────────

    /// Register a client session with their DID and sender channel.
    /// Returns the generated session ID.
    /// Broadcasts presence to federated peers if this is the first session for this DID.
    pub fn register_client(&self, did: &str, session_id: &str, sender: ClientSender) {
        let mut sessions = self.online_clients.entry(did.to_string()).or_default();
        let was_empty = sessions.is_empty();
        sessions.push((session_id.to_string(), sender));
        let session_count = sessions.len();
        drop(sessions);

        tracing::info!(did = did, session_id = session_id, sessions = session_count, "Client session registered");

        // Only broadcast presence when the first session connects
        if was_empty {
            if let Some(ref fed) = self.federation {
                fed.broadcast_presence_online(did);
            }
        }
    }

    /// Unregister a specific client session when it disconnects.
    /// Only broadcasts presence offline when the last session for a DID disconnects.
    pub fn unregister_client(&self, did: &str, session_id: &str) {
        let should_broadcast = if let Some(mut sessions) = self.online_clients.get_mut(did) {
            sessions.retain(|(sid, _)| sid != session_id);
            let is_empty = sessions.is_empty();
            drop(sessions);
            if is_empty {
                self.online_clients.remove(did);
                true
            } else {
                false
            }
        } else {
            false
        };

        tracing::info!(did = did, session_id = session_id, "Client session unregistered");

        if should_broadcast {
            if let Some(ref fed) = self.federation {
                fed.broadcast_presence_offline(did);
            }
        }
    }

    /// Check if a client is currently online (has at least one session).
    #[allow(dead_code)]
    pub fn is_online(&self, did: &str) -> bool {
        self.online_clients
            .get(did)
            .map(|sessions| !sessions.is_empty())
            .unwrap_or(false)
    }

    /// Send a message to ALL sessions of an online client.
    /// Returns true if sent to at least one session.
    pub fn send_to_client(&self, did: &str, message: ServerMessage) -> bool {
        if let Some(sessions) = self.online_clients.get(did) {
            let mut any_sent = false;
            for (_, sender) in sessions.iter() {
                if sender.send(message.clone()).is_ok() {
                    any_sent = true;
                }
            }
            any_sent
        } else {
            false
        }
    }

    /// Send a message to all sessions of a DID EXCEPT the specified session.
    /// Used for sync broadcasts (don't echo back to the sender).
    /// Returns true if sent to at least one other session.
    pub fn send_to_client_except(&self, did: &str, exclude_session: &str, message: ServerMessage) -> bool {
        if let Some(sessions) = self.online_clients.get(did) {
            let mut any_sent = false;
            for (sid, sender) in sessions.iter() {
                if sid != exclude_session {
                    if sender.send(message.clone()).is_ok() {
                        any_sent = true;
                    }
                }
            }
            any_sent
        } else {
            false
        }
    }

    /// Check if a DID is reachable — either locally connected or on a federated peer.
    #[allow(dead_code)]
    pub fn is_reachable(&self, did: &str) -> bool {
        if self.online_clients.contains_key(did) {
            return true;
        }
        if let Some(ref fed) = self.federation {
            return fed.find_peer_for_did(did).is_some();
        }
        false
    }

    /// Send a signaling payload to a DID, routing through federation if needed.
    /// Returns true if the signal was delivered or forwarded.
    pub fn route_signal(&self, from_did: &str, to_did: &str, payload: &str) -> bool {
        // Try local delivery first
        let local_msg = ServerMessage::Signal {
            from_did: from_did.to_string(),
            payload: payload.to_string(),
        };
        if self.send_to_client(to_did, local_msg) {
            return true;
        }

        // Try federation
        if let Some(ref fed) = self.federation {
            return fed.forward_signal(from_did, to_did, payload);
        }

        false
    }

    /// Send an encrypted message to a DID, routing through federation if needed.
    /// Returns a `RouteResult` indicating how (or whether) the message was routed.
    pub fn route_message(
        &self,
        from_did: &str,
        to_did: &str,
        payload: &str,
        timestamp: i64,
    ) -> RouteResult {
        // Try local delivery first
        let local_msg = ServerMessage::Message {
            from_did: from_did.to_string(),
            payload: payload.to_string(),
            timestamp,
        };
        if self.send_to_client(to_did, local_msg) {
            return RouteResult::DeliveredLocally;
        }

        // Try federation
        if let Some(ref fed) = self.federation {
            if fed.forward_message(from_did, to_did, payload, timestamp) {
                return RouteResult::ForwardedToPeer;
            }
        }

        RouteResult::Unreachable
    }

    /// Get the number of currently connected clients.
    pub fn online_count(&self) -> usize {
        self.online_clients.len()
    }

    /// Get the total number of reachable clients across the mesh.
    pub fn mesh_online_count(&self) -> usize {
        let local = self.online_clients.len();
        let remote = self
            .federation
            .as_ref()
            .map(|f| f.remote_did_count())
            .unwrap_or(0);
        local + remote
    }

    /// Get the number of connected federated peers.
    pub fn connected_peers(&self) -> usize {
        self.federation
            .as_ref()
            .map(|f| f.connected_peer_count())
            .unwrap_or(0)
    }

    /// Get the list of locally connected DIDs (for presence broadcasting).
    pub fn local_online_dids(&self) -> Vec<String> {
        self.online_clients
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    // ── Offline Message Queue ─────────────────────────────────────────────

    /// Queue a message for offline delivery.
    /// Returns false if the queue is full.
    pub fn queue_offline_message(
        &self,
        to_did: &str,
        from_did: &str,
        payload: &str,
        timestamp: i64,
    ) -> bool {
        let message = OfflineMessage {
            id: Uuid::new_v4().to_string(),
            from_did: from_did.to_string(),
            payload: payload.to_string(),
            timestamp,
            queued_at: Utc::now(),
        };

        let mut queue = self.offline_queue.entry(to_did.to_string()).or_default();

        if queue.len() >= self.config.max_offline_per_did {
            tracing::warn!(
                to_did = to_did,
                queue_size = queue.len(),
                "Offline queue full for DID, dropping oldest message"
            );
            // Remove oldest message to make room
            if !queue.is_empty() {
                queue.remove(0);
            }
        }

        queue.push(message);
        tracing::debug!(
            to_did = to_did,
            from_did = from_did,
            "Queued offline message"
        );
        true
    }

    /// Drain all offline messages for a DID.
    /// Returns the messages and removes them from the queue.
    pub fn drain_offline_messages(&self, did: &str) -> Vec<OfflineMessage> {
        if let Some((_, messages)) = self.offline_queue.remove(did) {
            let now = Utc::now().timestamp();
            // Filter out expired messages
            messages
                .into_iter()
                .filter(|m| now - m.queued_at.timestamp() < self.config.offline_ttl_secs)
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get the number of queued offline messages across all DIDs.
    pub fn offline_queue_size(&self) -> usize {
        self.offline_queue
            .iter()
            .map(|entry| entry.value().len())
            .sum()
    }

    /// Get the top DIDs by offline queue size (for stats/debugging).
    /// DID strings are truncated to the last 12 characters for privacy.
    /// Returns at most 20 entries, sorted by queue size descending.
    pub fn offline_queue_details(&self) -> Vec<(String, usize)> {
        let mut details: Vec<(String, usize)> = self
            .offline_queue
            .iter()
            .map(|entry| {
                let did = entry.key().clone();
                let suffix = if did.len() > 12 {
                    format!("...{}", &did[did.len() - 12..])
                } else {
                    did
                };
                (suffix, entry.value().len())
            })
            .collect();
        details.sort_by(|a, b| b.1.cmp(&a.1));
        details.truncate(20);
        details
    }

    // ── Signaling Sessions ────────────────────────────────────────────────

    /// Create a new signaling session for single-scan friend adding.
    /// Returns the session ID. Replicates the session to federated peers.
    pub fn create_session(&self, creator_did: &str, offer_payload: &str) -> String {
        let session_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let session = SignalingSession {
            id: session_id.clone(),
            creator_did: creator_did.to_string(),
            offer_payload: offer_payload.to_string(),
            created_at: now,
            consumed: false,
        };

        tracing::info!(
            session_id = session_id.as_str(),
            creator_did = creator_did,
            "Created signaling session"
        );
        self.sessions.insert(session_id.clone(), session);

        // Replicate to federated peers so the session can be joined from any relay
        if let Some(ref fed) = self.federation {
            fed.replicate_session(&session_id, creator_did, offer_payload, now.timestamp());
        }

        session_id
    }

    /// Import a signaling session replicated from a peer relay.
    pub fn import_session(
        &self,
        session_id: &str,
        creator_did: &str,
        offer_payload: &str,
        created_at: i64,
    ) {
        // Don't overwrite if we already have it
        if self.sessions.contains_key(session_id) {
            return;
        }

        let session = SignalingSession {
            id: session_id.to_string(),
            creator_did: creator_did.to_string(),
            offer_payload: offer_payload.to_string(),
            created_at: chrono::DateTime::from_timestamp(created_at, 0).unwrap_or_else(Utc::now),
            consumed: false,
        };

        tracing::debug!(
            session_id = session_id,
            creator_did = creator_did,
            "Imported federated session"
        );
        self.sessions.insert(session_id.to_string(), session);
    }

    /// Look up a signaling session by ID.
    /// Returns None if the session doesn't exist, is expired, or was already consumed.
    pub fn get_session(&self, session_id: &str) -> Option<SignalingSession> {
        if let Some(session) = self.sessions.get(session_id) {
            let now = Utc::now().timestamp();
            let age = now - session.created_at.timestamp();

            if age > self.config.session_ttl_secs {
                tracing::debug!(session_id = session_id, "Session expired");
                drop(session);
                self.sessions.remove(session_id);
                return None;
            }

            if session.consumed {
                tracing::debug!(session_id = session_id, "Session already consumed");
                return None;
            }

            Some(session.clone())
        } else {
            None
        }
    }

    /// Mark a session as consumed (used).
    pub fn consume_session(&self, session_id: &str) -> bool {
        if let Some(mut session) = self.sessions.get_mut(session_id) {
            session.consumed = true;
            true
        } else {
            false
        }
    }

    // ── Call Room Management ──────────────────────────────────────────────

    /// Create or join a call room for a given group_id (idempotent by group).
    /// Returns `(room_id, existing_participants_before_join)`.
    /// If a room already exists for this group_id, the caller is added as a
    /// participant (if not already present) and the pre-existing participant
    /// list is returned. For a brand-new room the vec is empty.
    pub fn create_call_room(&self, group_id: &str, creator_did: &str) -> (String, Vec<String>) {
        // Check if a room already exists for this group_id
        for mut entry in self.call_rooms.iter_mut() {
            if entry.group_id == group_id {
                let room_id = entry.room_id.clone();
                let existing: Vec<String> = entry.participants.clone();

                if !entry.participants.contains(&creator_did.to_string()) {
                    entry.participants.push(creator_did.to_string());
                    tracing::info!(
                        room_id = room_id.as_str(),
                        group_id = group_id,
                        joiner = creator_did,
                        "Joined existing call room via create (idempotent)"
                    );
                } else {
                    tracing::info!(
                        room_id = room_id.as_str(),
                        group_id = group_id,
                        did = creator_did,
                        "Already in call room, returning existing"
                    );
                }

                return (room_id, existing);
            }
        }

        // No existing room — create a new one
        let room_id = Uuid::new_v4().to_string();

        let room = CallRoom {
            room_id: room_id.clone(),
            group_id: group_id.to_string(),
            creator_did: creator_did.to_string(),
            participants: vec![creator_did.to_string()],
            max_participants: DEFAULT_MAX_CALL_PARTICIPANTS,
            created_at: Utc::now(),
        };

        tracing::info!(
            room_id = room_id.as_str(),
            group_id = group_id,
            creator = creator_did,
            "Created call room"
        );
        self.call_rooms.insert(room_id.clone(), room);
        (room_id, vec![])
    }

    /// Join an existing call room. Returns the list of existing participants
    /// (before joining) so the joiner can establish connections with them.
    /// Returns None if the room doesn't exist or is full.
    pub fn join_call_room(&self, room_id: &str, did: &str) -> Option<Vec<String>> {
        let mut room = self.call_rooms.get_mut(room_id)?;

        if room.participants.len() >= room.max_participants {
            tracing::warn!(room_id = room_id, "Call room full");
            return None;
        }

        // Don't add duplicate participants
        if room.participants.contains(&did.to_string()) {
            return Some(room.participants.clone());
        }

        let existing = room.participants.clone();
        room.participants.push(did.to_string());

        tracing::info!(
            room_id = room_id,
            did = did,
            participant_count = room.participants.len(),
            "Participant joined call room"
        );

        Some(existing)
    }

    /// Leave a call room. Returns the remaining participants.
    /// Removes the room if it becomes empty.
    pub fn leave_call_room(&self, room_id: &str, did: &str) -> Vec<String> {
        let remaining = if let Some(mut room) = self.call_rooms.get_mut(room_id) {
            room.participants.retain(|p| p != did);
            let remaining = room.participants.clone();
            drop(room);
            remaining
        } else {
            return Vec::new();
        };

        tracing::info!(
            room_id = room_id,
            did = did,
            remaining = remaining.len(),
            "Participant left call room"
        );

        // Remove empty rooms
        if remaining.is_empty() {
            self.call_rooms.remove(room_id);
            tracing::debug!(room_id = room_id, "Removed empty call room");
        }

        remaining
    }

    /// Get the participants in a call room.
    #[allow(dead_code)]
    pub fn get_call_room_participants(&self, room_id: &str) -> Option<Vec<String>> {
        self.call_rooms.get(room_id).map(|r| r.participants.clone())
    }

    /// Check if a DID is in a call room.
    pub fn is_in_call_room(&self, room_id: &str, did: &str) -> bool {
        self.call_rooms
            .get(room_id)
            .map(|r| r.participants.contains(&did.to_string()))
            .unwrap_or(false)
    }

    /// Remove a disconnected client from all call rooms they're in.
    /// Returns room_id → remaining participants for rooms they were in.
    pub fn remove_from_all_call_rooms(&self, did: &str) -> Vec<(String, Vec<String>)> {
        let mut affected = Vec::new();
        let room_ids: Vec<String> = self
            .call_rooms
            .iter()
            .filter(|r| r.participants.contains(&did.to_string()))
            .map(|r| r.room_id.clone())
            .collect();

        for room_id in room_ids {
            let remaining = self.leave_call_room(&room_id, did);
            affected.push((room_id, remaining));
        }

        affected
    }

    // ── Published Invites ──────────────────────────────────────────────

    /// Publish a community invite so it can be resolved by other clients.
    /// Replicates to federated peers.
    pub fn publish_invite(
        &self,
        code: &str,
        publisher_did: &str,
        community_id: &str,
        community_name: &str,
        community_description: Option<&str>,
        community_icon: Option<&str>,
        member_count: u32,
        max_uses: Option<i32>,
        expires_at: Option<i64>,
        invite_payload: &str,
    ) {
        let now = Utc::now();

        let invite = PublishedInvite {
            code: code.to_string(),
            publisher_did: publisher_did.to_string(),
            community_id: community_id.to_string(),
            community_name: community_name.to_string(),
            community_description: community_description.map(|s| s.to_string()),
            community_icon: community_icon.map(|s| s.to_string()),
            member_count,
            max_uses,
            use_count: 0,
            expires_at,
            invite_payload: invite_payload.to_string(),
            published_at: now,
        };

        tracing::info!(
            code = code,
            community = community_name,
            publisher = publisher_did,
            "Published community invite"
        );

        self.published_invites.insert(code.to_string(), invite);

        // Replicate to federated peers
        if let Some(ref fed) = self.federation {
            fed.broadcast_to_peers(crate::protocol::PeerMessage::InviteSync {
                code: code.to_string(),
                publisher_did: publisher_did.to_string(),
                community_id: community_id.to_string(),
                community_name: community_name.to_string(),
                community_description: community_description.map(|s| s.to_string()),
                community_icon: community_icon.map(|s| s.to_string()),
                member_count,
                max_uses,
                expires_at,
                invite_payload: invite_payload.to_string(),
                published_at: now.timestamp(),
            });
        }
    }

    /// Import a published invite from a federated peer.
    pub fn import_invite(&self, invite: PublishedInvite) {
        // Don't overwrite existing invites
        if self.published_invites.contains_key(&invite.code) {
            return;
        }

        tracing::debug!(
            code = invite.code.as_str(),
            community = invite.community_name.as_str(),
            "Imported federated invite"
        );

        self.published_invites.insert(invite.code.clone(), invite);
    }

    /// Resolve an invite code — look up published invite metadata.
    pub fn resolve_invite(&self, code: &str) -> Option<PublishedInvite> {
        if let Some(invite) = self.published_invites.get(code) {
            let now = Utc::now().timestamp();

            // Check expiration
            if let Some(expires_at) = invite.expires_at {
                if now * 1000 > expires_at {
                    // Expired in millis — remove it
                    drop(invite);
                    self.published_invites.remove(code);
                    return None;
                }
            }

            // Check max uses (0 means unlimited)
            if let Some(max_uses) = invite.max_uses {
                if max_uses > 0 && invite.use_count >= max_uses {
                    drop(invite);
                    self.published_invites.remove(code);
                    return None;
                }
            }

            Some(invite.clone())
        } else {
            None
        }
    }

    /// Revoke a published invite.
    pub fn revoke_invite(&self, code: &str) {
        if self.published_invites.remove(code).is_some() {
            tracing::info!(code = code, "Revoked published invite");

            // Propagate revocation to federation
            if let Some(ref fed) = self.federation {
                fed.broadcast_to_peers(crate::protocol::PeerMessage::InviteRevoke {
                    code: code.to_string(),
                });
            }
        }
    }

    /// Increment the use count for a published invite.
    pub fn increment_invite_use_count(&self, code: &str) {
        if let Some(mut invite) = self.published_invites.get_mut(code) {
            invite.use_count += 1;
        }
    }

    /// Remove expired sessions and offline messages.
    /// Called periodically by the cleanup task.
    pub fn cleanup_expired(&self) {
        let now = Utc::now().timestamp();

        // Clean expired sessions
        let expired_sessions: Vec<String> = self
            .sessions
            .iter()
            .filter(|entry| now - entry.created_at.timestamp() > self.config.session_ttl_secs)
            .map(|entry| entry.key().clone())
            .collect();

        for session_id in &expired_sessions {
            self.sessions.remove(session_id);
        }

        if !expired_sessions.is_empty() {
            tracing::debug!(
                count = expired_sessions.len(),
                "Cleaned up expired sessions"
            );
        }

        // Clean expired offline messages
        let mut cleaned_messages = 0usize;
        let mut empty_queues = Vec::new();

        for mut entry in self.offline_queue.iter_mut() {
            let before = entry.value().len();
            entry
                .value_mut()
                .retain(|m| now - m.queued_at.timestamp() < self.config.offline_ttl_secs);
            cleaned_messages += before - entry.value().len();

            if entry.value().is_empty() {
                empty_queues.push(entry.key().clone());
            }
        }

        for did in &empty_queues {
            self.offline_queue.remove(did);
        }

        if cleaned_messages > 0 {
            tracing::debug!(
                count = cleaned_messages,
                "Cleaned up expired offline messages"
            );
        }

        // Clean expired call rooms
        let expired_rooms: Vec<String> = self
            .call_rooms
            .iter()
            .filter(|entry| now - entry.created_at.timestamp() > DEFAULT_CALL_ROOM_TTL_SECS)
            .map(|entry| entry.room_id.clone())
            .collect();

        for room_id in &expired_rooms {
            self.call_rooms.remove(room_id);
        }

        if !expired_rooms.is_empty() {
            tracing::debug!(count = expired_rooms.len(), "Cleaned up expired call rooms");
        }

        // Clean expired published invites
        let expired_invites: Vec<String> = self
            .published_invites
            .iter()
            .filter(|entry| {
                // Check TTL (7 days since publish)
                if now - entry.published_at.timestamp() > DEFAULT_INVITE_TTL_SECS {
                    return true;
                }
                // Check invite-specific expiration (millis)
                if let Some(expires_at) = entry.expires_at {
                    if now * 1000 > expires_at {
                        return true;
                    }
                }
                // Check max uses
                if let Some(max_uses) = entry.max_uses {
                    if entry.use_count >= max_uses {
                        return true;
                    }
                }
                false
            })
            .map(|entry| entry.key().clone())
            .collect();

        for code in &expired_invites {
            self.published_invites.remove(code);
        }

        if !expired_invites.is_empty() {
            tracing::debug!(
                count = expired_invites.len(),
                "Cleaned up expired published invites"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> RelayConfig {
        RelayConfig {
            port: 8080,
            max_offline_per_did: 5,
            session_ttl_secs: 60,
            offline_ttl_secs: 300,
            region: "Test".to_string(),
            location: "Test City".to_string(),
        }
    }

    #[test]
    fn test_register_and_unregister_client() {
        let state = RelayState::new(test_config());
        let (tx, _rx) = mpsc::unbounded_channel();

        state.register_client("did:key:z6MkAlice", "session-1", tx);
        assert!(state.is_online("did:key:z6MkAlice"));
        assert_eq!(state.online_count(), 1);

        state.unregister_client("did:key:z6MkAlice", "session-1");
        assert!(!state.is_online("did:key:z6MkAlice"));
        assert_eq!(state.online_count(), 0);
    }

    #[test]
    fn test_multi_session_per_did() {
        let state = RelayState::new(test_config());
        let (tx1, mut rx1) = mpsc::unbounded_channel();
        let (tx2, mut rx2) = mpsc::unbounded_channel();

        state.register_client("did:key:z6MkAlice", "session-1", tx1);
        state.register_client("did:key:z6MkAlice", "session-2", tx2);
        assert!(state.is_online("did:key:z6MkAlice"));
        assert_eq!(state.online_count(), 1); // 1 DID, 2 sessions

        // send_to_client delivers to ALL sessions
        let sent = state.send_to_client("did:key:z6MkAlice", ServerMessage::Pong);
        assert!(sent);
        assert!(rx1.try_recv().is_ok());
        assert!(rx2.try_recv().is_ok());

        // send_to_client_except delivers only to other sessions
        let sent = state.send_to_client_except("did:key:z6MkAlice", "session-1", ServerMessage::Pong);
        assert!(sent);
        assert!(rx1.try_recv().is_err()); // session-1 excluded
        assert!(rx2.try_recv().is_ok());

        // Unregister one session — DID should still be online
        state.unregister_client("did:key:z6MkAlice", "session-1");
        assert!(state.is_online("did:key:z6MkAlice"));

        // Unregister last session — DID should be offline
        state.unregister_client("did:key:z6MkAlice", "session-2");
        assert!(!state.is_online("did:key:z6MkAlice"));
    }

    #[test]
    fn test_send_to_online_client() {
        let state = RelayState::new(test_config());
        let (tx, mut rx) = mpsc::unbounded_channel();

        state.register_client("did:key:z6MkAlice", "session-1", tx);

        let sent = state.send_to_client("did:key:z6MkAlice", ServerMessage::Pong);
        assert!(sent);

        let msg = rx.try_recv().unwrap();
        match msg {
            ServerMessage::Pong => {}
            _ => panic!("Expected Pong"),
        }
    }

    #[test]
    fn test_send_to_offline_client_returns_false() {
        let state = RelayState::new(test_config());
        let sent = state.send_to_client("did:key:z6MkNobody", ServerMessage::Pong);
        assert!(!sent);
    }

    #[test]
    fn test_queue_and_drain_offline_messages() {
        let state = RelayState::new(test_config());

        state.queue_offline_message("did:key:z6MkBob", "did:key:z6MkAlice", "hello", 1000);
        state.queue_offline_message("did:key:z6MkBob", "did:key:z6MkAlice", "world", 2000);

        assert_eq!(state.offline_queue_size(), 2);

        let messages = state.drain_offline_messages("did:key:z6MkBob");
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].payload, "hello");
        assert_eq!(messages[1].payload, "world");

        // Should be empty after drain
        let messages = state.drain_offline_messages("did:key:z6MkBob");
        assert!(messages.is_empty());
        assert_eq!(state.offline_queue_size(), 0);
    }

    #[test]
    fn test_offline_queue_limit() {
        let state = RelayState::new(test_config());

        // Queue 6 messages (limit is 5)
        for i in 0..6 {
            state.queue_offline_message(
                "did:key:z6MkBob",
                "did:key:z6MkAlice",
                &format!("msg-{}", i),
                i as i64,
            );
        }

        let messages = state.drain_offline_messages("did:key:z6MkBob");
        assert_eq!(messages.len(), 5);
        // Oldest should have been dropped
        assert_eq!(messages[0].payload, "msg-1");
        assert_eq!(messages[4].payload, "msg-5");
    }

    #[test]
    fn test_create_and_get_session() {
        let state = RelayState::new(test_config());

        let session_id = state.create_session("did:key:z6MkAlice", "{\"sdp\":\"offer\"}");
        assert!(!session_id.is_empty());

        let session = state.get_session(&session_id).unwrap();
        assert_eq!(session.creator_did, "did:key:z6MkAlice");
        assert_eq!(session.offer_payload, "{\"sdp\":\"offer\"}");
        assert!(!session.consumed);
    }

    #[test]
    fn test_consume_session() {
        let state = RelayState::new(test_config());

        let session_id = state.create_session("did:key:z6MkAlice", "offer");

        assert!(state.consume_session(&session_id));

        // Should not be retrievable after consumption
        assert!(state.get_session(&session_id).is_none());
    }

    #[test]
    fn test_nonexistent_session() {
        let state = RelayState::new(test_config());
        assert!(state.get_session("nonexistent").is_none());
    }

    #[test]
    fn test_cleanup_removes_expired_sessions() {
        let state = RelayState::new(RelayConfig {
            session_ttl_secs: -1, // Expire immediately
            ..test_config()
        });

        let session_id = state.create_session("did:key:z6MkAlice", "offer");
        assert!(state.sessions.contains_key(&session_id));

        state.cleanup_expired();
        assert!(!state.sessions.contains_key(&session_id));
    }

    #[test]
    fn test_drain_offline_with_no_messages() {
        let state = RelayState::new(test_config());
        let messages = state.drain_offline_messages("did:key:z6MkNobody");
        assert!(messages.is_empty());
    }

    // ── Call Room Tests ──────────────────────────────────────────────

    #[test]
    fn test_create_call_room() {
        let state = RelayState::new(test_config());
        let room_id = state.create_call_room("group-1", "did:key:z6MkAlice");
        assert!(!room_id.is_empty());

        let participants = state.get_call_room_participants(&room_id).unwrap();
        assert_eq!(participants.len(), 1);
        assert_eq!(participants[0], "did:key:z6MkAlice");
    }

    #[test]
    fn test_join_call_room() {
        let state = RelayState::new(test_config());
        let room_id = state.create_call_room("group-1", "did:key:z6MkAlice");

        let existing = state.join_call_room(&room_id, "did:key:z6MkBob").unwrap();
        assert_eq!(existing.len(), 1);
        assert_eq!(existing[0], "did:key:z6MkAlice");

        let participants = state.get_call_room_participants(&room_id).unwrap();
        assert_eq!(participants.len(), 2);
    }

    #[test]
    fn test_join_call_room_no_duplicates() {
        let state = RelayState::new(test_config());
        let room_id = state.create_call_room("group-1", "did:key:z6MkAlice");

        state.join_call_room(&room_id, "did:key:z6MkAlice");
        let participants = state.get_call_room_participants(&room_id).unwrap();
        assert_eq!(participants.len(), 1);
    }

    #[test]
    fn test_leave_call_room() {
        let state = RelayState::new(test_config());
        let room_id = state.create_call_room("group-1", "did:key:z6MkAlice");
        state.join_call_room(&room_id, "did:key:z6MkBob");

        let remaining = state.leave_call_room(&room_id, "did:key:z6MkAlice");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0], "did:key:z6MkBob");
    }

    #[test]
    fn test_leave_call_room_removes_empty() {
        let state = RelayState::new(test_config());
        let room_id = state.create_call_room("group-1", "did:key:z6MkAlice");

        state.leave_call_room(&room_id, "did:key:z6MkAlice");
        assert!(state.get_call_room_participants(&room_id).is_none());
    }

    #[test]
    fn test_is_in_call_room() {
        let state = RelayState::new(test_config());
        let room_id = state.create_call_room("group-1", "did:key:z6MkAlice");

        assert!(state.is_in_call_room(&room_id, "did:key:z6MkAlice"));
        assert!(!state.is_in_call_room(&room_id, "did:key:z6MkBob"));
    }

    #[test]
    fn test_remove_from_all_call_rooms() {
        let state = RelayState::new(test_config());
        let room1 = state.create_call_room("group-1", "did:key:z6MkAlice");
        let room2 = state.create_call_room("group-2", "did:key:z6MkAlice");
        state.join_call_room(&room1, "did:key:z6MkBob");

        let affected = state.remove_from_all_call_rooms("did:key:z6MkAlice");
        assert_eq!(affected.len(), 2);

        // Room 1 should still have Bob
        let p1 = state.get_call_room_participants(&room1).unwrap();
        assert_eq!(p1.len(), 1);
        assert_eq!(p1[0], "did:key:z6MkBob");

        // Room 2 should be removed (was empty after Alice left)
        assert!(state.get_call_room_participants(&room2).is_none());
    }

    #[test]
    fn test_join_nonexistent_room() {
        let state = RelayState::new(test_config());
        assert!(state
            .join_call_room("nonexistent", "did:key:z6MkAlice")
            .is_none());
    }
}
