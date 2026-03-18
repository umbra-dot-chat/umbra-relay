//! Relay protocol message definitions.
//!
//! The relay speaks a simple JSON-over-WebSocket protocol.
//! All payloads are opaque to the relay — E2E encryption happens client-side.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Client → Relay ────────────────────────────────────────────────────────────

/// Messages sent from a client to the relay server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Register this WebSocket connection with a DID.
    /// Must be sent first after connecting.
    Register { did: String },

    /// Forward a signaling payload (SDP offer/answer) to another peer.
    Signal { to_did: String, payload: String },

    /// Send an encrypted message to another peer.
    /// If the peer is offline, the relay queues it for later delivery.
    Send { to_did: String, payload: String },

    /// Create a signaling session for single-scan friend adding.
    /// Returns a session_id that can be shared via QR code/link.
    CreateSession {
        /// The SDP offer to store in the session
        offer_payload: String,
    },

    /// Join an existing signaling session (the "scanner" side).
    /// The relay forwards the stored offer to the joiner and relays the answer back.
    JoinSession {
        session_id: String,
        /// The SDP answer to send back to the session creator
        answer_payload: String,
    },

    /// Fetch all queued offline messages.
    FetchOffline,

    /// Ping to keep connection alive.
    Ping,

    /// Publish an invite to the relay so it can be resolved by other clients.
    /// The community owner sends this when creating an invite.
    PublishInvite {
        /// The invite code
        code: String,
        /// Community metadata for the invite preview
        community_id: String,
        community_name: String,
        community_description: Option<String>,
        community_icon: Option<String>,
        member_count: u32,
        /// Invite constraints
        max_uses: Option<i32>,
        expires_at: Option<i64>,
        /// The full invite data blob (encrypted community structure) that
        /// the joiner needs to bootstrap their local DB
        invite_payload: String,
    },

    /// Revoke a previously published invite.
    RevokeInvite { code: String },

    /// Resolve an invite code — request the relay to return invite details.
    ResolveInvite { code: String },

    /// Create a call room for group calling.
    /// Returns a room_id that participants can join.
    CreateCallRoom { group_id: String },

    /// Join an existing call room.
    JoinCallRoom { room_id: String },

    /// Leave a call room.
    LeaveCallRoom { room_id: String },

    /// Forward a call signaling payload (SDP offer/answer/ICE) to a specific
    /// participant within a call room.
    CallSignal {
        room_id: String,
        to_did: String,
        payload: String,
    },

    /// Push a sync delta to all other sessions of the same DID.
    /// Used for real-time preference/friend/group sync between devices.
    SyncPush {
        section: String,
        version: u64,
        encrypted_data: String,
    },

    /// Request current sync section versions from the relay.
    SyncFetch {
        sections: Option<Vec<String>>,
    },
}

// ── Relay → Client ────────────────────────────────────────────────────────────

/// Messages sent from the relay server to a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Acknowledgement of successful registration.
    Registered { did: String },

    /// A signaling payload forwarded from another peer.
    Signal { from_did: String, payload: String },

    /// An encrypted message forwarded from another peer (or delivered from offline queue).
    Message {
        from_did: String,
        payload: String,
        timestamp: i64,
    },

    /// Response to CreateSession — contains the session ID to share.
    SessionCreated { session_id: String },

    /// Notification that someone joined your session and sent an answer.
    SessionJoined {
        session_id: String,
        from_did: String,
        answer_payload: String,
    },

    /// The offer payload for a session the client is joining.
    SessionOffer {
        session_id: String,
        from_did: String,
        offer_payload: String,
    },

    /// All queued offline messages, delivered in response to FetchOffline.
    /// Messages are delivered in chunks to avoid OOM on large queues.
    /// Old clients ignore the new metadata fields (serde(default)).
    OfflineMessages {
        messages: Vec<OfflineMessage>,
        /// Total number of messages across all chunks.
        #[serde(default)]
        total_messages: usize,
        /// Zero-based index of this chunk.
        #[serde(default)]
        chunk_index: usize,
        /// Total number of chunks being delivered.
        #[serde(default)]
        total_chunks: usize,
    },

    /// Pong response to keep connection alive.
    Pong,

    /// Error response.
    Error { message: String },

    /// Generic acknowledgement.
    Ack { id: String },

    /// Response to ResolveInvite — the invite was found.
    InviteResolved {
        code: String,
        community_id: String,
        community_name: String,
        community_description: Option<String>,
        community_icon: Option<String>,
        member_count: u32,
        max_uses: Option<i32>,
        expires_at: Option<i64>,
        /// The full invite data payload the joiner needs to bootstrap
        invite_payload: String,
    },

    /// Response to ResolveInvite — the invite was not found.
    InviteNotFound { code: String },

    /// A call room was successfully created.
    CallRoomCreated { room_id: String, group_id: String },

    /// A participant joined the call room.
    CallParticipantJoined { room_id: String, did: String },

    /// A participant left the call room.
    CallParticipantLeft { room_id: String, did: String },

    /// A call signaling payload forwarded from another participant.
    CallSignalForward {
        room_id: String,
        from_did: String,
        payload: String,
    },

    /// A sync delta pushed from another device using the same account.
    SyncUpdate {
        section: String,
        version: u64,
        encrypted_data: String,
    },

    /// Current sync section versions (response to SyncFetch).
    SyncState {
        versions: std::collections::HashMap<String, u64>,
    },
}

// ── Relay ↔ Relay (Federation) ────────────────────────────────────────────────

/// Messages exchanged between federated relay peers.
///
/// Relays form a mesh network: each relay connects to its configured peers
/// and they gossip presence information and forward messages for DIDs that
/// aren't locally connected.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PeerMessage {
    /// Announce this relay's identity to a peer on first connect.
    Hello {
        /// Unique relay ID (stable across restarts)
        relay_id: String,
        /// Public WebSocket URL for this relay
        relay_url: String,
        /// Human-readable region
        region: String,
        /// Human-readable location
        location: String,
    },

    /// Broadcast the full set of DIDs currently online at the sending relay.
    /// Sent periodically (heartbeat) and on every connect/disconnect.
    PresenceSync {
        relay_id: String,
        /// All DIDs currently online at the sending relay
        online_dids: Vec<String>,
    },

    /// A single DID just came online at the sending relay.
    PresenceOnline { relay_id: String, did: String },

    /// A single DID just went offline at the sending relay.
    PresenceOffline { relay_id: String, did: String },

    /// Forward a signaling payload through the mesh to a DID on another relay.
    ForwardSignal {
        from_did: String,
        to_did: String,
        payload: String,
    },

    /// Forward an encrypted message through the mesh.
    ForwardMessage {
        from_did: String,
        to_did: String,
        payload: String,
        timestamp: i64,
    },

    /// Forward a session-join through the mesh (single-scan friend adding).
    ForwardSessionJoin {
        session_id: String,
        joiner_did: String,
        answer_payload: String,
    },

    /// Replicate a signaling session so it can be joined from any relay.
    SessionSync {
        session_id: String,
        creator_did: String,
        offer_payload: String,
        created_at: i64,
    },

    /// Queue an offline message on the relay that owns the recipient DID.
    ForwardOffline {
        to_did: String,
        from_did: String,
        payload: String,
        timestamp: i64,
    },

    /// Replicate a published invite across the federation mesh.
    InviteSync {
        code: String,
        publisher_did: String,
        community_id: String,
        community_name: String,
        community_description: Option<String>,
        community_icon: Option<String>,
        member_count: u32,
        max_uses: Option<i32>,
        expires_at: Option<i64>,
        invite_payload: String,
        published_at: i64,
    },

    /// Revoke a published invite across the federation mesh.
    InviteRevoke { code: String },

    /// Forward an invite resolution request to peer relays.
    ForwardResolveInvite { code: String, requester_did: String },

    /// Forward an invite resolution response from a peer relay.
    ForwardInviteResolved {
        code: String,
        requester_did: String,
        community_id: String,
        community_name: String,
        community_description: Option<String>,
        community_icon: Option<String>,
        member_count: u32,
        max_uses: Option<i32>,
        expires_at: Option<i64>,
        invite_payload: String,
    },

    /// Ping to keep inter-relay connection alive.
    PeerPing,

    /// Pong response.
    PeerPong,
}

// ── Supporting Types ──────────────────────────────────────────────────────────

/// A message that was queued while the recipient was offline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineMessage {
    pub id: String,
    pub from_did: String,
    pub payload: String,
    pub timestamp: i64,
    pub queued_at: DateTime<Utc>,
}

/// A call room for group calling.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CallRoom {
    /// Unique room identifier
    pub room_id: String,
    /// The group ID this room belongs to
    pub group_id: String,
    /// DID of the room creator
    pub creator_did: String,
    /// DIDs of all currently joined participants
    pub participants: Vec<String>,
    /// Maximum number of participants allowed
    pub max_participants: usize,
    /// When the room was created
    pub created_at: DateTime<Utc>,
}

/// A published community invite stored at the relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedInvite {
    /// The invite code
    pub code: String,
    /// DID of the community owner who published this invite
    pub publisher_did: String,
    /// Community metadata
    pub community_id: String,
    pub community_name: String,
    pub community_description: Option<String>,
    pub community_icon: Option<String>,
    pub member_count: u32,
    /// Invite constraints
    pub max_uses: Option<i32>,
    pub use_count: i32,
    pub expires_at: Option<i64>,
    /// The full invite payload (community bootstrap data)
    pub invite_payload: String,
    /// When the invite was published to the relay
    pub published_at: DateTime<Utc>,
}

/// A signaling session for single-scan friend adding.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SignalingSession {
    /// Unique session identifier
    pub id: String,
    /// DID of the session creator (the one showing the QR code)
    pub creator_did: String,
    /// The SDP offer stored for the joiner
    pub offer_payload: String,
    /// When the session was created
    pub created_at: DateTime<Utc>,
    /// Whether this session has been consumed (joined)
    pub consumed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_message_register_serialization() {
        let msg = ClientMessage::Register {
            did: "did:key:z6MkTest".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"register\""));
        assert!(json.contains("did:key:z6MkTest"));

        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ClientMessage::Register { did } => assert_eq!(did, "did:key:z6MkTest"),
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_client_message_signal_serialization() {
        let msg = ClientMessage::Signal {
            to_did: "did:key:z6MkBob".to_string(),
            payload: "{\"sdp\":\"...\"}".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"signal\""));

        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ClientMessage::Signal { to_did, payload } => {
                assert_eq!(to_did, "did:key:z6MkBob");
                assert!(payload.contains("sdp"));
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_client_message_send_serialization() {
        let msg = ClientMessage::Send {
            to_did: "did:key:z6MkBob".to_string(),
            payload: "encrypted_blob_base64".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"send\""));

        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ClientMessage::Send { to_did, payload } => {
                assert_eq!(to_did, "did:key:z6MkBob");
                assert_eq!(payload, "encrypted_blob_base64");
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_client_message_create_session_serialization() {
        let msg = ClientMessage::CreateSession {
            offer_payload: "{\"sdp_type\":\"offer\"}".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"create_session\""));
    }

    #[test]
    fn test_client_message_join_session_serialization() {
        let msg = ClientMessage::JoinSession {
            session_id: "sess-123".to_string(),
            answer_payload: "{\"sdp_type\":\"answer\"}".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"join_session\""));
    }

    #[test]
    fn test_client_message_fetch_offline_serialization() {
        let msg = ClientMessage::FetchOffline;
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"fetch_offline\""));
    }

    #[test]
    fn test_client_message_ping_serialization() {
        let msg = ClientMessage::Ping;
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"ping\""));
    }

    #[test]
    fn test_server_message_registered_serialization() {
        let msg = ServerMessage::Registered {
            did: "did:key:z6MkAlice".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"registered\""));
    }

    #[test]
    fn test_server_message_signal_serialization() {
        let msg = ServerMessage::Signal {
            from_did: "did:key:z6MkAlice".to_string(),
            payload: "sdp_data".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"signal\""));
        assert!(json.contains("from_did"));
    }

    #[test]
    fn test_server_message_offline_messages_serialization() {
        let msg = ServerMessage::OfflineMessages {
            messages: vec![OfflineMessage {
                id: "msg-1".to_string(),
                from_did: "did:key:z6MkAlice".to_string(),
                payload: "encrypted".to_string(),
                timestamp: 1234567890,
                queued_at: Utc::now(),
            }],
            total_messages: 1,
            chunk_index: 0,
            total_chunks: 1,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"offline_messages\""));
        assert!(json.contains("msg-1"));
        assert!(json.contains("\"total_messages\":1"));
        assert!(json.contains("\"chunk_index\":0"));
        assert!(json.contains("\"total_chunks\":1"));
    }

    #[test]
    fn test_offline_messages_backward_compat_deserialization() {
        // Old clients send OfflineMessages without metadata fields.
        // Verify serde(default) allows parsing without them.
        let old_json = r#"{"type":"offline_messages","messages":[]}"#;
        let parsed: ServerMessage = serde_json::from_str(old_json).unwrap();
        match parsed {
            ServerMessage::OfflineMessages {
                messages,
                total_messages,
                chunk_index,
                total_chunks,
            } => {
                assert!(messages.is_empty());
                assert_eq!(total_messages, 0);
                assert_eq!(chunk_index, 0);
                assert_eq!(total_chunks, 0);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_server_message_session_created_serialization() {
        let msg = ServerMessage::SessionCreated {
            session_id: "sess-abc".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"session_created\""));
        assert!(json.contains("sess-abc"));
    }

    #[test]
    fn test_server_message_error_serialization() {
        let msg = ServerMessage::Error {
            message: "Something went wrong".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"error\""));
    }

    #[test]
    fn test_server_message_pong_serialization() {
        let msg = ServerMessage::Pong;
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"pong\""));
    }

    #[test]
    fn test_all_client_message_variants_round_trip() {
        let messages = vec![
            ClientMessage::Register {
                did: "did:key:z6MkTest".to_string(),
            },
            ClientMessage::Signal {
                to_did: "did:key:z6MkBob".to_string(),
                payload: "offer".to_string(),
            },
            ClientMessage::Send {
                to_did: "did:key:z6MkBob".to_string(),
                payload: "msg".to_string(),
            },
            ClientMessage::CreateSession {
                offer_payload: "offer".to_string(),
            },
            ClientMessage::JoinSession {
                session_id: "s1".to_string(),
                answer_payload: "answer".to_string(),
            },
            ClientMessage::FetchOffline,
            ClientMessage::Ping,
            ClientMessage::PublishInvite {
                code: "abc123".to_string(),
                community_id: "comm-1".to_string(),
                community_name: "Test Community".to_string(),
                community_description: Some("A test".to_string()),
                community_icon: None,
                member_count: 42,
                max_uses: Some(100),
                expires_at: None,
                invite_payload: "{}".to_string(),
            },
            ClientMessage::RevokeInvite {
                code: "abc123".to_string(),
            },
            ClientMessage::ResolveInvite {
                code: "abc123".to_string(),
            },
            ClientMessage::CreateCallRoom {
                group_id: "group-1".to_string(),
            },
            ClientMessage::JoinCallRoom {
                room_id: "room-1".to_string(),
            },
            ClientMessage::LeaveCallRoom {
                room_id: "room-1".to_string(),
            },
            ClientMessage::CallSignal {
                room_id: "room-1".to_string(),
                to_did: "did:key:z6MkBob".to_string(),
                payload: "sdp".to_string(),
            },
        ];

        for msg in messages {
            let json = serde_json::to_string(&msg).unwrap();
            let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    #[test]
    fn test_client_message_create_call_room_serialization() {
        let msg = ClientMessage::CreateCallRoom {
            group_id: "group-abc".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"create_call_room\""));
        assert!(json.contains("group-abc"));

        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ClientMessage::CreateCallRoom { group_id } => assert_eq!(group_id, "group-abc"),
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_client_message_call_signal_serialization() {
        let msg = ClientMessage::CallSignal {
            room_id: "room-1".to_string(),
            to_did: "did:key:z6MkBob".to_string(),
            payload: "{\"sdp\":\"offer\"}".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"call_signal\""));

        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ClientMessage::CallSignal {
                room_id,
                to_did,
                payload,
            } => {
                assert_eq!(room_id, "room-1");
                assert_eq!(to_did, "did:key:z6MkBob");
                assert!(payload.contains("sdp"));
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_server_message_call_room_created_serialization() {
        let msg = ServerMessage::CallRoomCreated {
            room_id: "room-123".to_string(),
            group_id: "group-abc".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"call_room_created\""));
        assert!(json.contains("room-123"));
        assert!(json.contains("group-abc"));
    }

    #[test]
    fn test_server_message_call_participant_joined_serialization() {
        let msg = ServerMessage::CallParticipantJoined {
            room_id: "room-1".to_string(),
            did: "did:key:z6MkAlice".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"call_participant_joined\""));
    }

    #[test]
    fn test_server_message_call_signal_forward_serialization() {
        let msg = ServerMessage::CallSignalForward {
            room_id: "room-1".to_string(),
            from_did: "did:key:z6MkAlice".to_string(),
            payload: "sdp_data".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"call_signal_forward\""));
        assert!(json.contains("from_did"));
    }

    // ── Peer (Federation) Message Tests ──────────────────────────────────

    #[test]
    fn test_peer_message_hello_serialization() {
        let msg = PeerMessage::Hello {
            relay_id: "relay-us-east-1".to_string(),
            relay_url: "wss://relay.example.com/ws".to_string(),
            region: "US East".to_string(),
            location: "New York".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"hello\""));
        assert!(json.contains("relay-us-east-1"));

        let parsed: PeerMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            PeerMessage::Hello { relay_id, .. } => assert_eq!(relay_id, "relay-us-east-1"),
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_peer_message_presence_sync_serialization() {
        let msg = PeerMessage::PresenceSync {
            relay_id: "relay-1".to_string(),
            online_dids: vec![
                "did:key:z6MkAlice".to_string(),
                "did:key:z6MkBob".to_string(),
            ],
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"presence_sync\""));

        let parsed: PeerMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            PeerMessage::PresenceSync { online_dids, .. } => assert_eq!(online_dids.len(), 2),
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_peer_message_forward_message_serialization() {
        let msg = PeerMessage::ForwardMessage {
            from_did: "did:key:z6MkAlice".to_string(),
            to_did: "did:key:z6MkBob".to_string(),
            payload: "encrypted_blob".to_string(),
            timestamp: 1234567890,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"forward_message\""));

        let parsed: PeerMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            PeerMessage::ForwardMessage {
                from_did, to_did, ..
            } => {
                assert_eq!(from_did, "did:key:z6MkAlice");
                assert_eq!(to_did, "did:key:z6MkBob");
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_all_peer_message_variants_round_trip() {
        let messages: Vec<PeerMessage> = vec![
            PeerMessage::Hello {
                relay_id: "r1".to_string(),
                relay_url: "wss://r1.example.com/ws".to_string(),
                region: "US".to_string(),
                location: "NYC".to_string(),
            },
            PeerMessage::PresenceSync {
                relay_id: "r1".to_string(),
                online_dids: vec!["did:key:z6Mk1".to_string()],
            },
            PeerMessage::PresenceOnline {
                relay_id: "r1".to_string(),
                did: "did:key:z6Mk1".to_string(),
            },
            PeerMessage::PresenceOffline {
                relay_id: "r1".to_string(),
                did: "did:key:z6Mk1".to_string(),
            },
            PeerMessage::ForwardSignal {
                from_did: "did:key:z6MkA".to_string(),
                to_did: "did:key:z6MkB".to_string(),
                payload: "sdp".to_string(),
            },
            PeerMessage::ForwardMessage {
                from_did: "did:key:z6MkA".to_string(),
                to_did: "did:key:z6MkB".to_string(),
                payload: "msg".to_string(),
                timestamp: 100,
            },
            PeerMessage::ForwardSessionJoin {
                session_id: "s1".to_string(),
                joiner_did: "did:key:z6MkB".to_string(),
                answer_payload: "answer".to_string(),
            },
            PeerMessage::SessionSync {
                session_id: "s1".to_string(),
                creator_did: "did:key:z6MkA".to_string(),
                offer_payload: "offer".to_string(),
                created_at: 100,
            },
            PeerMessage::ForwardOffline {
                to_did: "did:key:z6MkB".to_string(),
                from_did: "did:key:z6MkA".to_string(),
                payload: "queued".to_string(),
                timestamp: 100,
            },
            PeerMessage::InviteSync {
                code: "test123".to_string(),
                publisher_did: "did:key:z6MkA".to_string(),
                community_id: "comm-1".to_string(),
                community_name: "Test".to_string(),
                community_description: None,
                community_icon: None,
                member_count: 10,
                max_uses: None,
                expires_at: None,
                invite_payload: "{}".to_string(),
                published_at: 100,
            },
            PeerMessage::InviteRevoke {
                code: "test123".to_string(),
            },
            PeerMessage::ForwardResolveInvite {
                code: "test123".to_string(),
                requester_did: "did:key:z6MkB".to_string(),
            },
            PeerMessage::ForwardInviteResolved {
                code: "test123".to_string(),
                requester_did: "did:key:z6MkB".to_string(),
                community_id: "comm-1".to_string(),
                community_name: "Test".to_string(),
                community_description: None,
                community_icon: None,
                member_count: 10,
                max_uses: None,
                expires_at: None,
                invite_payload: "{}".to_string(),
            },
            PeerMessage::PeerPing,
            PeerMessage::PeerPong,
        ];

        for msg in messages {
            let json = serde_json::to_string(&msg).unwrap();
            let parsed: PeerMessage = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2, "Round-trip failed for: {}", json);
        }
    }
}
