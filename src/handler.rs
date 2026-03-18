//! WebSocket connection handler.
//!
//! Manages individual WebSocket connections: parsing client messages,
//! routing them through the relay state, and sending responses.

use axum::extract::ws::{Message, WebSocket};
use chrono::Utc;
use futures::{SinkExt, StreamExt};
use tokio::sync::mpsc;

use uuid::Uuid;

use crate::protocol::{ClientMessage, OfflineMessage, PeerMessage, ServerMessage};
use crate::state::{RelayState, RouteResult};

/// Handle a single WebSocket connection.
///
/// This function runs for the lifetime of the connection:
/// 1. Waits for a `Register` message to associate the connection with a DID
/// 2. Spawns a sender task to forward outbound messages
/// 3. Processes incoming messages until the connection closes
pub async fn handle_websocket(socket: WebSocket, state: RelayState) {
    let (mut ws_sender, mut ws_receiver) = socket.split();

    // Create the outbound channel for this client
    let (tx, mut rx) = mpsc::unbounded_channel::<ServerMessage>();

    // ── Step 1: Wait for Registration ─────────────────────────────────────

    let client_did = loop {
        match ws_receiver.next().await {
            Some(Ok(Message::Text(text))) => {
                match serde_json::from_str::<ClientMessage>(&text) {
                    Ok(ClientMessage::Register { did }) => {
                        if did.is_empty() || !did.starts_with("did:") {
                            let err = ServerMessage::Error {
                                message: "Invalid DID format".to_string(),
                            };
                            let _ = ws_sender
                                .send(Message::Text(serde_json::to_string(&err).unwrap()))
                                .await;
                            continue;
                        }

                        // Send registration confirmation
                        let ack = ServerMessage::Registered { did: did.clone() };
                        if ws_sender
                            .send(Message::Text(serde_json::to_string(&ack).unwrap()))
                            .await
                            .is_err()
                        {
                            return; // Connection closed
                        }

                        break did;
                    }
                    Ok(ClientMessage::Ping) => {
                        let pong = ServerMessage::Pong;
                        let _ = ws_sender
                            .send(Message::Text(serde_json::to_string(&pong).unwrap()))
                            .await;
                    }
                    Ok(_) => {
                        let err = ServerMessage::Error {
                            message: "Must register before sending other messages".to_string(),
                        };
                        let _ = ws_sender
                            .send(Message::Text(serde_json::to_string(&err).unwrap()))
                            .await;
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse client message: {}", e);
                        let err = ServerMessage::Error {
                            message: format!("Invalid message format: {}", e),
                        };
                        let _ = ws_sender
                            .send(Message::Text(serde_json::to_string(&err).unwrap()))
                            .await;
                    }
                }
            }
            Some(Ok(Message::Ping(data))) => {
                let _ = ws_sender.send(Message::Pong(data)).await;
            }
            Some(Ok(Message::Close(_))) | None => {
                return; // Connection closed before registration
            }
            _ => continue,
        }
    };

    // ── Step 2: Register Client ───────────────────────────────────────────

    let session_id = Uuid::new_v4().to_string();
    state.register_client(&client_did, &session_id, tx);
    tracing::info!(did = client_did.as_str(), session_id = session_id.as_str(), "WebSocket registered");

    // Emit debug event for client connection
    let did_prefix = if client_did.len() > 20 {
        format!("{}...", &client_did[..20])
    } else {
        client_did.clone()
    };
    state.emit_debug("client_connect", 0, serde_json::json!({
        "did_prefix": did_prefix,
        "session_id": session_id,
    }));

    // ── Step 3: Spawn Sender Task ─────────────────────────────────────────

    let sender_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match serde_json::to_string(&msg) {
                Ok(json) => {
                    if ws_sender.send(Message::Text(json)).await.is_err() {
                        break; // Connection closed
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to serialize server message: {}", e);
                }
            }
        }
    });

    // ── Step 4: Process Messages ──────────────────────────────────────────

    while let Some(msg_result) = ws_receiver.next().await {
        match msg_result {
            Ok(Message::Text(text)) => match serde_json::from_str::<ClientMessage>(&text) {
                Ok(client_msg) => {
                    handle_client_message(&state, &client_did, &session_id, client_msg).await;
                }
                Err(e) => {
                    tracing::warn!(
                        did = client_did.as_str(),
                        error = %e,
                        "Failed to parse client message"
                    );
                    state.send_to_client(
                        &client_did,
                        ServerMessage::Error {
                            message: format!("Invalid message format: {}", e),
                        },
                    );
                }
            },
            Ok(Message::Ping(_data)) => {
                // Axum handles ping/pong at the protocol level,
                // but if we need to respond manually:
                state.send_to_client(&client_did, ServerMessage::Pong);
            }
            Ok(Message::Close(_)) => {
                tracing::info!(did = client_did.as_str(), "Client sent close frame");
                break;
            }
            Err(e) => {
                tracing::warn!(
                    did = client_did.as_str(),
                    error = %e,
                    "WebSocket error"
                );
                break;
            }
            _ => {} // Binary, Pong — ignore
        }
    }

    // ── Step 5: Cleanup ───────────────────────────────────────────────────

    // Remove from any call rooms and notify remaining participants
    let affected_rooms = state.remove_from_all_call_rooms(&client_did);
    for (room_id, remaining) in &affected_rooms {
        for participant_did in remaining {
            state.send_to_client(
                participant_did,
                ServerMessage::CallParticipantLeft {
                    room_id: room_id.clone(),
                    did: client_did.clone(),
                },
            );
        }
    }

    // Emit debug event for client disconnection
    state.emit_debug("client_disconnect", 0, serde_json::json!({
        "did_prefix": if client_did.len() > 20 {
            format!("{}...", &client_did[..20])
        } else {
            client_did.clone()
        },
        "session_id": session_id,
    }));

    state.unregister_client(&client_did, &session_id);
    sender_task.abort();
    tracing::info!(did = client_did.as_str(), session_id = session_id.as_str(), "WebSocket disconnected");
}

/// Handle a parsed client message.
async fn handle_client_message(state: &RelayState, from_did: &str, session_id: &str, msg: ClientMessage) {
    match msg {
        ClientMessage::Register { .. } => {
            // Already registered — ignore duplicate registrations
            state.send_to_client(
                from_did,
                ServerMessage::Error {
                    message: "Already registered".to_string(),
                },
            );
        }

        ClientMessage::Signal { to_did, payload } => {
            handle_signal(state, from_did, &to_did, &payload);
        }

        ClientMessage::Send { to_did, payload } => {
            handle_send(state, from_did, &to_did, &payload);
        }

        ClientMessage::CreateSession { offer_payload } => {
            handle_create_session(state, from_did, &offer_payload);
        }

        ClientMessage::JoinSession {
            session_id,
            answer_payload,
        } => {
            handle_join_session(state, from_did, &session_id, &answer_payload);
        }

        ClientMessage::FetchOffline => {
            handle_fetch_offline(state, from_did);
        }

        ClientMessage::Ping => {
            state.send_to_client(from_did, ServerMessage::Pong);
        }

        ClientMessage::PublishInvite {
            code,
            community_id,
            community_name,
            community_description,
            community_icon,
            member_count,
            max_uses,
            expires_at,
            invite_payload,
        } => {
            handle_publish_invite(
                state,
                from_did,
                &code,
                &community_id,
                &community_name,
                community_description.as_deref(),
                community_icon.as_deref(),
                member_count,
                max_uses,
                expires_at,
                &invite_payload,
            );
        }

        ClientMessage::RevokeInvite { code } => {
            handle_revoke_invite(state, from_did, &code);
        }

        ClientMessage::ResolveInvite { code } => {
            handle_resolve_invite(state, from_did, &code);
        }

        ClientMessage::CreateCallRoom { group_id } => {
            handle_create_call_room(state, from_did, &group_id);
        }

        ClientMessage::JoinCallRoom { room_id } => {
            handle_join_call_room(state, from_did, &room_id);
        }

        ClientMessage::LeaveCallRoom { room_id } => {
            handle_leave_call_room(state, from_did, &room_id);
        }

        ClientMessage::CallSignal {
            room_id,
            to_did,
            payload,
        } => {
            handle_call_signal(state, from_did, &room_id, &to_did, &payload);
        }

        ClientMessage::SyncPush {
            section,
            version,
            encrypted_data,
        } => {
            handle_sync_push(state, from_did, session_id, &section, version, &encrypted_data);
        }

        ClientMessage::SyncFetch { sections } => {
            handle_sync_fetch(state, from_did, sections.as_deref());
        }
    }
}

// ── Message Handlers ──────────────────────────────────────────────────────────

/// Forward a signaling payload (SDP offer/answer) to a peer.
/// Tries local delivery first, then federation, then offline queue.
fn handle_signal(state: &RelayState, from_did: &str, to_did: &str, payload: &str) {
    tracing::debug!(from = from_did, to = to_did, "Forwarding signal");

    // Try local + federation routing
    if state.route_signal(from_did, to_did, payload) {
        return;
    }

    // Peer is unreachable — queue for later delivery
    state.queue_offline_message(to_did, from_did, payload, Utc::now().timestamp());

    state.send_to_client(
        from_did,
        ServerMessage::Ack {
            id: format!("signal_queued_{}", to_did),
        },
    );

    tracing::debug!(
        to = to_did,
        "Signal target offline, queued for later delivery"
    );
}

/// Send an encrypted message to a peer (or queue it for offline delivery).
/// Tries local delivery first, then federation, then offline queue.
/// When federation forwards a message, we also queue locally as a safety net
/// — the recipient may not be reachable on the federated peer either, and
/// they will fetch offline messages from *this* relay when they reconnect.
fn handle_send(state: &RelayState, from_did: &str, to_did: &str, payload: &str) {
    let timestamp = Utc::now().timestamp();
    let payload_bytes = payload.len();

    // Try local + federation routing
    match state.route_message(from_did, to_did, payload, timestamp) {
        RouteResult::DeliveredLocally => {
            // Message delivered directly — no need to queue
            state.emit_debug("msg_route", payload_bytes, serde_json::json!({
                "from": from_did, "to": to_did, "route": "local"
            }));
        }
        RouteResult::ForwardedToPeer => {
            // Forwarded to a federated peer, but delivery is not guaranteed
            // (the recipient may go offline on the peer before it's delivered).
            // Queue locally as a safety net — the client will deduplicate.
            state.queue_offline_message(to_did, from_did, payload, timestamp);

            state.emit_debug("msg_route", payload_bytes, serde_json::json!({
                "from": from_did, "to": to_did, "route": "federation"
            }));
            state.emit_debug("msg_queue", payload_bytes, serde_json::json!({
                "to": to_did, "reason": "federation_safety_net"
            }));

            tracing::debug!(
                from = from_did,
                to = to_did,
                "Message forwarded to peer + queued locally as safety net"
            );
        }
        RouteResult::Unreachable => {
            // Peer is unreachable everywhere — queue for later delivery
            state.queue_offline_message(to_did, from_did, payload, timestamp);

            state.emit_debug("msg_queue", payload_bytes, serde_json::json!({
                "to": to_did, "reason": "recipient_offline"
            }));

            tracing::debug!(
                from = from_did,
                to = to_did,
                "Message target offline, queued for later delivery"
            );
        }
    }

    // Acknowledge receipt
    state.send_to_client(
        from_did,
        ServerMessage::Ack {
            id: format!("msg_{}_{}", to_did, timestamp),
        },
    );
}

/// Create a signaling session for single-scan friend adding.
fn handle_create_session(state: &RelayState, creator_did: &str, offer_payload: &str) {
    let session_id = state.create_session(creator_did, offer_payload);

    state.send_to_client(creator_did, ServerMessage::SessionCreated { session_id });
}

/// Join an existing signaling session.
/// Routes the answer to the creator through federation if they're on another relay.
fn handle_join_session(
    state: &RelayState,
    joiner_did: &str,
    session_id: &str,
    answer_payload: &str,
) {
    // Look up the session
    let session = match state.get_session(session_id) {
        Some(session) => session,
        None => {
            state.send_to_client(
                joiner_did,
                ServerMessage::Error {
                    message: format!("Session '{}' not found or expired", session_id),
                },
            );
            return;
        }
    };

    // Send the offer to the joiner
    state.send_to_client(
        joiner_did,
        ServerMessage::SessionOffer {
            session_id: session_id.to_string(),
            from_did: session.creator_did.clone(),
            offer_payload: session.offer_payload.clone(),
        },
    );

    // Try to deliver the answer to the session creator
    // First try local, then federation
    let answer_sent = state.send_to_client(
        &session.creator_did,
        ServerMessage::SessionJoined {
            session_id: session_id.to_string(),
            from_did: joiner_did.to_string(),
            answer_payload: answer_payload.to_string(),
        },
    );

    if !answer_sent {
        // Try federation
        let fed_sent = if let Some(ref fed) = state.federation {
            fed.forward_session_join(&session.creator_did, session_id, joiner_did, answer_payload)
        } else {
            false
        };

        if !fed_sent {
            // Creator unreachable — queue the answer
            state.queue_offline_message(
                &session.creator_did,
                joiner_did,
                answer_payload,
                Utc::now().timestamp(),
            );
        }
    }

    // Mark session as consumed
    state.consume_session(session_id);
}

/// Deliver all queued offline messages in chunks to avoid OOM on large queues.
/// Each chunk is sent as a separate WebSocket frame (~50 messages, ~50-100KB).
/// The client's offline_messages handler fires once per chunk and processes it
/// with existing batching logic.
fn handle_fetch_offline(state: &RelayState, did: &str) {
    let messages = state.drain_offline_messages(did);
    let total = messages.len();

    // Emit debug event for message dequeue
    if total > 0 {
        let total_bytes: usize = messages.iter().map(|m| m.payload.len()).sum();
        state.emit_debug("msg_dequeue", total_bytes, serde_json::json!({
            "did": did, "count": total
        }));
    }

    tracing::info!(
        did = did,
        count = total,
        "Delivering offline messages (chunked)"
    );

    if total == 0 {
        state.send_to_client(
            did,
            ServerMessage::OfflineMessages {
                messages: vec![],
                total_messages: 0,
                chunk_index: 0,
                total_chunks: 0,
            },
        );
        return;
    }

    let chunk_size = 50;
    let chunks: Vec<Vec<OfflineMessage>> = messages
        .chunks(chunk_size)
        .map(|c| c.to_vec())
        .collect();
    let total_chunks = chunks.len();

    for (i, chunk) in chunks.into_iter().enumerate() {
        tracing::debug!(
            did = did,
            chunk = i,
            total_chunks = total_chunks,
            chunk_msgs = chunk.len(),
            "Sending offline chunk"
        );
        state.send_to_client(
            did,
            ServerMessage::OfflineMessages {
                messages: chunk,
                total_messages: total,
                chunk_index: i,
                total_chunks,
            },
        );
    }
}

// ── Invite Handlers ──────────────────────────────────────────────────────────

/// Publish a community invite to the relay.
#[allow(clippy::too_many_arguments)]
fn handle_publish_invite(
    state: &RelayState,
    publisher_did: &str,
    code: &str,
    community_id: &str,
    community_name: &str,
    community_description: Option<&str>,
    community_icon: Option<&str>,
    member_count: u32,
    max_uses: Option<i32>,
    expires_at: Option<i64>,
    invite_payload: &str,
) {
    state.publish_invite(
        code,
        publisher_did,
        community_id,
        community_name,
        community_description,
        community_icon,
        member_count,
        max_uses,
        expires_at,
        invite_payload,
    );

    state.send_to_client(
        publisher_did,
        ServerMessage::Ack {
            id: format!("invite_published_{}", code),
        },
    );
}

/// Revoke a published invite.
fn handle_revoke_invite(state: &RelayState, publisher_did: &str, code: &str) {
    state.revoke_invite(code);

    state.send_to_client(
        publisher_did,
        ServerMessage::Ack {
            id: format!("invite_revoked_{}", code),
        },
    );
}

/// Resolve an invite code — look up published invite metadata.
/// Tries local store first, then asks federated peers.
fn handle_resolve_invite(state: &RelayState, requester_did: &str, code: &str) {
    // Try local resolution first
    if let Some(invite) = state.resolve_invite(code) {
        state.send_to_client(
            requester_did,
            ServerMessage::InviteResolved {
                code: invite.code,
                community_id: invite.community_id,
                community_name: invite.community_name,
                community_description: invite.community_description,
                community_icon: invite.community_icon,
                member_count: invite.member_count,
                max_uses: invite.max_uses,
                expires_at: invite.expires_at,
                invite_payload: invite.invite_payload,
            },
        );
        return;
    }

    // Try federation — ask all peers if they have this invite
    if let Some(ref fed) = state.federation {
        tracing::debug!(
            code = code,
            requester = requester_did,
            "Invite not found locally, forwarding to federation"
        );
        fed.broadcast_to_peers(PeerMessage::ForwardResolveInvite {
            code: code.to_string(),
            requester_did: requester_did.to_string(),
        });
        // The response will come back via ForwardInviteResolved
        // and be delivered by handle_federation_inbound
        return;
    }

    // Not found anywhere
    state.send_to_client(
        requester_did,
        ServerMessage::InviteNotFound {
            code: code.to_string(),
        },
    );
}

// ── Call Room Handlers ────────────────────────────────────────────────────────

/// Create (or join) a call room for group calling.
/// Idempotent by group_id: if a room already exists for the group, the creator
/// is added as a participant and existing members are notified.
fn handle_create_call_room(state: &RelayState, creator_did: &str, group_id: &str) {
    let (room_id, existing_participants) = state.create_call_room(group_id, creator_did);

    // If we joined an existing room, notify current participants about the new joiner
    // (mirrors the notification logic in handle_join_call_room).
    for participant_did in &existing_participants {
        if participant_did != creator_did {
            state.send_to_client(
                participant_did,
                ServerMessage::CallParticipantJoined {
                    room_id: room_id.to_string(),
                    did: creator_did.to_string(),
                },
            );
        }
    }

    state.send_to_client(
        creator_did,
        ServerMessage::CallRoomCreated {
            room_id,
            group_id: group_id.to_string(),
        },
    );
}

/// Join an existing call room and notify all participants.
fn handle_join_call_room(state: &RelayState, joiner_did: &str, room_id: &str) {
    match state.join_call_room(room_id, joiner_did) {
        Some(existing_participants) => {
            // Notify all existing participants that someone joined
            for participant_did in &existing_participants {
                state.send_to_client(
                    participant_did,
                    ServerMessage::CallParticipantJoined {
                        room_id: room_id.to_string(),
                        did: joiner_did.to_string(),
                    },
                );
            }

            // NOTE: Do NOT notify the joiner about existing participants here.
            // Existing participants create offers to the joiner (above notification).
            // If we also told the joiner about existing participants, both sides
            // would create offers simultaneously (WebRTC "glare"), breaking the
            // handshake. The joiner just waits for incoming offers.

            // Send ack to the joiner
            state.send_to_client(
                joiner_did,
                ServerMessage::Ack {
                    id: format!("call_room_joined_{}", room_id),
                },
            );
        }
        None => {
            state.send_to_client(
                joiner_did,
                ServerMessage::Error {
                    message: format!("Call room '{}' not found or full", room_id),
                },
            );
        }
    }
}

/// Leave a call room and notify remaining participants.
fn handle_leave_call_room(state: &RelayState, leaver_did: &str, room_id: &str) {
    let remaining = state.leave_call_room(room_id, leaver_did);

    // Notify remaining participants
    for participant_did in &remaining {
        state.send_to_client(
            participant_did,
            ServerMessage::CallParticipantLeft {
                room_id: room_id.to_string(),
                did: leaver_did.to_string(),
            },
        );
    }
}

/// Forward a call signaling payload to a specific participant within a room.
fn handle_call_signal(
    state: &RelayState,
    from_did: &str,
    room_id: &str,
    to_did: &str,
    payload: &str,
) {
    // Verify both sender and target are in the room
    if !state.is_in_call_room(room_id, from_did) {
        state.send_to_client(
            from_did,
            ServerMessage::Error {
                message: "You are not in this call room".to_string(),
            },
        );
        return;
    }

    if !state.is_in_call_room(room_id, to_did) {
        state.send_to_client(
            from_did,
            ServerMessage::Error {
                message: format!("Target '{}' is not in this call room", to_did),
            },
        );
        return;
    }

    state.send_to_client(
        to_did,
        ServerMessage::CallSignalForward {
            room_id: room_id.to_string(),
            from_did: from_did.to_string(),
            payload: payload.to_string(),
        },
    );
}

// ── Federation Peer Connection Handler ────────────────────────────────────────

/// Handle an inbound WebSocket connection from a peer relay.
///
/// This is the server-side handler for when another relay connects to us
/// via the `/federation` endpoint. It mirrors the outbound connection logic
/// in `federation.rs` — both sides exchange Hello, PresenceSync, and forward
/// messages bidirectionally.
pub async fn handle_federation_peer(socket: WebSocket, state: RelayState) {
    let (mut ws_sender, mut ws_receiver) = socket.split();

    let federation = match &state.federation {
        Some(fed) => fed.clone(),
        None => {
            tracing::warn!("Federation connection rejected: federation not enabled");
            let err = serde_json::to_string(&ServerMessage::Error {
                message: "Federation not enabled on this relay".to_string(),
            })
            .unwrap();
            let _ = ws_sender.send(Message::Text(err)).await;
            return;
        }
    };

    // Send our Hello
    let hello = PeerMessage::Hello {
        relay_id: federation.relay_id.clone(),
        relay_url: federation.relay_url.clone(),
        region: federation.region.clone(),
        location: federation.location.clone(),
    };
    if let Ok(json) = serde_json::to_string(&hello) {
        if ws_sender.send(Message::Text(json)).await.is_err() {
            return;
        }
    }

    // Send our current presence
    let presence = PeerMessage::PresenceSync {
        relay_id: federation.relay_id.clone(),
        online_dids: state.local_online_dids(),
    };
    if let Ok(json) = serde_json::to_string(&presence) {
        if ws_sender.send(Message::Text(json)).await.is_err() {
            return;
        }
    }

    // Create sender channel for this inbound peer
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<PeerMessage>();
    let mut peer_url: Option<String> = None;

    // Spawn sender task
    let sender_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Ok(json) = serde_json::to_string(&msg) {
                if ws_sender.send(Message::Text(json)).await.is_err() {
                    break;
                }
            }
        }
    });

    // Process incoming messages from peer
    while let Some(msg_result) = ws_receiver.next().await {
        match msg_result {
            Ok(Message::Text(text)) => {
                match serde_json::from_str::<PeerMessage>(&text) {
                    Ok(peer_msg) => {
                        // Capture peer URL from Hello
                        if let PeerMessage::Hello { ref relay_url, .. } = peer_msg {
                            peer_url = Some(relay_url.clone());
                            // Register this inbound peer's sender
                            federation
                                .peer_senders
                                .insert(relay_url.clone(), tx.clone());
                        }

                        let url = peer_url.as_deref().unwrap_or("unknown");
                        federation.handle_peer_message(url, peer_msg);
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to parse federation message");
                    }
                }
            }
            Ok(Message::Close(_)) => break,
            Err(e) => {
                tracing::warn!(error = %e, "Federation peer WebSocket error");
                break;
            }
            _ => {}
        }
    }

    // Cleanup
    if let Some(ref url) = peer_url {
        federation.peer_senders.remove(url);
        federation.remove_peer_presence_pub(url);
        tracing::info!(peer = url.as_str(), "Federation peer disconnected");
    }
    sender_task.abort();
}

// ── Federation Inbound Handler ───────────────────────────────────────────────

/// Handle a message forwarded from a federated peer relay.
///
/// This runs in a background task and processes messages that arrive from
/// peer relays via the federation inbound channel. It delivers them to
/// locally-connected clients.
pub async fn handle_federation_inbound(
    state: RelayState,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<PeerMessage>,
) {
    while let Some(msg) = rx.recv().await {
        match msg {
            PeerMessage::ForwardSignal {
                from_did,
                to_did,
                payload,
            } => {
                tracing::debug!(
                    from = from_did.as_str(),
                    to = to_did.as_str(),
                    "Delivering federated signal"
                );

                let server_msg = ServerMessage::Signal { from_did, payload };
                if !state.send_to_client(&to_did, server_msg) {
                    // Target went offline between routing lookup and delivery
                    tracing::debug!(to = to_did.as_str(), "Federated signal target offline");
                }
            }

            PeerMessage::ForwardMessage {
                from_did,
                to_did,
                payload,
                timestamp,
            } => {
                tracing::debug!(
                    from = from_did.as_str(),
                    to = to_did.as_str(),
                    "Delivering federated message"
                );

                let server_msg = ServerMessage::Message {
                    from_did: from_did.clone(),
                    payload: payload.clone(),
                    timestamp,
                };
                if !state.send_to_client(&to_did, server_msg) {
                    // Target went offline — queue locally
                    state.queue_offline_message(&to_did, &from_did, &payload, timestamp);
                }
            }

            PeerMessage::ForwardSessionJoin {
                session_id,
                joiner_did,
                answer_payload,
            } => {
                tracing::debug!(
                    session_id = session_id.as_str(),
                    joiner = joiner_did.as_str(),
                    "Delivering federated session join"
                );

                // Look up the session to find the creator
                if let Some(session) = state.get_session(&session_id) {
                    let answer_sent = state.send_to_client(
                        &session.creator_did,
                        ServerMessage::SessionJoined {
                            session_id: session_id.clone(),
                            from_did: joiner_did.clone(),
                            answer_payload: answer_payload.clone(),
                        },
                    );

                    if !answer_sent {
                        state.queue_offline_message(
                            &session.creator_did,
                            &joiner_did,
                            &answer_payload,
                            Utc::now().timestamp(),
                        );
                    }

                    state.consume_session(&session_id);
                }
            }

            PeerMessage::SessionSync {
                session_id,
                creator_did,
                offer_payload,
                created_at,
            } => {
                tracing::debug!(
                    session_id = session_id.as_str(),
                    creator = creator_did.as_str(),
                    "Importing federated session"
                );

                state.import_session(&session_id, &creator_did, &offer_payload, created_at);
            }

            PeerMessage::ForwardOffline {
                to_did,
                from_did,
                payload,
                timestamp,
            } => {
                tracing::debug!(
                    from = from_did.as_str(),
                    to = to_did.as_str(),
                    "Queuing federated offline message"
                );

                state.queue_offline_message(&to_did, &from_did, &payload, timestamp);
            }

            PeerMessage::InviteSync {
                code,
                publisher_did,
                community_id,
                community_name,
                community_description,
                community_icon,
                member_count,
                max_uses,
                expires_at,
                invite_payload,
                published_at,
            } => {
                tracing::debug!(
                    code = code.as_str(),
                    community = community_name.as_str(),
                    "Importing federated invite"
                );

                let invite = crate::protocol::PublishedInvite {
                    code,
                    publisher_did,
                    community_id,
                    community_name,
                    community_description,
                    community_icon,
                    member_count,
                    max_uses,
                    use_count: 0,
                    expires_at,
                    invite_payload,
                    published_at: chrono::DateTime::from_timestamp(published_at, 0)
                        .unwrap_or_else(Utc::now),
                };

                state.import_invite(invite);
            }

            PeerMessage::InviteRevoke { code } => {
                tracing::debug!(
                    code = code.as_str(),
                    "Processing federated invite revocation"
                );
                // Remove locally without re-broadcasting (avoid loops)
                state.published_invites.remove(&code);
            }

            PeerMessage::ForwardResolveInvite {
                code,
                requester_did,
            } => {
                tracing::debug!(
                    code = code.as_str(),
                    requester = requester_did.as_str(),
                    "Processing federated invite resolution request"
                );

                // Check if we have this invite locally
                if let Some(invite) = state.resolve_invite(&code) {
                    // Send the resolution back through federation
                    if let Some(ref fed) = state.federation {
                        fed.broadcast_to_peers(PeerMessage::ForwardInviteResolved {
                            code: invite.code,
                            requester_did,
                            community_id: invite.community_id,
                            community_name: invite.community_name,
                            community_description: invite.community_description,
                            community_icon: invite.community_icon,
                            member_count: invite.member_count,
                            max_uses: invite.max_uses,
                            expires_at: invite.expires_at,
                            invite_payload: invite.invite_payload,
                        });
                    }
                }
            }

            PeerMessage::ForwardInviteResolved {
                code,
                requester_did,
                community_id,
                community_name,
                community_description,
                community_icon,
                member_count,
                max_uses,
                expires_at,
                invite_payload,
            } => {
                tracing::debug!(
                    code = code.as_str(),
                    requester = requester_did.as_str(),
                    "Delivering federated invite resolution"
                );

                // Deliver the resolved invite to the local requester
                state.send_to_client(
                    &requester_did,
                    ServerMessage::InviteResolved {
                        code,
                        community_id,
                        community_name,
                        community_description,
                        community_icon,
                        member_count,
                        max_uses,
                        expires_at,
                        invite_payload,
                    },
                );
            }

            // Presence messages are handled by the federation module directly
            _ => {}
        }
    }
}

// ── Sync Handlers ────────────────────────────────────────────────────────────

/// Handle SyncPush — broadcast a sync delta to all OTHER sessions of the same DID.
/// This enables real-time preference/friend/group sync between devices using the
/// same account.
fn handle_sync_push(
    state: &RelayState,
    from_did: &str,
    sender_session_id: &str,
    section: &str,
    version: u64,
    encrypted_data: &str,
) {
    tracing::debug!(
        did = from_did,
        section = section,
        version = version,
        "Sync push received"
    );

    // Broadcast SyncUpdate to all connected sessions of the same DID,
    // EXCEPT the session that sent the push. This enables real-time sync
    // between multiple devices logged into the same account.
    let update_msg = ServerMessage::SyncUpdate {
        section: section.to_string(),
        version,
        encrypted_data: encrypted_data.to_string(),
    };
    let delivered = state.send_to_client_except(from_did, sender_session_id, update_msg);
    if delivered {
        tracing::debug!(did = from_did, section = section, "Sync delta broadcast to other sessions");
    }

    // If federation is enabled, broadcast to peers so other relays can deliver
    // to sessions of the same DID connected there.
    if let Some(ref fed) = state.federation {
        if let Some(_peer_url) = fed.find_peer_for_did(from_did) {
            let _ = fed.send_to_peer(
                &_peer_url,
                crate::protocol::PeerMessage::ForwardMessage {
                    from_did: from_did.to_string(),
                    to_did: from_did.to_string(),
                    payload: serde_json::to_string(&serde_json::json!({
                        "type": "sync_update",
                        "section": section,
                        "version": version,
                        "encrypted_data": encrypted_data,
                    }))
                    .unwrap_or_default(),
                    timestamp: chrono::Utc::now().timestamp(),
                },
            );
        }
    }

    state.send_to_client(
        from_did,
        ServerMessage::Ack {
            id: format!("sync_push_{}_{}", section, version),
        },
    );
}

/// Handle SyncFetch — return current sync state. For now, acknowledge the request.
/// Full sync state tracking will be added in Phase 4 when SyncContext handles it.
fn handle_sync_fetch(
    state: &RelayState,
    from_did: &str,
    _sections: Option<&[String]>,
) {
    tracing::debug!(did = from_did, "Sync fetch requested");

    // For now, return empty versions since the relay doesn't track section versions.
    // Clients use the REST GET /api/sync/:did endpoint for full blob retrieval.
    state.send_to_client(
        from_did,
        ServerMessage::SyncState {
            versions: std::collections::HashMap::new(),
        },
    );
}
