//! Account sync module — encrypted blob storage with challenge-response auth.
//!
//! Provides REST endpoints for storing/retrieving encrypted account sync blobs
//! and WebSocket message types for real-time delta sync between devices.

pub mod auth;
pub mod blob_store;
pub mod handlers;
pub mod types;

use std::sync::Arc;

use axum::{
    routing::{delete, get, post, put},
    Router,
};

use blob_store::SyncBlobStore;
use handlers::SyncState;

/// Build the sync API router with its own state.
pub fn router(store: Arc<SyncBlobStore>) -> Router {
    Router::new()
        .route("/api/sync/:did/auth", post(handlers::create_challenge))
        .route("/api/sync/:did/verify", post(handlers::verify_with_nonce))
        .route("/api/sync/:did", put(handlers::put_blob))
        .route("/api/sync/:did", get(handlers::get_blob))
        .route("/api/sync/:did/meta", get(handlers::get_blob_meta))
        .route("/api/sync/:did", delete(handlers::delete_blob))
        .with_state(store as SyncState)
}
