//! Discovery service for Umbra.
//!
//! Allows users to link external platform accounts (Discord, GitHub, etc.)
//! for privacy-preserving friend discovery.
//!
//! ## Architecture
//!
//! The discovery service runs as part of the relay server and provides:
//!
//! - OAuth2 flows for verifying platform account ownership
//! - Linked account storage with opt-in discoverability
//! - Privacy-preserving batch lookups using hashed platform IDs
//!
//! ## Privacy Design
//!
//! 1. **Opt-in only**: Users must explicitly enable discoverability
//! 2. **Hashed lookups**: Clients hash platform IDs locally before sending
//! 3. **No friend list storage**: Server only does point lookups, never stores contact lists
//! 4. **Immediate unlinking**: Accounts removed from index immediately on unlink

pub mod api;
pub mod config;
pub mod oauth;
pub mod store;
pub mod types;

pub use config::DiscoveryConfig;
pub use store::DiscoveryStore;
pub use types::*;
