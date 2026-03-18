//! Bridge configuration service for Discord ↔ Umbra message bridging.
//!
//! Manages bridge configs that map Discord guilds/channels to Umbra
//! communities/channels. The bridge bot reads these configs to know
//! which messages to proxy between platforms.
//!
//! ## Storage
//!
//! Configs are stored as JSON files in `{data_dir}/bridges/{communityId}.json`
//! and cached in memory for fast access. Uses the same atomic-write pattern
//! as the discovery store.

pub mod api;
pub mod store;

pub use store::BridgeStore;
