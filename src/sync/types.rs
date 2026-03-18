//! Sync module data types.

use serde::{Deserialize, Serialize};

/// Metadata returned when fetching a sync blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncBlobMeta {
    pub did: String,
    pub size: usize,
    pub updated_at: i64,
    pub expires_at: i64,
}
