//! File-backed asset store for community emoji, stickers, and other media.
//!
//! Assets are stored on disk at `{DATA_DIR}/community_assets/{communityId}/{hash}.{ext}`.
//! Files are deduplicated by SHA-256 hash — uploading the same file twice returns the
//! same URL. Metadata is kept in memory via DashMap for fast lookups.

use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;

/// Metadata about a stored asset.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetMeta {
    pub hash: String,
    pub filename: String,
    pub content_type: String,
    pub size: u64,
    pub community_id: String,
    pub uploaded_by: String,
    pub uploaded_at: i64,
}

/// Rate-limit state per DID.
struct RateEntry {
    count: u32,
    window_start: i64,
}

/// File-backed asset store.
#[derive(Clone)]
pub struct AssetStore {
    /// Maps "{communityId}/{filename}" → AssetMeta
    meta: Arc<DashMap<String, AssetMeta>>,
    /// Base directory for asset storage (None = in-memory only, assets rejected)
    assets_dir: Option<PathBuf>,
    /// Upload rate limiter: DID → RateEntry
    rate_limits: Arc<DashMap<String, RateEntry>>,
}

/// Max file size for emoji (256 KB).
pub const MAX_EMOJI_SIZE: usize = 256 * 1024;

/// Max file size for stickers (2 MB).
pub const MAX_STICKER_SIZE: usize = 2 * 1024 * 1024;

/// Max file size for branding assets - icons, banners, splashes (10 MB).
pub const MAX_BRANDING_SIZE: usize = 10 * 1024 * 1024;

/// Max total storage per community (500 MB).
pub const MAX_COMMUNITY_STORAGE: u64 = 500 * 1024 * 1024;

/// Rate limit: max uploads per window per user.
const RATE_LIMIT_MAX: u32 = 10;

/// Rate limit window in seconds.
const RATE_LIMIT_WINDOW_SECS: i64 = 60;

/// Allowed MIME types for uploads.
const ALLOWED_TYPES: &[&str] = &[
    "image/png",
    "image/gif",
    "image/webp",
    "image/apng",
    "image/jpeg",
    "application/json", // Lottie JSON
];

impl AssetStore {
    /// Create a new asset store.
    pub fn new(data_dir: Option<&str>) -> Self {
        let assets_dir = data_dir.map(|d| PathBuf::from(d).join("community_assets"));
        Self {
            meta: Arc::new(DashMap::new()),
            assets_dir,
            rate_limits: Arc::new(DashMap::new()),
        }
    }

    /// Load existing assets from disk into the metadata cache.
    pub fn load_from_disk(&self) -> usize {
        let dir = match &self.assets_dir {
            Some(d) => d,
            None => return 0,
        };

        if !dir.exists() {
            return 0;
        }

        let mut count = 0;

        // Iterate community directories
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to read community_assets directory");
                return 0;
            }
        };

        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }

            let community_id = entry.file_name().to_string_lossy().to_string();

            // Read files within this community's asset directory
            let files = match std::fs::read_dir(entry.path()) {
                Ok(f) => f,
                Err(_) => continue,
            };

            for file_entry in files.flatten() {
                let path = file_entry.path();
                if !path.is_file() {
                    continue;
                }

                let filename = path.file_name().unwrap().to_string_lossy().to_string();
                let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

                // Infer content type from extension
                let content_type = match path.extension().and_then(|e| e.to_str()) {
                    Some("png") => "image/png",
                    Some("gif") => "image/gif",
                    Some("webp") => "image/webp",
                    Some("apng") => "image/apng",
                    Some("jpg") | Some("jpeg") => "image/jpeg",
                    Some("json") => "application/json",
                    _ => "application/octet-stream",
                };

                let key = format!("{}/{}", community_id, filename);
                let hash = filename
                    .rsplit_once('.')
                    .map(|(h, _)| h.to_string())
                    .unwrap_or_else(|| filename.clone());

                self.meta.insert(
                    key,
                    AssetMeta {
                        hash,
                        filename: filename.clone(),
                        content_type: content_type.to_string(),
                        size,
                        community_id: community_id.clone(),
                        uploaded_by: String::new(), // Unknown for existing files
                        uploaded_at: 0,
                    },
                );

                count += 1;
            }
        }

        count
    }

    /// Check if an upload is rate-limited.
    pub fn check_rate_limit(&self, did: &str) -> bool {
        let now = chrono::Utc::now().timestamp();
        let mut entry = self
            .rate_limits
            .entry(did.to_string())
            .or_insert(RateEntry {
                count: 0,
                window_start: now,
            });

        // Reset window if expired
        if now - entry.window_start >= RATE_LIMIT_WINDOW_SECS {
            entry.count = 0;
            entry.window_start = now;
        }

        if entry.count >= RATE_LIMIT_MAX {
            return false; // Rate limited
        }

        entry.count += 1;
        true
    }

    /// Validate content type.
    pub fn is_valid_content_type(content_type: &str) -> bool {
        ALLOWED_TYPES.contains(&content_type)
    }

    /// Get the max size for an asset type.
    pub fn max_size_for_type(asset_type: &str) -> usize {
        match asset_type {
            "emoji" => MAX_EMOJI_SIZE,
            "sticker" => MAX_STICKER_SIZE,
            "branding" | "icon" | "banner" | "splash" => MAX_BRANDING_SIZE,
            _ => MAX_EMOJI_SIZE, // Default to emoji size
        }
    }

    /// Calculate total storage used by a community.
    pub fn community_storage_used(&self, community_id: &str) -> u64 {
        let prefix = format!("{}/", community_id);
        self.meta
            .iter()
            .filter(|entry| entry.key().starts_with(&prefix))
            .map(|entry| entry.value().size)
            .sum()
    }

    /// Store an asset on disk and return its metadata.
    ///
    /// Returns `Ok(AssetMeta)` with the stored asset's metadata.
    /// If a file with the same hash already exists, returns the existing metadata (dedup).
    pub fn store_asset(
        &self,
        community_id: &str,
        data: &[u8],
        content_type: &str,
        uploaded_by: &str,
    ) -> Result<AssetMeta, String> {
        let dir = match &self.assets_dir {
            Some(d) => d,
            None => return Err("No data directory configured".to_string()),
        };

        // Compute SHA-256 hash
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hex::encode(hasher.finalize());

        // Determine file extension from content type
        let ext = match content_type {
            "image/png" => "png",
            "image/gif" => "gif",
            "image/webp" => "webp",
            "image/apng" => "apng",
            "image/jpeg" => "jpg",
            "application/json" => "json",
            _ => "bin",
        };

        let filename = format!("{}.{}", hash, ext);
        let key = format!("{}/{}", community_id, filename);

        // Check if already exists (dedup)
        if let Some(existing) = self.meta.get(&key) {
            return Ok(existing.value().clone());
        }

        // Ensure community directory exists
        let community_dir = dir.join(community_id);
        if let Err(e) = std::fs::create_dir_all(&community_dir) {
            tracing::error!(error = %e, community_id, "Failed to create asset directory");
            return Err("Failed to create storage directory".to_string());
        }

        // Write file (atomic: write to .tmp, then rename)
        let file_path = community_dir.join(&filename);
        let tmp_path = file_path.with_extension(format!("{}.tmp", ext));

        if let Err(e) = std::fs::write(&tmp_path, data) {
            tracing::error!(error = %e, path = %tmp_path.display(), "Failed to write asset file");
            return Err("Failed to write asset file".to_string());
        }

        if let Err(e) = std::fs::rename(&tmp_path, &file_path) {
            tracing::error!(error = %e, "Failed to rename temp asset file");
            let _ = std::fs::remove_file(&tmp_path);
            return Err("Failed to finalize asset file".to_string());
        }

        let now = chrono::Utc::now().timestamp_millis();
        let meta = AssetMeta {
            hash: hash.clone(),
            filename: filename.clone(),
            content_type: content_type.to_string(),
            size: data.len() as u64,
            community_id: community_id.to_string(),
            uploaded_by: uploaded_by.to_string(),
            uploaded_at: now,
        };

        self.meta.insert(key, meta.clone());

        tracing::info!(
            community_id,
            hash = %hash,
            size = data.len(),
            content_type,
            "Asset stored"
        );

        Ok(meta)
    }

    /// Read an asset file from disk.
    pub fn get_asset(&self, community_id: &str, filename: &str) -> Option<(Vec<u8>, String)> {
        let dir = match &self.assets_dir {
            Some(d) => d,
            None => return None,
        };

        let key = format!("{}/{}", community_id, filename);
        let meta = self.meta.get(&key)?;
        let content_type = meta.content_type.clone();

        let file_path = dir.join(community_id).join(filename);
        let data = std::fs::read(&file_path).ok()?;

        Some((data, content_type))
    }

    /// Delete an asset from disk and metadata.
    pub fn delete_asset(&self, community_id: &str, filename: &str) -> bool {
        let key = format!("{}/{}", community_id, filename);
        let removed = self.meta.remove(&key).is_some();

        if removed {
            if let Some(dir) = &self.assets_dir {
                let file_path = dir.join(community_id).join(filename);
                let _ = std::fs::remove_file(file_path);
            }
        }

        removed
    }
}
