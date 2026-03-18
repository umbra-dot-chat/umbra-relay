//! File-based bridge config store.
//!
//! Each bridge config is stored as a JSON file in `{data_dir}/bridges/{communityId}.json`.
//! Uses atomic writes (write to .tmp, rename) to prevent corruption.

use std::path::PathBuf;
use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

// ── Bridge Config Types ──────────────────────────────────────────────────────

/// A channel mapping between Discord and Umbra.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeChannel {
    pub discord_channel_id: String,
    pub umbra_channel_id: String,
    pub name: String,
}

/// A seat mapping between a Discord user and an Umbra identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeSeat {
    pub discord_user_id: String,
    pub discord_username: String,
    pub avatar_url: Option<String>,
    /// The Umbra DID for this seat, if claimed.
    pub seat_did: Option<String>,
}

/// Full bridge configuration for a community.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeConfig {
    pub community_id: String,
    pub guild_id: String,
    pub enabled: bool,
    /// The DID the bridge bot uses to send messages on behalf of this community.
    pub bridge_did: Option<String>,
    pub channels: Vec<BridgeChannel>,
    pub seats: Vec<BridgeSeat>,
    /// DIDs of all community members (for fan-out delivery).
    pub member_dids: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Summary returned in list endpoint (omits large arrays).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeConfigSummary {
    pub community_id: String,
    pub guild_id: String,
    pub enabled: bool,
    pub channel_count: usize,
    pub seat_count: usize,
    pub member_count: usize,
    pub created_at: i64,
    pub updated_at: i64,
}

impl From<&BridgeConfig> for BridgeConfigSummary {
    fn from(config: &BridgeConfig) -> Self {
        Self {
            community_id: config.community_id.clone(),
            guild_id: config.guild_id.clone(),
            enabled: config.enabled,
            channel_count: config.channels.len(),
            seat_count: config.seats.len(),
            member_count: config.member_dids.len(),
            created_at: config.created_at,
            updated_at: config.updated_at,
        }
    }
}

// ── Store ────────────────────────────────────────────────────────────────────

/// File-backed bridge config store with in-memory cache.
#[derive(Clone)]
pub struct BridgeStore {
    /// In-memory cache: communityId -> BridgeConfig
    configs: Arc<DashMap<String, BridgeConfig>>,
    /// Directory for persistence (`{data_dir}/bridges/`).
    bridges_dir: Option<PathBuf>,
}

impl BridgeStore {
    /// Create a new bridge store.
    ///
    /// `data_dir` is the relay's shared data directory (e.g. `/data`).
    /// Bridge configs will be stored in `{data_dir}/bridges/`.
    pub fn new(data_dir: Option<&str>) -> Self {
        let bridges_dir = data_dir.map(|d| PathBuf::from(d).join("bridges"));
        Self {
            configs: Arc::new(DashMap::new()),
            bridges_dir,
        }
    }

    /// Load all bridge configs from disk into memory.
    ///
    /// Called once at startup. Returns the number of configs loaded.
    pub fn load_from_disk(&self) -> usize {
        let dir = match &self.bridges_dir {
            Some(d) => d,
            None => {
                tracing::info!("[Bridge] No data_dir configured, running in-memory only");
                return 0;
            }
        };

        if !dir.exists() {
            tracing::info!(
                path = %dir.display(),
                "[Bridge] No bridges directory, starting fresh"
            );
            return 0;
        }

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %dir.display(),
                    "[Bridge] Failed to read bridges directory"
                );
                return 0;
            }
        };

        let mut count = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            // Skip temp files
            if path.to_str().map_or(false, |s| s.ends_with(".json.tmp")) {
                continue;
            }

            match std::fs::read_to_string(&path) {
                Ok(contents) => match serde_json::from_str::<BridgeConfig>(&contents) {
                    Ok(config) => {
                        tracing::info!(
                            community_id = config.community_id.as_str(),
                            guild_id = config.guild_id.as_str(),
                            enabled = config.enabled,
                            channels = config.channels.len(),
                            "[Bridge] Loaded bridge config"
                        );
                        self.configs.insert(config.community_id.clone(), config);
                        count += 1;
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            path = %path.display(),
                            "[Bridge] Failed to parse bridge config, skipping"
                        );
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        path = %path.display(),
                        "[Bridge] Failed to read bridge config file"
                    );
                }
            }
        }

        tracing::info!(count = count, "[Bridge] Bridge configs loaded from disk");
        count
    }

    /// Persist a single bridge config to disk using atomic write.
    fn persist_config(&self, config: &BridgeConfig) {
        let dir = match &self.bridges_dir {
            Some(d) => d,
            None => return,
        };

        // Ensure directory exists
        if let Err(e) = std::fs::create_dir_all(dir) {
            tracing::error!(
                error = %e,
                path = %dir.display(),
                "[Bridge] Failed to create bridges directory"
            );
            return;
        }

        let path = dir.join(format!("{}.json", config.community_id));
        let json = match serde_json::to_string_pretty(config) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!(error = %e, "[Bridge] Failed to serialize bridge config");
                return;
            }
        };

        // Atomic write: temp file + rename
        let tmp_path = path.with_extension("json.tmp");
        match std::fs::write(&tmp_path, &json) {
            Ok(()) => {
                if let Err(e) = std::fs::rename(&tmp_path, &path) {
                    tracing::error!(error = %e, "[Bridge] Failed to rename temp bridge config");
                    let _ = std::fs::remove_file(&tmp_path);
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "[Bridge] Failed to write temp bridge config");
            }
        }
    }

    /// Remove a bridge config file from disk.
    fn remove_config_file(&self, community_id: &str) {
        let dir = match &self.bridges_dir {
            Some(d) => d,
            None => return,
        };

        let path = dir.join(format!("{}.json", community_id));
        if path.exists() {
            if let Err(e) = std::fs::remove_file(&path) {
                tracing::error!(
                    error = %e,
                    community_id = community_id,
                    "[Bridge] Failed to remove bridge config file"
                );
            }
        }
    }

    // ── CRUD Operations ──────────────────────────────────────────────────────

    /// Register (create or update) a bridge config.
    pub fn register(&self, config: BridgeConfig) {
        tracing::info!(
            community_id = config.community_id.as_str(),
            guild_id = config.guild_id.as_str(),
            channels = config.channels.len(),
            seats = config.seats.len(),
            members = config.member_dids.len(),
            "[Bridge] Registering bridge config"
        );
        self.persist_config(&config);
        self.configs.insert(config.community_id.clone(), config);
    }

    /// Get a bridge config by community ID.
    pub fn get(&self, community_id: &str) -> Option<BridgeConfig> {
        self.configs.get(community_id).map(|r| r.clone())
    }

    /// List all bridge configs (as summaries).
    pub fn list(&self) -> Vec<BridgeConfigSummary> {
        self.configs
            .iter()
            .map(|r| BridgeConfigSummary::from(r.value()))
            .collect()
    }

    /// Delete a bridge config.
    pub fn delete(&self, community_id: &str) -> bool {
        let removed = self.configs.remove(community_id).is_some();
        if removed {
            self.remove_config_file(community_id);
            tracing::info!(
                community_id = community_id,
                "[Bridge] Bridge config deleted"
            );
        }
        removed
    }

    /// Update the member DIDs list for a bridge.
    pub fn update_members(&self, community_id: &str, member_dids: Vec<String>) -> bool {
        if let Some(mut config) = self.configs.get_mut(community_id) {
            config.member_dids = member_dids;
            config.updated_at = chrono::Utc::now().timestamp_millis();
            let config_clone = config.clone();
            drop(config); // Release DashMap lock before I/O
            self.persist_config(&config_clone);
            tracing::info!(
                community_id = community_id,
                members = config_clone.member_dids.len(),
                "[Bridge] Updated member list"
            );
            true
        } else {
            false
        }
    }

    /// Toggle enabled/disabled for a bridge.
    pub fn set_enabled(&self, community_id: &str, enabled: bool) -> bool {
        if let Some(mut config) = self.configs.get_mut(community_id) {
            config.enabled = enabled;
            config.updated_at = chrono::Utc::now().timestamp_millis();
            let config_clone = config.clone();
            drop(config);
            self.persist_config(&config_clone);
            tracing::info!(
                community_id = community_id,
                enabled = enabled,
                "[Bridge] Toggled bridge"
            );
            true
        } else {
            false
        }
    }

    /// Get the number of registered bridges.
    pub fn count(&self) -> usize {
        self.configs.len()
    }

    /// Get the number of enabled bridges.
    pub fn enabled_count(&self) -> usize {
        self.configs.iter().filter(|r| r.value().enabled).count()
    }
}
