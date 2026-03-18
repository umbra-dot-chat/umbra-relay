//! Discovery store for linked accounts.
//!
//! Uses DashMap for concurrent access, similar to the relay's state module.
//! Persists discovery data (linked accounts, discoverability) to a JSON file
//! on disk when `data_dir` is configured.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::config::DiscoveryConfig;
use super::types::{
    validate_username_name, DiscoveryEntry, HashedLookup, LinkedAccount, LookupResult, OAuthState,
    Platform, UsernameEntry, MAX_TAG,
};

/// On-disk persistence format.
#[derive(Debug, Serialize, Deserialize)]
struct PersistedData {
    entries: HashMap<String, DiscoveryEntry>,
}

/// Store for discovery data.
///
/// Provides concurrent access to linked accounts and lookup indices.
/// When `data_dir` is set, automatically persists changes to disk.
#[derive(Clone)]
pub struct DiscoveryStore {
    /// DID → DiscoveryEntry mapping.
    /// Contains all linked accounts for each user.
    by_did: Arc<DashMap<String, DiscoveryEntry>>,

    /// Hash(platform:id) → DID mapping for reverse lookups.
    /// Only contains entries where discoverable=true.
    lookup_index: Arc<DashMap<String, String>>,

    /// OAuth state storage (state_nonce → OAuthState).
    /// Used during OAuth flows to verify callbacks.
    oauth_states: Arc<DashMap<String, OAuthState>>,

    /// Lowercase "name#tag" → DID mapping for exact username lookup.
    username_index: Arc<DashMap<String, String>>,

    /// Lowercase name → list of (tag, DID) for tag assignment and search.
    name_tags: Arc<DashMap<String, Vec<(String, String)>>>,

    /// Profile import results (state_nonce → ImportedProfile).
    /// Stored temporarily so mobile clients can poll for results.
    profile_results: Arc<DashMap<String, crate::discovery::types::ImportedProfile>>,

    /// Community import results (state_nonce → access_token).
    /// Stored temporarily so Tauri/mobile clients can poll for results.
    community_import_results: Arc<DashMap<String, String>>,

    /// Configuration for hashing.
    config: Arc<DiscoveryConfig>,

    /// Directory for persistence. None = in-memory only.
    data_dir: Option<PathBuf>,
}

impl DiscoveryStore {
    /// Create a new discovery store.
    pub fn new(config: DiscoveryConfig) -> Self {
        let data_dir = config.data_dir.as_ref().map(PathBuf::from);
        Self {
            by_did: Arc::new(DashMap::new()),
            lookup_index: Arc::new(DashMap::new()),
            oauth_states: Arc::new(DashMap::new()),
            username_index: Arc::new(DashMap::new()),
            name_tags: Arc::new(DashMap::new()),
            profile_results: Arc::new(DashMap::new()),
            community_import_results: Arc::new(DashMap::new()),
            config: Arc::new(config),
            data_dir,
        }
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    /// Path to the discovery data file.
    fn data_file_path(&self) -> Option<PathBuf> {
        self.data_dir.as_ref().map(|dir| dir.join("discovery.json"))
    }

    /// Load discovery data from disk.
    ///
    /// Called once at startup. If the file doesn't exist or is corrupt,
    /// logs a warning and starts with an empty store.
    pub fn load_from_disk(&self) -> usize {
        let path = match self.data_file_path() {
            Some(p) => p,
            None => {
                tracing::info!("No data_dir configured, running in-memory only");
                return 0;
            }
        };

        if !path.exists() {
            tracing::info!(path = %path.display(), "No existing discovery data file, starting fresh");
            return 0;
        }

        match std::fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str::<PersistedData>(&contents) {
                Ok(data) => {
                    let count = data.entries.len();

                    // Populate by_did
                    for (did, entry) in data.entries {
                        self.by_did.insert(did, entry);
                    }

                    // Rebuild indices from entries
                    self.rebuild_lookup_index();
                    self.rebuild_username_index();

                    tracing::info!(
                        entries = count,
                        index_size = self.lookup_index.len(),
                        usernames = self.username_index.len(),
                        path = %path.display(),
                        "Discovery data loaded from disk"
                    );
                    count
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        path = %path.display(),
                        "Failed to parse discovery data file, starting fresh"
                    );
                    0
                }
            },
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %path.display(),
                    "Failed to read discovery data file, starting fresh"
                );
                0
            }
        }
    }

    /// Rebuild the lookup index from the current by_did entries.
    fn rebuild_lookup_index(&self) {
        self.lookup_index.clear();
        for entry in self.by_did.iter() {
            if entry.discoverable {
                for account in &entry.accounts {
                    let hash = self.hash_platform_id(account.platform, &account.platform_id);
                    self.lookup_index.insert(hash, entry.did.clone());
                }
            }
        }
    }

    /// Rebuild the username indices from the current by_did entries.
    fn rebuild_username_index(&self) {
        self.username_index.clear();
        self.name_tags.clear();
        for entry in self.by_did.iter() {
            if let Some(ref uname) = entry.username {
                let key = format!("{}#{}", uname.name.to_lowercase(), uname.tag);
                self.username_index.insert(key, entry.did.clone());

                let name_lower = uname.name.to_lowercase();
                self.name_tags
                    .entry(name_lower)
                    .or_insert_with(Vec::new)
                    .push((uname.tag.clone(), entry.did.clone()));
            }
        }
    }

    /// Persist current state to disk.
    ///
    /// Uses atomic write (write to temp file, then rename) to prevent corruption.
    fn persist_to_disk(&self) {
        let path = match self.data_file_path() {
            Some(p) => p,
            None => return, // No persistence configured
        };

        // Collect all entries
        let entries: HashMap<String, DiscoveryEntry> = self
            .by_did
            .iter()
            .map(|r| (r.key().clone(), r.value().clone()))
            .collect();

        let data = PersistedData { entries };

        // Serialize
        let json = match serde_json::to_string_pretty(&data) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!(error = %e, "Failed to serialize discovery data");
                return;
            }
        };

        // Ensure directory exists
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                tracing::error!(error = %e, path = %parent.display(), "Failed to create data directory");
                return;
            }
        }

        // Atomic write: write to temp file, then rename
        let tmp_path = path.with_extension("json.tmp");
        match std::fs::write(&tmp_path, &json) {
            Ok(()) => {
                if let Err(e) = std::fs::rename(&tmp_path, &path) {
                    tracing::error!(error = %e, "Failed to rename temp file to discovery.json");
                    // Try to clean up temp file
                    let _ = std::fs::remove_file(&tmp_path);
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to write discovery data temp file");
            }
        }
    }

    // ── Account Management ───────────────────────────────────────────────────

    /// Get a user's discovery entry.
    pub fn get_entry(&self, did: &str) -> Option<DiscoveryEntry> {
        self.by_did.get(did).map(|e| e.clone())
    }

    /// Get or create a user's discovery entry.
    pub fn get_or_create_entry(&self, did: &str) -> DiscoveryEntry {
        self.by_did
            .entry(did.to_string())
            .or_insert_with(|| DiscoveryEntry::new(did.to_string()))
            .clone()
    }

    /// Link an account to a DID.
    ///
    /// Updates the lookup index if the user is discoverable.
    pub fn link_account(&self, did: &str, account: LinkedAccount) {
        let platform = account.platform;
        let platform_id = account.platform_id.clone();

        // Update the entry
        let mut entry = self
            .by_did
            .entry(did.to_string())
            .or_insert_with(|| DiscoveryEntry::new(did.to_string()));
        entry.add_account(account);

        // Update lookup index if discoverable
        if entry.discoverable {
            let hash = self.hash_platform_id(platform, &platform_id);
            self.lookup_index.insert(hash, did.to_string());
        }

        // Persist to disk
        drop(entry); // Release DashMap lock before I/O
        self.persist_to_disk();
    }

    /// Unlink an account from a DID.
    ///
    /// Removes from lookup index.
    pub fn unlink_account(&self, did: &str, platform: Platform) -> bool {
        let result = if let Some(mut entry) = self.by_did.get_mut(did) {
            // Get the platform ID before removing (for index cleanup)
            let platform_id = entry.get_account(platform).map(|a| a.platform_id.clone());

            if entry.remove_account(platform) {
                // Remove from lookup index
                if let Some(id) = platform_id {
                    let hash = self.hash_platform_id(platform, &id);
                    self.lookup_index.remove(&hash);
                }
                true
            } else {
                false
            }
        } else {
            false
        };

        if result {
            self.persist_to_disk();
        }
        result
    }

    /// Set a user's discoverability.
    ///
    /// Updates the lookup index accordingly.
    pub fn set_discoverable(&self, did: &str, discoverable: bool) {
        {
            let mut entry = self
                .by_did
                .entry(did.to_string())
                .or_insert_with(|| DiscoveryEntry::new(did.to_string()));

            let was_discoverable = entry.discoverable;
            entry.discoverable = discoverable;
            entry.updated_at = Utc::now();

            // Update lookup index
            if discoverable && !was_discoverable {
                // Add all accounts to index
                for account in &entry.accounts {
                    let hash = self.hash_platform_id(account.platform, &account.platform_id);
                    self.lookup_index.insert(hash, did.to_string());
                }
            } else if !discoverable && was_discoverable {
                // Remove all accounts from index
                for account in &entry.accounts {
                    let hash = self.hash_platform_id(account.platform, &account.platform_id);
                    self.lookup_index.remove(&hash);
                }
            }
        } // Release DashMap lock before I/O

        self.persist_to_disk();
    }

    // ── Lookup ───────────────────────────────────────────────────────────────

    /// Perform a batch lookup of hashed platform IDs.
    ///
    /// Only returns DIDs where the user has enabled discoverability.
    pub fn batch_lookup(&self, lookups: &[HashedLookup]) -> Vec<LookupResult> {
        lookups
            .iter()
            .map(|lookup| {
                let did = self.lookup_index.get(&lookup.id_hash).map(|r| r.clone());
                LookupResult {
                    did,
                    platform: lookup.platform,
                    id_hash: lookup.id_hash.clone(),
                }
            })
            .collect()
    }

    /// Hash a platform ID for privacy-preserving lookup.
    ///
    /// Uses SHA-256(salt + platform + platform_id).
    pub fn hash_platform_id(&self, platform: Platform, platform_id: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.config.discovery_salt.as_bytes());
        hasher.update(platform.as_str().as_bytes());
        hasher.update(platform_id.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Create a hash for a platform ID (public method for clients).
    pub fn create_lookup_hash(&self, platform: Platform, platform_id: &str) -> String {
        self.hash_platform_id(platform, platform_id)
    }

    /// Search for discoverable users by platform username.
    ///
    /// Performs a case-insensitive substring match on the platform username
    /// for all discoverable entries. Returns up to `limit` results.
    pub fn search_by_username(
        &self,
        platform: Platform,
        query: &str,
        limit: usize,
    ) -> Vec<(String, super::types::LinkedAccountInfo)> {
        let query_lower = query.to_lowercase();
        let mut results = Vec::new();

        for entry in self.by_did.iter() {
            if !entry.discoverable {
                continue;
            }
            if let Some(account) = entry.accounts.iter().find(|a| {
                a.platform == platform && a.platform_username.to_lowercase().contains(&query_lower)
            }) {
                results.push((
                    entry.did.clone(),
                    super::types::LinkedAccountInfo::from(account),
                ));
                if results.len() >= limit {
                    break;
                }
            }
        }

        results
    }

    // ── Username Management ────────────────────────────────────────────────────

    /// Register a username for a DID.
    ///
    /// Validates the name, auto-assigns the next available tag, and updates
    /// all indices. If the DID already has a username, releases the old one first.
    pub fn register_username(&self, did: &str, name: &str) -> Result<UsernameEntry, String> {
        validate_username_name(name)?;

        let name_lower = name.to_lowercase();

        // Release existing username if any
        if let Some(entry) = self.by_did.get(did) {
            if entry.username.is_some() {
                drop(entry); // release DashMap lock
                self.release_username_internal(did);
            }
        }

        // Find next available tag for this name
        let tag = {
            let existing = self.name_tags.get(&name_lower);
            let next_num = match existing {
                Some(ref tags) => {
                    if tags.len() >= (MAX_TAG as usize + 1) {
                        return Err("No tags available for this username".into());
                    }
                    // Find the max existing tag number and add 1
                    let max_tag = tags
                        .iter()
                        .filter_map(|(t, _)| t.parse::<u32>().ok())
                        .max()
                        .unwrap_or(0);
                    max_tag + 1
                }
                None => 1, // First user with this name gets tag #00001
            };
            format!("{:05}", next_num)
        };

        let username_entry = UsernameEntry {
            name: name.to_string(), // preserve original casing
            tag: tag.clone(),
            registered_at: Utc::now(),
        };

        // Update by_did entry
        {
            let mut entry = self
                .by_did
                .entry(did.to_string())
                .or_insert_with(|| DiscoveryEntry::new(did.to_string()));
            entry.username = Some(username_entry.clone());
            entry.updated_at = Utc::now();
        }

        // Update username_index
        let full_key = format!("{}#{}", name_lower, tag);
        self.username_index.insert(full_key, did.to_string());

        // Update name_tags
        self.name_tags
            .entry(name_lower)
            .or_insert_with(Vec::new)
            .push((tag, did.to_string()));

        // Persist
        self.persist_to_disk();

        tracing::info!(
            did = did,
            username = username_entry.full_username().as_str(),
            "Username registered"
        );

        Ok(username_entry)
    }

    /// Release (delete) a username from a DID.
    pub fn release_username(&self, did: &str) -> bool {
        let released = self.release_username_internal(did);
        if released {
            self.persist_to_disk();
        }
        released
    }

    /// Internal release without persistence (used by register_username to avoid double-persist).
    fn release_username_internal(&self, did: &str) -> bool {
        let old_username = {
            let mut entry = match self.by_did.get_mut(did) {
                Some(e) => e,
                None => return false,
            };
            let old = entry.username.take();
            entry.updated_at = Utc::now();
            old
        };

        if let Some(ref uname) = old_username {
            let name_lower = uname.name.to_lowercase();
            let full_key = format!("{}#{}", name_lower, uname.tag);
            self.username_index.remove(&full_key);

            if let Some(mut tags) = self.name_tags.get_mut(&name_lower) {
                tags.retain(|(_, d)| d != did);
                if tags.is_empty() {
                    drop(tags);
                    self.name_tags.remove(&name_lower);
                }
            }

            tracing::info!(
                did = did,
                username = uname.full_username().as_str(),
                "Username released"
            );
            true
        } else {
            false
        }
    }

    /// Look up a user by exact username (Name#Tag).
    ///
    /// Returns the DID if found. Case-insensitive.
    pub fn lookup_username(&self, username: &str) -> Option<String> {
        let key = username.to_lowercase();
        self.username_index.get(&key).map(|r| r.clone())
    }

    /// Search for users by partial name.
    ///
    /// Case-insensitive substring match on the name portion. Returns up to
    /// `limit` results as (DID, full_username) pairs.
    pub fn search_usernames(&self, query: &str, limit: usize) -> Vec<(String, String)> {
        let query_lower = query.to_lowercase();
        let mut results = Vec::new();

        for entry in self.by_did.iter() {
            if let Some(ref uname) = entry.username {
                if uname.name.to_lowercase().contains(&query_lower) {
                    results.push((entry.did.clone(), uname.full_username()));
                    if results.len() >= limit {
                        break;
                    }
                }
            }
        }

        results
    }

    /// Get the username for a DID.
    pub fn get_username(&self, did: &str) -> Option<UsernameEntry> {
        self.by_did.get(did).and_then(|e| e.username.clone())
    }

    /// Get the number of registered usernames.
    pub fn username_count(&self) -> usize {
        self.username_index.len()
    }

    // ── OAuth State Management ───────────────────────────────────────────────

    /// Store an OAuth state for later verification.
    pub fn store_oauth_state(&self, state: OAuthState) {
        tracing::info!(
            nonce = state.nonce.as_str(),
            platform = ?state.platform,
            profile_import = state.profile_import,
            "Storing OAuth state"
        );
        self.oauth_states.insert(state.nonce.clone(), state);
        tracing::info!(
            pending_states = self.oauth_states.len(),
            "OAuth state stored"
        );
    }

    /// Retrieve and remove an OAuth state.
    ///
    /// Returns None if not found or expired.
    pub fn take_oauth_state(&self, nonce: &str) -> Option<OAuthState> {
        tracing::info!(
            nonce = nonce,
            pending_states = self.oauth_states.len(),
            "Looking up OAuth state"
        );

        let state = self.oauth_states.remove(nonce).map(|(_, s)| s);

        match &state {
            Some(s) => {
                let age = Utc::now().timestamp() - s.created_at.timestamp();
                tracing::info!(
                    nonce = nonce,
                    age_secs = age,
                    platform = ?s.platform,
                    profile_import = s.profile_import,
                    "OAuth state found"
                );

                // Check if expired (10 minute TTL)
                if age > super::config::OAUTH_STATE_TTL_SECS {
                    tracing::warn!(nonce = nonce, age_secs = age, "OAuth state expired");
                    return None;
                }

                state
            }
            None => {
                tracing::warn!(
                    nonce = nonce,
                    pending_states = self.oauth_states.len(),
                    "OAuth state not found"
                );
                None
            }
        }
    }

    /// Clean up expired OAuth states.
    pub fn cleanup_expired_states(&self) {
        let now = Utc::now().timestamp();
        let expired: Vec<String> = self
            .oauth_states
            .iter()
            .filter(|r| now - r.created_at.timestamp() > super::config::OAUTH_STATE_TTL_SECS)
            .map(|r| r.key().clone())
            .collect();

        for nonce in expired {
            self.oauth_states.remove(&nonce);
        }
    }

    // ── Profile Import Results ────────────────────────────────────────────────

    /// Store a profile import result for mobile polling.
    pub fn store_profile_result(
        &self,
        state: &str,
        profile: crate::discovery::types::ImportedProfile,
    ) {
        self.profile_results.insert(state.to_string(), profile);
    }

    /// Retrieve and remove a profile import result.
    pub fn take_profile_result(
        &self,
        state: &str,
    ) -> Option<crate::discovery::types::ImportedProfile> {
        self.profile_results.remove(state).map(|(_, p)| p)
    }

    // ── Community Import Results ────────────────────────────────────────────

    /// Store a community import result (access token) for polling.
    pub fn store_community_import_result(&self, state: &str, access_token: String) {
        self.community_import_results
            .insert(state.to_string(), access_token);
    }

    /// Retrieve and remove a community import result.
    pub fn take_community_import_result(&self, state: &str) -> Option<String> {
        self.community_import_results.remove(state).map(|(_, t)| t)
    }

    // ── Stats ────────────────────────────────────────────────────────────────

    /// Get the number of registered users.
    pub fn user_count(&self) -> usize {
        self.by_did.len()
    }

    /// Get the number of discoverable accounts in the index.
    pub fn index_size(&self) -> usize {
        self.lookup_index.len()
    }

    /// Get the number of pending OAuth states.
    pub fn pending_oauth_count(&self) -> usize {
        self.oauth_states.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> DiscoveryConfig {
        DiscoveryConfig {
            discord_client_id: None,
            discord_client_secret: None,
            discord_redirect_uri: None,
            discord_profile_import_redirect_uri: None,
            discord_community_import_redirect_uri: None,
            discord_bot_token: None,
            github_client_id: None,
            github_client_secret: None,
            github_redirect_uri: None,
            github_profile_import_redirect_uri: None,
            steam_api_key: None,
            steam_profile_import_redirect_uri: None,
            bluesky_client_id: None,
            bluesky_client_secret: None,
            bluesky_profile_import_redirect_uri: None,
            xbox_client_id: None,
            xbox_client_secret: None,
            xbox_profile_import_redirect_uri: None,
            discovery_salt: "test-salt".to_string(),
            relay_base_url: "http://localhost:8080".to_string(),
            data_dir: None, // No persistence in tests
        }
    }

    #[test]
    fn test_link_account() {
        let store = DiscoveryStore::new(test_config());

        let account = LinkedAccount {
            platform: Platform::Discord,
            platform_id: "123456789".to_string(),
            platform_username: "testuser#1234".to_string(),
            linked_at: Utc::now(),
            verified: true,
        };

        store.link_account("did:key:z6MkTest", account);

        let entry = store.get_entry("did:key:z6MkTest").unwrap();
        assert_eq!(entry.accounts.len(), 1);
        assert_eq!(entry.accounts[0].platform_id, "123456789");
    }

    #[test]
    fn test_discoverable_index() {
        let store = DiscoveryStore::new(test_config());

        let account = LinkedAccount {
            platform: Platform::Discord,
            platform_id: "123456789".to_string(),
            platform_username: "testuser#1234".to_string(),
            linked_at: Utc::now(),
            verified: true,
        };

        store.link_account("did:key:z6MkTest", account);

        // Not discoverable by default
        let hash = store.hash_platform_id(Platform::Discord, "123456789");
        let results = store.batch_lookup(&[HashedLookup {
            platform: Platform::Discord,
            id_hash: hash.clone(),
        }]);
        assert!(results[0].did.is_none());

        // Enable discoverability
        store.set_discoverable("did:key:z6MkTest", true);

        let results = store.batch_lookup(&[HashedLookup {
            platform: Platform::Discord,
            id_hash: hash,
        }]);
        assert_eq!(results[0].did.as_deref(), Some("did:key:z6MkTest"));
    }

    #[test]
    fn test_unlink_removes_from_index() {
        let store = DiscoveryStore::new(test_config());

        let account = LinkedAccount {
            platform: Platform::Discord,
            platform_id: "123456789".to_string(),
            platform_username: "testuser#1234".to_string(),
            linked_at: Utc::now(),
            verified: true,
        };

        store.link_account("did:key:z6MkTest", account);
        store.set_discoverable("did:key:z6MkTest", true);

        let hash = store.hash_platform_id(Platform::Discord, "123456789");

        // Should be in index
        let results = store.batch_lookup(&[HashedLookup {
            platform: Platform::Discord,
            id_hash: hash.clone(),
        }]);
        assert!(results[0].did.is_some());

        // Unlink
        store.unlink_account("did:key:z6MkTest", Platform::Discord);

        // Should be removed from index
        let results = store.batch_lookup(&[HashedLookup {
            platform: Platform::Discord,
            id_hash: hash,
        }]);
        assert!(results[0].did.is_none());
    }

    #[test]
    fn test_oauth_state() {
        let store = DiscoveryStore::new(test_config());

        let state = OAuthState {
            did: "did:key:z6MkTest".to_string(),
            nonce: "test-nonce-123".to_string(),
            platform: Platform::Discord,
            created_at: Utc::now(),
            profile_import: false,
            community_import: false,
        };

        store.store_oauth_state(state);

        let retrieved = store.take_oauth_state("test-nonce-123").unwrap();
        assert_eq!(retrieved.did, "did:key:z6MkTest");

        // Should be removed after take
        assert!(store.take_oauth_state("test-nonce-123").is_none());
    }

    #[test]
    fn test_hash_consistency() {
        let store = DiscoveryStore::new(test_config());

        let hash1 = store.hash_platform_id(Platform::Discord, "123456789");
        let hash2 = store.hash_platform_id(Platform::Discord, "123456789");

        assert_eq!(hash1, hash2);

        // Different ID should produce different hash
        let hash3 = store.hash_platform_id(Platform::Discord, "987654321");
        assert_ne!(hash1, hash3);

        // Different platform should produce different hash
        let hash4 = store.hash_platform_id(Platform::GitHub, "123456789");
        assert_ne!(hash1, hash4);
    }

    // ── Username Tests ──────────────────────────────────────────────────

    #[test]
    fn test_register_username() {
        let store = DiscoveryStore::new(test_config());

        let result = store.register_username("did:key:z6MkAlice", "Alice");
        assert!(result.is_ok());

        let entry = result.unwrap();
        assert_eq!(entry.name, "Alice");
        assert_eq!(entry.tag, "00001");
        assert_eq!(entry.full_username(), "Alice#00001");

        // Verify it's stored
        let stored = store.get_username("did:key:z6MkAlice");
        assert!(stored.is_some());
        assert_eq!(stored.unwrap().full_username(), "Alice#00001");
    }

    #[test]
    fn test_register_username_auto_tag() {
        let store = DiscoveryStore::new(test_config());

        // First user gets #00001
        let r1 = store.register_username("did:key:z6Mk1", "Matt").unwrap();
        assert_eq!(r1.tag, "00001");

        // Second user with same name gets #00002
        let r2 = store.register_username("did:key:z6Mk2", "Matt").unwrap();
        assert_eq!(r2.tag, "00002");

        // Third user with same name (different case) gets #00003
        let r3 = store.register_username("did:key:z6Mk3", "matt").unwrap();
        assert_eq!(r3.tag, "00003");
    }

    #[test]
    fn test_lookup_username_exact() {
        let store = DiscoveryStore::new(test_config());
        store
            .register_username("did:key:z6MkAlice", "Alice")
            .unwrap();

        // Exact lookup (case-insensitive)
        assert_eq!(
            store.lookup_username("Alice#00001"),
            Some("did:key:z6MkAlice".to_string())
        );
        assert_eq!(
            store.lookup_username("alice#00001"),
            Some("did:key:z6MkAlice".to_string())
        );
        assert_eq!(
            store.lookup_username("ALICE#00001"),
            Some("did:key:z6MkAlice".to_string())
        );

        // Non-existent
        assert!(store.lookup_username("Bob#00001").is_none());
    }

    #[test]
    fn test_search_usernames() {
        let store = DiscoveryStore::new(test_config());
        store
            .register_username("did:key:z6Mk1", "MattCool")
            .unwrap();
        store
            .register_username("did:key:z6Mk2", "MattAwesome")
            .unwrap();
        store.register_username("did:key:z6Mk3", "Bob").unwrap();

        // Search for "matt" should match 2
        let results = store.search_usernames("matt", 10);
        assert_eq!(results.len(), 2);

        // Search for "bob" should match 1
        let results = store.search_usernames("bob", 10);
        assert_eq!(results.len(), 1);

        // Search with limit
        let results = store.search_usernames("matt", 1);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_release_username() {
        let store = DiscoveryStore::new(test_config());
        store
            .register_username("did:key:z6MkAlice", "Alice")
            .unwrap();

        // Verify it exists
        assert!(store.lookup_username("Alice#00001").is_some());

        // Release it
        assert!(store.release_username("did:key:z6MkAlice"));

        // Verify it's gone
        assert!(store.lookup_username("Alice#00001").is_none());
        assert!(store.get_username("did:key:z6MkAlice").is_none());

        // Release again should return false
        assert!(!store.release_username("did:key:z6MkAlice"));
    }

    #[test]
    fn test_change_username() {
        let store = DiscoveryStore::new(test_config());
        store
            .register_username("did:key:z6MkAlice", "Alice")
            .unwrap();

        // Change to a new name
        let result = store.register_username("did:key:z6MkAlice", "NewAlice");
        assert!(result.is_ok());
        let entry = result.unwrap();
        assert_eq!(entry.name, "NewAlice");
        assert_eq!(entry.tag, "00001");

        // Old username should be gone
        assert!(store.lookup_username("Alice#00001").is_none());

        // New username should be findable
        assert_eq!(
            store.lookup_username("NewAlice#00001"),
            Some("did:key:z6MkAlice".to_string())
        );
    }

    #[test]
    fn test_username_validation_in_store() {
        let store = DiscoveryStore::new(test_config());

        // Empty name
        assert!(store.register_username("did:key:z6Mk1", "").is_err());

        // Invalid chars
        assert!(store
            .register_username("did:key:z6Mk1", "hello world")
            .is_err());
        assert!(store
            .register_username("did:key:z6Mk1", "user@name")
            .is_err());

        // Too long
        let long_name = "a".repeat(33);
        assert!(store
            .register_username("did:key:z6Mk1", &long_name)
            .is_err());
    }

    #[test]
    fn test_username_count() {
        let store = DiscoveryStore::new(test_config());
        assert_eq!(store.username_count(), 0);

        store.register_username("did:key:z6Mk1", "Alice").unwrap();
        assert_eq!(store.username_count(), 1);

        store.register_username("did:key:z6Mk2", "Bob").unwrap();
        assert_eq!(store.username_count(), 2);

        store.release_username("did:key:z6Mk1");
        assert_eq!(store.username_count(), 1);
    }
}
