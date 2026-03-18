//! SQLite-backed sync blob storage.
//!
//! Stores encrypted account sync blobs, auth challenges, and tokens.
//! All data is opaque to the relay — encryption happens client-side.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection};

use super::types::SyncBlobMeta;

/// Maximum blob size (10 MB).
const DEFAULT_MAX_BLOB_SIZE: usize = 10 * 1024 * 1024;

/// Default retention period (90 days in seconds).
const DEFAULT_RETENTION_SECS: i64 = 90 * 24 * 3600;

/// Auth challenge TTL (5 minutes).
const CHALLENGE_TTL_SECS: i64 = 300;

/// Auth token TTL (24 hours).
const TOKEN_TTL_SECS: i64 = 24 * 3600;

pub struct SyncBlobStore {
    conn: Mutex<Connection>,
    max_blob_size: usize,
    retention_secs: i64,
}

impl SyncBlobStore {
    /// Create a new store. If `data_dir` is provided, uses a file-backed DB;
    /// otherwise uses in-memory SQLite.
    pub fn new(data_dir: Option<&str>) -> Result<Self, rusqlite::Error> {
        let conn = if let Some(dir) = data_dir {
            let path = Path::new(dir).join("sync_blobs.db");
            Connection::open(path)?
        } else {
            Connection::open_in_memory()?
        };

        let store = Self {
            conn: Mutex::new(conn),
            max_blob_size: DEFAULT_MAX_BLOB_SIZE,
            retention_secs: DEFAULT_RETENTION_SECS,
        };

        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS sync_blobs (
                did TEXT PRIMARY KEY,
                blob BLOB NOT NULL,
                size INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sync_auth_challenges (
                nonce TEXT PRIMARY KEY,
                did TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sync_tokens (
                token TEXT PRIMARY KEY,
                did TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );
            ",
        )?;

        Ok(())
    }

    // ── Blob CRUD ────────────────────────────────────────────────────────────

    /// Store or update an encrypted sync blob for a DID.
    pub fn put_blob(&self, did: &str, blob: &[u8]) -> Result<(), String> {
        if blob.len() > self.max_blob_size {
            return Err(format!(
                "Blob size {} exceeds maximum {}",
                blob.len(),
                self.max_blob_size
            ));
        }

        let now = chrono::Utc::now().timestamp();
        let expires_at = now + self.retention_secs;
        let size = blob.len() as i64;

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sync_blobs (did, blob, size, updated_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(did) DO UPDATE SET
                blob = excluded.blob,
                size = excluded.size,
                updated_at = excluded.updated_at,
                expires_at = excluded.expires_at",
            params![did, blob, size, now, expires_at],
        )
        .map_err(|e| format!("Failed to store blob: {}", e))?;

        Ok(())
    }

    /// Retrieve an encrypted sync blob for a DID.
    pub fn get_blob(&self, did: &str) -> Result<Option<Vec<u8>>, String> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();

        let result = conn.query_row(
            "SELECT blob FROM sync_blobs WHERE did = ?1 AND expires_at > ?2",
            params![did, now],
            |row| row.get::<_, Vec<u8>>(0),
        );

        match result {
            Ok(blob) => Ok(Some(blob)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(format!("Failed to get blob: {}", e)),
        }
    }

    /// Get metadata about a stored blob without downloading it.
    pub fn get_blob_meta(&self, did: &str) -> Result<Option<SyncBlobMeta>, String> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();

        let result = conn.query_row(
            "SELECT did, size, updated_at, expires_at FROM sync_blobs
             WHERE did = ?1 AND expires_at > ?2",
            params![did, now],
            |row| {
                Ok(SyncBlobMeta {
                    did: row.get(0)?,
                    size: row.get::<_, i64>(1)? as usize,
                    updated_at: row.get(2)?,
                    expires_at: row.get(3)?,
                })
            },
        );

        match result {
            Ok(meta) => Ok(Some(meta)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(format!("Failed to get blob meta: {}", e)),
        }
    }

    /// Delete a sync blob for a DID.
    pub fn delete_blob(&self, did: &str) -> Result<bool, String> {
        let conn = self.conn.lock().unwrap();
        let affected = conn
            .execute("DELETE FROM sync_blobs WHERE did = ?1", params![did])
            .map_err(|e| format!("Failed to delete blob: {}", e))?;
        Ok(affected > 0)
    }

    // ── Challenge-Response Auth ──────────────────────────────────────────────

    /// Create an auth challenge nonce for a DID.
    pub fn create_challenge(&self, did: &str) -> Result<String, String> {
        let nonce = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sync_auth_challenges (nonce, did, created_at) VALUES (?1, ?2, ?3)",
            params![nonce, did, now],
        )
        .map_err(|e| format!("Failed to create challenge: {}", e))?;

        Ok(nonce)
    }

    /// Verify a challenge — consumes the nonce and returns the associated DID.
    pub fn verify_challenge(&self, nonce: &str) -> Result<Option<String>, String> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        let min_created = now - CHALLENGE_TTL_SECS;

        let result = conn.query_row(
            "SELECT did FROM sync_auth_challenges
             WHERE nonce = ?1 AND created_at > ?2",
            params![nonce, min_created],
            |row| row.get::<_, String>(0),
        );

        match result {
            Ok(did) => {
                // Consume the nonce
                let _ = conn.execute(
                    "DELETE FROM sync_auth_challenges WHERE nonce = ?1",
                    params![nonce],
                );
                Ok(Some(did))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(format!("Failed to verify challenge: {}", e)),
        }
    }

    // ── Token Management ────────────────────────────────────────────────────

    /// Issue a Bearer token for an authenticated DID.
    pub fn create_token(&self, did: &str) -> Result<(String, i64), String> {
        let token = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();
        let expires_at = now + TOKEN_TTL_SECS;

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sync_tokens (token, did, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![token, did, now, expires_at],
        )
        .map_err(|e| format!("Failed to create token: {}", e))?;

        Ok((token, expires_at))
    }

    /// Validate a Bearer token. Returns the associated DID if valid.
    pub fn validate_token(&self, token: &str) -> Result<Option<String>, String> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();

        let result = conn.query_row(
            "SELECT did FROM sync_tokens WHERE token = ?1 AND expires_at > ?2",
            params![token, now],
            |row| row.get::<_, String>(0),
        );

        match result {
            Ok(did) => Ok(Some(did)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(format!("Failed to validate token: {}", e)),
        }
    }

    // ── Cleanup ─────────────────────────────────────────────────────────────

    /// Remove expired blobs, challenges, and tokens.
    pub fn cleanup_expired(&self) -> (usize, usize, usize) {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();

        let blobs = conn
            .execute("DELETE FROM sync_blobs WHERE expires_at <= ?1", params![now])
            .unwrap_or(0);

        let challenges = conn
            .execute(
                "DELETE FROM sync_auth_challenges WHERE created_at <= ?1",
                params![now - CHALLENGE_TTL_SECS],
            )
            .unwrap_or(0);

        let tokens = conn
            .execute(
                "DELETE FROM sync_tokens WHERE expires_at <= ?1",
                params![now],
            )
            .unwrap_or(0);

        (blobs, challenges, tokens)
    }
}
