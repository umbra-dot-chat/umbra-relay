//! Discovery service types.
//!
//! Types for linked accounts, platform identifiers, and discovery entries.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Supported platforms for account linking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Discord,
    GitHub,
    Steam,
    Bluesky,
    #[serde(rename = "xbox")]
    XboxLive,
}

impl Platform {
    /// Get the platform name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::Discord => "discord",
            Platform::GitHub => "github",
            Platform::Steam => "steam",
            Platform::Bluesky => "bluesky",
            Platform::XboxLive => "xbox",
        }
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A linked account from an external platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkedAccount {
    /// The platform this account is from.
    pub platform: Platform,
    /// Platform-specific user ID (e.g., Discord user ID).
    pub platform_id: String,
    /// Platform-specific username (e.g., "user#1234" for Discord).
    pub platform_username: String,
    /// When the account was linked.
    pub linked_at: DateTime<Utc>,
    /// Whether the account has been verified via OAuth.
    pub verified: bool,
}

/// A user's discovery entry containing all their linked accounts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryEntry {
    /// The user's Umbra DID.
    pub did: String,
    /// All linked accounts for this user.
    pub accounts: Vec<LinkedAccount>,
    /// Whether this user is discoverable by others.
    /// When false, their accounts won't appear in lookup results.
    pub discoverable: bool,
    /// When the entry was last updated.
    pub updated_at: DateTime<Utc>,
    /// Optional username in Name#Tag format.
    #[serde(default)]
    pub username: Option<UsernameEntry>,
}

impl DiscoveryEntry {
    /// Create a new discovery entry for a DID.
    pub fn new(did: String) -> Self {
        Self {
            did,
            accounts: Vec::new(),
            discoverable: false,
            updated_at: Utc::now(),
            username: None,
        }
    }

    /// Add a linked account.
    pub fn add_account(&mut self, account: LinkedAccount) {
        // Remove any existing account for the same platform
        self.accounts.retain(|a| a.platform != account.platform);
        self.accounts.push(account);
        self.updated_at = Utc::now();
    }

    /// Remove a linked account by platform.
    pub fn remove_account(&mut self, platform: Platform) -> bool {
        let initial_len = self.accounts.len();
        self.accounts.retain(|a| a.platform != platform);
        if self.accounts.len() < initial_len {
            self.updated_at = Utc::now();
            true
        } else {
            false
        }
    }

    /// Get a linked account by platform.
    pub fn get_account(&self, platform: Platform) -> Option<&LinkedAccount> {
        self.accounts.iter().find(|a| a.platform == platform)
    }
}

/// A hashed lookup request for privacy-preserving friend discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedLookup {
    /// The platform to search.
    pub platform: Platform,
    /// SHA-256 hash of (platform_id + salt).
    pub id_hash: String,
}

/// Result of a discovery lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookupResult {
    /// The matched Umbra DID (if found and discoverable).
    pub did: Option<String>,
    /// The platform that was matched.
    pub platform: Platform,
    /// The hashed ID that was queried.
    pub id_hash: String,
}

/// OAuth state stored during the OAuth flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthState {
    /// The user's Umbra DID (empty for profile import).
    pub did: String,
    /// Random nonce to prevent CSRF.
    pub nonce: String,
    /// The platform being linked.
    pub platform: Platform,
    /// When this state was created.
    pub created_at: DateTime<Utc>,
    /// Whether this is a profile import flow (vs account linking).
    #[serde(default)]
    pub profile_import: bool,
    /// Whether this is a community import flow (for Discord guild structure import).
    #[serde(default)]
    pub community_import: bool,
}

/// Imported profile data from OAuth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedProfile {
    /// The platform the profile was imported from.
    pub platform: Platform,
    /// Platform-specific user ID.
    pub platform_id: String,
    /// Display name / username.
    pub display_name: String,
    /// Username on the platform.
    pub username: String,
    /// Avatar as base64-encoded image data.
    pub avatar_base64: Option<String>,
    /// Avatar MIME type (e.g., "image/png", "image/gif").
    pub avatar_mime: Option<String>,
    /// User bio / status.
    pub bio: Option<String>,
    /// Email (if scope allows).
    pub email: Option<String>,
}

/// Response from profile import callback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileImportResponse {
    /// Whether the import was successful.
    pub success: bool,
    /// The imported profile data.
    pub profile: Option<ImportedProfile>,
    /// Error message if failed.
    pub error: Option<String>,
}

/// Request to start an OAuth flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartAuthRequest {
    /// The user's Umbra DID.
    pub did: String,
    /// Optional state nonce from the client.
    pub state: Option<String>,
}

/// Response from starting an OAuth flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartAuthResponse {
    /// The URL to redirect the user to.
    pub redirect_url: String,
    /// The state parameter to verify on callback.
    pub state: String,
}

/// Request to update discovery settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSettingsRequest {
    /// The user's Umbra DID.
    pub did: String,
    /// Whether the user should be discoverable.
    pub discoverable: bool,
}

/// Request to link an account directly (after OAuth profile import).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkAccountRequest {
    /// The user's Umbra DID.
    pub did: String,
    /// The platform to link.
    pub platform: Platform,
    /// Platform-specific user ID (e.g., Discord user ID).
    pub platform_id: String,
    /// Platform-specific username.
    pub username: String,
}

/// Request to unlink an account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlinkRequest {
    /// The user's Umbra DID.
    pub did: String,
    /// The platform to unlink.
    pub platform: Platform,
}

/// Request for batch lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchLookupRequest {
    /// List of hashed lookups to perform.
    pub lookups: Vec<HashedLookup>,
}

/// Response from batch lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchLookupResponse {
    /// Results for each lookup (in same order as request).
    pub results: Vec<LookupResult>,
}

/// Discovery status response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryStatusResponse {
    /// The user's DID.
    pub did: String,
    /// Whether the user is discoverable.
    pub discoverable: bool,
    /// All linked accounts.
    pub accounts: Vec<LinkedAccountInfo>,
}

/// Public info about a linked account (no internal IDs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkedAccountInfo {
    /// The platform.
    pub platform: Platform,
    /// The username on that platform.
    pub username: String,
    /// When the account was linked.
    pub linked_at: DateTime<Utc>,
}

impl From<&LinkedAccount> for LinkedAccountInfo {
    fn from(account: &LinkedAccount) -> Self {
        Self {
            platform: account.platform,
            username: account.platform_username.clone(),
            linked_at: account.linked_at,
        }
    }
}

// ── Username System ─────────────────────────────────────────────────────────

/// Maximum length for the name portion of a username.
pub const USERNAME_MAX_LENGTH: usize = 32;

/// Number of digits in the tag portion.
pub const TAG_DIGITS: usize = 5;

/// Maximum tag value (99999 for 5-digit tags).
pub const MAX_TAG: u32 = 99999;

/// A user's claimed username in Name#Tag format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsernameEntry {
    /// The name portion (case-preserved, 1-32 chars).
    pub name: String,
    /// The auto-assigned 5-digit numeric tag (e.g., "01283").
    pub tag: String,
    /// When the username was registered.
    pub registered_at: DateTime<Utc>,
}

impl UsernameEntry {
    /// Format as "Name#Tag" for display.
    pub fn full_username(&self) -> String {
        format!("{}#{}", self.name, self.tag)
    }
}

/// Validate a username name portion.
///
/// Rules: 1-32 chars, alphanumeric + underscores + hyphens only, ASCII only.
pub fn validate_username_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Username cannot be empty".into());
    }
    if name.len() > USERNAME_MAX_LENGTH {
        return Err(format!(
            "Username too long: max {} characters",
            USERNAME_MAX_LENGTH
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("Username can only contain letters, numbers, underscores, and hyphens".into());
    }
    Ok(())
}

/// Request to register a username (with Ed25519 signature for DID ownership proof).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterUsernameRequest {
    /// The user's Umbra DID.
    pub did: String,
    /// Desired name portion (will be validated).
    pub name: String,
    /// Base64-encoded Ed25519 signature over the canonical payload.
    pub signature: Option<String>,
    /// Base64-encoded Ed25519 public key (must match DID).
    pub public_key: Option<String>,
    /// Unix timestamp (seconds) — included in the signed payload for replay protection.
    pub timestamp: Option<i64>,
}

/// Request to change username (with Ed25519 signature).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeUsernameRequest {
    /// The user's Umbra DID.
    pub did: String,
    /// New desired name portion.
    pub name: String,
    /// Base64-encoded Ed25519 signature over the canonical payload.
    pub signature: Option<String>,
    /// Base64-encoded Ed25519 public key (must match DID).
    pub public_key: Option<String>,
    /// Unix timestamp (seconds).
    pub timestamp: Option<i64>,
}

/// Request to release (delete) a username (with Ed25519 signature).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseUsernameRequest {
    /// The user's Umbra DID.
    pub did: String,
    /// Base64-encoded Ed25519 signature over the canonical payload.
    pub signature: Option<String>,
    /// Base64-encoded Ed25519 public key (must match DID).
    pub public_key: Option<String>,
    /// Unix timestamp (seconds).
    pub timestamp: Option<i64>,
}

/// Response from username operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsernameResponse {
    /// The user's DID.
    pub did: String,
    /// The full username (Name#Tag), or null if no username.
    pub username: Option<String>,
    /// The name portion.
    pub name: Option<String>,
    /// The tag portion.
    pub tag: Option<String>,
    /// When registered.
    pub registered_at: Option<DateTime<Utc>>,
}

/// Query parameters for exact username lookup.
#[derive(Debug, Clone, Deserialize)]
pub struct UsernameLookupQuery {
    /// Exact username to look up (e.g., "Matt#01283").
    pub username: String,
}

/// Query parameters for username search.
#[derive(Debug, Clone, Deserialize)]
pub struct UsernameSearchQuery {
    /// Partial name to search for (min 2 chars).
    pub name: String,
    /// Max results (default 20).
    pub limit: Option<usize>,
}

/// Username search result item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsernameSearchResultItem {
    /// The user's DID.
    pub did: String,
    /// Full username (Name#Tag).
    pub username: String,
}

/// Query parameters for getting username by DID.
#[derive(Debug, Clone, Deserialize)]
pub struct UsernameForDidQuery {
    /// The user's Umbra DID.
    pub did: String,
}

// ── Discord Community Import Types ──────────────────────────────────────────

/// Discord guild (server) info returned from the guilds list endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscordGuildInfo {
    /// Discord guild ID.
    pub id: String,
    /// Guild name.
    pub name: String,
    /// Guild icon hash (can be used to construct icon URL).
    pub icon: Option<String>,
    /// Guild banner hash (for banner image).
    #[serde(default)]
    pub banner: Option<String>,
    /// Guild splash hash (for invite splash image).
    #[serde(default)]
    pub splash: Option<String>,
    /// Guild description.
    #[serde(default)]
    pub description: Option<String>,
    /// Whether the user is the owner.
    pub owner: bool,
    /// User's permissions in this guild (as integer bitfield).
    pub permissions: u64,
    /// Whether the user has MANAGE_GUILD permission.
    pub can_manage: bool,
}

/// Discord custom emoji.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscordEmoji {
    /// Emoji ID (null for unicode emoji).
    pub id: Option<String>,
    /// Emoji name.
    pub name: Option<String>,
    /// Whether the emoji is animated.
    pub animated: bool,
}

/// Discord guild sticker.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscordSticker {
    /// Sticker ID.
    pub id: String,
    /// Sticker name.
    pub name: String,
    /// Sticker description.
    pub description: Option<String>,
    /// Format type: 1 = PNG, 2 = APNG, 3 = Lottie, 4 = GIF.
    pub format_type: u8,
    /// Whether the sticker is available (not deleted/expired).
    #[serde(default = "default_true")]
    pub available: bool,
}

fn default_true() -> bool {
    true
}

/// Discord channel types (subset we care about).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscordChannelType {
    /// Text channel.
    Text,
    /// Voice channel.
    Voice,
    /// Category.
    Category,
    /// Announcement/news channel.
    Announcement,
    /// Forum channel.
    Forum,
    /// Stage channel.
    Stage,
    /// Unknown type (for forward compatibility).
    Unknown,
}

impl From<u8> for DiscordChannelType {
    fn from(value: u8) -> Self {
        match value {
            0 => DiscordChannelType::Text,
            2 => DiscordChannelType::Voice,
            4 => DiscordChannelType::Category,
            5 => DiscordChannelType::Announcement,
            13 => DiscordChannelType::Stage,
            15 => DiscordChannelType::Forum,
            _ => DiscordChannelType::Unknown,
        }
    }
}

/// An imported Discord channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscordImportedChannel {
    /// Discord channel ID.
    pub id: String,
    /// Channel name.
    pub name: String,
    /// Channel type.
    pub channel_type: DiscordChannelType,
    /// Parent category ID (if any).
    pub parent_id: Option<String>,
    /// Position in the channel list.
    pub position: i32,
    /// Topic/description.
    pub topic: Option<String>,
    /// Whether the channel is NSFW.
    pub nsfw: bool,
    /// Permission overwrites (simplified - we just pass the raw data).
    pub permission_overwrites: Vec<DiscordPermissionOverwrite>,
}

/// Discord permission overwrite (for channels).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscordPermissionOverwrite {
    /// ID of the role or user.
    pub id: String,
    /// Type: 0 = role, 1 = member.
    #[serde(rename = "type")]
    pub overwrite_type: u8,
    /// Allowed permissions bitfield.
    pub allow: String,
    /// Denied permissions bitfield.
    pub deny: String,
}

/// An imported Discord role.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscordImportedRole {
    /// Discord role ID.
    pub id: String,
    /// Role name.
    pub name: String,
    /// Role color (as integer).
    pub color: u32,
    /// Whether the role is hoisted (displayed separately).
    pub hoist: bool,
    /// Position in the role list.
    pub position: i32,
    /// Permissions bitfield (as string for large numbers).
    pub permissions: String,
    /// Whether the role is managed by an integration.
    pub managed: bool,
    /// Whether the role is mentionable.
    pub mentionable: bool,
}

/// Full imported structure of a Discord guild.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordImportedStructure {
    /// Guild info.
    pub guild: DiscordGuildInfo,
    /// All channels (including categories).
    pub channels: Vec<DiscordImportedChannel>,
    /// All roles (excluding @everyone which is position 0).
    pub roles: Vec<DiscordImportedRole>,
    /// Custom emojis.
    #[serde(default)]
    pub emojis: Vec<DiscordEmoji>,
    /// Guild stickers.
    #[serde(default)]
    pub stickers: Vec<DiscordSticker>,
}

/// Response from the guilds list endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordGuildsResponse {
    /// List of guilds the user has access to.
    pub guilds: Vec<DiscordGuildInfo>,
}

/// Response from the guild structure endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordGuildStructureResponse {
    /// Whether the fetch was successful.
    pub success: bool,
    /// The imported structure (if successful).
    pub structure: Option<DiscordImportedStructure>,
    /// Error message (if failed).
    pub error: Option<String>,
}

/// Query for fetching guild structure.
#[derive(Debug, Clone, Deserialize)]
pub struct GuildStructureQuery {
    /// Access token from OAuth flow.
    pub token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_serialization() {
        let discord = Platform::Discord;
        let json = serde_json::to_string(&discord).unwrap();
        assert_eq!(json, "\"discord\"");

        let parsed: Platform = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, Platform::Discord);
    }

    #[test]
    fn test_discovery_entry_add_account() {
        let mut entry = DiscoveryEntry::new("did:key:z6MkTest".to_string());
        assert!(entry.accounts.is_empty());

        let account = LinkedAccount {
            platform: Platform::Discord,
            platform_id: "123456789".to_string(),
            platform_username: "testuser#1234".to_string(),
            linked_at: Utc::now(),
            verified: true,
        };

        entry.add_account(account.clone());
        assert_eq!(entry.accounts.len(), 1);
        assert_eq!(entry.accounts[0].platform_id, "123456789");

        // Adding same platform should replace
        let account2 = LinkedAccount {
            platform: Platform::Discord,
            platform_id: "987654321".to_string(),
            platform_username: "newuser#5678".to_string(),
            linked_at: Utc::now(),
            verified: true,
        };

        entry.add_account(account2);
        assert_eq!(entry.accounts.len(), 1);
        assert_eq!(entry.accounts[0].platform_id, "987654321");
    }

    #[test]
    fn test_discovery_entry_remove_account() {
        let mut entry = DiscoveryEntry::new("did:key:z6MkTest".to_string());

        entry.add_account(LinkedAccount {
            platform: Platform::Discord,
            platform_id: "123".to_string(),
            platform_username: "user".to_string(),
            linked_at: Utc::now(),
            verified: true,
        });

        assert!(entry.remove_account(Platform::Discord));
        assert!(entry.accounts.is_empty());
        assert!(!entry.remove_account(Platform::Discord)); // Already removed
    }

    // ── Username Tests ──────────────────────────────────────────────────

    #[test]
    fn test_validate_username_valid() {
        assert!(validate_username_name("Matt").is_ok());
        assert!(validate_username_name("cool_user-123").is_ok());
        assert!(validate_username_name("a").is_ok());
        assert!(validate_username_name("A-B_C").is_ok());
    }

    #[test]
    fn test_validate_username_empty() {
        assert!(validate_username_name("").is_err());
    }

    #[test]
    fn test_validate_username_too_long() {
        let long = "a".repeat(USERNAME_MAX_LENGTH + 1);
        assert!(validate_username_name(&long).is_err());
    }

    #[test]
    fn test_validate_username_invalid_chars() {
        assert!(validate_username_name("hello world").is_err()); // space
        assert!(validate_username_name("user@name").is_err()); // @
        assert!(validate_username_name("名前").is_err()); // unicode
        assert!(validate_username_name("user#tag").is_err()); // #
    }

    #[test]
    fn test_username_entry_full_username() {
        let entry = UsernameEntry {
            name: "Matt".to_string(),
            tag: "01283".to_string(),
            registered_at: Utc::now(),
        };
        assert_eq!(entry.full_username(), "Matt#01283");
    }

    #[test]
    fn test_discovery_entry_with_username_serialization() {
        let mut entry = DiscoveryEntry::new("did:key:z6MkTest".to_string());
        entry.username = Some(UsernameEntry {
            name: "Alice".to_string(),
            tag: "00001".to_string(),
            registered_at: Utc::now(),
        });

        let json = serde_json::to_string(&entry).unwrap();
        let parsed: DiscoveryEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.username.as_ref().unwrap().full_username(),
            "Alice#00001"
        );
    }

    #[test]
    fn test_discovery_entry_without_username_backward_compat() {
        // Simulate old JSON that doesn't have the username field
        let json = r#"{
            "did": "did:key:z6MkTest",
            "accounts": [],
            "discoverable": false,
            "updated_at": "2025-01-01T00:00:00Z"
        }"#;
        let entry: DiscoveryEntry = serde_json::from_str(json).unwrap();
        assert!(entry.username.is_none());
    }
}
