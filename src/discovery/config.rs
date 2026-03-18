//! Discovery service configuration.
//!
//! OAuth2 client configurations and environment variables.

use std::env;

/// Discovery service configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Discord OAuth2 client ID.
    pub discord_client_id: Option<String>,
    /// Discord OAuth2 client secret.
    pub discord_client_secret: Option<String>,
    /// Discord OAuth2 redirect URI (for account linking).
    pub discord_redirect_uri: Option<String>,
    /// Discord OAuth2 redirect URI (for profile import).
    pub discord_profile_import_redirect_uri: Option<String>,
    /// Discord OAuth2 redirect URI (for community import).
    pub discord_community_import_redirect_uri: Option<String>,
    /// Discord Bot token (for fetching guild channels/roles via Bot API).
    pub discord_bot_token: Option<String>,

    /// GitHub OAuth2 client ID.
    pub github_client_id: Option<String>,
    /// GitHub OAuth2 client secret.
    pub github_client_secret: Option<String>,
    /// GitHub OAuth2 redirect URI (for account linking).
    pub github_redirect_uri: Option<String>,
    /// GitHub OAuth2 redirect URI (for profile import).
    pub github_profile_import_redirect_uri: Option<String>,

    /// Steam Web API key (for fetching player summaries after OpenID auth).
    pub steam_api_key: Option<String>,
    /// Steam redirect URI (for profile import).
    pub steam_profile_import_redirect_uri: Option<String>,

    /// Bluesky OAuth2 client ID.
    pub bluesky_client_id: Option<String>,
    /// Bluesky OAuth2 client secret.
    pub bluesky_client_secret: Option<String>,
    /// Bluesky redirect URI (for profile import).
    pub bluesky_profile_import_redirect_uri: Option<String>,

    /// Xbox (Microsoft) OAuth2 client ID (Azure AD app).
    pub xbox_client_id: Option<String>,
    /// Xbox (Microsoft) OAuth2 client secret.
    pub xbox_client_secret: Option<String>,
    /// Xbox redirect URI (for profile import).
    pub xbox_profile_import_redirect_uri: Option<String>,

    /// Salt for hashing platform IDs (for privacy-preserving lookups).
    pub discovery_salt: String,

    /// Base URL for the relay (used to construct redirect URIs).
    pub relay_base_url: String,

    /// Directory for persisting discovery data (linked accounts).
    /// When set, discovery data is saved to `{data_dir}/discovery.json`.
    pub data_dir: Option<String>,
}

impl DiscoveryConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> Self {
        let relay_base_url =
            env::var("RELAY_BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

        Self {
            discord_client_id: env::var("DISCORD_CLIENT_ID").ok(),
            discord_client_secret: env::var("DISCORD_CLIENT_SECRET").ok(),
            discord_redirect_uri: env::var("DISCORD_REDIRECT_URI")
                .ok()
                .or_else(|| Some(format!("{}/auth/discord/callback", relay_base_url))),
            discord_profile_import_redirect_uri: env::var("DISCORD_PROFILE_IMPORT_REDIRECT_URI")
                .ok()
                .or_else(|| {
                    Some(format!(
                        "{}/profile/import/discord/callback",
                        relay_base_url
                    ))
                }),
            discord_community_import_redirect_uri: env::var(
                "DISCORD_COMMUNITY_IMPORT_REDIRECT_URI",
            )
            .ok()
            .or_else(|| {
                Some(format!(
                    "{}/community/import/discord/callback",
                    relay_base_url
                ))
            }),
            discord_bot_token: env::var("DISCORD_BOT_TOKEN").ok(),

            github_client_id: env::var("GITHUB_CLIENT_ID").ok(),
            github_client_secret: env::var("GITHUB_CLIENT_SECRET").ok(),
            github_redirect_uri: env::var("GITHUB_REDIRECT_URI")
                .ok()
                .or_else(|| Some(format!("{}/auth/github/callback", relay_base_url))),
            github_profile_import_redirect_uri: env::var("GITHUB_PROFILE_IMPORT_REDIRECT_URI")
                .ok()
                .or_else(|| Some(format!("{}/profile/import/github/callback", relay_base_url))),

            steam_api_key: env::var("STEAM_API_KEY").ok(),
            steam_profile_import_redirect_uri: env::var("STEAM_PROFILE_IMPORT_REDIRECT_URI")
                .ok()
                .or_else(|| Some(format!("{}/profile/import/steam/callback", relay_base_url))),

            bluesky_client_id: env::var("BLUESKY_CLIENT_ID").ok(),
            bluesky_client_secret: env::var("BLUESKY_CLIENT_SECRET").ok(),
            bluesky_profile_import_redirect_uri: env::var("BLUESKY_PROFILE_IMPORT_REDIRECT_URI")
                .ok()
                .or_else(|| {
                    Some(format!(
                        "{}/profile/import/bluesky/callback",
                        relay_base_url
                    ))
                }),

            xbox_client_id: env::var("XBOX_CLIENT_ID").ok(),
            xbox_client_secret: env::var("XBOX_CLIENT_SECRET").ok(),
            xbox_profile_import_redirect_uri: env::var("XBOX_PROFILE_IMPORT_REDIRECT_URI")
                .ok()
                .or_else(|| Some(format!("{}/profile/import/xbox/callback", relay_base_url))),

            discovery_salt: env::var("DISCOVERY_SALT").unwrap_or_else(|_| {
                "umbra-discovery-default-salt-change-in-production".to_string()
            }),

            data_dir: env::var("DATA_DIR").ok(),

            relay_base_url,
        }
    }

    /// Check if Discord OAuth2 is configured.
    pub fn discord_enabled(&self) -> bool {
        self.discord_client_id.is_some() && self.discord_client_secret.is_some()
    }

    /// Check if GitHub OAuth2 is configured.
    pub fn github_enabled(&self) -> bool {
        self.github_client_id.is_some() && self.github_client_secret.is_some()
    }

    /// Check if Steam is configured (only needs API key for OpenID flow).
    pub fn steam_enabled(&self) -> bool {
        self.steam_api_key.is_some()
    }

    /// Check if Bluesky OAuth2 is configured.
    pub fn bluesky_enabled(&self) -> bool {
        self.bluesky_client_id.is_some() && self.bluesky_client_secret.is_some()
    }

    /// Check if Xbox (Microsoft) OAuth2 is configured.
    pub fn xbox_enabled(&self) -> bool {
        self.xbox_client_id.is_some() && self.xbox_client_secret.is_some()
    }

    /// Get Discord OAuth2 authorization URL.
    pub fn discord_auth_url(&self) -> &'static str {
        "https://discord.com/oauth2/authorize"
    }

    /// Get Discord OAuth2 token URL.
    pub fn discord_token_url(&self) -> &'static str {
        "https://discord.com/api/oauth2/token"
    }

    /// Get Discord API base URL.
    pub fn discord_api_url(&self) -> &'static str {
        "https://discord.com/api/v10"
    }

    /// Get GitHub OAuth2 authorization URL.
    pub fn github_auth_url(&self) -> &'static str {
        "https://github.com/login/oauth/authorize"
    }

    /// Get GitHub OAuth2 token URL.
    pub fn github_token_url(&self) -> &'static str {
        "https://github.com/login/oauth/access_token"
    }

    /// Get GitHub API base URL.
    pub fn github_api_url(&self) -> &'static str {
        "https://api.github.com"
    }

    /// Get Steam OpenID 2.0 endpoint.
    pub fn steam_openid_url(&self) -> &'static str {
        "https://steamcommunity.com/openid/login"
    }

    /// Get Steam Web API base URL.
    pub fn steam_api_url(&self) -> &'static str {
        "https://api.steampowered.com"
    }

    /// Get Bluesky OAuth2 authorization URL.
    pub fn bluesky_auth_url(&self) -> &'static str {
        "https://bsky.social/oauth/authorize"
    }

    /// Get Bluesky OAuth2 token URL.
    pub fn bluesky_token_url(&self) -> &'static str {
        "https://bsky.social/oauth/token"
    }

    /// Get Bluesky API base URL.
    pub fn bluesky_api_url(&self) -> &'static str {
        "https://bsky.social/xrpc"
    }

    /// Get Microsoft OAuth2 authorization URL (for Xbox Live).
    pub fn xbox_auth_url(&self) -> &'static str {
        "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize"
    }

    /// Get Microsoft OAuth2 token URL (for Xbox Live).
    pub fn xbox_token_url(&self) -> &'static str {
        "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
    }

    /// Get Xbox Live user authentication URL.
    pub fn xbox_user_auth_url(&self) -> &'static str {
        "https://user.auth.xboxlive.com/user/authenticate"
    }

    /// Get Xbox Live XSTS authorization URL.
    pub fn xbox_xsts_url(&self) -> &'static str {
        "https://xsts.auth.xboxlive.com/xsts/authorize"
    }

    /// Get Xbox Live profile URL.
    pub fn xbox_profile_url(&self) -> &'static str {
        "https://profile.xboxlive.com/users/me/profile/settings"
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

/// Discord OAuth2 scopes required for user identification.
/// - identify: Access username, avatar, discriminator
/// - connections: Access connected accounts (optional, for future use)
pub const DISCORD_SCOPES: &[&str] = &["identify", "connections"];

/// Discord OAuth2 scopes required for community import.
/// - identify: Access username, avatar, discriminator
/// - guilds: Access list of user's guilds (servers)
pub const DISCORD_COMMUNITY_IMPORT_SCOPES: &[&str] = &["identify", "guilds"];

/// GitHub OAuth2 scopes required for user identification.
pub const GITHUB_SCOPES: &[&str] = &["read:user"];

/// Bluesky OAuth2 scopes.
pub const BLUESKY_SCOPES: &[&str] = &["atproto", "transition:generic"];

/// Xbox (Microsoft) OAuth2 scopes.
pub const XBOX_SCOPES: &[&str] = &["XboxLive.signin", "XboxLive.offline_access"];

/// OAuth state TTL in seconds (30 minutes).
pub const OAUTH_STATE_TTL_SECS: i64 = 1800;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DiscoveryConfig::default();
        // Without env vars, OAuth should be disabled
        assert!(!config.discord_enabled());
        assert!(!config.github_enabled());
        assert!(!config.steam_enabled());
        assert!(!config.bluesky_enabled());
        assert!(!config.xbox_enabled());
    }

    #[test]
    fn test_oauth_urls() {
        let config = DiscoveryConfig::default();
        assert!(config.discord_auth_url().starts_with("https://"));
        assert!(config.github_auth_url().starts_with("https://"));
        assert!(config.steam_openid_url().starts_with("https://"));
        assert!(config.bluesky_auth_url().starts_with("https://"));
        assert!(config.xbox_auth_url().starts_with("https://"));
    }
}
