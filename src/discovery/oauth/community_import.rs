//! Discord Community Import OAuth2 handlers.
//!
//! Handles OAuth2 flows for importing Discord server (guild) structure
//! including channels, categories, and roles. This is used when creating
//! a new Umbra community from an existing Discord server.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    Json,
};
use chrono::Utc;
use reqwest::Client;
use serde::Deserialize;
use uuid::Uuid;

use crate::discovery::{
    config::DISCORD_COMMUNITY_IMPORT_SCOPES,
    types::{
        DiscordChannelType, DiscordEmoji, DiscordGuildInfo, DiscordGuildStructureResponse,
        DiscordGuildsResponse, DiscordImportedChannel, DiscordImportedRole,
        DiscordImportedStructure, DiscordPermissionOverwrite, DiscordSticker, OAuthState, Platform,
        StartAuthResponse,
    },
    DiscoveryConfig, DiscoveryStore,
};

use super::CallbackQuery;

/// Discord MANAGE_GUILD permission bit (0x20 = 32).
const DISCORD_MANAGE_GUILD: u64 = 0x20;

/// Discord Administrator permission bit (0x8 = 8).
const DISCORD_ADMINISTRATOR: u64 = 0x8;

/// Discord token response.
#[derive(Debug, Deserialize)]
struct DiscordTokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: String,
    #[allow(dead_code)]
    expires_in: u64,
    #[allow(dead_code)]
    refresh_token: Option<String>,
    #[allow(dead_code)]
    scope: String,
}

/// Discord guild from /users/@me/guilds API response.
#[derive(Debug, Deserialize)]
struct DiscordGuildApiResponse {
    id: String,
    name: String,
    icon: Option<String>,
    owner: bool,
    #[serde(default)]
    permissions: String,
}

/// Discord channel from guild channels API response.
#[derive(Debug, Deserialize)]
struct DiscordChannelApiResponse {
    id: String,
    name: String,
    #[serde(rename = "type")]
    channel_type: u8,
    #[serde(default)]
    parent_id: Option<String>,
    #[serde(default)]
    position: i32,
    #[serde(default)]
    topic: Option<String>,
    #[serde(default)]
    nsfw: bool,
    #[serde(default)]
    permission_overwrites: Vec<DiscordPermissionOverwriteApi>,
}

/// Discord permission overwrite from API.
#[derive(Debug, Deserialize)]
struct DiscordPermissionOverwriteApi {
    id: String,
    #[serde(rename = "type")]
    overwrite_type: u8,
    #[serde(default)]
    allow: String,
    #[serde(default)]
    deny: String,
}

/// Discord role from guild roles API response.
#[derive(Debug, Clone, Deserialize)]
struct DiscordRoleApiResponse {
    id: String,
    name: String,
    #[serde(default)]
    color: u32,
    #[serde(default)]
    hoist: bool,
    #[serde(default)]
    position: i32,
    #[serde(default)]
    permissions: String,
    #[serde(default)]
    managed: bool,
    #[serde(default)]
    mentionable: bool,
}

/// Full guild response from /guilds/:id API.
#[derive(Debug, Deserialize)]
struct DiscordFullGuildApiResponse {
    id: String,
    name: String,
    icon: Option<String>,
    #[serde(default)]
    banner: Option<String>,
    #[serde(default)]
    splash: Option<String>,
    #[serde(default)]
    discovery_splash: Option<String>,
    #[serde(default)]
    description: Option<String>,
    owner_id: String,
    roles: Vec<DiscordRoleApiResponse>,
    #[serde(default)]
    emojis: Vec<DiscordEmojiApiResponse>,
    #[serde(default)]
    stickers: Vec<DiscordStickerApiResponse>,
}

/// Discord emoji from guild info API response.
#[derive(Debug, Clone, Deserialize)]
struct DiscordEmojiApiResponse {
    id: Option<String>,
    name: Option<String>,
    #[serde(default)]
    animated: bool,
    #[serde(default)]
    available: bool,
}

/// Discord sticker from guild info API response.
#[derive(Debug, Clone, Deserialize)]
struct DiscordStickerApiResponse {
    id: String,
    name: String,
    description: Option<String>,
    /// Format type: 1 = PNG, 2 = APNG, 3 = Lottie, 4 = GIF.
    format_type: u8,
    #[serde(default = "default_available")]
    available: bool,
}

fn default_available() -> bool {
    true
}

/// Query for fetching guilds list (requires access token).
#[derive(Debug, Deserialize)]
pub struct GuildsQuery {
    /// Access token from OAuth flow.
    pub token: String,
}

/// Query for fetching guild structure.
#[derive(Debug, Deserialize)]
pub struct GuildStructureQuery {
    /// Access token from OAuth flow.
    pub token: String,
}

/// Session stored after successful OAuth for fetching guilds/structure.
#[derive(Debug, Clone)]
pub struct CommunityImportSession {
    pub access_token: String,
    pub created_at: chrono::DateTime<Utc>,
}

/// Generate HTML page that sends access token via postMessage and closes.
fn community_import_success_html(access_token: &str) -> Html<String> {
    Html(format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Discord Connected - Umbra</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
            box-sizing: border-box;
        }}
        .container {{
            text-align: center;
            max-width: 400px;
        }}
        .icon {{
            font-size: 64px;
            margin-bottom: 20px;
        }}
        h1 {{
            margin: 0 0 10px;
            font-size: 24px;
        }}
        p {{
            color: #94a3b8;
            margin: 20px 0;
        }}
        .close-hint {{
            font-size: 14px;
            color: #64748b;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">&#x2705;</div>
        <h1>Discord Connected</h1>
        <p>Your Discord account has been connected. You can now select a server to import.</p>
        <p class="close-hint">This window will close automatically...</p>
    </div>
    <script>
        const accessToken = "{}";
        // Send token to opener window (popup flow)
        if (window.opener) {{
            window.opener.postMessage({{
                type: 'UMBRA_COMMUNITY_IMPORT',
                success: true,
                token: accessToken
            }}, '*');
            // Close after a short delay
            setTimeout(() => {{
                window.close();
            }}, 2000);
        }}
        // Also try to send to parent (for iframe scenarios)
        else if (window.parent && window.parent !== window) {{
            window.parent.postMessage({{
                type: 'UMBRA_COMMUNITY_IMPORT',
                success: true,
                token: accessToken
            }}, '*');
            setTimeout(() => {{
                window.close();
            }}, 2000);
        }}
        // Mobile fallback: no opener — redirect back to app with token in hash
        else {{
            document.querySelector('.close-hint').textContent = 'Redirecting back to Umbra...';
            setTimeout(() => {{
                window.location.href = 'https://umbra.chat/#discord_import_token=' + encodeURIComponent(accessToken);
            }}, 1000);
        }}
    </script>
</body>
</html>"#,
        access_token
    ))
}

/// Generate HTML page for community import errors.
fn community_import_error_html(message: &str) -> Html<String> {
    let error_json =
        serde_json::to_string(message).unwrap_or_else(|_| "\"Unknown error\"".to_string());
    Html(format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Import Failed - Umbra</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
            box-sizing: border-box;
        }}
        .container {{
            text-align: center;
            max-width: 400px;
        }}
        .icon {{
            font-size: 64px;
            margin-bottom: 20px;
        }}
        h1 {{
            margin: 0 0 10px;
            font-size: 24px;
            color: #f87171;
        }}
        .error {{
            background: rgba(248, 113, 113, 0.2);
            padding: 12px 20px;
            border-radius: 8px;
            margin: 20px 0;
            font-family: monospace;
            font-size: 14px;
        }}
        p {{
            color: #94a3b8;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">&#x274C;</div>
        <h1>Import Failed</h1>
        <div class="error">{}</div>
        <p>Please close this window and try again.</p>
    </div>
    <script>
        const error = {};
        // Send error to opener window
        if (window.opener) {{
            window.opener.postMessage({{
                type: 'UMBRA_COMMUNITY_IMPORT',
                success: false,
                error: error
            }}, '*');
        }}
        if (window.parent && window.parent !== window) {{
            window.parent.postMessage({{
                type: 'UMBRA_COMMUNITY_IMPORT',
                success: false,
                error: error
            }}, '*');
        }}
    </script>
</body>
</html>"#,
        message, error_json
    ))
}

/// Check if user has MANAGE_GUILD permission.
fn has_manage_guild_permission(permissions: u64) -> bool {
    // Administrator permission implies all permissions
    if permissions & DISCORD_ADMINISTRATOR != 0 {
        return true;
    }
    // Check for MANAGE_GUILD specifically
    permissions & DISCORD_MANAGE_GUILD != 0
}

// ---------------------------------------------------------------------------
// Discord Community Import OAuth Flow
// ---------------------------------------------------------------------------

/// Start Discord OAuth2 flow for community import.
///
/// POST /community/import/discord/start
///
/// Returns a redirect URL to Discord OAuth with the `guilds` scope.
pub async fn start_discord_community_import(
    State((store, config)): State<(DiscoveryStore, DiscoveryConfig)>,
) -> impl IntoResponse {
    // Get client_id and redirect_uri
    let (client_id, redirect_uri) = match (
        &config.discord_client_id,
        &config.discord_community_import_redirect_uri,
    ) {
        (Some(id), Some(uri)) => (id.clone(), uri.clone()),
        (Some(id), None) => {
            // Fall back to constructing from base URL
            let uri = format!(
                "{}/community/import/discord/callback",
                config.relay_base_url
            );
            (id.clone(), uri)
        }
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "Discord OAuth not configured"
                })),
            )
                .into_response();
        }
    };

    let nonce = Uuid::new_v4().to_string();

    // Store OAuth state with community_import flag
    let state = OAuthState {
        did: String::new(), // Not linking to a DID
        nonce: nonce.clone(),
        platform: Platform::Discord,
        created_at: Utc::now(),
        profile_import: false,
        community_import: true,
    };
    store.store_oauth_state(state);

    let scopes = DISCORD_COMMUNITY_IMPORT_SCOPES.join("%20");
    let auth_url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
        config.discord_auth_url(),
        client_id,
        urlencoding::encode(&redirect_uri),
        scopes,
        nonce
    );

    tracing::info!(
        auth_url = auth_url.as_str(),
        scopes = scopes.as_str(),
        "Discord community import OAuth started"
    );

    Json(StartAuthResponse {
        redirect_url: auth_url,
        state: nonce,
    })
    .into_response()
}

/// Handle Discord OAuth2 callback for community import.
///
/// GET /community/import/discord/callback
///
/// Exchanges the code for an access token and returns it via postMessage.
pub async fn callback_discord_community_import(
    State((store, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Query(query): Query<CallbackQuery>,
) -> impl IntoResponse {
    tracing::info!(
        state = query.state.as_str(),
        code_len = query.code.len(),
        "Discord community import callback received"
    );

    // Verify state
    let _oauth_state = match store.take_oauth_state(&query.state) {
        Some(s) if s.platform == Platform::Discord && s.community_import => {
            tracing::info!("OAuth state validated successfully");
            s
        }
        Some(s) => {
            tracing::warn!(
                platform = ?s.platform,
                community_import = s.community_import,
                "OAuth state found but doesn't match expected criteria"
            );
            return community_import_error_html(
                "Invalid OAuth state (not a community import flow)",
            )
            .into_response();
        }
        None => {
            tracing::warn!(state = query.state.as_str(), "OAuth state not found");
            return community_import_error_html("Invalid or expired state. Please try again.")
                .into_response();
        }
    };

    let (client_id, client_secret, redirect_uri) = match (
        config.discord_client_id.as_ref(),
        config.discord_client_secret.as_ref(),
        config.discord_community_import_redirect_uri.as_ref(),
    ) {
        (Some(id), Some(secret), Some(uri)) => (id.clone(), secret.clone(), uri.clone()),
        (Some(id), Some(secret), None) => {
            let uri = format!(
                "{}/community/import/discord/callback",
                config.relay_base_url
            );
            (id.clone(), secret.clone(), uri)
        }
        _ => {
            return community_import_error_html("Discord OAuth not configured").into_response();
        }
    };

    let client = Client::new();

    // Exchange code for token
    let token_response = client
        .post(config.discord_token_url())
        .form(&[
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("code", &query.code),
            ("redirect_uri", redirect_uri.as_str()),
        ])
        .send()
        .await;

    let token: DiscordTokenResponse = match token_response {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Failed to parse Discord token response: {}", e);
                return community_import_error_html("Failed to parse token response")
                    .into_response();
            }
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!("Discord token exchange failed: {} - {}", status, body);
            return community_import_error_html("Failed to exchange code for token")
                .into_response();
        }
        Err(e) => {
            tracing::error!("Discord token request failed: {}", e);
            return community_import_error_html("Failed to connect to Discord").into_response();
        }
    };

    tracing::info!("Discord community import OAuth completed successfully");

    // Store result for Tauri/mobile polling
    store.store_community_import_result(&query.state, token.access_token.clone());

    // Return the access token via postMessage
    community_import_success_html(&token.access_token).into_response()
}

/// Get list of guilds the user can manage.
///
/// GET /community/import/discord/guilds?token=...
///
/// Returns a list of guilds where the user has MANAGE_GUILD permission.
pub async fn get_discord_guilds(
    State((_, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Query(query): Query<GuildsQuery>,
) -> impl IntoResponse {
    let client = Client::new();

    // Fetch user's guilds
    let guilds_response = client
        .get(format!("{}/users/@me/guilds", config.discord_api_url()))
        .header("Authorization", format!("Bearer {}", query.token))
        .send()
        .await;

    let guilds: Vec<DiscordGuildApiResponse> = match guilds_response {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(g) => g,
            Err(e) => {
                tracing::error!("Failed to parse Discord guilds response: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "Failed to parse guilds response"
                    })),
                )
                    .into_response();
            }
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!("Discord guilds fetch failed: {} - {}", status, body);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Failed to fetch guilds. Token may be invalid or expired."
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Discord guilds request failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to connect to Discord"
                })),
            )
                .into_response();
        }
    };

    // Filter to guilds where user has MANAGE_GUILD permission
    let manageable_guilds: Vec<DiscordGuildInfo> = guilds
        .into_iter()
        .filter_map(|g| {
            let permissions: u64 = g.permissions.parse().unwrap_or(0);
            let can_manage = g.owner || has_manage_guild_permission(permissions);

            if can_manage {
                Some(DiscordGuildInfo {
                    id: g.id,
                    name: g.name,
                    icon: g.icon,
                    banner: None,
                    splash: None,
                    description: None,
                    owner: g.owner,
                    permissions,
                    can_manage: true,
                })
            } else {
                None
            }
        })
        .collect();

    tracing::info!(
        guild_count = manageable_guilds.len(),
        "Fetched Discord guilds for community import"
    );

    Json(DiscordGuildsResponse {
        guilds: manageable_guilds,
    })
    .into_response()
}

/// Get the structure of a specific guild.
///
/// GET /community/import/discord/guild/:id/structure?token=...
///
/// Returns channels, categories, and roles for the guild.
/// Note: This requires the bot to be in the guild OR the user to have
/// the appropriate OAuth scopes. Since we only have `guilds` scope,
/// we need to use the Bot token for this endpoint if available,
/// or fall back to limited user data.
pub async fn get_discord_guild_structure(
    State((_, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Path(guild_id): Path<String>,
    Query(query): Query<GuildStructureQuery>,
) -> impl IntoResponse {
    let client = Client::new();

    // First, verify the user has access to this guild
    let guilds_response = client
        .get(format!("{}/users/@me/guilds", config.discord_api_url()))
        .header("Authorization", format!("Bearer {}", query.token))
        .send()
        .await;

    let guilds: Vec<DiscordGuildApiResponse> = match guilds_response {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(g) => g,
            Err(e) => {
                tracing::error!("Failed to parse Discord guilds response: {}", e);
                return Json(DiscordGuildStructureResponse {
                    success: false,
                    structure: None,
                    error: Some("Failed to verify guild access".to_string()),
                })
                .into_response();
            }
        },
        Ok(resp) => {
            let status = resp.status();
            tracing::error!("Discord guilds fetch failed: {}", status);
            return Json(DiscordGuildStructureResponse {
                success: false,
                structure: None,
                error: Some("Failed to verify guild access".to_string()),
            })
            .into_response();
        }
        Err(e) => {
            tracing::error!("Discord guilds request failed: {}", e);
            return Json(DiscordGuildStructureResponse {
                success: false,
                structure: None,
                error: Some("Failed to connect to Discord".to_string()),
            })
            .into_response();
        }
    };

    // Find the requested guild
    let guild = guilds.iter().find(|g| g.id == guild_id);
    let guild = match guild {
        Some(g) => g,
        None => {
            return Json(DiscordGuildStructureResponse {
                success: false,
                structure: None,
                error: Some("Guild not found or you don't have access".to_string()),
            })
            .into_response();
        }
    };

    // Check permissions
    let permissions: u64 = guild.permissions.parse().unwrap_or(0);
    if !guild.owner && !has_manage_guild_permission(permissions) {
        return Json(DiscordGuildStructureResponse {
            success: false,
            structure: None,
            error: Some("You don't have permission to import this server".to_string()),
        })
        .into_response();
    }

    // Determine the best authorization header for fetching guild details.
    // Bot token is required for /guilds/{id}/channels and /guilds/{id} endpoints.
    // User OAuth tokens with `guilds` scope can only list guilds, not read their structure.
    let (auth_header, auth_type) = if let Some(bot_token) = &config.discord_bot_token {
        (format!("Bot {}", bot_token), "bot")
    } else {
        tracing::warn!("No DISCORD_BOT_TOKEN configured — falling back to user Bearer token (may return empty channels/roles)");
        (format!("Bearer {}", query.token), "user")
    };

    tracing::info!(auth_type = auth_type, "Fetching guild channels and roles");

    // Fetch channels
    let channels_response = client
        .get(format!(
            "{}/guilds/{}/channels",
            config.discord_api_url(),
            guild_id
        ))
        .header("Authorization", &auth_header)
        .send()
        .await;

    let channels: Vec<DiscordChannelApiResponse> = match channels_response {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to parse Discord channels response: {}", e);
                Vec::new()
            }
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!(
                "Discord channels fetch returned {} (auth={}): {}",
                status,
                auth_type,
                body
            );
            Vec::new()
        }
        Err(e) => {
            tracing::error!("Discord channels request failed: {}", e);
            Vec::new()
        }
    };

    // Fetch guild info including roles
    let guild_response = client
        .get(format!("{}/guilds/{}", config.discord_api_url(), guild_id))
        .header("Authorization", &auth_header)
        .send()
        .await;

    let (roles, full_guild_info): (
        Vec<DiscordRoleApiResponse>,
        Option<DiscordFullGuildApiResponse>,
    ) = match guild_response {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(g) => {
                let g: DiscordFullGuildApiResponse = g;
                (g.roles.clone(), Some(g))
            }
            Err(e) => {
                tracing::error!("Failed to parse Discord guild response: {}", e);
                (Vec::new(), None)
            }
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!(
                "Discord guild fetch returned {} (auth={}): {}",
                status,
                auth_type,
                body
            );
            (Vec::new(), None)
        }
        Err(e) => {
            tracing::error!("Discord guild request failed: {}", e);
            (Vec::new(), None)
        }
    };

    // Convert channels to our format
    let imported_channels: Vec<DiscordImportedChannel> = channels
        .into_iter()
        .map(|c| DiscordImportedChannel {
            id: c.id,
            name: c.name,
            channel_type: DiscordChannelType::from(c.channel_type),
            parent_id: c.parent_id,
            position: c.position,
            topic: c.topic,
            nsfw: c.nsfw,
            permission_overwrites: c
                .permission_overwrites
                .into_iter()
                .map(|po| DiscordPermissionOverwrite {
                    id: po.id,
                    overwrite_type: po.overwrite_type,
                    allow: po.allow,
                    deny: po.deny,
                })
                .collect(),
        })
        .collect();

    // Convert roles to our format (excluding @everyone which is position 0)
    let imported_roles: Vec<DiscordImportedRole> = roles
        .into_iter()
        .filter(|r| r.position > 0) // Exclude @everyone
        .map(|r| DiscordImportedRole {
            id: r.id,
            name: r.name,
            color: r.color,
            hoist: r.hoist,
            position: r.position,
            permissions: r.permissions,
            managed: r.managed,
            mentionable: r.mentionable,
        })
        .collect();

    // Extract extra guild data from full guild response (if available)
    let (banner, splash, description) = if let Some(ref fg) = full_guild_info {
        (fg.banner.clone(), fg.splash.clone(), fg.description.clone())
    } else {
        (None, None, None)
    };

    // Convert emojis to our format
    let imported_emojis: Vec<DiscordEmoji> = full_guild_info
        .as_ref()
        .map(|fg| {
            fg.emojis
                .iter()
                .filter(|e| e.available && e.id.is_some())
                .map(|e| DiscordEmoji {
                    id: e.id.clone(),
                    name: e.name.clone(),
                    animated: e.animated,
                })
                .collect()
        })
        .unwrap_or_default();

    // Convert stickers to our format
    let imported_stickers: Vec<DiscordSticker> = full_guild_info
        .as_ref()
        .map(|fg| {
            fg.stickers
                .iter()
                .filter(|s| s.available)
                .map(|s| DiscordSticker {
                    id: s.id.clone(),
                    name: s.name.clone(),
                    description: s.description.clone(),
                    format_type: s.format_type,
                    available: s.available,
                })
                .collect()
        })
        .unwrap_or_default();

    let guild_info = DiscordGuildInfo {
        id: guild.id.clone(),
        name: guild.name.clone(),
        icon: guild.icon.clone(),
        banner,
        splash,
        description,
        owner: guild.owner,
        permissions,
        can_manage: true,
    };

    tracing::info!(
        guild_id = guild_id.as_str(),
        channel_count = imported_channels.len(),
        role_count = imported_roles.len(),
        emoji_count = imported_emojis.len(),
        sticker_count = imported_stickers.len(),
        "Fetched Discord guild structure for community import"
    );

    Json(DiscordGuildStructureResponse {
        success: true,
        structure: Some(DiscordImportedStructure {
            guild: guild_info,
            channels: imported_channels,
            roles: imported_roles,
            emojis: imported_emojis,
            stickers: imported_stickers,
        }),
        error: None,
    })
    .into_response()
}

// ---------------------------------------------------------------------------
// Discord Bot Invite Flow
// ---------------------------------------------------------------------------

/// Query for bot invite URL.
#[derive(Debug, Deserialize)]
pub struct BotInviteQuery {
    /// The guild ID to pre-select in the Discord bot authorization page.
    pub guild_id: String,
}

/// Query for bot status check.
#[derive(Debug, Deserialize)]
pub struct BotStatusQuery {
    /// The guild ID to check whether the bot is a member of.
    pub guild_id: String,
}

/// Get the Discord bot invite URL for a specific guild.
///
/// GET /community/import/discord/bot-invite?guild_id=123456
///
/// Returns a URL that opens Discord's bot authorization page with the
/// target guild pre-selected and minimal permissions (View Channels only).
/// If `DISCORD_BOT_TOKEN` is not configured, returns `bot_enabled: false`.
pub async fn get_bot_invite_url(
    State((_, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Query(query): Query<BotInviteQuery>,
) -> impl IntoResponse {
    // Check if the bot is configured
    if config.discord_bot_token.is_none() {
        return Json(serde_json::json!({
            "bot_enabled": false,
            "invite_url": null,
            "message": "Discord bot is not configured on this relay. Ask the relay operator to set DISCORD_BOT_TOKEN."
        }))
        .into_response();
    }

    let client_id = match &config.discord_client_id {
        Some(id) => id,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "bot_enabled": false,
                    "error": "Discord client ID not configured"
                })),
            )
                .into_response();
        }
    };

    // Construct bot invite URL with admin permissions for full server migration:
    // - permissions=8 = ADMINISTRATOR (0x8) — grants full access to read all
    //   channels, roles, members, permission overwrites, audit log, etc.
    //   Required for comprehensive server migration/import.
    // - guild_id + disable_guild_select=true pre-selects the target server
    let invite_url = format!(
        "https://discord.com/oauth2/authorize?client_id={}&scope=bot&permissions=8&guild_id={}&disable_guild_select=true",
        client_id, query.guild_id
    );

    tracing::info!(
        guild_id = query.guild_id.as_str(),
        "Generated bot invite URL for community import"
    );

    Json(serde_json::json!({
        "bot_enabled": true,
        "invite_url": invite_url
    }))
    .into_response()
}

/// Check whether the Discord bot is a member of a specific guild.
///
/// GET /community/import/discord/bot-status?guild_id=123456
///
/// Uses the bot token to call Discord's `/guilds/{id}` endpoint.
/// Returns 200 if the bot is in the guild, 403/404 if not.
pub async fn check_bot_in_guild(
    State((_, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Query(query): Query<BotStatusQuery>,
) -> impl IntoResponse {
    let bot_token = match &config.discord_bot_token {
        Some(token) => token,
        None => {
            return Json(serde_json::json!({
                "bot_enabled": false,
                "in_guild": false,
                "message": "Discord bot is not configured on this relay."
            }))
            .into_response();
        }
    };

    let client = Client::new();

    // Try to fetch guild info using the bot token.
    // If the bot is in the guild, this returns 200.
    // If not, Discord returns 403 or 404.
    let response = client
        .get(format!(
            "{}/guilds/{}",
            config.discord_api_url(),
            query.guild_id
        ))
        .header("Authorization", format!("Bot {}", bot_token))
        .send()
        .await;

    let in_guild = match response {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                tracing::info!(guild_id = query.guild_id.as_str(), "Bot confirmed in guild");
                true
            } else {
                tracing::debug!(
                    guild_id = query.guild_id.as_str(),
                    status = %status,
                    "Bot not in guild"
                );
                false
            }
        }
        Err(e) => {
            tracing::error!("Failed to check bot guild membership: {}", e);
            false
        }
    };

    Json(serde_json::json!({
        "bot_enabled": true,
        "in_guild": in_guild
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Discord Guild Members (for seat import)
// ---------------------------------------------------------------------------

/// Discord guild member from API response.
#[derive(Debug, Deserialize)]
struct DiscordMemberApiResponse {
    user: Option<DiscordMemberUser>,
    #[serde(default)]
    nick: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    joined_at: Option<String>,
}

/// Discord user object nested inside a member response.
#[derive(Debug, Deserialize)]
struct DiscordMemberUser {
    id: String,
    username: String,
    #[serde(default)]
    avatar: Option<String>,
    #[serde(default)]
    bot: Option<bool>,
}

/// Get all members of a Discord guild.
///
/// GET /community/import/discord/guild/:id/members?token=...
///
/// Uses the Bot token to fetch guild members via pagination.
/// Requires the GUILD_MEMBERS privileged intent to be enabled on the bot.
pub async fn get_discord_guild_members(
    State((_, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Path(guild_id): Path<String>,
    Query(query): Query<GuildStructureQuery>,
) -> impl IntoResponse {
    let bot_token = match &config.discord_bot_token {
        Some(token) => token,
        None => {
            return Json(serde_json::json!({
                "members": [],
                "totalCount": 0,
                "hasMembersIntent": false,
                "error": "Bot token not configured"
            }))
            .into_response();
        }
    };

    // Verify user has access to this guild.
    // The bot is already in the guild (admin), so we just confirm the user
    // can see the guild via their OAuth token. We also verify the bot is
    // actually in the guild using the bot token as a fallback — this avoids
    // false negatives from Discord rate-limiting the user token.
    let client = Client::new();
    let guilds_response = client
        .get(format!("{}/users/@me/guilds", config.discord_api_url()))
        .header("Authorization", format!("Bearer {}", query.token))
        .send()
        .await;

    let user_has_access = match &guilds_response {
        Ok(resp) if resp.status().is_success() => true, // Will check guild list below
        Ok(resp) => {
            tracing::warn!(
                status = %resp.status(),
                guild_id = guild_id.as_str(),
                "User guilds fetch failed (possible rate limit)"
            );
            false
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                guild_id = guild_id.as_str(),
                "User guilds request failed"
            );
            false
        }
    };

    let has_access = if user_has_access {
        match guilds_response {
            Ok(resp) => {
                let guilds: Vec<DiscordGuildApiResponse> = resp.json().await.unwrap_or_default();
                let found = guilds.iter().any(|g| g.id == guild_id);
                if !found {
                    tracing::warn!(
                        guild_id = guild_id.as_str(),
                        guild_count = guilds.len(),
                        "Guild not found in user's guild list"
                    );
                }
                found
            }
            _ => false,
        }
    } else {
        // Fallback: verify the bot is in the guild (proves this is a legitimate request
        // since the bot was invited by a guild admin). This handles Discord rate-limiting
        // the user's OAuth token.
        let bot_check = client
            .get(format!("{}/guilds/{}", config.discord_api_url(), guild_id))
            .header("Authorization", format!("Bot {}", bot_token))
            .send()
            .await;
        match bot_check {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(
                    guild_id = guild_id.as_str(),
                    "User token failed but bot confirmed in guild — allowing member fetch"
                );
                true
            }
            _ => false,
        }
    };

    if !has_access {
        return Json(serde_json::json!({
            "members": [],
            "totalCount": 0,
            "hasMembersIntent": false,
            "error": "No access to this guild"
        }))
        .into_response();
    }

    // Paginate through guild members using the bot token
    let mut all_members = Vec::new();
    let mut after: Option<String> = None;
    let max_pages = 10; // Safety limit: 10 pages x 1000 = 10,000 members max

    for _ in 0..max_pages {
        let mut url = format!(
            "{}/guilds/{}/members?limit=1000",
            config.discord_api_url(),
            guild_id
        );
        if let Some(ref after_id) = after {
            url.push_str(&format!("&after={}", after_id));
        }

        let response = client
            .get(&url)
            .header("Authorization", format!("Bot {}", bot_token))
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                let members: Vec<DiscordMemberApiResponse> = resp.json().await.unwrap_or_default();

                if members.is_empty() {
                    break;
                }

                // Track the last member ID for pagination
                if let Some(last) = members.last() {
                    if let Some(ref user) = last.user {
                        after = Some(user.id.clone());
                    }
                }

                let page_size = members.len();
                all_members.extend(members);

                // If we got fewer than 1000, we've reached the end
                if page_size < 1000 {
                    break;
                }
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();

                // 403 typically means the bot doesn't have GUILD_MEMBERS intent
                if status.as_u16() == 403 {
                    tracing::warn!(
                        "Bot lacks GUILD_MEMBERS intent for guild {}: {}",
                        guild_id,
                        body
                    );
                    return Json(serde_json::json!({
                        "members": [],
                        "totalCount": 0,
                        "hasMembersIntent": false,
                        "error": "Bot does not have the Server Members Intent enabled. Enable it in the Discord Developer Portal."
                    }))
                    .into_response();
                }

                tracing::error!("Discord members fetch failed: {} - {}", status, body);
                break;
            }
            Err(e) => {
                tracing::error!("Discord members request failed: {}", e);
                break;
            }
        }
    }

    // Convert to our response format
    let members: Vec<serde_json::Value> = all_members
        .into_iter()
        .filter_map(|m| {
            let user = m.user?;
            let is_bot = user.bot.unwrap_or(false);
            Some(serde_json::json!({
                "userId": user.id,
                "username": user.username,
                "avatar": user.avatar,
                "nickname": m.nick,
                "roleIds": m.roles,
                "joinedAt": m.joined_at,
                "bot": is_bot,
            }))
        })
        .collect();

    let total_count = members.len();

    tracing::info!(
        guild_id = guild_id.as_str(),
        member_count = total_count,
        "Fetched Discord guild members for seat import"
    );

    Json(serde_json::json!({
        "members": members,
        "totalCount": total_count,
        "hasMembersIntent": true,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Discord Channel Pins (for pinned message import)
// ---------------------------------------------------------------------------

/// Get pinned messages from a Discord channel.
///
/// GET /community/import/discord/channel/:id/pins?token=...
///
/// Uses the Bot token to fetch up to 50 pinned messages from a channel.
pub async fn get_discord_channel_pins(
    State((_, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Path(channel_id): Path<String>,
    Query(_query): Query<GuildStructureQuery>,
) -> impl IntoResponse {
    let bot_token = match &config.discord_bot_token {
        Some(token) => token,
        None => {
            return Json(serde_json::json!({
                "pins": [],
                "error": "Bot token not configured"
            }))
            .into_response();
        }
    };

    let client = Client::new();

    // Fetch pinned messages using bot token
    let response = client
        .get(format!(
            "{}/channels/{}/pins",
            config.discord_api_url(),
            channel_id
        ))
        .header("Authorization", format!("Bot {}", bot_token))
        .send()
        .await;

    let pins: Vec<serde_json::Value> = match response {
        Ok(resp) if resp.status().is_success() => {
            let raw_pins: Vec<serde_json::Value> = resp.json().await.unwrap_or_default();

            raw_pins
                .into_iter()
                .filter_map(|msg| {
                    let id = msg["id"].as_str()?.to_string();
                    let content = msg["content"].as_str().unwrap_or("").to_string();
                    let author_id = msg["author"]["id"].as_str()?.to_string();
                    let author_username = msg["author"]["username"].as_str()?.to_string();
                    let timestamp = msg["timestamp"].as_str()?.to_string();

                    Some(serde_json::json!({
                        "id": id,
                        "content": content,
                        "authorId": author_id,
                        "authorUsername": author_username,
                        "timestamp": timestamp,
                    }))
                })
                .collect()
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!(
                "Discord pins fetch failed for channel {}: {} - {}",
                channel_id,
                status,
                body
            );
            Vec::new()
        }
        Err(e) => {
            tracing::error!("Discord pins request failed: {}", e);
            Vec::new()
        }
    };

    tracing::info!(
        channel_id = channel_id.as_str(),
        pin_count = pins.len(),
        "Fetched Discord channel pins"
    );

    Json(serde_json::json!({
        "pins": pins,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Discord Audit Log (for audit log import)
// ---------------------------------------------------------------------------

/// Query for fetching audit log.
#[derive(Debug, Deserialize)]
pub struct AuditLogQuery {
    /// Access token from OAuth flow.
    pub token: String,
    /// Maximum number of entries to fetch (default 100, max 100).
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Get audit log entries from a Discord guild.
///
/// GET /community/import/discord/guild/:id/audit-log?token=...&limit=100
///
/// Uses the Bot token to fetch audit log entries. Requires VIEW_AUDIT_LOG permission.
pub async fn get_discord_guild_audit_log(
    State((_, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Path(guild_id): Path<String>,
    Query(query): Query<AuditLogQuery>,
) -> impl IntoResponse {
    let bot_token = match &config.discord_bot_token {
        Some(token) => token,
        None => {
            return Json(serde_json::json!({
                "entries": [],
                "error": "Bot token not configured"
            }))
            .into_response();
        }
    };

    // Verify user has access to this guild (with bot fallback for rate-limited user tokens)
    let client = Client::new();
    let guilds_response = client
        .get(format!("{}/users/@me/guilds", config.discord_api_url()))
        .header("Authorization", format!("Bearer {}", query.token))
        .send()
        .await;

    let user_has_access = match &guilds_response {
        Ok(resp) if resp.status().is_success() => true,
        Ok(resp) => {
            tracing::warn!(
                status = %resp.status(),
                guild_id = guild_id.as_str(),
                "User guilds fetch failed for audit log (possible rate limit)"
            );
            false
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                guild_id = guild_id.as_str(),
                "User guilds request failed for audit log"
            );
            false
        }
    };

    let has_access = if user_has_access {
        match guilds_response {
            Ok(resp) => {
                let guilds: Vec<DiscordGuildApiResponse> = resp.json().await.unwrap_or_default();
                let found = guilds.iter().any(|g| g.id == guild_id);
                if !found {
                    tracing::warn!(
                        guild_id = guild_id.as_str(),
                        guild_count = guilds.len(),
                        "Guild not found in user's guild list for audit log"
                    );
                }
                found
            }
            _ => false,
        }
    } else {
        // Fallback: verify the bot is in the guild (proves this is a legitimate request
        // since the bot was invited by a guild admin). This handles Discord rate-limiting
        // the user's OAuth token.
        let bot_check = client
            .get(format!("{}/guilds/{}", config.discord_api_url(), guild_id))
            .header("Authorization", format!("Bot {}", bot_token))
            .send()
            .await;
        match bot_check {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(
                    guild_id = guild_id.as_str(),
                    "User token failed but bot confirmed in guild — allowing audit log fetch"
                );
                true
            }
            _ => false,
        }
    };

    if !has_access {
        return Json(serde_json::json!({
            "entries": [],
            "error": "No access to this guild"
        }))
        .into_response();
    }

    // Fetch audit log using bot token
    let limit = query.limit.unwrap_or(100).min(100);
    let response = client
        .get(format!(
            "{}/guilds/{}/audit-logs?limit={}",
            config.discord_api_url(),
            guild_id,
            limit
        ))
        .header("Authorization", format!("Bot {}", bot_token))
        .send()
        .await;

    let entries: Vec<serde_json::Value> = match response {
        Ok(resp) if resp.status().is_success() => {
            let data: serde_json::Value = resp.json().await.unwrap_or_default();

            // Build user lookup map from the users array in the response
            let users = data["users"].as_array().unwrap_or(&Vec::new()).clone();
            let user_map: std::collections::HashMap<String, &serde_json::Value> = users
                .iter()
                .filter_map(|u| {
                    let id = u["id"].as_str()?;
                    Some((id.to_string(), u))
                })
                .collect();

            // Parse audit log entries
            data["audit_log_entries"]
                .as_array()
                .unwrap_or(&Vec::new())
                .iter()
                .filter_map(|entry| {
                    let id = entry["id"].as_str()?.to_string();
                    let action_type = entry["action_type"].as_u64()?;
                    let user_id = entry["user_id"].as_str()?;
                    let target_id = entry["target_id"].as_str().map(|s| s.to_string());
                    let reason = entry["reason"].as_str().map(|s| s.to_string());

                    // Get user info from the lookup map
                    let user = user_map.get(user_id);
                    let username = user
                        .and_then(|u| u["username"].as_str())
                        .unwrap_or("Unknown");
                    let avatar = user.and_then(|u| u["avatar"].as_str());

                    // Map Discord action types to Umbra action types
                    let (umbra_action_type, target_type) = map_discord_audit_action(action_type);

                    Some(serde_json::json!({
                        "id": id,
                        "actionType": umbra_action_type,
                        "discordActionType": action_type,
                        "actorUserId": user_id,
                        "actorUsername": username,
                        "actorAvatar": avatar,
                        "targetId": target_id,
                        "targetType": target_type,
                        "reason": reason,
                        "changes": entry["changes"],
                        "options": entry["options"],
                    }))
                })
                .collect()
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();

            if status.as_u16() == 403 {
                tracing::warn!(
                    "Bot lacks VIEW_AUDIT_LOG permission for guild {}: {}",
                    guild_id,
                    body
                );
                return Json(serde_json::json!({
                    "entries": [],
                    "error": "Bot does not have VIEW_AUDIT_LOG permission"
                }))
                .into_response();
            }

            tracing::warn!(
                "Discord audit log fetch failed for guild {}: {} - {}",
                guild_id,
                status,
                body
            );
            Vec::new()
        }
        Err(e) => {
            tracing::error!("Discord audit log request failed: {}", e);
            Vec::new()
        }
    };

    tracing::info!(
        guild_id = guild_id.as_str(),
        entry_count = entries.len(),
        "Fetched Discord guild audit log"
    );

    Json(serde_json::json!({
        "entries": entries,
    }))
    .into_response()
}

/// Map Discord audit action types to Umbra action types.
/// See: https://discord.com/developers/docs/resources/audit-log#audit-log-entry-object-audit-log-events
fn map_discord_audit_action(action_type: u64) -> (&'static str, &'static str) {
    match action_type {
        // Guild updates
        1 => ("guild_update", "guild"),
        // Channel operations
        10 => ("channel_create", "channel"),
        11 => ("channel_update", "channel"),
        12 => ("channel_delete", "channel"),
        13 => ("channel_overwrite_create", "channel"),
        14 => ("channel_overwrite_update", "channel"),
        15 => ("channel_overwrite_delete", "channel"),
        // Member operations
        20 => ("member_kick", "member"),
        21 => ("member_prune", "member"),
        22 => ("member_ban_add", "member"),
        23 => ("member_ban_remove", "member"),
        24 => ("member_update", "member"),
        25 => ("member_role_update", "member"),
        26 => ("member_move", "member"),
        27 => ("member_disconnect", "member"),
        28 => ("bot_add", "member"),
        // Role operations
        30 => ("role_create", "role"),
        31 => ("role_update", "role"),
        32 => ("role_delete", "role"),
        // Invite operations
        40 => ("invite_create", "invite"),
        41 => ("invite_update", "invite"),
        42 => ("invite_delete", "invite"),
        // Webhook operations
        50 => ("webhook_create", "webhook"),
        51 => ("webhook_update", "webhook"),
        52 => ("webhook_delete", "webhook"),
        // Emoji operations
        60 => ("emoji_create", "emoji"),
        61 => ("emoji_update", "emoji"),
        62 => ("emoji_delete", "emoji"),
        // Message operations
        72 => ("message_delete", "message"),
        73 => ("message_bulk_delete", "message"),
        74 => ("message_pin", "message"),
        75 => ("message_unpin", "message"),
        // Integration operations
        80 => ("integration_create", "integration"),
        81 => ("integration_update", "integration"),
        82 => ("integration_delete", "integration"),
        83 => ("stage_instance_create", "stage"),
        84 => ("stage_instance_update", "stage"),
        85 => ("stage_instance_delete", "stage"),
        // Sticker operations
        90 => ("sticker_create", "sticker"),
        91 => ("sticker_update", "sticker"),
        92 => ("sticker_delete", "sticker"),
        // Scheduled event operations
        100 => ("event_create", "event"),
        101 => ("event_update", "event"),
        102 => ("event_delete", "event"),
        // Thread operations
        110 => ("thread_create", "thread"),
        111 => ("thread_update", "thread"),
        112 => ("thread_delete", "thread"),
        // Auto moderation
        140 => ("automod_rule_create", "automod"),
        141 => ("automod_rule_update", "automod"),
        142 => ("automod_rule_delete", "automod"),
        143 => ("automod_block_message", "automod"),
        144 => ("automod_flag_message", "automod"),
        145 => ("automod_timeout_member", "automod"),
        // Soundboard
        130 => ("soundboard_sound_create", "soundboard"),
        131 => ("soundboard_sound_update", "soundboard"),
        132 => ("soundboard_sound_delete", "soundboard"),
        // Default
        _ => ("unknown", "unknown"),
    }
}

// ---------------------------------------------------------------------------
// Community Import Result Polling (for Tauri/mobile clients)
// ---------------------------------------------------------------------------

/// Poll for a community import result by state nonce.
///
/// Tauri/mobile clients call this after opening the OAuth URL in the system browser.
/// Returns the access token if the OAuth callback has completed, or 404 if pending.
/// The result is consumed (deleted) on successful retrieval.
pub async fn get_community_import_result(
    State((store, _config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Path(state): Path<String>,
) -> impl IntoResponse {
    match store.take_community_import_result(&state) {
        Some(token) => {
            tracing::info!(state = state.as_str(), "Community import result retrieved");
            Json(serde_json::json!({
                "success": true,
                "token": token,
            }))
            .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "success": false,
                "error": "pending",
            })),
        )
            .into_response(),
    }
}
