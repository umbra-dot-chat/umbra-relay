//! Profile Import OAuth2 handlers.
//!
//! Handles OAuth2 flows for importing profile data (username, avatar, bio)
//! during signup. Unlike account linking, this returns an HTML page that
//! sends the profile data via postMessage to the opener window.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use reqwest::Client;
use serde::Deserialize;
use uuid::Uuid;

use crate::discovery::{
    config::{DISCORD_SCOPES, GITHUB_SCOPES, XBOX_SCOPES},
    types::{ImportedProfile, LinkedAccount, OAuthState, Platform, StartAuthResponse},
    DiscoveryConfig, DiscoveryStore,
};

use super::CallbackQuery;

/// Optional JSON body for profile import start endpoints.
/// When `did` is provided, the callback will also link the account
/// to that DID for friend discovery.
#[derive(Debug, Deserialize, Default)]
pub struct ProfileImportStartBody {
    /// Optional Umbra DID — if provided, auto-link the account on callback.
    #[serde(default)]
    pub did: Option<String>,
}

/// Generate HTML page that sends profile data via postMessage and closes.
fn profile_success_html(profile: &ImportedProfile) -> Html<String> {
    let profile_json = serde_json::to_string(profile).unwrap_or_else(|_| "null".to_string());
    Html(format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Profile Imported - Umbra</title>
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
        .username {{
            background: rgba(168, 85, 247, 0.2);
            padding: 8px 16px;
            border-radius: 8px;
            display: inline-block;
            margin: 10px 0;
            font-family: monospace;
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
        <h1>Profile Imported</h1>
        <div class="username">{}</div>
        <p>Your profile has been imported successfully.</p>
        <p class="close-hint">Returning to app...</p>
    </div>
    <script>
        const profile = {};
        // Send profile to opener window (web popup flow)
        if (window.opener) {{
            window.opener.postMessage({{
                type: 'UMBRA_PROFILE_IMPORT',
                success: true,
                profile: profile
            }}, '*');
        }}
        // Also try to send to parent (for iframe scenarios)
        if (window.parent && window.parent !== window) {{
            window.parent.postMessage({{
                type: 'UMBRA_PROFILE_IMPORT',
                success: true,
                profile: profile
            }}, '*');
        }}
        // Close or redirect back to app
        setTimeout(() => {{
            if (window.opener) {{
                // Web popup — close the window
                window.close();
            }} else {{
                // In-app browser (mobile) — redirect to app scheme to dismiss
                window.location.href = 'umbra://oauth/callback?success=true';
            }}
        }}, 1500);
    </script>
</body>
</html>"#,
        profile.display_name, profile_json
    ))
}

/// Generate HTML page for profile import errors.
fn profile_error_html(message: &str) -> Html<String> {
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
                type: 'UMBRA_PROFILE_IMPORT',
                success: false,
                error: error
            }}, '*');
        }}
        if (window.parent && window.parent !== window) {{
            window.parent.postMessage({{
                type: 'UMBRA_PROFILE_IMPORT',
                success: false,
                error: error
            }}, '*');
        }}
        // On mobile in-app browser, redirect back to app after delay
        if (!window.opener) {{
            setTimeout(() => {{
                window.location.href = 'umbra://oauth/callback?success=false';
            }}, 2000);
        }}
    </script>
</body>
</html>"#,
        message, error_json
    ))
}

// ---------------------------------------------------------------------------
// Discord Profile Import
// ---------------------------------------------------------------------------

/// Discord user response from API.
#[derive(Debug, Deserialize)]
struct DiscordUser {
    id: String,
    username: String,
    discriminator: String,
    global_name: Option<String>,
    avatar: Option<String>,
    banner: Option<String>,
    bio: Option<String>,
    email: Option<String>,
}

impl DiscordUser {
    /// Get the display name (global_name or username).
    fn display_name(&self) -> String {
        if let Some(ref name) = self.global_name {
            name.clone()
        } else if self.discriminator == "0" {
            self.username.clone()
        } else {
            format!("{}#{}", self.username, self.discriminator)
        }
    }
}

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

/// Start Discord OAuth2 flow for profile import.
///
/// Accepts an optional JSON body with `did` — when provided, the callback
/// will also link the Discord account to that DID for friend discovery.
pub async fn start_discord(
    State((store, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    body: Option<Json<ProfileImportStartBody>>,
) -> impl IntoResponse {
    let did = body.and_then(|b| b.did.clone()).unwrap_or_default();

    // Get client_id and redirect_uri, falling back to regular redirect URI if needed
    let (client_id, redirect_uri) = match (
        &config.discord_client_id,
        &config.discord_profile_import_redirect_uri,
    ) {
        (Some(id), Some(uri)) => (id.clone(), uri.clone()),
        (Some(id), None) => {
            // Fall back to regular redirect URI
            if let Some(uri) = &config.discord_redirect_uri {
                let profile_uri =
                    uri.replace("/auth/discord/callback", "/profile/import/discord/callback");
                (id.clone(), profile_uri)
            } else {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "error": "Discord OAuth not configured"
                    })),
                )
                    .into_response();
            }
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

    start_discord_with_uri(store, config, client_id, redirect_uri, did).await
}

async fn start_discord_with_uri(
    store: DiscoveryStore,
    config: DiscoveryConfig,
    client_id: String,
    redirect_uri: String,
    did: String,
) -> axum::response::Response {
    let nonce = Uuid::new_v4().to_string();

    // Store OAuth state with profile_import flag
    // If a DID is provided, the callback will also link the account
    let state = OAuthState {
        did,
        nonce: nonce.clone(),
        platform: Platform::Discord,
        created_at: Utc::now(),
        profile_import: true,
        community_import: false,
    };
    store.store_oauth_state(state);

    let scopes = DISCORD_SCOPES.join("%20");
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
        "Discord profile import OAuth started"
    );

    Json(StartAuthResponse {
        redirect_url: auth_url,
        state: nonce,
    })
    .into_response()
}

/// Handle Discord OAuth2 callback for profile import.
pub async fn callback_discord(
    State((store, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Query(query): Query<CallbackQuery>,
) -> impl IntoResponse {
    tracing::info!(
        state = query.state.as_str(),
        code_len = query.code.len(),
        "Discord profile import callback received"
    );

    // Verify state
    let oauth_state = match store.take_oauth_state(&query.state) {
        Some(s) if s.platform == Platform::Discord && s.profile_import => {
            tracing::info!("OAuth state validated successfully");
            s
        }
        Some(s) => {
            tracing::warn!(
                platform = ?s.platform,
                profile_import = s.profile_import,
                "OAuth state found but doesn't match expected criteria"
            );
            return profile_error_html("Invalid OAuth state (not a profile import flow)")
                .into_response();
        }
        None => {
            tracing::warn!(state = query.state.as_str(), "OAuth state not found");
            return profile_error_html("Invalid or expired state. Please try again.")
                .into_response();
        }
    };

    let (client_id, client_secret, redirect_uri) = match (
        config.discord_client_id.as_ref(),
        config.discord_client_secret.as_ref(),
        config
            .discord_profile_import_redirect_uri
            .as_ref()
            .or(config
                .discord_redirect_uri
                .as_ref()
                .map(|uri| {
                    uri.replace("/auth/discord/callback", "/profile/import/discord/callback")
                })
                .as_ref()),
    ) {
        (Some(id), Some(secret), Some(uri)) => (id.clone(), secret.clone(), uri.clone()),
        _ => {
            return profile_error_html("Discord OAuth not configured").into_response();
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
                return profile_error_html("Failed to parse token response").into_response();
            }
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!("Discord token exchange failed: {} - {}", status, body);
            return profile_error_html("Failed to exchange code for token").into_response();
        }
        Err(e) => {
            tracing::error!("Discord token request failed: {}", e);
            return profile_error_html("Failed to connect to Discord").into_response();
        }
    };

    // Fetch user info
    let user_response = client
        .get(format!("{}/users/@me", config.discord_api_url()))
        .header("Authorization", format!("Bearer {}", token.access_token))
        .send()
        .await;

    let user: DiscordUser = match user_response {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(u) => u,
            Err(e) => {
                tracing::error!("Failed to parse Discord user response: {}", e);
                return profile_error_html("Failed to parse user info").into_response();
            }
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!("Discord user fetch failed: {} - {}", status, body);
            return profile_error_html("Failed to fetch user info").into_response();
        }
        Err(e) => {
            tracing::error!("Discord user request failed: {}", e);
            return profile_error_html("Failed to connect to Discord").into_response();
        }
    };

    // Download avatar
    let (avatar_base64, avatar_mime) = download_discord_avatar(&client, &user).await;

    tracing::info!(
        discord_id = user.id.as_str(),
        discord_username = user.display_name().as_str(),
        has_avatar = avatar_base64.is_some(),
        avatar_size = avatar_base64.as_ref().map(|s| s.len()).unwrap_or(0),
        "Discord profile imported"
    );

    // If a DID was provided, also link the account for friend discovery
    if !oauth_state.did.is_empty() {
        let account = LinkedAccount {
            platform: Platform::Discord,
            platform_id: user.id.clone(),
            platform_username: user.display_name(),
            linked_at: Utc::now(),
            verified: true,
        };
        store.link_account(&oauth_state.did, account);
        tracing::info!(
            did = oauth_state.did.as_str(),
            discord_id = user.id.as_str(),
            "Discord account auto-linked during profile import"
        );
    }

    let profile = ImportedProfile {
        platform: Platform::Discord,
        platform_id: user.id.clone(),
        display_name: user.display_name(),
        username: user.username.clone(),
        avatar_base64,
        avatar_mime,
        bio: user.bio.clone(),
        email: user.email.clone(),
    };

    // Store result for mobile polling
    store.store_profile_result(&query.state, profile.clone());

    profile_success_html(&profile).into_response()
}

/// Download Discord avatar and return as base64.
async fn download_discord_avatar(
    client: &Client,
    user: &DiscordUser,
) -> (Option<String>, Option<String>) {
    let avatar_url = if let Some(ref hash) = user.avatar {
        let ext = if hash.starts_with("a_") { "gif" } else { "png" };
        format!(
            "https://cdn.discordapp.com/avatars/{}/{}.{}?size=256",
            user.id, hash, ext
        )
    } else {
        // Default avatar based on user ID
        let index: u64 = user.id.parse().unwrap_or(0) % 5;
        format!("https://cdn.discordapp.com/embed/avatars/{}.png", index)
    };

    match client.get(&avatar_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("image/png")
                .to_string();

            match resp.bytes().await {
                Ok(bytes) => {
                    let base64_data = BASE64.encode(&bytes);
                    (Some(base64_data), Some(content_type))
                }
                Err(e) => {
                    tracing::warn!("Failed to read avatar bytes: {}", e);
                    (None, None)
                }
            }
        }
        Ok(resp) => {
            tracing::warn!("Failed to download avatar: {}", resp.status());
            (None, None)
        }
        Err(e) => {
            tracing::warn!("Failed to request avatar: {}", e);
            (None, None)
        }
    }
}

// ---------------------------------------------------------------------------
// GitHub Profile Import
// ---------------------------------------------------------------------------

/// GitHub user response from API.
#[derive(Debug, Deserialize)]
struct GitHubUser {
    id: i64,
    login: String,
    name: Option<String>,
    avatar_url: Option<String>,
    bio: Option<String>,
    email: Option<String>,
}

/// GitHub token response.
#[derive(Debug, Deserialize)]
struct GitHubTokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: String,
    #[allow(dead_code)]
    scope: String,
}

/// Start GitHub OAuth2 flow for profile import.
///
/// Accepts an optional JSON body with `did` — when provided, the callback
/// will also link the GitHub account to that DID for friend discovery.
pub async fn start_github(
    State((store, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    body: Option<Json<ProfileImportStartBody>>,
) -> impl IntoResponse {
    let did = body.and_then(|b| b.did.clone()).unwrap_or_default();

    // Get client_id and redirect_uri, falling back to regular redirect URI if needed
    let (client_id, redirect_uri) = match (
        &config.github_client_id,
        &config.github_profile_import_redirect_uri,
    ) {
        (Some(id), Some(uri)) => (id.clone(), uri.clone()),
        (Some(id), None) => {
            // Fall back to regular redirect URI
            if let Some(uri) = &config.github_redirect_uri {
                let profile_uri =
                    uri.replace("/auth/github/callback", "/profile/import/github/callback");
                (id.clone(), profile_uri)
            } else {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "error": "GitHub OAuth not configured"
                    })),
                )
                    .into_response();
            }
        }
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "GitHub OAuth not configured"
                })),
            )
                .into_response();
        }
    };

    start_github_with_uri(store, config, client_id, redirect_uri, did).await
}

async fn start_github_with_uri(
    store: DiscoveryStore,
    config: DiscoveryConfig,
    client_id: String,
    redirect_uri: String,
    did: String,
) -> axum::response::Response {
    let nonce = Uuid::new_v4().to_string();

    let state = OAuthState {
        did,
        nonce: nonce.clone(),
        platform: Platform::GitHub,
        created_at: Utc::now(),
        profile_import: true,
        community_import: false,
    };
    store.store_oauth_state(state);

    let scopes = GITHUB_SCOPES.join("%20");
    let auth_url = format!(
        "{}?client_id={}&redirect_uri={}&scope={}&state={}",
        config.github_auth_url(),
        client_id,
        urlencoding::encode(&redirect_uri),
        scopes,
        nonce
    );

    Json(StartAuthResponse {
        redirect_url: auth_url,
        state: nonce,
    })
    .into_response()
}

/// Handle GitHub OAuth2 callback for profile import.
pub async fn callback_github(
    State((store, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Query(query): Query<CallbackQuery>,
) -> impl IntoResponse {
    // Verify state
    let oauth_state = match store.take_oauth_state(&query.state) {
        Some(s) if s.platform == Platform::GitHub && s.profile_import => s,
        Some(_) => {
            return profile_error_html("Invalid OAuth state (not a profile import flow)")
                .into_response();
        }
        None => {
            return profile_error_html("Invalid or expired state. Please try again.")
                .into_response();
        }
    };

    let (client_id, client_secret, redirect_uri) = match (
        config.github_client_id.as_ref(),
        config.github_client_secret.as_ref(),
        config.github_profile_import_redirect_uri.as_ref().or(config
            .github_redirect_uri
            .as_ref()
            .map(|uri| uri.replace("/auth/github/callback", "/profile/import/github/callback"))
            .as_ref()),
    ) {
        (Some(id), Some(secret), Some(uri)) => (id.clone(), secret.clone(), uri.clone()),
        _ => {
            return profile_error_html("GitHub OAuth not configured").into_response();
        }
    };

    let client = Client::new();

    // Exchange code for token
    let token_response = client
        .post(config.github_token_url())
        .header("Accept", "application/json")
        .form(&[
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("code", &query.code),
            ("redirect_uri", redirect_uri.as_str()),
        ])
        .send()
        .await;

    let token: GitHubTokenResponse = match token_response {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Failed to parse GitHub token response: {}", e);
                return profile_error_html("Failed to parse token response").into_response();
            }
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!("GitHub token exchange failed: {} - {}", status, body);
            return profile_error_html("Failed to exchange code for token").into_response();
        }
        Err(e) => {
            tracing::error!("GitHub token request failed: {}", e);
            return profile_error_html("Failed to connect to GitHub").into_response();
        }
    };

    // Fetch user info
    let user_response = client
        .get(format!("{}/user", config.github_api_url()))
        .header("Authorization", format!("Bearer {}", token.access_token))
        .header("User-Agent", "Umbra-Relay")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await;

    let user: GitHubUser = match user_response {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(u) => u,
            Err(e) => {
                tracing::error!("Failed to parse GitHub user response: {}", e);
                return profile_error_html("Failed to parse user info").into_response();
            }
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!("GitHub user fetch failed: {} - {}", status, body);
            return profile_error_html("Failed to fetch user info").into_response();
        }
        Err(e) => {
            tracing::error!("GitHub user request failed: {}", e);
            return profile_error_html("Failed to connect to GitHub").into_response();
        }
    };

    // Download avatar
    let (avatar_base64, avatar_mime) = if let Some(ref avatar_url) = user.avatar_url {
        download_avatar(&client, avatar_url).await
    } else {
        (None, None)
    };

    tracing::info!(
        github_id = user.id,
        github_username = user.login.as_str(),
        "GitHub profile imported"
    );

    // If a DID was provided, also link the account for friend discovery
    let display_name = user.name.clone().unwrap_or_else(|| user.login.clone());
    if !oauth_state.did.is_empty() {
        let account = LinkedAccount {
            platform: Platform::GitHub,
            platform_id: user.id.to_string(),
            platform_username: display_name.clone(),
            linked_at: Utc::now(),
            verified: true,
        };
        store.link_account(&oauth_state.did, account);
        tracing::info!(
            did = oauth_state.did.as_str(),
            github_id = user.id,
            "GitHub account auto-linked during profile import"
        );
    }

    let profile = ImportedProfile {
        platform: Platform::GitHub,
        platform_id: user.id.to_string(),
        display_name,
        username: user.login,
        avatar_base64,
        avatar_mime,
        bio: user.bio,
        email: user.email,
    };

    // Store result for mobile polling
    store.store_profile_result(&query.state, profile.clone());

    profile_success_html(&profile).into_response()
}

/// Download avatar from URL and return as base64.
async fn download_avatar(client: &Client, url: &str) -> (Option<String>, Option<String>) {
    match client.get(url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("image/png")
                .to_string();

            match resp.bytes().await {
                Ok(bytes) => {
                    let base64_data = BASE64.encode(&bytes);
                    (Some(base64_data), Some(content_type))
                }
                Err(e) => {
                    tracing::warn!("Failed to read avatar bytes: {}", e);
                    (None, None)
                }
            }
        }
        Ok(resp) => {
            tracing::warn!("Failed to download avatar: {}", resp.status());
            (None, None)
        }
        Err(e) => {
            tracing::warn!("Failed to request avatar: {}", e);
            (None, None)
        }
    }
}

// ---------------------------------------------------------------------------
// Steam Profile Import (OpenID 2.0)
// ---------------------------------------------------------------------------

/// Steam player summary from GetPlayerSummaries API.
#[derive(Debug, Deserialize)]
struct SteamPlayerSummary {
    steamid: String,
    personaname: String,
    #[allow(dead_code)]
    profileurl: Option<String>,
    #[allow(dead_code)]
    avatar: Option<String>,
    #[allow(dead_code)]
    avatarmedium: Option<String>,
    avatarfull: Option<String>,
}

/// Steam API response wrapper.
#[derive(Debug, Deserialize)]
struct SteamApiResponse {
    response: SteamPlayersResponse,
}

#[derive(Debug, Deserialize)]
struct SteamPlayersResponse {
    players: Vec<SteamPlayerSummary>,
}

/// Steam OpenID callback query parameters.
#[derive(Debug, Deserialize)]
pub struct SteamProfileCallbackQuery {
    #[serde(rename = "openid.claimed_id")]
    pub claimed_id: Option<String>,
    #[serde(rename = "openid.identity")]
    pub identity: Option<String>,
    #[serde(rename = "openid.sig")]
    pub sig: Option<String>,
    #[serde(rename = "openid.signed")]
    pub signed: Option<String>,
    #[serde(rename = "openid.assoc_handle")]
    pub assoc_handle: Option<String>,
    #[serde(rename = "openid.ns")]
    pub ns: Option<String>,
    #[serde(rename = "openid.op_endpoint")]
    pub op_endpoint: Option<String>,
    #[serde(rename = "openid.response_nonce")]
    pub response_nonce: Option<String>,
    #[serde(rename = "openid.return_to")]
    pub return_to: Option<String>,
    /// Our state nonce passed via return_to URL.
    pub state: Option<String>,
}

/// Start Steam OpenID 2.0 flow for profile import.
pub async fn start_steam(
    State((store, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    body: Option<Json<ProfileImportStartBody>>,
) -> impl IntoResponse {
    let did = body.and_then(|b| b.did.clone()).unwrap_or_default();

    if !config.steam_enabled() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "Steam not configured"
            })),
        )
            .into_response();
    }

    let nonce = Uuid::new_v4().to_string();

    let state = OAuthState {
        did,
        nonce: nonce.clone(),
        platform: Platform::Steam,
        created_at: Utc::now(),
        profile_import: true,
        community_import: false,
    };
    store.store_oauth_state(state);

    let default_redirect = format!("{}/profile/import/steam/callback", config.relay_base_url);
    let redirect_uri = config
        .steam_profile_import_redirect_uri
        .as_deref()
        .unwrap_or(&default_redirect);

    let return_to = format!("{}?state={}", redirect_uri, nonce);

    let auth_url = format!(
        "{}?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=checkid_setup&openid.return_to={}&openid.realm={}&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select",
        config.steam_openid_url(),
        urlencoding::encode(&return_to),
        urlencoding::encode(&config.relay_base_url),
    );

    tracing::info!("Steam profile import OpenID started");

    Json(StartAuthResponse {
        redirect_url: auth_url,
        state: nonce,
    })
    .into_response()
}

/// Handle Steam OpenID 2.0 callback for profile import.
pub async fn callback_steam(
    State((store, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Query(query): Query<SteamProfileCallbackQuery>,
) -> impl IntoResponse {
    let state_nonce = match &query.state {
        Some(s) => s.clone(),
        None => {
            return profile_error_html("Missing state parameter").into_response();
        }
    };

    // Verify state
    let oauth_state = match store.take_oauth_state(&state_nonce) {
        Some(s) if s.platform == Platform::Steam && s.profile_import => s,
        Some(_) => {
            return profile_error_html("Invalid OAuth state (not a profile import flow)")
                .into_response();
        }
        None => {
            return profile_error_html("Invalid or expired state. Please try again.")
                .into_response();
        }
    };

    // Extract Steam64 ID from claimed_id
    let steam_id = match &query.claimed_id {
        Some(claimed_id) => {
            if let Some(id) = claimed_id.strip_prefix("https://steamcommunity.com/openid/id/") {
                id.to_string()
            } else {
                return profile_error_html("Invalid Steam claimed_id format").into_response();
            }
        }
        None => {
            return profile_error_html("No Steam claimed_id in callback").into_response();
        }
    };

    // Verify the OpenID assertion with Steam
    let client = Client::new();
    let verify_ok = verify_steam_openid(&client, &config, &query).await;
    if !verify_ok {
        return profile_error_html("Steam OpenID verification failed").into_response();
    }

    // Fetch player profile using Steam Web API
    let api_key = match &config.steam_api_key {
        Some(key) => key,
        None => {
            return profile_error_html("Steam API key not configured").into_response();
        }
    };

    let profile_url = format!(
        "{}/ISteamUser/GetPlayerSummaries/v0002/?key={}&steamids={}",
        config.steam_api_url(),
        api_key,
        steam_id,
    );

    let profile_response = client.get(&profile_url).send().await;

    let player = match profile_response {
        Ok(resp) if resp.status().is_success() => match resp.json::<SteamApiResponse>().await {
            Ok(api_resp) => api_resp.response.players.into_iter().next(),
            Err(e) => {
                tracing::error!("Failed to parse Steam API response: {}", e);
                None
            }
        },
        Ok(resp) => {
            tracing::error!("Steam API request failed: {}", resp.status());
            None
        }
        Err(e) => {
            tracing::error!("Steam API request error: {}", e);
            None
        }
    };

    let persona_name = player
        .as_ref()
        .map(|p| p.personaname.clone())
        .unwrap_or_else(|| steam_id.clone());

    let avatar_url = player.as_ref().and_then(|p| p.avatarfull.clone());

    // Download avatar
    let (avatar_base64, avatar_mime) = if let Some(ref url) = avatar_url {
        download_avatar(&client, url).await
    } else {
        (None, None)
    };

    tracing::info!(
        steam_id = steam_id.as_str(),
        persona_name = persona_name.as_str(),
        has_avatar = avatar_base64.is_some(),
        "Steam profile imported"
    );

    // If a DID was provided, also link the account for friend discovery
    if !oauth_state.did.is_empty() {
        let account = LinkedAccount {
            platform: Platform::Steam,
            platform_id: steam_id.clone(),
            platform_username: persona_name.clone(),
            linked_at: Utc::now(),
            verified: true,
        };
        store.link_account(&oauth_state.did, account);
        tracing::info!(
            did = oauth_state.did.as_str(),
            steam_id = steam_id.as_str(),
            "Steam account auto-linked during profile import"
        );
    }

    let profile = ImportedProfile {
        platform: Platform::Steam,
        platform_id: steam_id,
        display_name: persona_name.clone(),
        username: persona_name,
        avatar_base64,
        avatar_mime,
        bio: None,
        email: None,
    };

    // Store result for mobile polling
    store.store_profile_result(&state_nonce, profile.clone());

    profile_success_html(&profile).into_response()
}

/// Verify Steam OpenID 2.0 assertion by calling Steam back.
async fn verify_steam_openid(
    client: &Client,
    config: &DiscoveryConfig,
    query: &SteamProfileCallbackQuery,
) -> bool {
    let params = vec![
        ("openid.ns", query.ns.clone().unwrap_or_default()),
        ("openid.mode", "check_authentication".to_string()),
        ("openid.sig", query.sig.clone().unwrap_or_default()),
        ("openid.signed", query.signed.clone().unwrap_or_default()),
        (
            "openid.assoc_handle",
            query.assoc_handle.clone().unwrap_or_default(),
        ),
        (
            "openid.claimed_id",
            query.claimed_id.clone().unwrap_or_default(),
        ),
        (
            "openid.identity",
            query.identity.clone().unwrap_or_default(),
        ),
        (
            "openid.op_endpoint",
            query.op_endpoint.clone().unwrap_or_default(),
        ),
        (
            "openid.response_nonce",
            query.response_nonce.clone().unwrap_or_default(),
        ),
        (
            "openid.return_to",
            query.return_to.clone().unwrap_or_default(),
        ),
    ];

    match client
        .post(config.steam_openid_url())
        .form(&params)
        .send()
        .await
    {
        Ok(resp) => {
            if let Ok(body) = resp.text().await {
                body.contains("is_valid:true")
            } else {
                false
            }
        }
        Err(e) => {
            tracing::error!("Steam OpenID verification request failed: {}", e);
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Bluesky Profile Import (Public API handle lookup)
// ---------------------------------------------------------------------------
//
// Bluesky's AT Protocol OAuth requires DPoP proofs, PAR, and hosted client
// metadata — far too complex for a simple account link. Instead, we use the
// public API: the user enters their handle in a relay-hosted page, we look
// it up via public.api.bsky.app, and link the account.

/// Bluesky profile from app.bsky.actor.getProfile (public API).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlueskyProfile {
    did: String,
    handle: String,
    display_name: Option<String>,
    avatar: Option<String>,
    description: Option<String>,
}

/// Query params for the Bluesky handle verification callback.
#[derive(Debug, Deserialize)]
pub struct BlueskyVerifyQuery {
    pub handle: String,
    pub state: String,
}

/// Start Bluesky handle verification flow for profile import.
///
/// Returns a redirect URL to a relay-hosted page where the user enters
/// their Bluesky handle. No OAuth credentials needed.
pub async fn start_bluesky(
    State((store, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    body: Option<Json<ProfileImportStartBody>>,
) -> impl IntoResponse {
    let did = body.and_then(|b| b.did.clone()).unwrap_or_default();

    let nonce = Uuid::new_v4().to_string();

    let state = OAuthState {
        did,
        nonce: nonce.clone(),
        platform: Platform::Bluesky,
        created_at: Utc::now(),
        profile_import: true,
        community_import: false,
    };
    store.store_oauth_state(state);

    // Redirect to relay-hosted handle input page
    let verify_url = format!(
        "{}/profile/import/bluesky/verify?state={}",
        config.relay_base_url, nonce,
    );

    tracing::info!("Bluesky profile import handle verification started");

    Json(StartAuthResponse {
        redirect_url: verify_url,
        state: nonce,
    })
    .into_response()
}

/// Serve the Bluesky handle input page.
///
/// This is an HTML page (opened in a popup) where the user types their
/// Bluesky handle. On submit, it redirects to the callback endpoint.
pub async fn verify_bluesky_page(
    Query(query): Query<std::collections::HashMap<String, String>>,
    State((_store, config)): State<(DiscoveryStore, DiscoveryConfig)>,
) -> impl IntoResponse {
    let state = query.get("state").cloned().unwrap_or_default();
    let callback_url = format!("{}/profile/import/bluesky/callback", config.relay_base_url);

    Html(format!(
        r##"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Link Bluesky - Umbra</title>
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
            width: 100%;
        }}
        .logo {{
            width: 48px;
            height: 48px;
            margin-bottom: 16px;
        }}
        h2 {{
            margin: 0 0 8px;
            font-size: 20px;
            font-weight: 600;
        }}
        p {{
            color: #94a3b8;
            font-size: 14px;
            margin: 0 0 24px;
        }}
        .input-group {{
            display: flex;
            flex-direction: column;
            gap: 12px;
        }}
        input {{
            width: 100%;
            padding: 12px 16px;
            border: 1px solid #334155;
            border-radius: 8px;
            background: #1e293b;
            color: #fff;
            font-size: 16px;
            outline: none;
            box-sizing: border-box;
        }}
        input:focus {{
            border-color: #0085FF;
        }}
        input::placeholder {{
            color: #64748b;
        }}
        button {{
            width: 100%;
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            background: #0085FF;
            color: #fff;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }}
        button:hover {{
            background: #0070d6;
        }}
        button:disabled {{
            background: #334155;
            cursor: not-allowed;
        }}
        .error {{
            color: #ef4444;
            font-size: 13px;
            margin-top: 8px;
        }}
        .spinner {{
            display: none;
            width: 20px;
            height: 20px;
            border: 2px solid #fff3;
            border-top-color: #fff;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin: 0 auto;
        }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
    </style>
</head>
<body>
    <div class="container">
        <svg class="logo" viewBox="0 0 600 530" fill="#0085FF" xmlns="http://www.w3.org/2000/svg">
            <path d="M135.72 44.03C202.216 93.951 273.74 195.401 300 249.98C326.26 195.401 397.784 93.951 464.28 44.03C512.694 8.169 588 -18.896 588 71.947C588 93.896 576.013 285.316 569.01 307.266C548.267 373.835 480.404 390.891 420.08 379.833C516.424 397.862 543.5 462.554 489 527.247C384.159 651.78 328.956 503.038 306.981 434.01C304.982 428.08 304.019 425.255 300 425.255C295.981 425.255 295.018 428.08 293.019 434.01C271.044 503.038 215.841 651.78 111 527.247C56.5 462.554 83.576 397.862 179.92 379.833C119.596 390.891 51.733 373.835 30.99 307.266C23.987 285.316 12 93.896 12 71.947C12 -18.896 87.306 8.169 135.72 44.03Z"/>
        </svg>
        <h2>Link Bluesky Account</h2>
        <p>Enter your Bluesky handle to link it to your Umbra identity.</p>
        <div class="input-group">
            <input
                type="text"
                id="handle"
                placeholder="yourname.bsky.social"
                autocapitalize="none"
                autocorrect="off"
                spellcheck="false"
            />
            <button id="submit" onclick="verify()">Link Account</button>
            <div class="spinner" id="spinner"></div>
            <div class="error" id="error"></div>
        </div>
    </div>
    <script>
        const callbackUrl = "{callback_url}";
        const stateNonce = "{state}";

        document.getElementById('handle').addEventListener('keydown', function(e) {{
            if (e.key === 'Enter') verify();
        }});

        function verify() {{
            const handle = document.getElementById('handle').value.trim();
            const errorEl = document.getElementById('error');
            const btn = document.getElementById('submit');
            const spinner = document.getElementById('spinner');

            errorEl.textContent = '';

            if (!handle) {{
                errorEl.textContent = 'Please enter your Bluesky handle.';
                return;
            }}

            if (!handle.includes('.')) {{
                errorEl.textContent = 'Handle should look like: yourname.bsky.social';
                return;
            }}

            btn.disabled = true;
            btn.textContent = 'Looking up...';
            spinner.style.display = 'block';

            window.location.href = callbackUrl + '?handle=' + encodeURIComponent(handle) + '&state=' + encodeURIComponent(stateNonce);
        }}
    </script>
</body>
</html>"##,
        callback_url = callback_url,
        state = state,
    ))
}

/// Handle Bluesky handle verification callback.
///
/// Looks up the handle via the public Bluesky API (no auth required),
/// fetches the profile, links the account, and returns postMessage HTML.
pub async fn callback_bluesky(
    State((store, _config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Query(query): Query<BlueskyVerifyQuery>,
) -> impl IntoResponse {
    tracing::info!(
        handle = query.handle.as_str(),
        state = query.state.as_str(),
        "Bluesky handle verification callback received"
    );

    // Verify state
    let oauth_state = match store.take_oauth_state(&query.state) {
        Some(s) if s.platform == Platform::Bluesky && s.profile_import => s,
        Some(_) => {
            return profile_error_html("Invalid state (not a Bluesky profile import flow)")
                .into_response();
        }
        None => {
            return profile_error_html("Invalid or expired state. Please try again.")
                .into_response();
        }
    };

    let client = Client::new();
    let handle = query.handle.trim().to_string();

    // Look up profile via public Bluesky API (no auth required)
    let profile_url = format!(
        "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={}",
        urlencoding::encode(&handle),
    );

    let profile_response = client
        .get(&profile_url)
        .header("Accept", "application/json")
        .send()
        .await;

    let bsky_profile: BlueskyProfile = match profile_response {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Failed to parse Bluesky profile: {}", e);
                return profile_error_html("Failed to parse Bluesky profile data").into_response();
            }
        },
        Ok(resp) if resp.status().as_u16() == 400 => {
            return profile_error_html("Bluesky handle not found. Check the handle and try again.")
                .into_response();
        }
        Ok(resp) => {
            let status = resp.status();
            tracing::error!("Bluesky profile fetch failed: {}", status);
            return profile_error_html("Failed to look up Bluesky profile").into_response();
        }
        Err(e) => {
            tracing::error!("Bluesky API request failed: {}", e);
            return profile_error_html("Failed to connect to Bluesky").into_response();
        }
    };

    let bsky_did = bsky_profile.did.clone();
    let bsky_handle = bsky_profile.handle.clone();
    let display_name = bsky_profile
        .display_name
        .clone()
        .unwrap_or_else(|| bsky_handle.clone());
    let avatar_url = bsky_profile.avatar.clone();
    let bio = bsky_profile.description.clone();

    // Download avatar
    let (avatar_base64, avatar_mime) = if let Some(ref url) = avatar_url {
        download_avatar(&client, url).await
    } else {
        (None, None)
    };

    tracing::info!(
        bsky_did = bsky_did.as_str(),
        bsky_handle = bsky_handle.as_str(),
        has_avatar = avatar_base64.is_some(),
        "Bluesky profile imported via handle lookup"
    );

    // If a DID was provided, also link the account for friend discovery
    if !oauth_state.did.is_empty() {
        let account = LinkedAccount {
            platform: Platform::Bluesky,
            platform_id: bsky_did.clone(),
            platform_username: bsky_handle.clone(),
            linked_at: Utc::now(),
            verified: true,
        };
        store.link_account(&oauth_state.did, account);
        tracing::info!(
            did = oauth_state.did.as_str(),
            bsky_did = bsky_did.as_str(),
            "Bluesky account auto-linked during profile import"
        );
    }

    let profile = ImportedProfile {
        platform: Platform::Bluesky,
        platform_id: bsky_did,
        display_name,
        username: bsky_handle,
        avatar_base64,
        avatar_mime,
        bio,
        email: None,
    };

    // Store result for mobile polling
    store.store_profile_result(&query.state, profile.clone());

    profile_success_html(&profile).into_response()
}

// ---------------------------------------------------------------------------
// Xbox Live Profile Import (Microsoft OAuth 2.0)
// ---------------------------------------------------------------------------

/// Microsoft OAuth token response.
#[derive(Debug, Deserialize)]
struct MsTokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: Option<String>,
    #[allow(dead_code)]
    expires_in: Option<u64>,
    #[allow(dead_code)]
    refresh_token: Option<String>,
}

/// Xbox Live user authenticate response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct XboxUserAuthResponse {
    token: String,
    #[allow(dead_code)]
    display_claims: Option<serde_json::Value>,
}

/// Xbox XSTS token response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct XstsResponse {
    token: String,
    display_claims: Option<XstsDisplayClaims>,
}

#[derive(Debug, Deserialize)]
struct XstsDisplayClaims {
    xui: Option<Vec<XstsXui>>,
}

#[derive(Debug, Deserialize)]
struct XstsXui {
    /// Xbox User Hash.
    uhs: Option<String>,
    /// Gamertag.
    gtg: Option<String>,
    /// XUID.
    xid: Option<String>,
}

/// Xbox profile settings response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct XboxProfileResponse {
    profile_users: Option<Vec<XboxProfileUser>>,
}

#[derive(Debug, Deserialize)]
struct XboxProfileUser {
    id: Option<String>,
    settings: Option<Vec<XboxProfileSetting>>,
}

#[derive(Debug, Deserialize)]
struct XboxProfileSetting {
    id: Option<String>,
    value: Option<String>,
}

/// Start Xbox (Microsoft) OAuth2 flow for profile import.
pub async fn start_xbox(
    State((store, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    body: Option<Json<ProfileImportStartBody>>,
) -> impl IntoResponse {
    let did = body.and_then(|b| b.did.clone()).unwrap_or_default();

    let (client_id, redirect_uri) = match (
        &config.xbox_client_id,
        &config.xbox_profile_import_redirect_uri,
    ) {
        (Some(id), Some(uri)) => (id.clone(), uri.clone()),
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "Xbox OAuth not configured"
                })),
            )
                .into_response();
        }
    };

    let nonce = Uuid::new_v4().to_string();

    let state = OAuthState {
        did,
        nonce: nonce.clone(),
        platform: Platform::XboxLive,
        created_at: Utc::now(),
        profile_import: true,
        community_import: false,
    };
    store.store_oauth_state(state);

    let scopes = XBOX_SCOPES.join(" ");
    let auth_url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
        config.xbox_auth_url(),
        urlencoding::encode(&client_id),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(&scopes),
        nonce
    );

    tracing::info!("Xbox profile import OAuth started");

    Json(StartAuthResponse {
        redirect_url: auth_url,
        state: nonce,
    })
    .into_response()
}

/// Handle Xbox (Microsoft) OAuth2 callback for profile import.
///
/// Multi-step flow: MS token → Xbox Live token → XSTS token → profile.
pub async fn callback_xbox(
    State((store, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Query(query): Query<CallbackQuery>,
) -> impl IntoResponse {
    tracing::info!(
        state = query.state.as_str(),
        code_len = query.code.len(),
        "Xbox profile import callback received"
    );

    // Verify state
    let oauth_state = match store.take_oauth_state(&query.state) {
        Some(s) if s.platform == Platform::XboxLive && s.profile_import => s,
        Some(_) => {
            return profile_error_html("Invalid OAuth state (not a profile import flow)")
                .into_response();
        }
        None => {
            return profile_error_html("Invalid or expired state. Please try again.")
                .into_response();
        }
    };

    let (client_id, client_secret, redirect_uri) = match (
        config.xbox_client_id.as_ref(),
        config.xbox_client_secret.as_ref(),
        config.xbox_profile_import_redirect_uri.as_ref(),
    ) {
        (Some(id), Some(secret), Some(uri)) => (id.clone(), secret.clone(), uri.clone()),
        _ => {
            return profile_error_html("Xbox OAuth not configured").into_response();
        }
    };

    let client = Client::new();

    // Step 1: Exchange code for Microsoft access token
    let token_response = client
        .post(config.xbox_token_url())
        .form(&[
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("code", query.code.as_str()),
            ("grant_type", "authorization_code"),
            ("redirect_uri", redirect_uri.as_str()),
        ])
        .send()
        .await;

    let ms_token: MsTokenResponse = match token_response {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Failed to parse Microsoft token response: {}", e);
                return profile_error_html("Failed to parse token response").into_response();
            }
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!("Microsoft token exchange failed: {} - {}", status, body);
            return profile_error_html("Failed to exchange code for token").into_response();
        }
        Err(e) => {
            tracing::error!("Microsoft token request failed: {}", e);
            return profile_error_html("Failed to connect to Microsoft").into_response();
        }
    };

    // Step 2: Authenticate with Xbox Live
    let xbox_auth_response = client
        .post(config.xbox_user_auth_url())
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&serde_json::json!({
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT",
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": format!("d={}", ms_token.access_token)
            }
        }))
        .send()
        .await;

    let xbox_token: XboxUserAuthResponse = match xbox_auth_response {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Failed to parse Xbox Live auth response: {}", e);
                return profile_error_html("Failed to authenticate with Xbox Live").into_response();
            }
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!("Xbox Live auth failed: {} - {}", status, body);
            return profile_error_html("Failed to authenticate with Xbox Live").into_response();
        }
        Err(e) => {
            tracing::error!("Xbox Live auth request failed: {}", e);
            return profile_error_html("Failed to connect to Xbox Live").into_response();
        }
    };

    // Step 3: Get XSTS token
    let xsts_response = client
        .post(config.xbox_xsts_url())
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&serde_json::json!({
            "RelyingParty": "http://xboxlive.com",
            "TokenType": "JWT",
            "Properties": {
                "SandboxId": "RETAIL",
                "UserTokens": [xbox_token.token]
            }
        }))
        .send()
        .await;

    let xsts: XstsResponse = match xsts_response {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Failed to parse XSTS response: {}", e);
                return profile_error_html("Failed to get Xbox authorization").into_response();
            }
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!("XSTS authorization failed: {} - {}", status, body);
            return profile_error_html("Failed to get Xbox authorization").into_response();
        }
        Err(e) => {
            tracing::error!("XSTS request failed: {}", e);
            return profile_error_html("Failed to connect to Xbox services").into_response();
        }
    };

    // Extract gamertag and XUID from XSTS display claims
    let xui = xsts
        .display_claims
        .and_then(|dc| dc.xui)
        .and_then(|xui| xui.into_iter().next());

    let user_hash = xui.as_ref().and_then(|x| x.uhs.clone()).unwrap_or_default();
    let gamertag = xui.as_ref().and_then(|x| x.gtg.clone()).unwrap_or_default();
    let xuid = xui.as_ref().and_then(|x| x.xid.clone()).unwrap_or_default();

    // Step 4: Fetch profile with gamerpic
    let auth_header = format!("XBL3.0 x={};{}", user_hash, xsts.token);

    let profile_response = client
        .get(format!(
            "{}?settings=Gamertag,GameDisplayPicRaw,RealName,Bio",
            config.xbox_profile_url(),
        ))
        .header("Authorization", &auth_header)
        .header("x-xbl-contract-version", "3")
        .header("Accept-Language", "en-US")
        .send()
        .await;

    let mut display_pic_url: Option<String> = None;
    let mut bio: Option<String> = None;
    let mut real_gamertag = gamertag.clone();

    if let Ok(resp) = profile_response {
        if resp.status().is_success() {
            if let Ok(profile_data) = resp.json::<XboxProfileResponse>().await {
                if let Some(users) = profile_data.profile_users {
                    if let Some(user) = users.into_iter().next() {
                        if let Some(settings) = user.settings {
                            for setting in settings {
                                match setting.id.as_deref() {
                                    Some("Gamertag") => {
                                        if let Some(v) = setting.value {
                                            real_gamertag = v;
                                        }
                                    }
                                    Some("GameDisplayPicRaw") => {
                                        display_pic_url = setting.value;
                                    }
                                    Some("Bio") => {
                                        bio = setting.value;
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Download avatar
    let (avatar_base64, avatar_mime) = if let Some(ref url) = display_pic_url {
        download_avatar(&client, url).await
    } else {
        (None, None)
    };

    let platform_id = if xuid.is_empty() {
        user_hash.clone()
    } else {
        xuid
    };

    tracing::info!(
        xbox_id = platform_id.as_str(),
        gamertag = real_gamertag.as_str(),
        has_avatar = avatar_base64.is_some(),
        "Xbox profile imported"
    );

    // If a DID was provided, also link the account for friend discovery
    if !oauth_state.did.is_empty() {
        let account = LinkedAccount {
            platform: Platform::XboxLive,
            platform_id: platform_id.clone(),
            platform_username: real_gamertag.clone(),
            linked_at: Utc::now(),
            verified: true,
        };
        store.link_account(&oauth_state.did, account);
        tracing::info!(
            did = oauth_state.did.as_str(),
            xbox_id = platform_id.as_str(),
            "Xbox account auto-linked during profile import"
        );
    }

    let profile = ImportedProfile {
        platform: Platform::XboxLive,
        platform_id,
        display_name: real_gamertag.clone(),
        username: real_gamertag,
        avatar_base64,
        avatar_mime,
        bio,
        email: None,
    };

    // Store result for mobile polling
    store.store_profile_result(&query.state, profile.clone());

    profile_success_html(&profile).into_response()
}

// ---------------------------------------------------------------------------
// Profile Import Result Polling (for mobile clients)
// ---------------------------------------------------------------------------

/// Poll for a profile import result by state nonce.
///
/// Mobile clients call this after opening the OAuth URL in the system browser.
/// Returns the profile data if the OAuth callback has completed, or 404 if pending.
/// The result is consumed (deleted) on successful retrieval.
pub async fn get_profile_result(
    State((store, _config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Path(state): Path<String>,
) -> impl IntoResponse {
    match store.take_profile_result(&state) {
        Some(profile) => {
            tracing::info!(state = state.as_str(), "Profile import result retrieved");
            Json(serde_json::json!({
                "success": true,
                "profile": profile,
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
