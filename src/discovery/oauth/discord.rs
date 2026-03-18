//! Discord OAuth2 implementation.
//!
//! Handles the Discord OAuth2 flow for account linking.

use axum::{
    extract::{Query, State},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use reqwest::Client;
use serde::Deserialize;
use uuid::Uuid;

use super::{error_html, success_html, CallbackQuery, ErrorCallbackQuery, StartAuthQuery};
use crate::discovery::{
    config::DISCORD_SCOPES, types::StartAuthResponse, DiscoveryConfig, DiscoveryStore,
    LinkedAccount, OAuthState, Platform,
};

/// Discord user response from API.
#[derive(Debug, Deserialize)]
struct DiscordUser {
    id: String,
    username: String,
    discriminator: String,
    global_name: Option<String>,
}

impl DiscordUser {
    /// Get the display username (global_name or username#discriminator).
    fn display_name(&self) -> String {
        if let Some(ref name) = self.global_name {
            name.clone()
        } else if self.discriminator == "0" {
            // New Discord usernames don't have discriminators
            self.username.clone()
        } else {
            format!("{}#{}", self.username, self.discriminator)
        }
    }
}

/// Discord token response.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: Option<String>,
    scope: String,
}

/// Start Discord OAuth2 flow.
///
/// Returns a redirect URL to Discord's authorization page.
pub async fn start(
    State((store, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Query(query): Query<StartAuthQuery>,
) -> impl IntoResponse {
    // Check if Discord OAuth is configured
    let (client_id, redirect_uri) = match (
        config.discord_client_id.as_ref(),
        config.discord_redirect_uri.as_ref(),
    ) {
        (Some(id), Some(uri)) => (id, uri),
        _ => {
            return (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "Discord OAuth not configured"
                })),
            )
                .into_response();
        }
    };

    // Generate state nonce
    let nonce = Uuid::new_v4().to_string();

    // Store OAuth state
    let state = OAuthState {
        did: query.did,
        nonce: nonce.clone(),
        platform: Platform::Discord,
        created_at: Utc::now(),
        profile_import: false,
        community_import: false,
    };
    store.store_oauth_state(state);

    // Build authorization URL
    let scopes = DISCORD_SCOPES.join("%20");
    let auth_url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
        config.discord_auth_url(),
        client_id,
        urlencoding::encode(redirect_uri),
        scopes,
        nonce
    );

    Json(StartAuthResponse {
        redirect_url: auth_url,
        state: nonce,
    })
    .into_response()
}

/// Handle Discord OAuth2 callback.
///
/// Exchanges the code for tokens, fetches user info, and links the account.
pub async fn callback(
    State((store, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Query(query): Query<CallbackQuery>,
) -> impl IntoResponse {
    // Verify state and get the associated DID
    let oauth_state = match store.take_oauth_state(&query.state) {
        Some(s) if s.platform == Platform::Discord => s,
        _ => {
            return error_html("Invalid or expired state. Please try again.").into_response();
        }
    };

    let (client_id, client_secret, redirect_uri) = match (
        config.discord_client_id.as_ref(),
        config.discord_client_secret.as_ref(),
        config.discord_redirect_uri.as_ref(),
    ) {
        (Some(id), Some(secret), Some(uri)) => (id, secret, uri),
        _ => {
            return error_html("Discord OAuth not configured").into_response();
        }
    };

    // Exchange code for token
    let client = Client::new();
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

    let token: TokenResponse = match token_response {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Failed to parse Discord token response: {}", e);
                return error_html("Failed to parse token response").into_response();
            }
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!("Discord token exchange failed: {} - {}", status, body);
            return error_html("Failed to exchange code for token").into_response();
        }
        Err(e) => {
            tracing::error!("Discord token request failed: {}", e);
            return error_html("Failed to connect to Discord").into_response();
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
                return error_html("Failed to parse user info").into_response();
            }
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!("Discord user fetch failed: {} - {}", status, body);
            return error_html("Failed to fetch user info").into_response();
        }
        Err(e) => {
            tracing::error!("Discord user request failed: {}", e);
            return error_html("Failed to connect to Discord").into_response();
        }
    };

    // Link the account
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
        discord_username = user.display_name().as_str(),
        "Discord account linked"
    );

    success_html("Discord", &user.display_name()).into_response()
}

/// Handle OAuth error callback.
pub async fn error_callback(Query(query): Query<ErrorCallbackQuery>) -> impl IntoResponse {
    let message = query
        .error_description
        .or(query.error)
        .unwrap_or_else(|| "Unknown error".to_string());

    error_html(&message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discord_user_display_name() {
        // Old style with discriminator
        let user1 = DiscordUser {
            id: "123".to_string(),
            username: "testuser".to_string(),
            discriminator: "1234".to_string(),
            global_name: None,
        };
        assert_eq!(user1.display_name(), "testuser#1234");

        // New style without discriminator
        let user2 = DiscordUser {
            id: "123".to_string(),
            username: "testuser".to_string(),
            discriminator: "0".to_string(),
            global_name: None,
        };
        assert_eq!(user2.display_name(), "testuser");

        // With global name
        let user3 = DiscordUser {
            id: "123".to_string(),
            username: "testuser".to_string(),
            discriminator: "0".to_string(),
            global_name: Some("Test User".to_string()),
        };
        assert_eq!(user3.display_name(), "Test User");
    }
}
