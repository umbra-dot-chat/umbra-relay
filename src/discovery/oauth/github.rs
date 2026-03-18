//! GitHub OAuth2 implementation.
//!
//! Handles the GitHub OAuth2 flow for account linking.

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
    config::GITHUB_SCOPES, types::StartAuthResponse, DiscoveryConfig, DiscoveryStore,
    LinkedAccount, OAuthState, Platform,
};

/// GitHub user response from API.
#[derive(Debug, Deserialize)]
struct GitHubUser {
    id: i64,
    login: String,
    name: Option<String>,
    avatar_url: Option<String>,
}

impl GitHubUser {
    /// Get the display name (name or login).
    fn display_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| self.login.clone())
    }
}

/// GitHub token response.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    scope: String,
}

/// Start GitHub OAuth2 flow.
///
/// Returns a redirect URL to GitHub's authorization page.
pub async fn start(
    State((store, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Query(query): Query<StartAuthQuery>,
) -> impl IntoResponse {
    // Check if GitHub OAuth is configured
    let (client_id, redirect_uri) = match (
        config.github_client_id.as_ref(),
        config.github_redirect_uri.as_ref(),
    ) {
        (Some(id), Some(uri)) => (id, uri),
        _ => {
            return (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "GitHub OAuth not configured"
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
        platform: Platform::GitHub,
        created_at: Utc::now(),
        profile_import: false,
        community_import: false,
    };
    store.store_oauth_state(state);

    // Build authorization URL
    let scopes = GITHUB_SCOPES.join("%20");
    let auth_url = format!(
        "{}?client_id={}&redirect_uri={}&scope={}&state={}",
        config.github_auth_url(),
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

/// Handle GitHub OAuth2 callback.
///
/// Exchanges the code for tokens, fetches user info, and links the account.
pub async fn callback(
    State((store, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Query(query): Query<CallbackQuery>,
) -> impl IntoResponse {
    // Verify state and get the associated DID
    let oauth_state = match store.take_oauth_state(&query.state) {
        Some(s) if s.platform == Platform::GitHub => s,
        _ => {
            return error_html("Invalid or expired state. Please try again.").into_response();
        }
    };

    let (client_id, client_secret, redirect_uri) = match (
        config.github_client_id.as_ref(),
        config.github_client_secret.as_ref(),
        config.github_redirect_uri.as_ref(),
    ) {
        (Some(id), Some(secret), Some(uri)) => (id, secret, uri),
        _ => {
            return error_html("GitHub OAuth not configured").into_response();
        }
    };

    // Exchange code for token
    let client = Client::new();
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

    let token: TokenResponse = match token_response {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Failed to parse GitHub token response: {}", e);
                return error_html("Failed to parse token response").into_response();
            }
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!("GitHub token exchange failed: {} - {}", status, body);
            return error_html("Failed to exchange code for token").into_response();
        }
        Err(e) => {
            tracing::error!("GitHub token request failed: {}", e);
            return error_html("Failed to connect to GitHub").into_response();
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
                return error_html("Failed to parse user info").into_response();
            }
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!("GitHub user fetch failed: {} - {}", status, body);
            return error_html("Failed to fetch user info").into_response();
        }
        Err(e) => {
            tracing::error!("GitHub user request failed: {}", e);
            return error_html("Failed to connect to GitHub").into_response();
        }
    };

    // Link the account
    let account = LinkedAccount {
        platform: Platform::GitHub,
        platform_id: user.id.to_string(),
        platform_username: user.login.clone(),
        linked_at: Utc::now(),
        verified: true,
    };

    store.link_account(&oauth_state.did, account);

    tracing::info!(
        did = oauth_state.did.as_str(),
        github_id = user.id,
        github_username = user.login.as_str(),
        "GitHub account linked"
    );

    success_html("GitHub", &user.login).into_response()
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
    fn test_github_user_display_name() {
        // With name
        let user1 = GitHubUser {
            id: 123,
            login: "octocat".to_string(),
            name: Some("The Octocat".to_string()),
            avatar_url: None,
        };
        assert_eq!(user1.display_name(), "The Octocat");

        // Without name
        let user2 = GitHubUser {
            id: 123,
            login: "octocat".to_string(),
            name: None,
            avatar_url: None,
        };
        assert_eq!(user2.display_name(), "octocat");
    }
}
