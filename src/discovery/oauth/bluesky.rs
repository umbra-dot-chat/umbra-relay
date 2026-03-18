//! Bluesky AT Protocol OAuth 2.0 implementation.
//!
//! Handles the Bluesky OAuth2 flow for account linking.

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
    config::BLUESKY_SCOPES, types::StartAuthResponse, DiscoveryConfig, DiscoveryStore,
    LinkedAccount, OAuthState, Platform,
};

/// Bluesky token response.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: Option<String>,
    #[allow(dead_code)]
    refresh_token: Option<String>,
    /// The user's DID (decentralized identifier).
    sub: Option<String>,
}

/// Bluesky profile from app.bsky.actor.getProfile.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlueskyProfile {
    did: String,
    handle: String,
    display_name: Option<String>,
}

/// Start Bluesky OAuth2 flow.
///
/// Returns a redirect URL to Bluesky's authorization page.
pub async fn start(
    State((store, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Query(query): Query<StartAuthQuery>,
) -> impl IntoResponse {
    let (client_id, redirect_uri) = match (
        config.bluesky_client_id.as_ref(),
        // For account linking, use the auth redirect URI
        // (fall back to constructing from relay_base_url)
        Some(&format!("{}/auth/bluesky/callback", config.relay_base_url)),
    ) {
        (Some(id), Some(uri)) => (id.clone(), uri.clone()),
        _ => {
            return (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "Bluesky OAuth not configured"
                })),
            )
                .into_response();
        }
    };

    let nonce = Uuid::new_v4().to_string();

    let state = OAuthState {
        did: query.did,
        nonce: nonce.clone(),
        platform: Platform::Bluesky,
        created_at: Utc::now(),
        profile_import: false,
        community_import: false,
    };
    store.store_oauth_state(state);

    let scopes = BLUESKY_SCOPES.join(" ");
    let auth_url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
        config.bluesky_auth_url(),
        urlencoding::encode(&client_id),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(&scopes),
        nonce
    );

    Json(StartAuthResponse {
        redirect_url: auth_url,
        state: nonce,
    })
    .into_response()
}

/// Handle Bluesky OAuth2 callback.
///
/// Exchanges the code for tokens, fetches user profile, and links the account.
pub async fn callback(
    State((store, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Query(query): Query<CallbackQuery>,
) -> impl IntoResponse {
    let oauth_state = match store.take_oauth_state(&query.state) {
        Some(s) if s.platform == Platform::Bluesky => s,
        _ => {
            return error_html("Invalid or expired state. Please try again.").into_response();
        }
    };

    let (client_id, client_secret) = match (
        config.bluesky_client_id.as_ref(),
        config.bluesky_client_secret.as_ref(),
    ) {
        (Some(id), Some(secret)) => (id.clone(), secret.clone()),
        _ => {
            return error_html("Bluesky OAuth not configured").into_response();
        }
    };

    let redirect_uri = format!("{}/auth/bluesky/callback", config.relay_base_url);
    let client = Client::new();

    // Exchange code for token
    let token_response = client
        .post(config.bluesky_token_url())
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "grant_type": "authorization_code",
            "code": query.code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
        }))
        .send()
        .await;

    let token: TokenResponse = match token_response {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Failed to parse Bluesky token response: {}", e);
                return error_html("Failed to parse token response").into_response();
            }
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!("Bluesky token exchange failed: {} - {}", status, body);
            return error_html("Failed to exchange code for token").into_response();
        }
        Err(e) => {
            tracing::error!("Bluesky token request failed: {}", e);
            return error_html("Failed to connect to Bluesky").into_response();
        }
    };

    let bsky_did = token.sub.unwrap_or_default();

    // Fetch profile
    let profile_url = format!(
        "{}/app.bsky.actor.getProfile?actor={}",
        config.bluesky_api_url(),
        urlencoding::encode(&bsky_did),
    );

    let profile_response = client
        .get(&profile_url)
        .header("Authorization", format!("Bearer {}", token.access_token))
        .send()
        .await;

    let bsky_profile: Option<BlueskyProfile> = match profile_response {
        Ok(resp) if resp.status().is_success() => resp.json().await.ok(),
        _ => None,
    };

    let handle = bsky_profile
        .as_ref()
        .map(|p| p.handle.clone())
        .unwrap_or_else(|| bsky_did.clone());

    let display_name = bsky_profile
        .as_ref()
        .and_then(|p| p.display_name.clone())
        .unwrap_or_else(|| handle.clone());

    // Link the account
    let account = LinkedAccount {
        platform: Platform::Bluesky,
        platform_id: bsky_did.clone(),
        platform_username: handle.clone(),
        linked_at: Utc::now(),
        verified: true,
    };

    store.link_account(&oauth_state.did, account);

    tracing::info!(
        did = oauth_state.did.as_str(),
        bsky_did = bsky_did.as_str(),
        bsky_handle = handle.as_str(),
        "Bluesky account linked"
    );

    success_html("Bluesky", &display_name).into_response()
}

/// Handle OAuth error callback.
pub async fn error_callback(Query(query): Query<ErrorCallbackQuery>) -> impl IntoResponse {
    let message = query
        .error_description
        .or(query.error)
        .unwrap_or_else(|| "Unknown error".to_string());

    error_html(&message)
}
