//! Xbox Live (Microsoft OAuth 2.0) implementation.
//!
//! Handles the Xbox Live auth flow for account linking.
//! Multi-step: MS OAuth → Xbox Live token → XSTS token → profile.

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
    config::XBOX_SCOPES, types::StartAuthResponse, DiscoveryConfig, DiscoveryStore, LinkedAccount,
    OAuthState, Platform,
};

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

/// Start Xbox (Microsoft) OAuth2 flow.
///
/// Returns a redirect URL to Microsoft's authorization page.
pub async fn start(
    State((store, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Query(query): Query<StartAuthQuery>,
) -> impl IntoResponse {
    let (client_id, redirect_uri) = match (
        config.xbox_client_id.as_ref(),
        Some(&format!("{}/auth/xbox/callback", config.relay_base_url)),
    ) {
        (Some(id), Some(uri)) => (id.clone(), uri.clone()),
        _ => {
            return (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "Xbox OAuth not configured"
                })),
            )
                .into_response();
        }
    };

    let nonce = Uuid::new_v4().to_string();

    let state = OAuthState {
        did: query.did,
        nonce: nonce.clone(),
        platform: Platform::XboxLive,
        created_at: Utc::now(),
        profile_import: false,
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

    Json(StartAuthResponse {
        redirect_url: auth_url,
        state: nonce,
    })
    .into_response()
}

/// Handle Xbox (Microsoft) OAuth2 callback.
///
/// Multi-step flow: MS token → Xbox Live token → XSTS token → link account.
pub async fn callback(
    State((store, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Query(query): Query<CallbackQuery>,
) -> impl IntoResponse {
    let oauth_state = match store.take_oauth_state(&query.state) {
        Some(s) if s.platform == Platform::XboxLive => s,
        _ => {
            return error_html("Invalid or expired state. Please try again.").into_response();
        }
    };

    let (client_id, client_secret) = match (
        config.xbox_client_id.as_ref(),
        config.xbox_client_secret.as_ref(),
    ) {
        (Some(id), Some(secret)) => (id.clone(), secret.clone()),
        _ => {
            return error_html("Xbox OAuth not configured").into_response();
        }
    };

    let redirect_uri = format!("{}/auth/xbox/callback", config.relay_base_url);
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
                return error_html("Failed to parse token response").into_response();
            }
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!("Microsoft token exchange failed: {} - {}", status, body);
            return error_html("Failed to exchange code for token").into_response();
        }
        Err(e) => {
            tracing::error!("Microsoft token request failed: {}", e);
            return error_html("Failed to connect to Microsoft").into_response();
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
                return error_html("Failed to authenticate with Xbox Live").into_response();
            }
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!("Xbox Live auth failed: {} - {}", status, body);
            return error_html("Failed to authenticate with Xbox Live").into_response();
        }
        Err(e) => {
            tracing::error!("Xbox Live auth request failed: {}", e);
            return error_html("Failed to connect to Xbox Live").into_response();
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
                return error_html("Failed to get Xbox authorization").into_response();
            }
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!("XSTS authorization failed: {} - {}", status, body);
            return error_html("Failed to get Xbox authorization").into_response();
        }
        Err(e) => {
            tracing::error!("XSTS request failed: {}", e);
            return error_html("Failed to connect to Xbox services").into_response();
        }
    };

    // Extract gamertag and XUID from XSTS display claims
    let xui = xsts
        .display_claims
        .and_then(|dc| dc.xui)
        .and_then(|xui| xui.into_iter().next());

    let gamertag = xui.as_ref().and_then(|x| x.gtg.clone()).unwrap_or_default();
    let xuid = xui.as_ref().and_then(|x| x.xid.clone()).unwrap_or_default();

    let platform_id = if xuid.is_empty() {
        xui.as_ref().and_then(|x| x.uhs.clone()).unwrap_or_default()
    } else {
        xuid
    };

    // Link the account
    let account = LinkedAccount {
        platform: Platform::XboxLive,
        platform_id: platform_id.clone(),
        platform_username: gamertag.clone(),
        linked_at: Utc::now(),
        verified: true,
    };

    store.link_account(&oauth_state.did, account);

    tracing::info!(
        did = oauth_state.did.as_str(),
        xbox_id = platform_id.as_str(),
        gamertag = gamertag.as_str(),
        "Xbox account linked"
    );

    success_html("Xbox", &gamertag).into_response()
}

/// Handle OAuth error callback.
pub async fn error_callback(Query(query): Query<ErrorCallbackQuery>) -> impl IntoResponse {
    let message = query
        .error_description
        .or(query.error)
        .unwrap_or_else(|| "Unknown error".to_string());

    error_html(&message)
}
