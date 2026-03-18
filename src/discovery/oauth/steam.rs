//! Steam OpenID 2.0 implementation.
//!
//! Handles the Steam OpenID 2.0 flow for account linking.
//! Steam uses OpenID 2.0 (not OAuth 2.0) — the callback receives a
//! `claimed_id` URL containing the Steam64 ID directly.

use axum::{
    extract::{Query, State},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use reqwest::Client;
use serde::Deserialize;
use uuid::Uuid;

use super::{error_html, success_html, StartAuthQuery};
use crate::discovery::{
    types::StartAuthResponse, DiscoveryConfig, DiscoveryStore, LinkedAccount, OAuthState, Platform,
};

/// Steam player summary from GetPlayerSummaries API.
#[derive(Debug, Deserialize)]
struct SteamPlayerSummary {
    steamid: String,
    personaname: String,
    #[allow(dead_code)]
    profileurl: Option<String>,
    avatar: Option<String>,
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
pub struct SteamCallbackQuery {
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
    /// We pass our state nonce in a custom parameter.
    pub state: Option<String>,
}

/// Start Steam OpenID 2.0 flow.
///
/// Returns a redirect URL to Steam's OpenID login page.
pub async fn start(
    State((store, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Query(query): Query<StartAuthQuery>,
) -> impl IntoResponse {
    // Check if Steam is configured
    if !config.steam_enabled() {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "Steam not configured"
            })),
        )
            .into_response();
    }

    let nonce = Uuid::new_v4().to_string();

    // Store OAuth state
    let state = OAuthState {
        did: query.did,
        nonce: nonce.clone(),
        platform: Platform::Steam,
        created_at: Utc::now(),
        profile_import: false,
        community_import: false,
    };
    store.store_oauth_state(state);

    // Build Steam OpenID 2.0 redirect URL
    let return_to = format!(
        "{}/auth/steam/callback?state={}",
        config.relay_base_url, nonce
    );

    let auth_url = format!(
        "{}?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=checkid_setup&openid.return_to={}&openid.realm={}&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select",
        config.steam_openid_url(),
        urlencoding::encode(&return_to),
        urlencoding::encode(&config.relay_base_url),
    );

    Json(StartAuthResponse {
        redirect_url: auth_url,
        state: nonce,
    })
    .into_response()
}

/// Handle Steam OpenID 2.0 callback.
///
/// Verifies the OpenID assertion, extracts the Steam64 ID, fetches the
/// player profile, and links the account.
pub async fn callback(
    State((store, config)): State<(DiscoveryStore, DiscoveryConfig)>,
    Query(query): Query<SteamCallbackQuery>,
) -> impl IntoResponse {
    let state_nonce = match &query.state {
        Some(s) => s.clone(),
        None => {
            return error_html("Missing state parameter").into_response();
        }
    };

    // Verify state
    let oauth_state = match store.take_oauth_state(&state_nonce) {
        Some(s) if s.platform == Platform::Steam => s,
        _ => {
            return error_html("Invalid or expired state. Please try again.").into_response();
        }
    };

    // Extract Steam64 ID from claimed_id
    // Format: https://steamcommunity.com/openid/id/76561198xxxxxxxxx
    let steam_id = match &query.claimed_id {
        Some(claimed_id) => {
            if let Some(id) = claimed_id.strip_prefix("https://steamcommunity.com/openid/id/") {
                id.to_string()
            } else {
                return error_html("Invalid Steam claimed_id format").into_response();
            }
        }
        None => {
            return error_html("No Steam claimed_id in callback").into_response();
        }
    };

    // Verify the OpenID assertion with Steam
    let client = Client::new();
    let verify_ok = verify_steam_openid(&client, &config, &query).await;
    if !verify_ok {
        return error_html("Steam OpenID verification failed").into_response();
    }

    // Fetch player profile using Steam Web API
    let api_key = match &config.steam_api_key {
        Some(key) => key,
        None => {
            return error_html("Steam API key not configured").into_response();
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

    // Link the account
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
        persona_name = persona_name.as_str(),
        "Steam account linked"
    );

    success_html("Steam", &persona_name).into_response()
}

/// Verify Steam OpenID 2.0 assertion by calling Steam back.
async fn verify_steam_openid(
    client: &Client,
    config: &DiscoveryConfig,
    query: &SteamCallbackQuery,
) -> bool {
    // Build verification request — re-send all params with mode=check_authentication
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

/// Handle OpenID error callback.
pub async fn error_callback() -> impl IntoResponse {
    error_html("Steam authentication was cancelled or failed.")
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_steam_id_extraction() {
        let claimed_id = "https://steamcommunity.com/openid/id/76561198012345678";
        let id = claimed_id
            .strip_prefix("https://steamcommunity.com/openid/id/")
            .unwrap();
        assert_eq!(id, "76561198012345678");
    }
}
