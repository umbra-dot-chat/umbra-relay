//! OAuth2 handlers for platform account linking.
//!
//! Provides OAuth2/OpenID flows for Discord, GitHub, Steam, Bluesky, and Xbox.

pub mod bluesky;
pub mod community_import;
pub mod discord;
pub mod github;
pub mod profile_import;
pub mod steam;
pub mod xbox;

use axum::response::Html;
use serde::Deserialize;

/// Common query parameters for OAuth start.
#[derive(Debug, Deserialize)]
pub struct StartAuthQuery {
    /// The user's Umbra DID.
    pub did: String,
    /// Optional client-provided state for CSRF protection.
    pub state: Option<String>,
}

/// Query parameters for OAuth callback.
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    /// Authorization code from the OAuth provider.
    pub code: String,
    /// State parameter for CSRF verification.
    pub state: String,
}

/// Error query parameters for OAuth callback.
#[derive(Debug, Deserialize)]
pub struct ErrorCallbackQuery {
    /// Error from the OAuth provider.
    pub error: Option<String>,
    /// Error description.
    pub error_description: Option<String>,
}

/// Generate a success HTML page after OAuth linking.
pub fn success_html(platform: &str, username: &str) -> Html<String> {
    Html(format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Account Linked - Umbra</title>
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
        .platform {{
            color: #a855f7;
            text-transform: capitalize;
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
        <h1><span class="platform">{}</span> Account Linked</h1>
        <div class="username">{}</div>
        <p>Your account has been successfully linked to Umbra.</p>
        <p class="close-hint">Returning to app...</p>
    </div>
    <script>
        // Close or redirect back to app
        setTimeout(() => {{
            if (window.opener) {{
                window.close();
            }} else {{
                window.location.href = 'umbra://oauth/callback?success=true';
            }}
        }}, 1500);
    </script>
</body>
</html>"#,
        platform, username
    ))
}

/// Generate an error HTML page.
pub fn error_html(message: &str) -> Html<String> {
    Html(format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Error - Umbra</title>
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
        <h1>Something went wrong</h1>
        <div class="error">{}</div>
        <p>Please close this window and try again.</p>
    </div>
    <script>
        // On mobile in-app browser, redirect back to app after delay
        if (!window.opener) {{
            setTimeout(() => {{
                window.location.href = 'umbra://oauth/callback?success=false';
            }}, 2000);
        }}
    </script>
</body>
</html>"#,
        message
    ))
}
