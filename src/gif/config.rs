//! GIF proxy configuration.
//!
//! Reads the Tenor API key from environment variables.

use std::env;

/// Configuration for the Tenor GIF proxy.
#[derive(Debug, Clone)]
pub struct GifConfig {
    /// Tenor API v2 key (Google Cloud project key).
    pub tenor_api_key: Option<String>,
}

impl GifConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> Self {
        Self {
            tenor_api_key: env::var("TENOR_API_KEY").ok(),
        }
    }

    /// Check if the GIF proxy is configured (API key present).
    pub fn enabled(&self) -> bool {
        self.tenor_api_key.is_some()
    }

    /// Tenor API v2 base URL.
    pub fn tenor_base_url(&self) -> &'static str {
        "https://tenor.googleapis.com/v2"
    }
}

impl Default for GifConfig {
    fn default() -> Self {
        Self::from_env()
    }
}
