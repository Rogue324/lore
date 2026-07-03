// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//
// Settings for the optional HTTP admin backend that lives on the same port
// as `/health_check`. When `enabled = false` (the default), the admin router
// is not mounted and zero cost is paid.

use serde::Deserialize;

/// All knobs for the admin subsystem, deserialized directly from the
/// `[server.http.admin]` block in `local.toml`.
#[derive(Clone, Debug, Deserialize)]
//#[serde(deny_unknown_fields)]
pub struct AdminSettings {
    /// Master switch. When false, the entire admin subsystem is skipped.
    pub enabled: bool,
    /// Path to the JSON file backing the user store. Created on first start
    /// with a default `admin` / `admin` account if missing.
    pub users_file: String,
    /// HS256 signing key. **At least 32 bytes.** When omitted the admin
    /// subsystem is rejected at startup; this is intentional — it prevents
    /// shipping a default key.
    pub session_jwt_secret: String,
    /// How long a session is valid for, in seconds.
    #[serde(default = "default_session_ttl_seconds")]
    pub session_ttl_seconds: u64,
    /// Set `true` when terminating TLS upstream (typical prod); this adds
    /// the `Secure` flag to the session cookie.
    #[serde(default)]
    pub cookie_secure: bool,
    /// Cookie name used to carry the session JWT. Defaults to `session`.
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,
    /// Bind the admin endpoints to a separate listener (e.g. 127.0.0.1).
    /// When set, the admin router is served on a *dedicated* TcpListener
    /// instead of being merged into the main HTTP port. Optional.
    #[serde(default)]
    pub listen_address: Option<String>,
    /// Port for the dedicated admin listener. Required iff `listen_address`
    /// is set.
    #[serde(default)]
    pub listen_port: Option<i32>,
    /// Public base URL used in browser login links generated for the CLI.
    #[serde(default)]
    pub public_base_url: String,
}

fn default_session_ttl_seconds() -> u64 {
    super::session::DEFAULT_SESSION_TTL_SECONDS
}

fn default_cookie_name() -> String {
    super::session::DEFAULT_COOKIE_NAME.to_string()
}

impl Default for AdminSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            users_file: String::new(),
            session_jwt_secret: String::new(),
            session_ttl_seconds: default_session_ttl_seconds(),
            cookie_secure: false,
            cookie_name: default_cookie_name(),
            listen_address: None,
            listen_port: None,
            public_base_url: String::new(),
        }
    }
}
