// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//
// HTTP admin backend — login / user management / self-service password.
//
// Lives on the same port as `/health_check` (default 41339). To disable
// entirely, set `[server.http.admin] enabled = false` (or omit the section).
//
// The admin subsystem is intentionally separate from the gRPC business
// path: it uses its own HS256 secret, its own issuer/audience claims, and
// its own session store. Admin tokens can never be replayed against the
// business API, and vice versa.
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use axum::Router;
use axum::routing::get;

use self::client_auth::{PendingClientAuthStore, pending_store};
use self::config::AdminSettings;
use self::session::{SessionStore, SessionVerifier};
use self::store::{JsonFileUserStore, UserStore};
pub mod audit;
pub mod auth;
pub mod client_auth;
pub mod config;
pub mod middleware;
pub mod session;
pub mod store;
pub mod users;

#[cfg(test)]
mod tests;

const INDEX_HTML: &str = include_str!("static/index.html");
const APP_JS: &str = include_str!("static/app.js");
const APP_CSS: &str = include_str!("static/app.css");

/// Shared state for every admin endpoint. Cheap to clone — it is just a
/// few `Arc`s.
#[derive(Clone)]
pub struct AdminAppState {
    pub user_store: Arc<dyn UserStore>,
    pub session_verifier: Arc<SessionVerifier>,
    pub session_store: Arc<SessionStore>,
    pub cookie_name: String,
    pub cookie_secure: bool,
    pub session_ttl_seconds: u64,
    pub public_base_url: String,
    pub business_jwt_secret: String,
    pub client_auth_sessions: Arc<PendingClientAuthStore>,
}

impl AsRef<AdminAppState> for AdminAppState {
    fn as_ref(&self) -> &AdminAppState {
        self
    }
}

/// Build the application state from raw settings. Used both at server
/// startup and in tests.
pub async fn build_admin_state(settings: &AdminSettings) -> Result<AdminAppState> {
    if !settings.enabled {
        return Err(anyhow!("admin subsystem is disabled"));
    }
    if settings.session_jwt_secret.len() < 32 {
        return Err(anyhow!(
            "server.http.admin.session_jwt_secret must be at least 32 bytes"
        ));
    }
    if settings.users_file.trim().is_empty() {
        return Err(anyhow!("server.http.admin.users_file must be set"));
    }

    let user_store = JsonFileUserStore::load(&settings.users_file)
        .await
        .with_context(|| format!("loading user store from {}", settings.users_file))?;

    let session_verifier = SessionVerifier::new(settings.session_jwt_secret.as_bytes())
        .map_err(|e| anyhow!("session verifier: {e}"))?;

    let public_base_url = if settings.public_base_url.trim().is_empty() {
        format!(
            "http://{}:{}",
            settings.listen_address.as_deref().unwrap_or("127.0.0.1"),
            settings.listen_port.unwrap_or(41339),
        )
    } else {
        settings.public_base_url.trim_end_matches('/').to_string()
    };

    Ok(AdminAppState {
        user_store,
        session_verifier: Arc::new(session_verifier),
        session_store: SessionStore::new(),
        cookie_name: settings.cookie_name.clone(),
        cookie_secure: settings.cookie_secure,
        session_ttl_seconds: settings.session_ttl_seconds,
        public_base_url,
        business_jwt_secret: settings.session_jwt_secret.clone(),
        client_auth_sessions: pending_store(),
    })
}

/// Build the admin sub-router. Returns a `Router<()>` (stateless) so it can
/// be merged with the main HTTP router (which has its own state type) via
/// `Router::nest`.
pub fn create_router(state: AdminAppState) -> Router {
    let stateful: Router<AdminAppState> = Router::new()
        .nest("/api/auth", auth::router(state.clone()))
        .nest("/api/client-auth", client_auth::router(state.clone()))
        .nest("/api/users", users::router(state.clone()));

    // Static SPA assets (index.html, app.js, app.css) — no state needed.
    let static_routes = Router::new()
        .route(
            "/",
            get(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    INDEX_HTML.to_string(),
                )
            }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [(
                        axum::http::header::CONTENT_TYPE,
                        "application/javascript; charset=utf-8",
                    )],
                    APP_JS.to_string(),
                )
            }),
        )
        .route(
            "/app.css",
            get(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    APP_CSS.to_string(),
                )
            }),
        );

    stateful.with_state(state).merge(static_routes)
}

/// Mount the admin router on the parent HTTP router. Pass `None` to skip.
pub fn mount(parent: Router, state: Option<AdminAppState>) -> Router {
    match state {
        Some(state) => parent
            .route(
                "/admin/",
                get(|| async {
                    (
                        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                        INDEX_HTML.to_string(),
                    )
                }),
            )
            .nest("/admin", create_router(state)),
        None => parent,
    }
}
