// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::auth::jwt::{AuthorizationToken, ResourcePermission};

use super::AdminAppState;
use super::middleware::{AdminAuth, ApiAuthError, ok};
use super::session::current_unix_seconds;

pub const LOCAL_AUTH_ISSUER: &str = "lore-admin";
pub const LOCAL_AUTH_AUDIENCE: &str = "lore-local";

#[derive(Debug, Clone)]
pub struct ClientAuthSession {
    pub client_state: String,
    pub token: Option<ClientAuthToken>,
}

pub type PendingClientAuthStore = RwLock<HashMap<String, ClientAuthSession>>;

#[derive(Debug, Deserialize)]
pub struct StartClientAuthRequest {
    pub client_state: String,
}

#[derive(Debug, Serialize)]
pub struct StartClientAuthResponse {
    pub session_code: String,
    pub login_url: String,
}

#[derive(Debug, Deserialize)]
pub struct CompleteClientAuthRequest {
    pub client_state: String,
    pub session_code: String,
}

#[derive(Debug, Deserialize)]
pub struct PollClientAuthQuery {
    pub client_state: String,
}

#[derive(Debug, Serialize)]
pub struct PollClientAuthResponse {
    pub token: Option<ClientAuthToken>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientAuthToken {
    pub token: String,
    pub user_id: String,
    pub user_name: String,
    pub expires_ms: u64,
}

pub fn pending_store() -> std::sync::Arc<PendingClientAuthStore> {
    std::sync::Arc::new(RwLock::new(HashMap::new()))
}

pub async fn start(
    State(state): State<AdminAppState>,
    Json(req): Json<StartClientAuthRequest>,
) -> Response {
    if req.client_state.trim().is_empty() {
        return ApiAuthError::BadRequest("client_state is required".into()).into_response();
    }

    let session_code = Uuid::new_v4().to_string();
    state.client_auth_sessions.write().await.insert(
        session_code.clone(),
        ClientAuthSession {
            client_state: req.client_state.clone(),
            token: None,
        },
    );

    ok(StartClientAuthResponse {
        session_code: session_code.clone(),
        login_url: format!(
            "{}/admin/?client_auth_session={}&client_state={}",
            state.public_base_url,
            urlencoding::encode(&session_code),
            urlencoding::encode(&req.client_state),
        ),
    })
}

pub async fn complete(
    State(state): State<AdminAppState>,
    AdminAuth(claims): AdminAuth,
    Json(req): Json<CompleteClientAuthRequest>,
) -> Response {
    let Some(pending) = state
        .client_auth_sessions
        .read()
        .await
        .get(&req.session_code)
        .cloned()
    else {
        return ApiAuthError::NotFound("client auth session not found".into()).into_response();
    };
    if pending.client_state != req.client_state {
        return ApiAuthError::Forbidden.into_response();
    }

    let user = match state.user_store.get(claims.sub).await {
        Ok(Some(user)) if !user.disabled => user,
        Ok(_) => return ApiAuthError::Unauthorized.into_response(),
        Err(e) => return ApiAuthError::Internal(e.to_string()).into_response(),
    };

    let now = current_unix_seconds() as u64;
    let exp = now + state.session_ttl_seconds;
    let token = AuthorizationToken {
        user_id: user.id.to_string(),
        issuer: LOCAL_AUTH_ISSUER.to_string(),
        issued_at: now,
        expires: exp,
        audience: vec![
            LOCAL_AUTH_AUDIENCE.to_string(),
            "127.0.0.1".to_string(),
            "localhost".to_string(),
        ],
        env: "local".to_string(),
        name: user.display_name.clone(),
        preferred_username: user.username.clone(),
        resources: Some(vec![ResourcePermission {
            resource_id: "urc-*".to_string(),
            permission: vec!["*".to_string()],
        }]),
        groups: None,
        is_service_account: Some(false),
        idp: "lore-admin".to_string(),
    };

    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("lore-admin-local".to_string());
    let token = match encode(
        &header,
        &token,
        &EncodingKey::from_secret(state.business_jwt_secret.as_bytes()),
    ) {
        Ok(token) => token,
        Err(e) => {
            return ApiAuthError::Internal(format!("signing client token: {e}")).into_response();
        }
    };

    let response = ClientAuthToken {
        token,
        user_id: user.id.to_string(),
        user_name: user.display_name,
        expires_ms: exp * 1000,
    };
    if let Some(session) = state
        .client_auth_sessions
        .write()
        .await
        .get_mut(&req.session_code)
    {
        session.token = Some(response.clone());
    }
    ok(response)
}

pub async fn poll(
    State(state): State<AdminAppState>,
    Path(session_code): Path<String>,
    Query(query): Query<PollClientAuthQuery>,
) -> Response {
    let mut sessions = state.client_auth_sessions.write().await;
    let Some(session) = sessions.get(&session_code) else {
        return ApiAuthError::NotFound("client auth session not found".into()).into_response();
    };
    if session.client_state != query.client_state {
        return ApiAuthError::Forbidden.into_response();
    }
    if session.token.is_some() {
        let session = sessions.remove(&session_code).expect("session exists");
        return (
            StatusCode::OK,
            Json(PollClientAuthResponse {
                token: session.token,
            }),
        )
            .into_response();
    }
    (StatusCode::OK, Json(PollClientAuthResponse { token: None })).into_response()
}

pub fn router(state: AdminAppState) -> Router<AdminAppState> {
    Router::new()
        .route("/start", post(start))
        .route("/complete", post(complete))
        .route("/poll/{session_code}", get(poll))
        .with_state(state)
}
