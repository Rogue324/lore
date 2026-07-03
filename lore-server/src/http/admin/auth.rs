// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//
// Login / logout / me endpoints. Login takes a username + password,
// issues an HS256 session JWT, and stores it as an HttpOnly cookie.
//
// Failure responses are deliberately indistinguishable between
// "unknown user" and "wrong password" so callers cannot enumerate
// valid usernames by timing or message text.
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::AdminAppState;
use super::audit::audit;
use super::middleware::{AdminAuth, build_set_cookie_header, ok};
use super::session::{SessionClaims, current_unix_seconds};
use super::store::{
    AdminUserView, DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_USERNAME, hash_password, verify_password,
};

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: i64,
    pub user: AdminUserView,
}

pub async fn login(State(state): State<AdminAppState>, Json(req): Json<LoginRequest>) -> Response {
    // Look up user. Always take roughly the same code path so timing
    // doesn't leak whether the username exists.
    let user = match state.user_store.find_by_username(&req.username).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            // Burn a tiny bit of CPU so timing is closer to the hash path.
            let _ = verify_password(
                &req.password,
                "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$\
                 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            );
            return unauthorized();
        }
        Err(e) => return internal(format!("user store: {e}")),
    };

    if user.disabled {
        return unauthorized();
    }

    let pass_ok = match verify_password(&req.password, &user.password_hash) {
        Ok(b) => b,
        Err(e) => return internal(format!("verification error: {e}")),
    };

    if !pass_ok {
        return unauthorized();
    }

    let now = current_unix_seconds();
    let exp = now + state.session_ttl_seconds as i64;
    let claims = SessionClaims {
        sub: user.id,
        username: user.username.clone(),
        role: user.role,
        iat: now,
        exp,
        jti: Uuid::new_v4(),
    };

    let token = match state.session_verifier.sign(&claims) {
        Ok(t) => t,
        Err(e) => return internal(format!("signing error: {e}")),
    };

    state.session_store.put(claims.jti, exp).await;

    if user.username == DEFAULT_ADMIN_USERNAME
        && verify_password(DEFAULT_ADMIN_PASSWORD, &user.password_hash).unwrap_or(false)
    {
        tracing::warn!(
            user = %user.username,
            "admin is still using the default password; rotate it via PATCH /admin/api/users/{{id}}"
        );
    }

    audit(
        &claims,
        "login",
        Some(&user.username),
        Some(serde_json::json!({"event": "login"})),
    );

    let cookie = build_set_cookie_header(
        &state.cookie_name,
        &token,
        state.session_ttl_seconds,
        state.cookie_secure,
    );

    let body = LoginResponse {
        token: token.clone(),
        expires_at: exp,
        user: AdminUserView::from(&user),
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        cookie.parse().expect("cookie header should be valid"),
    );
    (StatusCode::OK, headers, Json(body)).into_response()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({
            "error": "invalid credentials"
        })),
    )
        .into_response()
}

fn internal(msg: impl Into<String>) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": msg.into() })),
    )
        .into_response()
}

fn bad_request(msg: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": msg.into() })),
    )
        .into_response()
}

#[derive(Debug, Serialize)]
pub struct LogoutResponse {
    pub ok: bool,
}

pub async fn logout(State(state): State<AdminAppState>, AdminAuth(claims): AdminAuth) -> Response {
    state.session_store.revoke(claims.jti).await;
    audit(&claims, "logout", Some(&claims.username), None);
    let body = LogoutResponse { ok: true };

    // Best-effort cookie clear. We don't know if the request used a cookie
    // or a bearer header, so we always include the clear-cookie path.
    let clear = format!(
        "{}=; Path=/; Max-Age=0{}; HttpOnly; SameSite=Strict",
        state.cookie_name,
        if state.cookie_secure { "; Secure" } else { "" },
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        clear.parse().expect("cookie header should be valid"),
    );
    (StatusCode::OK, headers, Json(body)).into_response()
}

pub async fn me(State(state): State<AdminAppState>, AdminAuth(claims): AdminAuth) -> Response {
    let user_id = claims.sub;
    let user = match state.user_store.get(user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            // Session points at a user that no longer exists; revoke.
            state.session_store.revoke(claims.jti).await;
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "user no longer exists" })),
            )
                .into_response();
        }
        Err(e) => return internal(format!("user store: {e}")),
    };
    ok(serde_json::json!({
        "session": claims,
        "user": AdminUserView::from(&user),
        "server_time": Utc::now().timestamp(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct ChangeOwnPasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

pub async fn change_my_password(
    State(state): State<AdminAppState>,
    AdminAuth(claims): AdminAuth,
    Json(req): Json<ChangeOwnPasswordRequest>,
) -> Response {
    let mut user = match state.user_store.get(claims.sub).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "user no longer exists" })),
            )
                .into_response();
        }
        Err(e) => return internal(format!("user store: {e}")),
    };

    if !verify_password(&req.current_password, &user.password_hash).unwrap_or(false) {
        return unauthorized();
    }

    if req.new_password.len() < 8 {
        return bad_request("new password must be at least 8 characters");
    }

    user.password_hash = match hash_password(&req.new_password) {
        Ok(h) => h,
        Err(e) => return internal(format!("hashing error: {e}")),
    };

    if let Err(e) = state.user_store.update(user.clone()).await {
        return internal(format!("persistence error: {e}"));
    }
    audit(&claims, "change_own_password", Some(&user.username), None);
    ok(serde_json::json!({"ok": true}))
}

pub fn router(state: AdminAppState) -> Router<AdminAppState> {
    Router::new()
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/me", get(me))
        .route("/me/password", post(change_my_password))
        .with_state(state)
}
