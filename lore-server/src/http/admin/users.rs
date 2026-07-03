// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//
// User CRUD endpoints. All state-changing routes require role=Admin.
// List / get endpoints require at least role=Operator (otherwise an
// unauthorized user could harvest usernames).
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use super::AdminAppState;
use super::audit::audit;
use super::middleware::{AdminAuth, ApiAuthError, parse_uuid_param};
use super::session::AdminRole;
use super::store::{AdminUser, AdminUserView, hash_password};

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub display_name: String,
    pub role: AdminRole,
}

pub async fn list_users(State(state): State<AdminAppState>, auth: AdminAuth) -> Response {
    if let Err(e) = auth.require_operator() {
        return e.into_response();
    }
    let users = match state.user_store.list().await {
        Ok(u) => u,
        Err(e) => return ApiAuthError::Internal(e.to_string()).into_response(),
    };
    let view: Vec<AdminUserView> = users.iter().map(AdminUserView::from).collect();
    (StatusCode::OK, Json(view)).into_response()
}

pub async fn get_user(
    State(state): State<AdminAppState>,
    auth: AdminAuth,
    Path(id): Path<String>,
) -> Response {
    if let Err(e) = auth.require_operator() {
        return e.into_response();
    }
    let id = match parse_uuid_param(&id) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    match state.user_store.get(id).await {
        Ok(Some(u)) => (StatusCode::OK, Json(AdminUserView::from(&u))).into_response(),
        Ok(None) => ApiAuthError::NotFound("user not found".into()).into_response(),
        Err(e) => ApiAuthError::Internal(e.to_string()).into_response(),
    }
}

pub async fn create_user(
    State(state): State<AdminAppState>,
    auth: AdminAuth,
    Json(req): Json<CreateUserRequest>,
) -> Response {
    if let Err(e) = auth.require_admin() {
        return e.into_response();
    }
    if req.username.trim().is_empty() {
        return ApiAuthError::BadRequest("username must not be empty".into()).into_response();
    }
    if req.password.len() < 8 {
        return ApiAuthError::BadRequest("password must be at least 8 characters".into())
            .into_response();
    }
    if req.display_name.trim().is_empty() {
        return ApiAuthError::BadRequest("display_name must not be empty".into()).into_response();
    }

    let password_hash = match hash_password(&req.password) {
        Ok(h) => h,
        Err(e) => return ApiAuthError::Internal(format!("hash error: {e}")).into_response(),
    };

    let user = AdminUser {
        id: Uuid::new_v4(),
        username: req.username,
        password_hash,
        display_name: req.display_name,
        role: req.role,
        created_at: Utc::now(),
        disabled: false,
    };
    match state.user_store.create(user.clone()).await {
        Ok(_) => {
            audit(
                &auth.0,
                "create_user",
                Some(&user.username),
                Some(serde_json::json!({"role": user.role})),
            );
            (StatusCode::CREATED, Json(AdminUserView::from(&user))).into_response()
        }
        Err(super::store::UserStoreError::UsernameTaken) => {
            ApiAuthError::BadRequest("username already taken".into()).into_response()
        }
        Err(e) => ApiAuthError::Internal(e.to_string()).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub display_name: Option<String>,
    pub role: Option<AdminRole>,
    pub disabled: Option<bool>,
}

pub async fn update_user(
    State(state): State<AdminAppState>,
    auth: AdminAuth,
    Path(id): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> Response {
    if let Err(e) = auth.require_admin() {
        return e.into_response();
    }
    let id = match parse_uuid_param(&id) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let mut user = match state.user_store.get(id).await {
        Ok(Some(u)) => u,
        Ok(None) => return ApiAuthError::NotFound("user not found".into()).into_response(),
        Err(e) => return ApiAuthError::Internal(e.to_string()).into_response(),
    };
    let mut changed = serde_json::Map::new();
    if let Some(d) = req.display_name {
        if d.trim().is_empty() {
            return ApiAuthError::BadRequest("display_name must not be empty".into())
                .into_response();
        }
        changed.insert(
            "display_name".into(),
            serde_json::json!({"old": user.display_name, "new": d}),
        );
        user.display_name = d;
    }
    if let Some(r) = req.role {
        changed.insert(
            "role".into(),
            serde_json::json!({"old": user.role, "new": r}),
        );
        user.role = r;
    }
    if let Some(d) = req.disabled {
        changed.insert(
            "disabled".into(),
            serde_json::json!({"old": user.disabled, "new": d}),
        );
        user.disabled = d;
    }
    if let Err(e) = state.user_store.update(user.clone()).await {
        return ApiAuthError::Internal(e.to_string()).into_response();
    }
    audit(
        &auth.0,
        "update_user",
        Some(&user.username),
        Some(serde_json::Value::Object(changed)),
    );
    (StatusCode::OK, Json(AdminUserView::from(&user))).into_response()
}

pub async fn delete_user(
    State(state): State<AdminAppState>,
    auth: AdminAuth,
    Path(id): Path<String>,
) -> Response {
    if let Err(e) = auth.require_admin() {
        return e.into_response();
    }
    let id = match parse_uuid_param(&id) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    // Self-delete guard: don't let an admin accidentally nuke themselves.
    if id == auth.0.sub {
        return ApiAuthError::BadRequest("cannot delete the currently authenticated user".into())
            .into_response();
    }
    let user = match state.user_store.get(id).await {
        Ok(Some(u)) => u,
        Ok(None) => return ApiAuthError::NotFound("user not found".into()).into_response(),
        Err(e) => return ApiAuthError::Internal(e.to_string()).into_response(),
    };
    if let Err(e) = state.user_store.delete(id).await {
        return ApiAuthError::Internal(e.to_string()).into_response();
    }
    audit(
        &auth.0,
        "delete_user",
        Some(&user.username),
        Some(serde_json::json!({"role": user.role})),
    );
    (StatusCode::NO_CONTENT, "").into_response()
}

#[derive(Debug, Deserialize)]
pub struct AdminSetPasswordRequest {
    pub new_password: String,
}

pub async fn admin_set_password(
    State(state): State<AdminAppState>,
    auth: AdminAuth,
    Path(id): Path<String>,
    Json(req): Json<AdminSetPasswordRequest>,
) -> Response {
    if let Err(e) = auth.require_admin() {
        return e.into_response();
    }
    if req.new_password.len() < 8 {
        return ApiAuthError::BadRequest("password must be at least 8 characters".into())
            .into_response();
    }
    let id = match parse_uuid_param(&id) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let mut user = match state.user_store.get(id).await {
        Ok(Some(u)) => u,
        Ok(None) => return ApiAuthError::NotFound("user not found".into()).into_response(),
        Err(e) => return ApiAuthError::Internal(e.to_string()).into_response(),
    };
    user.password_hash = match hash_password(&req.new_password) {
        Ok(h) => h,
        Err(e) => return ApiAuthError::Internal(format!("hash error: {e}")).into_response(),
    };
    if let Err(e) = state.user_store.update(user.clone()).await {
        return ApiAuthError::Internal(e.to_string()).into_response();
    }
    audit(&auth.0, "admin_set_password", Some(&user.username), None);
    (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response()
}

pub fn router(state: AdminAppState) -> Router<AdminAppState> {
    Router::new()
        .route("/", get(list_users).post(create_user))
        .route(
            "/{id}",
            get(get_user).patch(update_user).delete(delete_user),
        )
        .route("/{id}/password", post(admin_set_password))
        .with_state(state)
}
