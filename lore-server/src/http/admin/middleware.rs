// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//
// Axum extractor that validates a session cookie (or `Authorization: Bearer`)
// header and yields the parsed `SessionClaims`.
//
// Two pieces work together: this extractor (short-circuits with 401) and the
// role-check helpers below (return 403). The cookie path is used by the
// browser SPA; the bearer path is used by API clients.
use std::str::FromStr;

use axum::extract::{FromRef, FromRequestParts, State};
use axum::http::header::{AUTHORIZATION, COOKIE, HeaderMap};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

use super::session::{SessionClaims, SessionError};
use super::AdminAppState;

/// Wraps an authenticated session. Use as a handler argument.
#[derive(Clone, Debug)]
pub struct AdminAuth(pub SessionClaims);

impl AdminAuth {
    /// Reject the request unless the actor's role is at least `Operator`.
    pub fn require_operator(&self) -> Result<(), ApiAuthError> {
        match self.0.role {
            super::session::AdminRole::Admin | super::session::AdminRole::Operator => Ok(()),
            _ => Err(ApiAuthError::Forbidden),
        }
    }

    /// Reject the request unless the actor is an `Admin`.
    pub fn require_admin(&self) -> Result<(), ApiAuthError> {
        match self.0.role {
            super::session::AdminRole::Admin => Ok(()),
            _ => Err(ApiAuthError::Forbidden),
        }
    }
}

#[derive(Debug, Error)]
pub enum ApiAuthError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    NotFound(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl ApiAuthError {
    pub fn into_response(self) -> Response {
        let (status, code) = match &self {
            ApiAuthError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            ApiAuthError::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            ApiAuthError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            ApiAuthError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            ApiAuthError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.as_str()),
        };
        let body = ErrorBody { error: code.to_string() };
        (status, Json(body)).into_response()
    }
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

impl FromRef<AdminAppState> for AdminAppState {
    fn from_ref(input: &AdminAppState) -> Self {
        input.clone()
    }
}

#[async_trait::async_trait]
impl FromRequestParts<AdminAppState> for AdminAuth {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AdminAppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_token(&parts.headers, &state.cookie_name)
            .ok_or_else(|| ApiAuthError::Unauthorized.into_response())?;

        let claims = state
            .session_verifier
            .verify(&token)
            .map_err(|_| ApiAuthError::Unauthorized.into_response())?;

        if state.session_store.is_revoked(&claims.jti).await {
            return Err(ApiAuthError::Unauthorized.into_response());
        }

        Ok(AdminAuth(claims))
    }
}

fn extract_token(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    // 1. Cookie first (browser SPA path).
    if let Some(raw) = headers.get(COOKIE).and_then(|v| v.to_str().ok()) {
        for part in raw.split(';') {
            let trimmed = part.trim();
            if let Some((k, v)) = trimmed.split_once('=')
                && k == cookie_name
            {
                return Some(v.to_string());
            }
        }
    }
    // 2. Bearer fallback (CLI / API path).
    if let Some(raw) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok())
        && let Some(stripped) = raw.strip_prefix("Bearer ")
    {
        return Some(stripped.to_string());
    }
    None
}

/// Helper for handlers that want to write a 200 + JSON body.
pub fn ok<T: Serialize>(value: T) -> Response {
    (StatusCode::OK, Json(value)).into_response()
}

pub fn build_set_cookie_header(
    cookie_name: &str,
    token: &str,
    ttl_seconds: u64,
    secure: bool,
) -> String {
    format!(
        "{}={}; Path=/; Max-Age={}{}; HttpOnly; SameSite=Strict",
        cookie_name,
        token,
        ttl_seconds,
        if secure { "; Secure" } else { "" },
    )
}

pub fn parse_uuid_param(s: &str) -> Result<Uuid, ApiAuthError> {
    Uuid::from_str(s).map_err(|_| ApiAuthError::BadRequest(format!("invalid uuid: {s}")))
}

#[allow(dead_code)]
pub fn ensure_content_type_json(headers: &HeaderMap) -> Result<(), ApiAuthError> {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !ct.starts_with("application/json") {
        return Err(ApiAuthError::BadRequest("expected application/json body".into()));
    }
    Ok(())
}

// Make `State` available to handler modules that import this file.
#[allow(unused_imports)]
use State as _State;
