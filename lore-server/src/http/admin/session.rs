// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//
// Admin session management — HS256 JWT issue/verify + in-memory revocation store.
//
// Sessions are independent of the gRPC `AuthorizationToken` path. The admin
// JWTs use their own issuer/audience/secret so admin tokens can never be
// confused for (or replayed against) the business API.
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Minimum recommended length for the session HMAC key (256 bits).
pub const MIN_SESSION_KEY_BYTES: usize = 32;

/// Default cookie name used to deliver the session token to the browser.
pub const DEFAULT_COOKIE_NAME: &str = "session";

/// Default session lifetime (8 hours).
pub const DEFAULT_SESSION_TTL_SECONDS: u64 = 8 * 60 * 60;

/// Issuer claim for admin-issued session JWTs.
pub const SESSION_ISSUER: &str = "lore-server-admin";

/// Audience claim for admin-issued session JWTs.
pub const SESSION_AUDIENCE: &str = "lore-admin";

/// Roles an admin user can be granted.
///
/// `Admin` can manage users; `Operator` can manage repositories; `Viewer`
/// is read-only. The matrix is enforced inside individual handlers — the
/// role check is a simple match on this enum.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminRole {
    Admin,
    Operator,
    Viewer,
}

/// Claims embedded in the session JWT.
///
/// `jti` is checked against the in-memory revocation store on every request,
/// which lets `POST /admin/api/logout` invalidate tokens even before `exp`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    pub sub: Uuid,
    pub username: String,
    pub role: AdminRole,
    pub iat: i64,
    pub exp: i64,
    pub jti: Uuid,
}

/// Errors that can occur when issuing or verifying session tokens.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("session HMAC key is too short (need at least {MIN_SESSION_KEY_BYTES} bytes)")]
    KeyTooShort,
    #[error("session JWT validation failed: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("session has been revoked")]
    Revoked,
    #[error("session has expired")]
    Expired,
}

/// HS256 issuer + verifier. The same struct is used on both sides — the
/// `EncodingKey` and `DecodingKey` are derived from the same secret.
#[derive(Clone)]
pub struct SessionVerifier {
    encoding_key: Arc<EncodingKey>,
    decoding_key: Arc<DecodingKey>,
    validation: Validation,
}

impl SessionVerifier {
    /// Build a verifier from a raw secret. The secret must be at least
    /// `MIN_SESSION_KEY_BYTES` long; shorter keys are rejected outright
    /// (HMAC-SHA256 with <256 bit keys is widely considered unsafe).
    pub fn new(secret: &[u8]) -> Result<Self, SessionError> {
        if secret.len() < MIN_SESSION_KEY_BYTES {
            return Err(SessionError::KeyTooShort);
        }
        let encoding_key = EncodingKey::from_secret(secret);
        let decoding_key = DecodingKey::from_secret(secret);
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[SESSION_ISSUER]);
        validation.set_audience(&[SESSION_AUDIENCE]);
        validation.validate_exp = true;
        Ok(Self {
            encoding_key: Arc::new(encoding_key),
            decoding_key: Arc::new(decoding_key),
            validation,
        })
    }

    /// Sign a claims struct into a compact JWT.
    pub fn sign(&self, claims: &SessionClaims) -> Result<String, SessionError> {
        encode(&Header::new(Algorithm::HS256), claims, &self.encoding_key).map_err(Into::into)
    }

    /// Verify a token. Returns the parsed claims on success.
    ///
    /// Note: revocation must be checked separately via `SessionStore::is_revoked`,
    /// because JWT decoding alone cannot see the in-memory revocation list.
    pub fn verify(&self, token: &str) -> Result<SessionClaims, SessionError> {
        let data = decode::<SessionClaims>(token, &self.decoding_key, &self.validation)?;
        Ok(data.claims)
    }
}

/// In-memory revocation store keyed by `jti`. Re-validating a revoked
/// session returns `SessionError::Revoked`. Expired entries are pruned
/// lazily on access — there is no background sweeper.
#[derive(Default)]
pub struct SessionStore {
    inner: RwLock<HashMap<Uuid, i64>>, // jti -> exp (unix seconds)
}

impl SessionStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub async fn put(&self, jti: Uuid, exp: i64) {
        self.inner.write().await.insert(jti, exp);
    }

    pub async fn revoke(&self, jti: Uuid) {
        self.inner.write().await.remove(&jti);
    }

    pub async fn is_revoked(&self, jti: &Uuid) -> bool {
        let now = current_unix_seconds();
        let mut guard = self.inner.write().await;
        // Lazy GC: drop expired entries as we walk past them.
        guard.retain(|_, exp| *exp > now);
        !guard.contains_key(jti)
    }

    #[cfg(test)]
    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }
}

pub(crate) fn current_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> Vec<u8> {
        b"0123456789abcdef0123456789abcdef".to_vec() // 32 bytes
    }

    fn claims() -> SessionClaims {
        SessionClaims {
            sub: Uuid::new_v4(),
            username: "alice".into(),
            role: AdminRole::Admin,
            iat: current_unix_seconds(),
            exp: current_unix_seconds() + 60,
            jti: Uuid::new_v4(),
        }
    }

    #[test]
    fn rejects_short_key() {
        assert!(matches!(
            SessionVerifier::new(b"short"),
            Err(SessionError::KeyTooShort)
        ));
    }

    #[tokio::test]
    async fn round_trip_sign_and_verify() {
        let v = SessionVerifier::new(&secret()).unwrap();
        let c = claims();
        let token = v.sign(&c).unwrap();
        let parsed = v.verify(&token).unwrap();
        assert_eq!(parsed.username, c.username);
        assert_eq!(parsed.sub, c.sub);
    }

    #[tokio::test]
    async fn revocation_marks_session_invalid() {
        let v = SessionVerifier::new(&secret()).unwrap();
        let store = SessionStore::new();
        let c = claims();
        let token = v.sign(&c).unwrap();
        store.put(c.jti, c.exp).await;
        assert!(!store.is_revoked(&c.jti).await);
        store.revoke(c.jti).await;
        assert!(store.is_revoked(&c.jti).await);
    }
}
