// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//
// User store trait + JSON-file backed implementation.
//
// On startup the file is read; on every mutation it is rewritten atomically
// (write to `users.json.tmp`, fsync, rename) so a crash mid-write never leaves
// a truncated file.
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, anyhow};
use argon2::{self, Config};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::session::AdminRole;

/// Default username for the bootstrap admin account created on first start.
pub const DEFAULT_ADMIN_USERNAME: &str = "admin";
/// Default password for the bootstrap admin account. **MUST be rotated on
/// first successful login** — the server emits a startup `WARN` log when the
/// default credential is in use.
pub const DEFAULT_ADMIN_PASSWORD: &str = "admin";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminUser {
    pub id: Uuid,
    pub username: String,
    /// argon2 PHC string (e.g. `$argon2id$v=19$m=...`). Never serialized to
    /// API responses; see `serialize_with_password_omitted`.
    pub password_hash: String,
    pub display_name: String,
    pub role: AdminRole,
    pub created_at: DateTime<Utc>,
    pub disabled: bool,
}

#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("user not found")]
    NotFound,
    #[error("username already taken")]
    UsernameTaken,
    #[error("password hashing failed: {0}")]
    Hashing(String),
    #[error("password verification failed: {0}")]
    Verification(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("internal error: {0}")]
    Internal(String),
}

/// The shape returned by the API — never includes the password hash.
#[derive(Clone, Debug, Serialize)]
pub struct AdminUserView {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub role: AdminRole,
    pub created_at: DateTime<Utc>,
    pub disabled: bool,
}

impl From<&AdminUser> for AdminUserView {
    fn from(u: &AdminUser) -> Self {
        Self {
            id: u.id,
            username: u.username.clone(),
            display_name: u.display_name.clone(),
            role: u.role,
            created_at: u.created_at,
            disabled: u.disabled,
        }
    }
}

#[async_trait::async_trait]
pub trait UserStore: Send + Sync {
    async fn list(&self) -> Result<Vec<AdminUser>, UserStoreError>;
    async fn get(&self, id: Uuid) -> Result<Option<AdminUser>, UserStoreError>;
    async fn find_by_username(&self, username: &str) -> Result<Option<AdminUser>, UserStoreError>;
    async fn create(&self, user: AdminUser) -> Result<AdminUser, UserStoreError>;
    async fn update(&self, user: AdminUser) -> Result<AdminUser, UserStoreError>;
    async fn delete(&self, id: Uuid) -> Result<(), UserStoreError>;
}

/// Hash a plaintext password with argon2id (m=19MiB, t=2, p=1) and return the
/// PHC string. This is the OWASP-recommended baseline for interactive logins.
pub fn hash_password(plain: &str) -> Result<String, UserStoreError> {
    let salt = rand::random::<[u8; 16]>();
    let config = Config::default();
    argon2::hash_encoded(plain.as_bytes(), &salt, &config)
        .map_err(|e| UserStoreError::Hashing(e.to_string()))
}

/// Verify a plaintext password against a PHC string. Returns `Ok(true)` on
/// match; `Ok(false)` on mismatch; `Err` only on truly malformed hashes.
pub fn verify_password(plain: &str, phc: &str) -> Result<bool, UserStoreError> {
    Ok(argon2::verify_encoded(phc, plain.as_bytes())
        .map_err(|e| UserStoreError::Verification(e.to_string()))?)
}

/// Simple in-memory store, useful for tests and the M1 (demo) tier.
pub struct InMemoryUserStore {
    inner: RwLock<HashMap<Uuid, AdminUser>>,
}

impl InMemoryUserStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { inner: RwLock::new(HashMap::new()) })
    }
}

#[async_trait::async_trait]
impl UserStore for InMemoryUserStore {
    async fn list(&self) -> Result<Vec<AdminUser>, UserStoreError> {
        Ok(self.inner.read().await.values().cloned().collect())
    }

    async fn get(&self, id: Uuid) -> Result<Option<AdminUser>, UserStoreError> {
        Ok(self.inner.read().await.get(&id).cloned())
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<AdminUser>, UserStoreError> {
        Ok(self
            .inner
            .read()
            .await
            .values()
            .find(|u| u.username == username)
            .cloned())
    }

    async fn create(&self, user: AdminUser) -> Result<AdminUser, UserStoreError> {
        let mut g = self.inner.write().await;
        if g.values().any(|u| u.username == user.username) {
            return Err(UserStoreError::UsernameTaken);
        }
        g.insert(user.id, user.clone());
        Ok(user)
    }

    async fn update(&self, user: AdminUser) -> Result<AdminUser, UserStoreError> {
        let mut g = self.inner.write().await;
        if !g.contains_key(&user.id) {
            return Err(UserStoreError::NotFound);
        }
        g.insert(user.id, user.clone());
        Ok(user)
    }

    async fn delete(&self, id: Uuid) -> Result<(), UserStoreError> {
        let mut g = self.inner.write().await;
        if g.remove(&id).is_none() {
            return Err(UserStoreError::NotFound);
        }
        Ok(())
    }
}

/// JSON-file backed store (M2 tier). Atomic writes: write to `.tmp` then
/// rename into place, fsync the directory entry.
pub struct JsonFileUserStore {
    path: PathBuf,
    inner: RwLock<HashMap<Uuid, AdminUser>>,
}

impl JsonFileUserStore {
    /// Load (or initialize) the store from `path`. If the file does not exist,
    /// a bootstrap admin account is created and persisted.
    pub async fn load(path: impl AsRef<Path>) -> anyhow::Result<Arc<Self>> {
        let path = path.as_ref().to_path_buf();
        let (users, created) = if path.exists() {
            let bytes = tokio::fs::read(&path)
                .await
                .with_context(|| format!("reading user store at {}", path.display()))?;
            let users: HashMap<Uuid, AdminUser> = serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing user store at {}", path.display()))?;
            (users, false)
        } else {
            // Bootstrap default admin so the operator can log in immediately.
            let admin = AdminUser {
                id: Uuid::new_v4(),
                username: DEFAULT_ADMIN_USERNAME.into(),
                password_hash: hash_password(DEFAULT_ADMIN_PASSWORD)
                    .map_err(|e| anyhow!("hashing default admin password: {e}"))?,
                display_name: "Default Admin".into(),
                role: AdminRole::Admin,
                created_at: Utc::now(),
                disabled: false,
            };
            let mut m = HashMap::new();
            m.insert(admin.id, admin);
            (m, true)
        };

        let store = Arc::new(Self { path, inner: RwLock::new(users) });

        if created {
            store.flush().await.context("writing bootstrap admin to disk")?;
            tracing::warn!(
                username = DEFAULT_ADMIN_USERNAME,
                "bootstrapped default admin account; rotate the password on first login"
            );
        }

        Ok(store)
    }

    /// Atomically persist the current state to disk. Used both on bootstrap
    /// and on every mutation.
    pub async fn flush(&self) -> anyhow::Result<()> {
        let snapshot = {
            let g = self.inner.read().await;
            serde_json::to_vec_pretty(&*g)?
        };
        let tmp = self.path.with_extension("json.tmp");
        tokio::fs::write(&tmp, &snapshot)
            .await
            .with_context(|| format!("writing temp file at {}", tmp.display()))?;
        // Persist across crashes: rename is atomic on POSIX and on NTFS.
        tokio::fs::rename(&tmp, &self.path)
            .await
            .with_context(|| format!("renaming {} -> {}", tmp.display(), self.path.display()))?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl UserStore for JsonFileUserStore {
    async fn list(&self) -> Result<Vec<AdminUser>, UserStoreError> {
        Ok(self.inner.read().await.values().cloned().collect())
    }

    async fn get(&self, id: Uuid) -> Result<Option<AdminUser>, UserStoreError> {
        Ok(self.inner.read().await.get(&id).cloned())
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<AdminUser>, UserStoreError> {
        Ok(self
            .inner
            .read()
            .await
            .values()
            .find(|u| u.username == username)
            .cloned())
    }

    async fn create(&self, user: AdminUser) -> Result<AdminUser, UserStoreError> {
        {
            let mut g = self.inner.write().await;
            if g.values().any(|u| u.username == user.username) {
                return Err(UserStoreError::UsernameTaken);
            }
            g.insert(user.id, user.clone());
        }
        self.flush().await.map_err(|e| UserStoreError::Internal(e.to_string()))?;
        Ok(user)
    }

    async fn update(&self, user: AdminUser) -> Result<AdminUser, UserStoreError> {
        {
            let mut g = self.inner.write().await;
            if !g.contains_key(&user.id) {
                return Err(UserStoreError::NotFound);
            }
            g.insert(user.id, user.clone());
        }
        self.flush().await.map_err(|e| UserStoreError::Internal(e.to_string()))?;
        Ok(user)
    }

    async fn delete(&self, id: Uuid) -> Result<(), UserStoreError> {
        {
            let mut g = self.inner.write().await;
            if g.remove(&id).is_none() {
                return Err(UserStoreError::NotFound);
            }
        }
        self.flush().await.map_err(|e| UserStoreError::Internal(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn password_hash_round_trip() {
        let h = hash_password("hunter2").unwrap();
        assert!(verify_password("hunter2", &h).unwrap());
        assert!(!verify_password("wrong", &h).unwrap());
    }

    #[tokio::test]
    async fn in_memory_create_and_get() {
        let s = InMemoryUserStore::new();
        let u = AdminUser {
            id: Uuid::new_v4(),
            username: "bob".into(),
            password_hash: hash_password("x").unwrap(),
            display_name: "Bob".into(),
            role: AdminRole::Operator,
            created_at: Utc::now(),
            disabled: false,
        };
        s.create(u.clone()).await.unwrap();
        assert_eq!(s.find_by_username("bob").await.unwrap().unwrap().id, u.id);
    }

    #[tokio::test]
    async fn in_memory_rejects_duplicate_username() {
        let s = InMemoryUserStore::new();
        let mk = || AdminUser {
            id: Uuid::new_v4(),
            username: "bob".into(),
            password_hash: "x".into(),
            display_name: "Bob".into(),
            role: AdminRole::Operator,
            created_at: Utc::now(),
            disabled: false,
        };
        s.create(mk()).await.unwrap();
        assert!(matches!(s.create(mk()).await, Err(UserStoreError::UsernameTaken)));
    }

    #[tokio::test]
    async fn json_file_round_trip() {
        let dir = tempdir();
        let path = dir.join("users.json");
        let s = JsonFileUserStore::load(&path).await.unwrap();
        // bootstrap admin was created
        assert_eq!(s.list().await.unwrap().len(), 1);
        let admin = s.list().await.unwrap().remove(0);
        assert_eq!(admin.username, DEFAULT_ADMIN_USERNAME);

        // Add a new user
        s.create(AdminUser {
            id: Uuid::new_v4(),
            username: "alice".into(),
            password_hash: hash_password("a").unwrap(),
            display_name: "Alice".into(),
            role: AdminRole::Viewer,
            created_at: Utc::now(),
            disabled: false,
        })
        .await
        .unwrap();

        // Reload from disk in a fresh store
        let s2 = JsonFileUserStore::load(&path).await.unwrap();
        assert_eq!(s2.list().await.unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn tempdir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("lore-admin-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
