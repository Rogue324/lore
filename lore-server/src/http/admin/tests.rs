// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//
// End-to-end integration tests for the admin HTTP backend. These exercise the
// full request/response cycle through axum + the session extractor + the
// user store trait, so they catch issues that pure unit tests miss (cookie
// parsing, middleware ordering, JSON serialization of claims, etc.).
//
// We deliberately use the `InMemoryUserStore` here — these tests are about
// the HTTP surface, not persistence. The `JsonFileUserStore` has its own
// dedicated round-trip test in `store.rs`.

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use axum_test::TestServer;
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use super::AdminAppState;
use super::session::{AdminRole, SessionStore, SessionVerifier};
use super::store::{
    AdminUser, DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_USERNAME, InMemoryUserStore, hash_password,
};
use crate::store::test_store_create;

const TEST_SECRET: &str = "test_secret_must_be_at_least_32_bytes_long!!";

/// Build an `AdminAppState` with an in-memory user store pre-populated with
/// the default `admin / admin` bootstrap account.
async fn make_state() -> AdminAppState {
    let user_store = InMemoryUserStore::new();
    let admin = AdminUser {
        id: Uuid::new_v4(),
        username: DEFAULT_ADMIN_USERNAME.into(),
        password_hash: hash_password(DEFAULT_ADMIN_PASSWORD).unwrap(),
        display_name: "Default Admin".into(),
        role: AdminRole::Admin,
        created_at: Utc::now(),
        disabled: false,
    };
    user_store.create(admin).await.unwrap();

    let session_verifier = Arc::new(SessionVerifier::new(TEST_SECRET.as_bytes()).unwrap());
    AdminAppState {
        user_store,
        session_verifier,
        session_store: SessionStore::new(),
        cookie_name: "session".into(),
        cookie_secure: false,
        session_ttl_seconds: 3600,
    }
}

/// Mount the admin router under `/admin` on a fresh parent and wrap it in
/// a `TestServer`. The parent has no routes of its own; we only need it to
/// carry a `ServerState` so `admin::mount` can accept it.
async fn make_server() -> TestServer {
    let (immutable_store, mutable_store, _execution) =
        test_store_create().await.expect("Failed to create stores");
    let shared_state = crate::http::server::ServerState {
        immutable_store,
        mutable_store,
        jwt_verifier: None,
        max_file_size: 1024,
        presign_config: None,
    };
    let parent: Router<crate::http::server::ServerState> = Router::new().with_state(shared_state);
    let app = super::mount(parent, Some(make_state().await));
    TestServer::new(app).expect("test server should build")
}

#[tokio::test]
async fn login_then_me_returns_admin_user() {
    let server = make_server().await;

    let resp = server
        .post("/admin/auth/login")
        .json(&json!({
            "username": DEFAULT_ADMIN_USERNAME,
            "password": DEFAULT_ADMIN_PASSWORD,
        }))
        .await;
    assert_eq!(resp.status_code(), StatusCode::OK);
    let body: serde_json::Value = resp.json();
    assert_eq!(body["user"]["username"], DEFAULT_ADMIN_USERNAME);
    assert_eq!(body["user"]["role"], "Admin");
    assert!(body["token"].as_str().is_some_and(|s| !s.is_empty()));
    // The password hash must never leak to the API surface.
    assert!(body["user"].get("password_hash").is_none());

    // Pull the token out of the JSON body (the SPA can use either cookie
    // or bearer — both are valid).
    let token = body["token"].as_str().unwrap().to_string();

    let me = server
        .get("/admin/auth/me")
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(me.status_code(), StatusCode::OK);
    let me_body: serde_json::Value = me.json();
    assert_eq!(me_body["user"]["username"], DEFAULT_ADMIN_USERNAME);
    assert!(me_body["session"]["jti"].as_str().is_some());
}

#[tokio::test]
async fn login_with_wrong_password_returns_401_no_enumeration() {
    let server = make_server().await;

    // Unknown user
    let r1 = server
        .post("/admin/auth/login")
        .json(&json!({"username": "ghost", "password": "whatever"}))
        .await;
    assert_eq!(r1.status_code(), StatusCode::UNAUTHORIZED);
    let r1_body: serde_json::Value = r1.json();
    assert_eq!(r1_body["error"], "invalid credentials");

    // Known user, wrong password
    let r2 = server
        .post("/admin/auth/login")
        .json(&json!({"username": DEFAULT_ADMIN_USERNAME, "password": "wrong"}))
        .await;
    assert_eq!(r2.status_code(), StatusCode::UNAUTHORIZED);
    let r2_body: serde_json::Value = r2.json();
    assert_eq!(r2_body["error"], "invalid credentials");
}

#[tokio::test]
async fn admin_can_create_list_update_and_delete_users() {
    let server = make_server().await;
    let token = login_as_admin(&server).await;

    // list — should only contain the bootstrap admin
    let list_resp = server
        .get("/admin/users/")
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(list_resp.status_code(), StatusCode::OK);
    let list: Vec<serde_json::Value> = list_resp.json();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["username"], DEFAULT_ADMIN_USERNAME);

    // create
    let create_resp = server
        .post("/admin/users/")
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "username": "alice",
            "password": "alicepass1",
            "display_name": "Alice",
            "role": "Operator",
        }))
        .await;
    assert_eq!(create_resp.status_code(), StatusCode::CREATED);
    let created: serde_json::Value = create_resp.json();
    assert_eq!(created["username"], "alice");
    assert_eq!(created["role"], "Operator");
    let alice_id = created["id"].as_str().unwrap().to_string();

    // list again — now 2 users
    let list2: Vec<serde_json::Value> = server
        .get("/admin/users/")
        .add_header("Authorization", format!("Bearer {token}"))
        .await
        .json();
    assert_eq!(list2.len(), 2);

    // update (rename + demote to Viewer)
    let upd = server
        .patch(&format!("/admin/users/{alice_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "display_name": "Alice (renamed)",
            "role": "Viewer",
        }))
        .await;
    assert_eq!(upd.status_code(), StatusCode::OK);
    let upd_body: serde_json::Value = upd.json();
    assert_eq!(upd_body["display_name"], "Alice (renamed)");
    assert_eq!(upd_body["role"], "Viewer");

    // delete
    let del = server
        .delete(&format!("/admin/users/{alice_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(del.status_code(), StatusCode::NO_CONTENT);

    // list — back to 1
    let list3: Vec<serde_json::Value> = server
        .get("/admin/users/")
        .add_header("Authorization", format!("Bearer {token}"))
        .await
        .json();
    assert_eq!(list3.len(), 1);
}

#[tokio::test]
async fn admin_cannot_delete_themselves() {
    let server = make_server().await;
    let token = login_as_admin(&server).await;

    // look up the admin's own id from /me
    let me: serde_json::Value = server
        .get("/admin/auth/me")
        .add_header("Authorization", format!("Bearer {token}"))
        .await
        .json();
    let my_id = me["session"]["sub"].as_str().unwrap().to_string();

    let resp = server
        .delete(&format!("/admin/users/{my_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn non_admin_cannot_create_users_but_can_list() {
    let server = make_server().await;
    let admin_token = login_as_admin(&server).await;

    // Create an Operator user
    let create_resp = server
        .post("/admin/users/")
        .add_header("Authorization", format!("Bearer {admin_token}"))
        .json(&json!({
            "username": "bob",
            "password": "bobpassword",
            "display_name": "Bob",
            "role": "Operator",
        }))
        .await;
    assert_eq!(create_resp.status_code(), StatusCode::CREATED);

    // Login as Bob
    let bob_login = server
        .post("/admin/auth/login")
        .json(&json!({"username": "bob", "password": "bobpassword"}))
        .await;
    assert_eq!(bob_login.status_code(), StatusCode::OK);
    let bob_body: serde_json::Value = bob_login.json();
    let bob_token = bob_body["token"].as_str().unwrap().to_string();

    // Bob can list users (Operator+ allowed)
    let list = server
        .get("/admin/users/")
        .add_header("Authorization", format!("Bearer {bob_token}"))
        .await;
    assert_eq!(list.status_code(), StatusCode::OK);

    // Bob cannot create users (Admin only)
    let create_attempt = server
        .post("/admin/users/")
        .add_header("Authorization", format!("Bearer {bob_token}"))
        .json(&json!({
            "username": "carol",
            "password": "carolpass1",
            "display_name": "Carol",
            "role": "Viewer",
        }))
        .await;
    assert_eq!(create_attempt.status_code(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn change_own_password_then_login_with_new_password() {
    let server = make_server().await;
    let token = login_as_admin(&server).await;

    let resp = server
        .post("/admin/auth/me/password")
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "current_password": DEFAULT_ADMIN_PASSWORD,
            "new_password": "newadminpass1",
        }))
        .await;
    assert_eq!(resp.status_code(), StatusCode::OK);

    // old password no longer works
    let old = server
        .post("/admin/auth/login")
        .json(&json!({
            "username": DEFAULT_ADMIN_USERNAME,
            "password": DEFAULT_ADMIN_PASSWORD,
        }))
        .await;
    assert_eq!(old.status_code(), StatusCode::UNAUTHORIZED);

    // new password works
    let new = server
        .post("/admin/auth/login")
        .json(&json!({
            "username": DEFAULT_ADMIN_USERNAME,
            "password": "newadminpass1",
        }))
        .await;
    assert_eq!(new.status_code(), StatusCode::OK);
}

#[tokio::test]
async fn logout_revokes_session() {
    let server = make_server().await;
    let token = login_as_admin(&server).await;

    // /me works before logout
    let before = server
        .get("/admin/auth/me")
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(before.status_code(), StatusCode::OK);

    let logout = server
        .post("/admin/auth/logout")
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(logout.status_code(), StatusCode::OK);

    // /me must now reject the same token
    let after = server
        .get("/admin/auth/me")
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(after.status_code(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn missing_token_is_rejected() {
    let server = make_server().await;
    let resp = server.get("/admin/auth/me").await;
    assert_eq!(resp.status_code(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn static_index_is_served() {
    let server = make_server().await;
    let resp = server.get("/admin/").await;
    assert_eq!(resp.status_code(), StatusCode::OK);
    let body = resp.text();
    // The index file embeds the login screen markup.
    assert!(body.contains("<title>") || body.contains("login"));
}

// ---- helpers ----

async fn login_as_admin(server: &TestServer) -> String {
    let resp = server
        .post("/admin/auth/login")
        .json(&json!({
            "username": DEFAULT_ADMIN_USERNAME,
            "password": DEFAULT_ADMIN_PASSWORD,
        }))
        .await;
    assert_eq!(
        resp.status_code(),
        StatusCode::OK,
        "admin login must succeed"
    );
    let body: serde_json::Value = resp.json();
    body["token"].as_str().unwrap().to_string()
}
