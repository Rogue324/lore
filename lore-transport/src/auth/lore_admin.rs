// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use async_trait::async_trait;
use lore_base::error::NotSupported;
use lore_base::types::RepositoryId;
use serde::{Deserialize, Serialize};

use crate::error::ProtocolError;
use crate::traits::Authentication;
use crate::types::{AuthSession, AuthenticationToken, AuthorizationToken, ResolvedUser};

#[derive(Default)]
pub struct LoreAdminAuthentication;

fn http_base(auth_url: &str) -> Result<String, ProtocolError> {
    let Some((scheme, rest)) = auth_url.split_once("://") else {
        return Err(ProtocolError::internal("invalid lore-admin auth URL"));
    };
    match scheme {
        "lore-admin" => Ok(format!("http://{rest}").trim_end_matches('/').to_string()),
        "lore-admins" => Ok(format!("https://{rest}").trim_end_matches('/').to_string()),
        _ => Err(ProtocolError::internal(format!(
            "unsupported lore admin auth scheme: {scheme}"
        ))),
    }
}

#[derive(Serialize)]
struct StartRequest<'a> {
    client_state: &'a str,
}

#[derive(Deserialize)]
struct StartResponse {
    session_code: String,
    login_url: String,
}

#[derive(Deserialize)]
struct PollResponse {
    token: Option<PollToken>,
}

#[derive(Deserialize)]
struct PollToken {
    token: String,
    user_id: String,
    user_name: String,
    expires_ms: u64,
}

async fn post_json<T: Serialize, R: for<'de> Deserialize<'de>>(
    url: String,
    body: &T,
) -> Result<R, ProtocolError> {
    let client = reqwest::Client::new();
    let response = client
        .post(url)
        .header("content-type", "application/json")
        .body(
            serde_json::to_vec(body)
                .map_err(|e| ProtocolError::internal(format!("auth request encode failed: {e}")))?,
        )
        .send()
        .await
        .map_err(|e| ProtocolError::internal(format!("auth request failed: {e}")))?;
    if !response.status().is_success() {
        return Err(ProtocolError::internal(format!(
            "auth request failed with HTTP {}",
            response.status()
        )));
    }
    let body = response
        .text()
        .await
        .map_err(|e| ProtocolError::internal(format!("auth response read failed: {e}")))?;
    serde_json::from_str::<R>(&body)
        .map_err(|e| ProtocolError::internal(format!("auth response parse failed: {e}")))
}

async fn get_json<R: for<'de> Deserialize<'de>>(url: String) -> Result<R, ProtocolError> {
    let client = reqwest::Client::new();
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| ProtocolError::internal(format!("auth request failed: {e}")))?;
    if !response.status().is_success() {
        return Err(ProtocolError::internal(format!(
            "auth request failed with HTTP {}",
            response.status()
        )));
    }
    let body = response
        .text()
        .await
        .map_err(|e| ProtocolError::internal(format!("auth response read failed: {e}")))?;
    serde_json::from_str::<R>(&body)
        .map_err(|e| ProtocolError::internal(format!("auth response parse failed: {e}")))
}

#[async_trait]
impl Authentication for LoreAdminAuthentication {
    async fn start_auth_session(
        &self,
        auth_url: &str,
        client_state: &str,
        _correlation_id: &str,
    ) -> Result<AuthSession, ProtocolError> {
        let base = http_base(auth_url)?;
        let response: StartResponse = post_json(
            format!("{base}/admin/api/client-auth/start"),
            &StartRequest { client_state },
        )
        .await?;
        Ok(AuthSession {
            session_code: response.session_code,
            login_url: response.login_url,
        })
    }

    async fn poll_auth_session(
        &self,
        auth_url: &str,
        client_state: &str,
        session_code: &str,
        _correlation_id: &str,
    ) -> Result<Option<AuthenticationToken>, ProtocolError> {
        let base = http_base(auth_url)?;
        let response: PollResponse = get_json(format!(
            "{base}/admin/api/client-auth/poll/{session_code}?client_state={}",
            urlencoding::encode(client_state),
        ))
        .await?;
        Ok(response.token.map(|token| AuthenticationToken {
            token: token.token,
            user_id: token.user_id,
            user_name: token.user_name,
            expires_ms: token.expires_ms,
            acceptable_root_domains: Vec::new(),
            refresh_token: None,
        }))
    }

    async fn exchange_external_token(
        &self,
        _auth_url: &str,
        _token: &str,
        _token_type: &str,
        _correlation_id: &str,
    ) -> Result<AuthenticationToken, ProtocolError> {
        Err(ProtocolError::from(NotSupported {
            operation: "exchange_external_token".to_string(),
        }))
    }

    async fn refresh_authentication(
        &self,
        _auth_url: &str,
        _refresh_token: &str,
        _correlation_id: &str,
    ) -> Result<AuthenticationToken, ProtocolError> {
        Err(ProtocolError::from(NotSupported {
            operation: "refresh_authentication".to_string(),
        }))
    }

    async fn exchange_for_repository(
        &self,
        _auth_url: &str,
        authn_token: &str,
        _repository: RepositoryId,
        _correlation_id: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        Ok(AuthorizationToken {
            token: authn_token.to_string(),
            expires_ms: 0,
            acceptable_root_domains: Vec::new(),
        })
    }

    async fn exchange_for_custom_resource(
        &self,
        _auth_url: &str,
        authn_token: &str,
        _resource_id: &str,
        _correlation_id: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        Ok(AuthorizationToken {
            token: authn_token.to_string(),
            expires_ms: 0,
            acceptable_root_domains: Vec::new(),
        })
    }

    async fn get_user_info(
        &self,
        _auth_url: &str,
        _authz_token: &str,
        _repository: RepositoryId,
        user_ids: &[String],
        _correlation_id: &str,
    ) -> Result<Vec<ResolvedUser>, ProtocolError> {
        Ok(user_ids
            .iter()
            .map(|id| ResolvedUser {
                user_id: id.clone(),
                user_name: id.clone(),
            })
            .collect())
    }

    async fn get_user_id(
        &self,
        _auth_url: &str,
        _authz_token: &str,
        _repository: RepositoryId,
        display_name: &str,
        _correlation_id: &str,
    ) -> Result<Option<ResolvedUser>, ProtocolError> {
        Ok(Some(ResolvedUser {
            user_id: display_name.to_string(),
            user_name: display_name.to_string(),
        }))
    }
}
