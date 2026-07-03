// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//
// Audit log helper. Every state-changing admin endpoint routes through
// `audit!` so we have a single point of truth for "who did what when".
//
// Output goes through `tracing` at INFO level, with the `target` set to
// `lore.admin.audit` so operators can filter it independently of the rest
// of the server logs (e.g. `RUST_LOG=lore.admin.audit=info`).
use chrono::Utc;
use serde::Serialize;
use uuid::Uuid;

use super::session::SessionClaims;

#[derive(Debug, Serialize)]
struct AuditEvent<'a> {
    at: chrono::DateTime<Utc>,
    actor_id: Uuid,
    actor_username: &'a str,
    action: &'a str,
    target: Option<&'a str>,
    detail: Option<serde_json::Value>,
}

/// Emit a structured audit event. `target` and `detail` are optional.
pub fn audit(
    actor: &SessionClaims,
    action: &str,
    target: Option<&str>,
    detail: Option<serde_json::Value>,
) {
    let event = AuditEvent {
        at: Utc::now(),
        actor_id: actor.sub,
        actor_username: &actor.username,
        action,
        target,
        detail,
    };
    tracing::info!(target: "lore.admin.audit", event = ?event, "admin_audit");
}
