//! The HTTP surface: versioned JSON envelopes, same shape as every
//! EST CLI (`{"ok":…,"v":1,…}`). Success is 200 (creation: 201);
//! misuse is 400, unknown 404, conflicts 409 — all envelopes. The one
//! exception: a body that is not JSON at all gets axum's plain 400,
//! before any handler runs. No route here ever needs the vault: the
//! hub answers from its own SQLite state.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, put},
};
use base64::Engine as _;
use serde_json::{Value, json};

use crate::{apns, db, live, model, util};

/// Shared across handlers: where the SQLite file lives (handlers open
/// per request — microsecond calls at single-user scale), the alert
/// throttle (key hex → last alert, unix seconds), and the APNs sender's
/// key path plus its one shared HTTP/2 client.
#[derive(Clone)]
pub struct AppState {
    /// Where the SQLite file lives.
    pub db_path: PathBuf,
    /// Alert throttle, 1/hour per key.
    pub throttle: Arc<Mutex<HashMap<String, u64>>>,
    /// Explicit `--apns-key` path; `None` falls back to
    /// `EST_HUB_APNS_KEY`, then `apns.p8` beside the db.
    pub apns_key: Option<PathBuf>,
    /// The one shared Apple push client (`serve` builds it once).
    pub apns: reqwest::Client,
}

impl AppState {
    /// One state for the single (tailnet) listener.
    pub fn new(db_path: PathBuf) -> Self {
        AppState {
            db_path,
            throttle: Arc::new(Mutex::new(HashMap::new())),
            apns_key: None,
            apns: apns::shared_client(),
        }
    }
}

/// Every route the hub serves, with its CLI twin. The parity gate
/// (`tests/cli_parity.rs`) serves each one and demands the twin in
/// `est-hub help` — a route without a twin fails CI.
/// One route plus the CLI twin the parity gate demands for it.
pub struct RouteDef {
    /// `GET`, `POST`, `PUT`, `DELETE`.
    pub method: &'static str,
    /// Axum path (`{name}`/`{id}` are placeholders).
    pub path: &'static str,
    /// Twin command as it appears in `est-hub help`.
    pub cli: &'static str,
}

/// The served registry. Add a route here and in [`router`] together.
pub const ROUTES: &[RouteDef] = &[
    RouteDef {
        method: "GET",
        path: "/ping",
        cli: "ping",
    },
    RouteDef {
        method: "GET",
        path: "/devices",
        cli: "devices list",
    },
    RouteDef {
        method: "POST",
        path: "/devices",
        cli: "devices add",
    },
    RouteDef {
        method: "GET",
        path: "/devices/{name}",
        cli: "devices show",
    },
    RouteDef {
        method: "DELETE",
        path: "/devices/{name}",
        cli: "devices revoke",
    },
    RouteDef {
        method: "PUT",
        path: "/devices/{name}",
        cli: "devices set",
    },
    RouteDef {
        method: "GET",
        path: "/checks",
        cli: "checks list",
    },
    RouteDef {
        method: "POST",
        path: "/checks",
        cli: "checks add",
    },
    RouteDef {
        method: "GET",
        path: "/checks/{name}",
        cli: "checks show",
    },
    RouteDef {
        method: "PUT",
        path: "/checks/{name}",
        cli: "checks set",
    },
    RouteDef {
        method: "DELETE",
        path: "/checks/{name}",
        cli: "checks delete",
    },
    RouteDef {
        method: "PUT",
        path: "/checks/{name}/ack",
        cli: "checks ack",
    },
    RouteDef {
        method: "DELETE",
        path: "/checks/{name}/ack",
        cli: "checks unack",
    },
    RouteDef {
        method: "PUT",
        path: "/checks/{name}/mute",
        cli: "checks mute",
    },
    RouteDef {
        method: "DELETE",
        path: "/checks/{name}/mute",
        cli: "checks unmute",
    },
    RouteDef {
        method: "GET",
        path: "/projects",
        cli: "projects list",
    },
    RouteDef {
        method: "GET",
        path: "/projects/{name}",
        cli: "projects show",
    },
    RouteDef {
        method: "PUT",
        path: "/projects/{name}",
        cli: "projects set",
    },
    RouteDef {
        method: "GET",
        path: "/projects/{name}/icon",
        cli: "projects icon",
    },
    RouteDef {
        method: "PUT",
        path: "/projects/{name}/icon",
        cli: "projects icon",
    },
    RouteDef {
        method: "POST",
        path: "/results",
        cli: "results report",
    },
    RouteDef {
        method: "GET",
        path: "/checks/{name}/results",
        cli: "results list",
    },
    RouteDef {
        method: "POST",
        path: "/heartbeats",
        cli: "heartbeats beat",
    },
    RouteDef {
        method: "GET",
        path: "/secrets",
        cli: "secrets list",
    },
    RouteDef {
        method: "PUT",
        path: "/secrets/{name}",
        cli: "secrets push",
    },
    RouteDef {
        method: "GET",
        path: "/secrets/{name}",
        cli: "secrets pull",
    },
    RouteDef {
        method: "DELETE",
        path: "/secrets/{name}",
        cli: "secrets delete",
    },
    RouteDef {
        method: "POST",
        path: "/secrets/{name}/token",
        cli: "secrets token",
    },
    RouteDef {
        method: "DELETE",
        path: "/secrets/{name}/token",
        cli: "secrets revoke",
    },
    RouteDef {
        method: "GET",
        path: "/balances",
        cli: "balances list",
    },
    RouteDef {
        method: "PUT",
        path: "/balances/{name}",
        cli: "balances set",
    },
    RouteDef {
        method: "DELETE",
        path: "/balances/{name}",
        cli: "balances delete",
    },
    RouteDef {
        method: "GET",
        path: "/agents",
        cli: "agents list",
    },
    RouteDef {
        method: "GET",
        path: "/agents/{name}",
        cli: "agents show",
    },
    RouteDef {
        method: "PUT",
        path: "/agents/{name}",
        cli: "agents push",
    },
    RouteDef {
        method: "DELETE",
        path: "/agents/{name}",
        cli: "agents delete",
    },
    RouteDef {
        method: "POST",
        path: "/approvals",
        cli: "approvals request",
    },
    RouteDef {
        method: "GET",
        path: "/approvals",
        cli: "approvals list",
    },
    RouteDef {
        method: "GET",
        path: "/approvals/{id}",
        cli: "approvals show",
    },
    RouteDef {
        method: "POST",
        path: "/approvals/{id}/decision",
        cli: "approvals decide",
    },
    RouteDef {
        method: "POST",
        path: "/notify",
        cli: "notify send",
    },
    RouteDef {
        method: "GET",
        path: "/notifications",
        cli: "notifications list",
    },
    RouteDef {
        method: "POST",
        path: "/notify/test",
        cli: "notify test",
    },
    RouteDef {
        method: "POST",
        path: "/notify/alive",
        cli: "notify alive",
    },
    RouteDef {
        method: "GET",
        path: "/apns",
        cli: "apns show",
    },
    RouteDef {
        method: "PUT",
        path: "/apns",
        cli: "apns set",
    },
    RouteDef {
        method: "PUT",
        path: "/devices/{name}/live-activity",
        cli: "devices live set",
    },
    RouteDef {
        method: "GET",
        path: "/devices/{name}/live-activity",
        cli: "devices live show",
    },
    RouteDef {
        method: "POST",
        path: "/devices/{name}/live-activity/tokens",
        cli: "devices live token",
    },
    RouteDef {
        method: "DELETE",
        path: "/devices/{name}/live-activity/tokens/{id}",
        cli: "devices live untoken",
    },
    RouteDef {
        method: "POST",
        path: "/live-activities/test",
        cli: "live test",
    },
];

type Reply = (StatusCode, Json<Value>);

fn ok(status: StatusCode, data: Value) -> Reply {
    let mut m = data.as_object().cloned().unwrap_or_default();
    m.insert("ok".to_string(), Value::Bool(true));
    m.insert("v".to_string(), Value::from(1));
    (status, Json(Value::Object(m)))
}

fn err(status: StatusCode, msg: &str) -> Reply {
    (status, Json(json!({"ok": false, "v": 1, "error": msg})))
}

fn db_err(e: db::Error) -> Reply {
    match &e {
        db::Error::Missing(what) => err(StatusCode::NOT_FOUND, what),
        db::Error::Exists(what) => err(StatusCode::CONFLICT, what),
        db::Error::Invalid(why) => err(StatusCode::BAD_REQUEST, why),
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

fn conn(state: &AppState) -> Result<rusqlite::Connection, Reply> {
    db::open(&state.db_path).map_err(db_err)
}

// ---------------------------------------------------------------- ping

async fn ping() -> Reply {
    ok(
        StatusCode::OK,
        json!({"name": "est-hub", "version": crate::VERSION}),
    )
}

async fn not_found() -> Reply {
    err(StatusCode::NOT_FOUND, "no such route")
}

// ---------------------------------------------------------------- devices

async fn devices_list(State(s): State<AppState>) -> Reply {
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::device_list(&conn) {
        Ok(devices) => ok(StatusCode::OK, json!({"devices": devices})),
        Err(e) => db_err(e),
    }
}

async fn devices_create(State(s): State<AppState>, Json(body): Json<model::NewDevice>) -> Reply {
    let (name, apns) = match model::validate_device(&body) {
        Ok(v) => v,
        Err(why) => return err(StatusCode::BAD_REQUEST, &why),
    };
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::device_add(&conn, &name, apns.as_deref()) {
        Ok(d) => ok(StatusCode::CREATED, json!({"device": d})),
        Err(e) => db_err(e),
    }
}

async fn devices_show(State(s): State<AppState>, Path(name): Path<String>) -> Reply {
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::device_get(&conn, name.trim()) {
        Ok(d) => ok(StatusCode::OK, json!({"device": d})),
        Err(e) => db_err(e),
    }
}

async fn devices_delete(State(s): State<AppState>, Path(name): Path<String>) -> Reply {
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::device_delete(&conn, name.trim()) {
        Ok(()) => ok(StatusCode::OK, json!({"revoked": name.trim()})),
        Err(e) => db_err(e),
    }
}

async fn devices_update(
    State(s): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    let name = name.trim();
    if let Some(env) = body.get("apns_env").and_then(Value::as_str)
        && !["development", "production"].contains(&env)
    {
        return err(
            StatusCode::BAD_REQUEST,
            "apns_env is development or production",
        );
    }
    if !model::valid_name(name) {
        return err(
            StatusCode::BAD_REQUEST,
            "name must match [a-z][a-z0-9_-]{0,31}",
        );
    }
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    // Self-registration: a tailnet device may upsert its own row.
    let current = match db::device_get(&conn, name) {
        Ok(d) => d,
        Err(db::Error::Missing(_)) => match db::device_add(&conn, name, None) {
            Ok(d) => d,
            Err(db::Error::Exists(_)) => match db::device_get(&conn, name) {
                Ok(d) => d,
                Err(e) => return db_err(e),
            },
            Err(e) => return db_err(e),
        },
        Err(e) => return db_err(e),
    };
    // Present sets (empty clears), absent keeps.
    let token = match body.get("apns_token") {
        None => current.apns_token,
        Some(Value::Null) => None,
        Some(Value::String(t)) if t.trim().is_empty() => None,
        Some(Value::String(t)) => Some(t.trim().to_string()),
        Some(_) => return err(StatusCode::BAD_REQUEST, "apns_token is a string"),
    };
    if token.as_deref().unwrap_or("").len() > 512 {
        return err(StatusCode::BAD_REQUEST, "apns_token is too long (512 max)");
    }
    let env = match body.get("apns_env") {
        None => current.apns_env,
        Some(Value::Null) => None,
        Some(Value::String(e)) if e.trim().is_empty() => None,
        Some(Value::String(e)) => Some(e.to_string()),
        Some(_) => return err(StatusCode::BAD_REQUEST, "apns_env is a string"),
    };
    let topic = match body.get("apns_topic") {
        None => current.apns_topic,
        Some(Value::Null) => None,
        Some(Value::String(t)) if t.trim().is_empty() => None,
        Some(Value::String(t)) => Some(t.trim().to_string()),
        Some(_) => return err(StatusCode::BAD_REQUEST, "apns_topic is a string"),
    };
    if topic.as_deref().unwrap_or("").len() > 256 {
        return err(StatusCode::BAD_REQUEST, "apns_topic is too long (256 max)");
    }
    match db::device_update_apns(
        &conn,
        name,
        token.as_deref(),
        env.as_deref(),
        topic.as_deref(),
    ) {
        Ok(d) => ok(StatusCode::OK, json!({"device": d})),
        Err(e) => db_err(e),
    }
}

// ---------------------------------------------------------------- checks

async fn checks_list(State(s): State<AppState>, Query(q): Query<HashMap<String, String>>) -> Reply {
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::check_list(&conn) {
        Ok(checks) => {
            let owner = q.get("owner").map(|o| o.trim()).filter(|o| !o.is_empty());
            let checks: Vec<_> = checks
                .into_iter()
                .filter(|c| owner.is_none_or(|o| c.owner == o))
                .collect();
            ok(StatusCode::OK, json!({"checks": checks}))
        }
        Err(e) => db_err(e),
    }
}

async fn checks_create(State(s): State<AppState>, Json(body): Json<model::NewCheck>) -> Reply {
    let valid = match model::validate_check(&body) {
        Ok(v) => v,
        Err(why) => return err(StatusCode::BAD_REQUEST, &why),
    };
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::check_add(&conn, &valid) {
        Ok(c) => ok(StatusCode::CREATED, json!({"check": c})),
        Err(e) => db_err(e),
    }
}

async fn checks_show(State(s): State<AppState>, Path(name): Path<String>) -> Reply {
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::check_get(&conn, name.trim()) {
        Ok(c) => ok(StatusCode::OK, json!({"check": c})),
        Err(e) => db_err(e),
    }
}

async fn checks_replace(
    State(s): State<AppState>,
    Path(name): Path<String>,
    Json(mut body): Json<model::NewCheck>,
) -> Reply {
    let name = name.trim();
    if let Some(n) = body.name.as_deref()
        && n.trim() != name
    {
        return err(StatusCode::BAD_REQUEST, "body name must match the path");
    }
    body.name = Some(name.to_string());
    let valid = match model::validate_check(&body) {
        Ok(v) => v,
        Err(why) => return err(StatusCode::BAD_REQUEST, &why),
    };
    // PUT replaces the definition; it must carry one (owner/type/target).
    if body.owner.is_none() || body.ctype.is_none() || body.target.is_none() {
        return err(
            StatusCode::BAD_REQUEST,
            "PUT replaces: owner, type, and target are required",
        );
    }
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::check_replace(&conn, name, &valid) {
        Ok(c) => ok(StatusCode::OK, json!({"check": c})),
        Err(e) => db_err(e),
    }
}

async fn checks_delete(State(s): State<AppState>, Path(name): Path<String>) -> Reply {
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::check_delete(&conn, name.trim()) {
        Ok(()) => ok(StatusCode::OK, json!({"deleted": name.trim()})),
        Err(e) => db_err(e),
    }
}

/// Silence a check: `PUT /checks/{name}/ack` quiets the down page
/// (recovery still buzzes, and clears it); `PUT .../mute` quiets
/// both directions. Body `{until_secs?, note?}`; missing `until_secs`
/// reads the kind's default, 0 or past-the-max refuses. Answers the
/// fresh check, horizons included.
async fn checks_silence(
    State(s): State<AppState>,
    Path(name): Path<String>,
    kind: &str,
    body: Value,
) -> Reply {
    let name = name.trim();
    let (default, max) = match kind {
        "ack" => (model::ACK_DEFAULT_SECS, model::ACK_MAX_SECS),
        _ => (model::MUTE_DEFAULT_SECS, model::MUTE_MAX_SECS),
    };
    let until_secs = match body.get("until_secs") {
        None | Some(Value::Null) => default,
        Some(Value::Number(n)) => match n.as_u64() {
            Some(v) => v,
            None => return err(StatusCode::BAD_REQUEST, "until_secs is seconds, 1 or more"),
        },
        Some(_) => return err(StatusCode::BAD_REQUEST, "until_secs is seconds, 1 or more"),
    };
    if until_secs == 0 || until_secs > max {
        return err(
            StatusCode::BAD_REQUEST,
            &format!("until_secs is 1-{max} for {kind}"),
        );
    }
    let note = match body.get("note") {
        None | Some(Value::Null) => "",
        Some(Value::String(note)) => note.as_str(),
        Some(_) => return err(StatusCode::BAD_REQUEST, "note is a string"),
    };
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let now = model::now_epoch();
    if let Err(e) = db::silence_set(&conn, name, kind, now + until_secs, note, now) {
        return db_err(e);
    }
    match db::check_get(&conn, name) {
        Ok(c) => ok(StatusCode::OK, json!({"check": c})),
        Err(e) => db_err(e),
    }
}

async fn checks_ack(
    State(s): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    checks_silence(State(s), Path(name), "ack", body).await
}

async fn checks_mute(
    State(s): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    checks_silence(State(s), Path(name), "mute", body).await
}

/// Lift a silence: `DELETE /checks/{name}/ack|mute`. Clearing a quiet
/// check is a no-op; only a missing check 404s.
async fn checks_unsilence(
    State(s): State<AppState>,
    Path(name): Path<String>,
    kind: &str,
) -> Reply {
    let name = name.trim();
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(e) = db::check_get(&conn, name) {
        return db_err(e);
    }
    match db::silence_clear(&conn, name, kind) {
        Ok(()) => ok(StatusCode::OK, json!({"cleared": name, "kind": kind})),
        Err(e) => db_err(e),
    }
}

async fn checks_unack(State(s): State<AppState>, Path(name): Path<String>) -> Reply {
    checks_unsilence(State(s), Path(name), "ack").await
}

async fn checks_unmute(State(s): State<AppState>, Path(name): Path<String>) -> Reply {
    checks_unsilence(State(s), Path(name), "mute").await
}

// ---------------------------------------------------------------- secrets

/// Every secret's public face (never any env). Tailnet-only.
async fn secrets_list(State(s): State<AppState>) -> Reply {
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::secret_list(&conn) {
        Ok(secrets) => ok(StatusCode::OK, json!({"secrets": secrets})),
        Err(e) => db_err(e),
    }
}

/// Push one project's env: `PUT /secrets/{project}` with
/// `{env}` (64KB max, upsert). Answers the public face — the blob
/// never echoes. Tailnet-only.
async fn secrets_push(
    State(s): State<AppState>,
    Path(project): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    let env = match body.get("env") {
        Some(Value::String(env)) => env.clone(),
        _ => return err(StatusCode::BAD_REQUEST, "env is a string"),
    };
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::secret_set(&conn, project.trim(), &env, model::now_epoch()) {
        Ok(meta) => ok(StatusCode::OK, json!({"secret": meta})),
        Err(e) => db_err(e),
    }
}

/// The bearer off an `Authorization` header (`Bearer …`), or `None`
/// when missing or malformed.
fn bearer(headers: &axum::http::HeaderMap) -> Option<String> {
    let v = headers.get(axum::http::header::AUTHORIZATION)?;
    let v = v.to_str().ok()?;
    let token = v
        .strip_prefix("Bearer ")
        .or_else(|| v.strip_prefix("bearer "))?;
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_string())
}

/// Pull one project's env: `GET /secrets/{project}` with the
/// project token as bearer. Answers `{project, sha, env}` — the one
/// route that ever serves a blob. Tailnet-only; a token for another
/// project 404s (never confirm what you cannot pull).
async fn secrets_pull(
    State(s): State<AppState>,
    Path(project): Path<String>,
    headers: axum::http::HeaderMap,
) -> Reply {
    let project = project.trim();
    let Some(token) = bearer(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "project token required");
    };
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let now = model::now_epoch();
    if !db::secret_token_check(&conn, project, &token, now) {
        return err(StatusCode::NOT_FOUND, "no such secret");
    }
    match db::secret_env(&conn, project) {
        Ok((env, sha)) => ok(
            StatusCode::OK,
            json!({"project": project, "sha": sha, "env": env}),
        ),
        Err(e) => db_err(e),
    }
}

/// Mint a project's pull token: `POST /secrets/{project}/token`.
/// One live token per project (re-minting kills the old one); the
/// plaintext shows here once and never again. Tailnet-only.
async fn secrets_token_mint(State(s): State<AppState>, Path(project): Path<String>) -> Reply {
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::secret_token_mint(&conn, project.trim(), model::now_epoch()) {
        Ok(token) => ok(
            StatusCode::CREATED,
            json!({"project": project.trim(), "token": token}),
        ),
        Err(e) => db_err(e),
    }
}

/// Revoke a project's pull token. Quiet when none. Tailnet-only.
async fn secrets_token_revoke(State(s): State<AppState>, Path(project): Path<String>) -> Reply {
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::secret_token_revoke(&conn, project.trim()) {
        Ok(()) => ok(StatusCode::OK, json!({"revoked": project.trim()})),
        Err(e) => db_err(e),
    }
}

/// Delete a secret and its pull token. Tailnet-only.
async fn secrets_delete(State(s): State<AppState>, Path(project): Path<String>) -> Reply {
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::secret_delete(&conn, project.trim()) {
        Ok(()) => ok(StatusCode::OK, json!({"deleted": project.trim()})),
        Err(e) => db_err(e),
    }
}

// ---------------------------------------------------------------- balances

/// Every balance row, by provider.
async fn balances_list(State(s): State<AppState>) -> Reply {
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::balance_list(&conn) {
        Ok(balances) => ok(StatusCode::OK, json!({"balances": balances})),
        Err(e) => db_err(e),
    }
}

/// Upsert one balance row: `PUT /balances/{provider}` with
/// `{amount, label?, currency?, note?}` (all display strings).
async fn balances_set(
    State(s): State<AppState>,
    Path(provider): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    let field = |key: &str| -> Result<String, Reply> {
        match body.get(key) {
            None | Some(Value::Null) => Ok(String::new()),
            Some(Value::String(v)) => Ok(v.clone()),
            Some(_) => Err(err(StatusCode::BAD_REQUEST, &format!("{key} is a string"))),
        }
    };
    let (label, amount, currency, note) = match (
        field("label"),
        field("amount"),
        field("currency"),
        field("note"),
    ) {
        (Ok(label), Ok(amount), Ok(currency), Ok(note)) => (label, amount, currency, note),
        (Err(r), _, _, _) | (_, Err(r), _, _) | (_, _, Err(r), _) | (_, _, _, Err(r)) => return r,
    };
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::balance_set(
        &conn,
        provider.trim(),
        &label,
        &amount,
        &currency,
        &note,
        model::now_epoch(),
    ) {
        Ok(balance) => ok(StatusCode::OK, json!({"balance": balance})),
        Err(e) => db_err(e),
    }
}

/// Delete one balance row.
async fn balances_delete(State(s): State<AppState>, Path(provider): Path<String>) -> Reply {
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::balance_delete(&conn, provider.trim()) {
        Ok(()) => ok(StatusCode::OK, json!({"deleted": provider.trim()})),
        Err(e) => db_err(e),
    }
}

// ---------------------------------------------------------------- agents

/// Every agent snapshot, working first. The phone's AI mirror.
async fn agents_list(State(s): State<AppState>) -> Reply {
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::agent_list(&conn, model::now_epoch()) {
        Ok(agents) => ok(StatusCode::OK, json!({"agents": agents})),
        Err(e) => db_err(e),
    }
}

/// One agent snapshot.
async fn agents_show(State(s): State<AppState>, Path(pane): Path<String>) -> Reply {
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::agent_get(&conn, pane.trim(), model::now_epoch()) {
        Ok(agent) => ok(StatusCode::OK, json!({"agent": agent})),
        Err(e) => db_err(e),
    }
}

/// Upsert one agent snapshot: `PUT /agents/{pane}` with `{status,
/// title?, cwd?, space?, tab?, output?}`. Space, tab, and output are
/// keep-on-absent (a failed read must not wipe the last output).
/// Tailnet-only (the watcher pushes from the Mac).
async fn agents_push(
    State(s): State<AppState>,
    Path(pane): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    let field = |key: &str| -> Result<String, Reply> {
        match body.get(key) {
            None | Some(Value::Null) => Ok(String::new()),
            Some(Value::String(v)) => Ok(v.clone()),
            Some(_) => Err(err(StatusCode::BAD_REQUEST, &format!("{key} is a string"))),
        }
    };
    let field_opt = |key: &str| -> Result<Option<String>, Reply> {
        match body.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(v)) => Ok(Some(v.clone())),
            Some(_) => Err(err(StatusCode::BAD_REQUEST, &format!("{key} is a string"))),
        }
    };
    let (status, title, cwd) = match (field("status"), field("title"), field("cwd")) {
        (Ok(status), Ok(title), Ok(cwd)) => (status, title, cwd),
        (Err(r), _, _) | (_, Err(r), _) | (_, _, Err(r)) => return r,
    };
    let (space, tab, output) = match (field_opt("space"), field_opt("tab"), field_opt("output")) {
        (Ok(space), Ok(tab), Ok(output)) => (space, tab, output),
        (Err(r), _, _) | (_, Err(r), _) | (_, _, Err(r)) => return r,
    };
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::agent_set(
        &conn,
        pane.trim(),
        db::AgentSnapshot {
            title: &title,
            cwd: &cwd,
            status: &status,
            space: space.as_deref(),
            tab: tab.as_deref(),
            output: output.as_deref(),
        },
        model::now_epoch(),
    ) {
        Ok(agent) => {
            // The mirror moved: converge the fleet card (diff-gated).
            let ctx = live::Ctx::new(s.apns.clone(), s.apns_key.clone(), s.throttle.clone());
            live::on_agents_changed(&ctx, &s.db_path).await;
            ok(StatusCode::OK, json!({"agent": agent}))
        }
        Err(e) => db_err(e),
    }
}

/// Delete one agent snapshot (the pane closed). Tailnet-only.
async fn agents_delete(State(s): State<AppState>, Path(pane): Path<String>) -> Reply {
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::agent_delete(&conn, pane.trim()) {
        Ok(()) => {
            // The mirror moved: converge the fleet card (diff-gated).
            let ctx = live::Ctx::new(s.apns.clone(), s.apns_key.clone(), s.throttle.clone());
            live::on_agents_changed(&ctx, &s.db_path).await;
            ok(StatusCode::OK, json!({"deleted": pane.trim()}))
        }
        Err(e) => db_err(e),
    }
}

// ---------------------------------------------------------------- projects

/// Every project with its health rollup (checks roll by owner == slug).
async fn projects_list(State(s): State<AppState>) -> Reply {
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let projects = match db::project_list(&conn) {
        Ok(p) => p,
        Err(e) => return db_err(e),
    };
    let checks = match db::check_list(&conn) {
        Ok(c) => c,
        Err(e) => return db_err(e),
    };
    let live: Vec<_> = projects.iter().map(|p| p.live(&checks)).collect();
    ok(StatusCode::OK, json!({"projects": live}))
}

/// One project with its rollup, or missing.
async fn projects_show(State(s): State<AppState>, Path(slug): Path<String>) -> Reply {
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let project = match db::project_get(&conn, slug.trim()) {
        Ok(p) => p,
        Err(e) => return db_err(e),
    };
    let checks = match db::check_list(&conn) {
        Ok(c) => c,
        Err(e) => return db_err(e),
    };
    ok(StatusCode::OK, json!({"project": project.live(&checks)}))
}

/// Create or replace a project's metadata (tailnet only). The icon
/// rides `PUT .../icon` separately and survives metadata writes.
async fn projects_set(
    State(s): State<AppState>,
    Path(slug): Path<String>,
    Json(body): Json<model::NewProject>,
) -> Reply {
    let valid = match model::validate_project(slug.trim(), &body) {
        Ok(v) => v,
        Err(why) => return err(StatusCode::BAD_REQUEST, &why),
    };
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let project = match db::project_upsert(&conn, &valid) {
        Ok(p) => p,
        Err(e) => return db_err(e),
    };
    let checks = match db::check_list(&conn) {
        Ok(c) => c,
        Err(e) => return db_err(e),
    };
    ok(StatusCode::OK, json!({"project": project.live(&checks)}))
}

/// Largest icon the hub stores: app icons run ~1MB at most, and the
/// phone caches them — anything bigger is a mistake, not a logo.
const ICON_MAX_BYTES: usize = 1024 * 1024;

/// PNG magic, the only format the hub stores.
const PNG_MAGIC: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

/// Store a project's icon, raw PNG bytes (tailnet only). Missing
/// projects refuse: metadata lands first, then the bytes.
async fn projects_icon_set(
    State(s): State<AppState>,
    Path(slug): Path<String>,
    body: axum::body::Bytes,
) -> Reply {
    if body.len() > ICON_MAX_BYTES {
        return err(StatusCode::PAYLOAD_TOO_LARGE, "icon is 1MB max");
    }
    if body.len() < PNG_MAGIC.len() || body[..PNG_MAGIC.len()] != PNG_MAGIC {
        return err(StatusCode::BAD_REQUEST, "icon is PNG only");
    }
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let sha = {
        use sha2::{Digest, Sha256};
        util::hex(&Sha256::digest(&body))
    };
    let project = match db::project_set_icon(&conn, slug.trim(), &body, &sha) {
        Ok(p) => p,
        Err(e) => return db_err(e),
    };
    let checks = match db::check_list(&conn) {
        Ok(c) => c,
        Err(e) => return db_err(e),
    };
    ok(StatusCode::OK, json!({"project": project.live(&checks)}))
}

/// A project's icon as base64 inside the envelope (every route answers
/// envelopes, binary included), or 404 when the row or icon is missing.
async fn projects_icon_show(State(s): State<AppState>, Path(slug): Path<String>) -> Reply {
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::project_icon(&conn, slug.trim()) {
        Ok(bytes) => ok(
            StatusCode::OK,
            json!({
                "icon": base64::engine::general_purpose::STANDARD.encode(&bytes),
                "bytes": bytes.len(),
            }),
        ),
        Err(e) => db_err(e),
    }
}

// ---------------------------------------------------------------- results

async fn results_report(State(s): State<AppState>, Json(body): Json<model::NewResult>) -> Reply {
    let name = body.check.as_deref().unwrap_or("").trim();
    if name.is_empty() {
        return err(StatusCode::BAD_REQUEST, "check names the check");
    }
    let Some(ok_flag) = body.ok else {
        return err(StatusCode::BAD_REQUEST, "ok is true or false");
    };
    if let Some(code) = body.code
        && !(100..=599).contains(&code)
    {
        return err(StatusCode::BAD_REQUEST, "code is an HTTP status 100-599");
    }
    let reason = body.reason.as_deref().unwrap_or("");
    if reason.len() > 512 {
        return err(StatusCode::BAD_REQUEST, "reason is 512 max");
    }
    let value = match model::parse_result_value(body.value.as_ref()) {
        Ok(v) => v,
        Err(why) => return err(StatusCode::BAD_REQUEST, &why),
    };
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let ts = body.ts.unwrap_or_else(model::now_epoch);
    match db::record_result(&conn, name, ok_flag, body.code, reason, ts, value) {
        Ok((flipped, row)) => {
            if flipped {
                // Best-effort fan-out (unconfigured hubs converge to
                // nothing): a push plus the card refresh, loud on a
                // fresh down, quiet on recovery.
                let ctx = live::Ctx::new(s.apns.clone(), s.apns_key.clone(), s.throttle.clone());
                let note = if ok_flag {
                    format!("🟢 {name} is back up")
                } else {
                    format!("🔴 {name} is DOWN — {reason}")
                };
                live::on_flip(&ctx, &s.db_path, name, !ok_flag, &note, row.as_ref()).await;
            }
            ok(
                StatusCode::OK,
                json!({"recorded": name, "flipped": flipped}),
            )
        }
        Err(e) => db_err(e),
    }
}

async fn results_list(
    State(s): State<AppState>,
    Path(name): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Reply {
    let limit = q
        .get("limit")
        .and_then(|l| l.parse::<u64>().ok())
        .unwrap_or(20);
    let since = q
        .get("since")
        .and_then(|l| l.parse::<u64>().ok())
        .unwrap_or(0);
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::result_list(&conn, name.trim(), limit, since) {
        Ok(results) => ok(
            StatusCode::OK,
            json!({"check": name.trim(), "results": results}),
        ),
        Err(e) => db_err(e),
    }
}

// ---------------------------------------------------------------- heartbeats

async fn heartbeats_beat(State(s): State<AppState>, Json(body): Json<Value>) -> Reply {
    let name = body
        .get("check")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if name.is_empty() {
        return err(StatusCode::BAD_REQUEST, "check names the check");
    }
    let ts = body
        .get("ts")
        .and_then(Value::as_u64)
        .unwrap_or_else(model::now_epoch);
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::heartbeat_beat(&conn, name, ts) {
        Ok(()) => ok(StatusCode::OK, json!({"beat": name, "ts": ts})),
        Err(e) => db_err(e),
    }
}

// ---------------------------------------------------------------- approvals

async fn approvals_create(
    State(s): State<AppState>,
    Json(body): Json<model::NewApproval>,
) -> Reply {
    let title = body.title.as_deref().unwrap_or("");
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::approval_create(
        &conn,
        title,
        body.body.as_deref().unwrap_or(""),
        body.reply_to.as_deref().unwrap_or(""),
        body.ttl_secs.unwrap_or(3600),
    ) {
        Ok((a, row)) => {
            // The counts moved: quiet card refresh for counters — plus
            // the loud ask itself. An approval nobody hears is a queue
            // entry, not a decision path: configured hubs push the full
            // title + body now, unconfigured ones stay queue-only.
            let ctx = live::Ctx::new(s.apns.clone(), s.apns_key.clone(), s.throttle.clone());
            live::on_approvals_changed(&ctx, &s.db_path).await;
            if let Some(n) = row {
                match apns::load(s.apns_key.as_deref(), &s.db_path, &conn) {
                    Ok(Some(cfg)) => {
                        let _ = apns::deliver_approval(&s.apns, &s.db_path, &cfg, &n, a.id).await;
                    }
                    Ok(None) => {}
                    Err(why) => est_core::log::info(&format!("apns skipped: {why}")),
                }
            }
            ok(StatusCode::CREATED, json!({"approval": a}))
        }
        Err(e) => db_err(e),
    }
}

async fn approvals_list(
    State(s): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Reply {
    if let Some(st) = q.get("state")
        && !["pending", "approved", "rejected", "expired"].contains(&st.as_str())
    {
        return err(
            StatusCode::BAD_REQUEST,
            "state is pending, approved, rejected, or expired",
        );
    }
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::approval_list(&conn, q.get("state").map(String::as_str)) {
        Ok(approvals) => ok(StatusCode::OK, json!({"approvals": approvals})),
        Err(e) => db_err(e),
    }
}

async fn approvals_show(State(s): State<AppState>, Path(id): Path<i64>) -> Reply {
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::approval_get(&conn, id) {
        Ok(a) => ok(StatusCode::OK, json!({"approval": a})),
        Err(e) => db_err(e),
    }
}

async fn approvals_decide(
    State(s): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<model::Decision>,
) -> Reply {
    let Some(approve) = body.approve else {
        return err(StatusCode::BAD_REQUEST, "approve is true or false");
    };
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::approval_decide(&conn, id, approve, body.by.as_deref().unwrap_or("")) {
        Ok(a) => {
            // One fewer pending: quiet card refresh for counters.
            let ctx = live::Ctx::new(s.apns.clone(), s.apns_key.clone(), s.throttle.clone());
            live::on_approvals_changed(&ctx, &s.db_path).await;
            ok(StatusCode::OK, json!({"approval": a}))
        }
        Err(e) => db_err(e),
    }
}

// ---------------------------------------------------------------- notify

async fn notify_send(State(s): State<AppState>, Json(body): Json<model::NewNotification>) -> Reply {
    let title = body.title.as_deref().unwrap_or("");
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::notification_push(
        &conn,
        body.to.as_deref().unwrap_or(""),
        body.topic.as_deref().unwrap_or("notify"),
        title,
        body.body.as_deref().unwrap_or(""),
    ) {
        Ok(n) => {
            est_core::log::info(&format!("notify queued #{}: {title}", n.id));
            // Best-effort immediate push on top of the queued row (the
            // audit trail above never depends on it): configured hubs
            // deliver now, unconfigured ones stay queue-only.
            match apns::load(s.apns_key.as_deref(), &s.db_path, &conn) {
                Ok(Some(cfg)) => {
                    let _ = apns::deliver(&s.apns, &s.db_path, &cfg, &n).await;
                }
                Ok(None) => {}
                Err(why) => est_core::log::info(&format!("apns skipped: {why}")),
            }
            ok(StatusCode::CREATED, json!({"notification": n}))
        }
        Err(e) => db_err(e),
    }
}

async fn notifications_list(
    State(s): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Reply {
    let limit = q
        .get("limit")
        .and_then(|l| l.parse::<u64>().ok())
        .unwrap_or(20);
    let to = q.get("to").map(|t| t.trim()).filter(|t| !t.is_empty());
    let since_id = match q.get("since_id") {
        None => None,
        Some(v) => match v.parse::<i64>() {
            Ok(n) => Some(n),
            Err(_) => return err(StatusCode::BAD_REQUEST, "since_id is a notification id"),
        },
    };
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::notification_list_filtered(&conn, limit, to, since_id) {
        Ok(notifications) => ok(StatusCode::OK, json!({"notifications": notifications})),
        Err(e) => db_err(e),
    }
}

/// Direct push, no queue: the Debug screen's Test button and `notify
/// test`'s twin. Tailnet-only (404 on the public listener, like
/// tickets/confirm). Unconfigured hubs refuse in 4xx with the fix.
async fn notify_test(State(s): State<AppState>, Json(body): Json<Value>) -> Reply {
    let field = |key: &str| -> Result<String, Reply> {
        match body.get(key) {
            None | Some(Value::Null) => Ok(String::new()),
            Some(Value::String(v)) => Ok(v.trim().to_string()),
            Some(_) => Err(err(StatusCode::BAD_REQUEST, &format!("{key} is a string"))),
        }
    };
    let to = match field("to") {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut title = match field("title") {
        Ok(v) => v,
        Err(r) => return r,
    };
    if title.is_empty() {
        title = "test".to_string();
    }
    let topic_in = match field("topic") {
        Ok(v) => v,
        Err(r) => return r,
    };
    let topic = if topic_in.is_empty() {
        "notify".to_string()
    } else {
        topic_in
    };
    let content = match field("body") {
        Ok(v) => v,
        Err(r) => return r,
    };
    if to.len() > 64 || title.len() > 512 || content.len() > 4096 || topic.len() > 128 {
        return err(
            StatusCode::BAD_REQUEST,
            "to 64, title 512, body 4096, topic 128 max",
        );
    }
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let cfg = match apns::load(s.apns_key.as_deref(), &s.db_path, &conn) {
        Ok(Some(cfg)) => cfg,
        Ok(None) => {
            return err(
                StatusCode::BAD_REQUEST,
                "APNs is not configured — install apns.p8 (0600) beside the hub db, \
                 then `est-hub apns set --key-id K --team-id T --topic P`",
            );
        }
        Err(why) => return err(StatusCode::BAD_REQUEST, &why),
    };
    let targets = match apns::resolve_targets(&conn, &to) {
        Ok(t) => t,
        Err(why) => return err(StatusCode::NOT_FOUND, &why),
    };
    // One named device with no token: a per-device error, not silence.
    if !to.is_empty()
        && targets.first().is_some_and(|d| !d.apns_configured())
        && let Some(d) = targets.first()
    {
        return ok(
            StatusCode::OK,
            json!({"results": [{"device": d.name, "env": d.apns_env,
                                "error": "device has no apns token"}]}),
        );
    }
    let out = apns::deliver_to(
        &s.apns, &s.db_path, &cfg, &targets, &title, &content, &topic,
    )
    .await;
    let results: Vec<Value> = out.iter().map(|d| d.to_json()).collect();
    ok(StatusCode::OK, json!({"results": results}))
}

/// Fire one alive round now: the watchdog tick the serve loop sends
/// every 6h, on demand. Broadcast-only (the tick is for every
/// device); the body is ignored. Answers the tick plus per-device
/// results, in the notify_test shape.
async fn notify_alive(State(s): State<AppState>, Json(_): Json<Value>) -> Reply {
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let cfg = match apns::load(s.apns_key.as_deref(), &s.db_path, &conn) {
        Ok(Some(cfg)) => cfg,
        Ok(None) => {
            return err(
                StatusCode::BAD_REQUEST,
                "APNs is not configured — install apns.p8 (0600) beside the hub db, \
                 then `est-hub apns set --key-id K --team-id T --topic P`",
            );
        }
        Err(why) => return err(StatusCode::BAD_REQUEST, &why),
    };
    let now = model::now_epoch();
    let out = apns::deliver_alive(&s.apns, &s.db_path, &cfg).await;
    let results: Vec<Value> = out.iter().map(|d| d.to_json()).collect();
    ok(StatusCode::OK, json!({"alive_ts": now, "results": results}))
}

// ---------------------------------------------------------------- live activity

/// Push tokens are hex, 1-512 chars (Apple's are 64; the ceiling is slack).
fn valid_push_token(t: &str) -> bool {
    (1..=512).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_hexdigit())
}

/// One bool field of `PUT …/live-activity`: absent keeps, a bool sets.
fn live_bool(body: &Value, key: &str) -> Result<Option<bool>, Reply> {
    match body.get(key) {
        None => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(err(
            StatusCode::BAD_REQUEST,
            &format!("{key} is true or false"),
        )),
    }
}

/// Write one device's Live Activity feed (`devices live set`'s twin):
/// every field present-sets, absent-keeps. `enabled:false` ends the
/// running card and stops; any other change converges it. Answers the
/// same shape `GET` serves.
async fn live_set(
    State(s): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    let name = name.trim();
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let device = match db::device_get(&conn, name) {
        Ok(d) => d,
        Err(e) => return db_err(e),
    };
    let mut cfg = device.la_config_parsed();
    if let Some(enabled) = match live_bool(&body, "enabled") {
        Ok(v) => v,
        Err(r) => return r,
    } {
        cfg.enabled = enabled;
    }
    if let Some(v) = body.get("min_severity") {
        let Some(sev) = v.as_str().and_then(model::parse_severity) else {
            return err(
                StatusCode::BAD_REQUEST,
                "min_severity is low, normal, or high",
            );
        };
        cfg.min_severity = sev.to_string();
    }
    for key in ["approvals", "alert_on_down"] {
        match live_bool(&body, key) {
            Ok(None) => {}
            Ok(Some(b)) => {
                if key == "approvals" {
                    cfg.approvals = b;
                } else {
                    cfg.alert_on_down = b;
                }
            }
            Err(r) => return r,
        }
    }
    if let Some(v) = body.get("checks") {
        match v {
            Value::Null => cfg.checks = None,
            Value::String(which) if which.trim() == "all" => cfg.checks = None,
            Value::Array(items) => {
                if items.len() > 256 {
                    return err(StatusCode::BAD_REQUEST, "checks lists 256 max");
                }
                let mut list = Vec::with_capacity(items.len());
                for item in items {
                    let Some(check) = item.as_str().map(str::trim).filter(|n| !n.is_empty()) else {
                        return err(
                            StatusCode::BAD_REQUEST,
                            "checks is null, \"all\", or an array of check names",
                        );
                    };
                    if !model::valid_name(check) {
                        return err(
                            StatusCode::BAD_REQUEST,
                            "check names match [a-z][a-z0-9_-]{0,31}",
                        );
                    }
                    if db::check_get(&conn, check).is_err() {
                        return err(StatusCode::NOT_FOUND, &format!("no such check {check}"));
                    }
                    list.push(check.to_string());
                }
                list.sort();
                list.dedup();
                // Empty selects everything, like null and "all" — the app
                // sends [] for its "All checks" toggle.
                cfg.checks = if list.is_empty() { None } else { Some(list) };
            }
            _ => {
                return err(
                    StatusCode::BAD_REQUEST,
                    "checks is null, \"all\", or an array of check names",
                );
            }
        }
    }
    // The PTS token: absent keeps, null/empty clears, hex sets.
    let mut pts = device.la_pts_token.clone();
    if let Some(v) = body.get("pts_token") {
        match v {
            Value::Null => pts = None,
            Value::String(t) if t.trim().is_empty() => pts = None,
            Value::String(t) if valid_push_token(t.trim()) => {
                pts = Some(t.trim().to_string());
            }
            Value::String(_) => return err(StatusCode::BAD_REQUEST, "pts_token is hex, 512 max"),
            _ => return err(StatusCode::BAD_REQUEST, "pts_token is a hex string"),
        }
    }
    if let Err(e) = db::la_config_set(&conn, name, &cfg) {
        return db_err(e);
    }
    if let Err(e) = db::la_pts_set(&conn, name, pts.as_deref()) {
        return db_err(e);
    }
    let ctx = live::Ctx::new(s.apns.clone(), s.apns_key.clone(), s.throttle.clone());
    if !cfg.enabled {
        live::disable_device(&ctx, &s.db_path, name).await;
    } else {
        live::converge_device(&ctx, &s.db_path, name, false, None).await;
    }
    live_show_inner(&s, name)
}

/// One device's feed plus its card: config, PTS bit (never the token),
/// status, current activity, stamps, and reported activity ids (never
/// token values — only the hub sends).
async fn live_show(State(s): State<AppState>, Path(name): Path<String>) -> Reply {
    live_show_inner(&s, name.trim())
}

fn live_show_inner(s: &AppState, name: &str) -> Reply {
    let conn = match conn(s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let device = match db::device_get(&conn, name) {
        Ok(d) => d,
        Err(e) => return db_err(e),
    };
    let cfg = device.la_config_parsed();
    let last_push = db::live_last_push_get(&conn, name);
    let status = live::status_of(
        cfg.enabled,
        device.la_activity_id.as_deref(),
        device.la_started_ts,
        last_push,
        model::now_epoch(),
    );
    let tokens = db::la_tokens_for_device(&conn, name).unwrap_or_default();
    let token_rows: Vec<Value> = tokens
        .iter()
        .map(|t| {
            json!({
                "activity_id": t.activity_id,
                "label": t.label,
                "updated_ts": t.updated_ts,
            })
        })
        .collect();
    ok(
        StatusCode::OK,
        json!({
            "device": name,
            "config": cfg,
            "pts_configured": device.la_pts_token.as_deref().is_some_and(|t| !t.is_empty()),
            "status": status,
            "active": status == "active",
            "started": device.la_activity_id.is_some(),
            "activity_id": device.la_activity_id,
            "started_ts": device.la_started_ts,
            "last_push_ts": last_push,
            "tokens": token_rows,
        }),
    )
}

/// The app reports an activity push token (`devices live token`'s twin):
/// upserted by activity id, and the device points at it as current.
async fn live_token_add(
    State(s): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    let name = name.trim();
    let activity = body
        .get("activity_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if activity.is_empty() || activity.len() > 128 {
        return err(StatusCode::BAD_REQUEST, "activity_id is 1-128 chars");
    }
    let token = body
        .get("token")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if !valid_push_token(token) {
        return err(StatusCode::BAD_REQUEST, "token is hex, 1-512");
    }
    let label = body
        .get("label")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if label.len() > 128 {
        return err(StatusCode::BAD_REQUEST, "label is 128 max");
    }
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let now = model::now_epoch();
    match db::la_token_upsert(&conn, name, activity, token, label, now) {
        Ok(t) => {
            // Only status tokens move the activity pointer — incident
            // rows (`incident:{check}`) ride beside it, never through it.
            if label.is_empty() {
                let _ = db::la_activity_set(&conn, name, Some(activity), Some(now));
            }
            ok(
                StatusCode::CREATED,
                json!({
                    "activity_id": t.activity_id,
                    "device": t.device,
                    "label": t.label,
                    "updated_ts": t.updated_ts,
                }),
            )
        }
        Err(e) => db_err(e),
    }
}

/// Forget one activity token (`devices live untoken`'s twin). The id
/// must belong to this device; anything else reads 404. Deleting the
/// current activity unpoints the device.
async fn live_token_del(
    State(s): State<AppState>,
    Path((name, id)): Path<(String, String)>,
) -> Reply {
    let (name, id) = (name.trim(), id.trim());
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::la_token_delete(&conn, name, id) {
        Ok(()) => {
            if let Ok(d) = db::device_get(&conn, name)
                && d.la_activity_id.as_deref() == Some(id)
            {
                let _ = db::la_activity_set(&conn, name, None, None);
            }
            ok(StatusCode::OK, json!({"deleted": id}))
        }
        Err(e) => db_err(e),
    }
}

/// Direct Live Activity push, no feed involved (`live test`'s twin):
/// a canned card to one device, now. Tailnet-only, like `notify/test`.
/// Unconfigured hubs and tokenless devices refuse in 4xx with the fix.
async fn live_test(State(s): State<AppState>, Json(body): Json<Value>) -> Reply {
    let to = body.get("to").and_then(Value::as_str).unwrap_or("").trim();
    if to.is_empty() {
        return err(StatusCode::BAD_REQUEST, "to names the device");
    }
    let event = body
        .get("event")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if !["update", "end", "start"].contains(&event) {
        return err(StatusCode::BAD_REQUEST, "event is update, end, or start");
    }
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let device = match db::device_get(&conn, to) {
        Ok(d) => d,
        Err(_) => return err(StatusCode::NOT_FOUND, &format!("no such device {to}")),
    };
    let cfg = match apns::load(s.apns_key.as_deref(), &s.db_path, &conn) {
        Ok(Some(cfg)) => cfg,
        Ok(None) => {
            return err(
                StatusCode::BAD_REQUEST,
                "APNs is not configured — install apns.p8 (0600) beside the hub db, \
                 then `est-hub apns set --key-id K --team-id T --topic P`",
            );
        }
        Err(why) => return err(StatusCode::BAD_REQUEST, &why),
    };
    // The canned card: visibly fake, loud enough to prove the path.
    let now = model::now_epoch();
    let state = apns::live_content_state(1, "high", 2, now);
    // Update and end ride the current activity token; start rides PTS.
    let current_token: Option<String> = if event == "start" {
        None
    } else {
        device.la_activity_id.as_deref().and_then(|id| {
            db::la_tokens_for_device(&conn, to)
                .unwrap_or_default()
                .into_iter()
                .find(|t| t.activity_id == id)
                .map(|t| t.push_token)
        })
    };
    if event != "start" && current_token.is_none() {
        return err(
            StatusCode::BAD_REQUEST,
            &format!(
                "no live activity tokens for {to} — the app reports them \
                 via POST /devices/{to}/live-activity/tokens"
            ),
        );
    }
    let (token, payload): (&str, Value) = match event {
        "update" => (
            current_token.as_deref().unwrap_or(""),
            apns::live_update_payload(&state, Some(("EST status", "Live Activity test")), now),
        ),
        "end" => (
            current_token.as_deref().unwrap_or(""),
            apns::live_end_payload(&state, now + live::END_DISMISS_AFTER_SECS, now),
        ),
        _ => {
            let Some(pts) = device.la_pts_token.as_deref().filter(|t| !t.is_empty()) else {
                return err(
                    StatusCode::BAD_REQUEST,
                    &format!(
                        "no push-to-start token for {to} — set one \
                         via PUT /devices/{to}/live-activity"
                    ),
                );
            };
            let payload = apns::live_start_payload(
                to,
                live::CARD_TITLE,
                &state,
                "EST status",
                "Live Activity test",
                now,
            );
            (pts, payload)
        }
    };
    let base = apns::resolve_topic(device.apns_topic.as_deref(), &cfg.topic);
    let topic = apns::live_topic(&base);
    let bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let send = apns::LiveSend {
        token,
        env: device.apns_env.as_deref(),
        topic: &topic,
        priority: 10,
        payload: &bytes,
        base_override: None,
    };
    let outcome = apns::send_live(&s.apns, &cfg, &send).await;
    match &outcome {
        apns::SendOutcome::Sent { .. } => {
            let _ = db::live_last_push_set(&conn, to, now);
        }
        apns::SendOutcome::Unregistered => {
            // The test named a dead token: same feedback loop as the
            // triggers — delete, then the one throttled notice.
            if event == "start" {
                let _ = db::la_pts_set(&conn, to, None);
                live::stale_notice(
                    &conn,
                    &s.throttle,
                    to,
                    "Apple rejected the push-to-start token (410/BadDeviceToken); it was cleared",
                );
            } else {
                if let Some(id) = device.la_activity_id.as_deref() {
                    let _ = db::la_token_delete(&conn, to, id);
                    let _ = db::la_activity_set(&conn, to, None, None);
                }
                live::stale_notice(
                    &conn,
                    &s.throttle,
                    to,
                    "Apple rejected the activity token (410/BadDeviceToken); it was deleted",
                );
            }
        }
        _ => {}
    }
    match outcome {
        apns::SendOutcome::Sent { apns_id } => ok(
            StatusCode::OK,
            json!({"device": to, "event": event, "env": device.apns_env, "apns_id": apns_id}),
        ),
        other => ok(
            StatusCode::OK,
            json!({"device": to, "event": event, "env": device.apns_env, "error": other.error_line()}),
        ),
    }
}

/// One id field of `PUT /apns`: absent keeps, null/empty clears,
/// a string sets. Mirrors `PUT /devices/{name}`.
fn apns_id_field(body: &Value, key: &str, max: usize) -> Result<Option<Option<String>>, Reply> {
    match body.get(key) {
        None => Ok(None),
        Some(Value::Null) => Ok(Some(None)),
        Some(Value::String(v)) if v.trim().is_empty() => Ok(Some(None)),
        Some(Value::String(v)) if v.len() <= max => Ok(Some(Some(v.trim().to_string()))),
        Some(Value::String(_)) => Err(err(
            StatusCode::BAD_REQUEST,
            &format!("{key} is {max} chars max"),
        )),
        Some(_) => Err(err(StatusCode::BAD_REQUEST, &format!("{key} is a string"))),
    }
}

/// Read the APNs sender state (`apns show`'s twin): whether pushes
/// can send, plus the topic they send on. Secret-free (ids and the key
/// stay put), so both listeners serve it — the phone's Hub screen
/// answers "are notifications working?" off this.
async fn apns_show(State(s): State<AppState>) -> Reply {
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let configured =
        apns::load(s.apns_key.as_deref(), &s.db_path, &conn).is_ok_and(|c| c.is_some());
    ok(
        StatusCode::OK,
        json!({"apns": {
            "configured": configured,
            "topic": db::meta_get(&conn, apns::META_TOPIC),
        }}),
    )
}

/// Write the APNs sender ids (`apns set`'s twin): key/team/topic, each
/// present-sets, absent-keeps, null-clears. Tailnet-only. Answers the
/// three ids as they now stand (`null` for unset).
async fn apns_set(State(s): State<AppState>, Json(body): Json<Value>) -> Reply {
    let key_id = match apns_id_field(&body, "key_id", 64) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let team_id = match apns_id_field(&body, "team_id", 64) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let topic = match apns_id_field(&body, "topic", 256) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    for (meta, v) in [
        (apns::META_KEY_ID, key_id),
        (apns::META_TEAM_ID, team_id),
        (apns::META_TOPIC, topic),
    ] {
        match v {
            None => {}
            Some(Some(id)) => {
                if let Err(e) = db::meta_set(&conn, meta, &id) {
                    return db_err(e);
                }
            }
            Some(None) => {
                if let Err(e) = db::meta_del(&conn, meta) {
                    return db_err(e);
                }
            }
        }
    }
    ok(
        StatusCode::OK,
        json!({"apns": {
            "key_id": db::meta_get(&conn, apns::META_KEY_ID),
            "team_id": db::meta_get(&conn, apns::META_TEAM_ID),
            "topic": db::meta_get(&conn, apns::META_TOPIC),
        }}),
    )
}

/// The whole API on the single (tailnet) listener. Access control is
/// Tailscale membership — the bind address is the gate. Grows one route
/// per slice; each lands with its CLI twin the same day.
pub fn router(state: AppState) -> Router {
    routes().with_state(state)
}

fn routes() -> Router<AppState> {
    Router::new()
        .route("/ping", get(ping))
        .route("/devices", get(devices_list).post(devices_create))
        .route(
            "/devices/{name}",
            get(devices_show).put(devices_update).delete(devices_delete),
        )
        .route("/checks", get(checks_list).post(checks_create))
        .route(
            "/checks/{name}",
            get(checks_show).put(checks_replace).delete(checks_delete),
        )
        .route("/checks/{name}/ack", put(checks_ack).delete(checks_unack))
        .route(
            "/checks/{name}/mute",
            put(checks_mute).delete(checks_unmute),
        )
        .route("/checks/{name}/results", get(results_list))
        .route("/secrets", get(secrets_list))
        .route(
            "/secrets/{name}",
            get(secrets_pull).put(secrets_push).delete(secrets_delete),
        )
        .route(
            "/secrets/{name}/token",
            axum::routing::post(secrets_token_mint).delete(secrets_token_revoke),
        )
        .route("/balances", get(balances_list))
        .route(
            "/balances/{name}",
            put(balances_set).delete(balances_delete),
        )
        .route("/agents", get(agents_list))
        .route(
            "/agents/{name}",
            get(agents_show).put(agents_push).delete(agents_delete),
        )
        .route("/projects", get(projects_list))
        .route("/projects/{name}", get(projects_show).put(projects_set))
        .route(
            "/projects/{name}/icon",
            get(projects_icon_show).put(projects_icon_set),
        )
        .route("/results", axum::routing::post(results_report))
        .route("/heartbeats", axum::routing::post(heartbeats_beat))
        .route("/approvals", get(approvals_list).post(approvals_create))
        .route("/approvals/{id}", get(approvals_show))
        .route(
            "/approvals/{id}/decision",
            axum::routing::post(approvals_decide),
        )
        .route("/notify", axum::routing::post(notify_send))
        .route("/notify/test", axum::routing::post(notify_test))
        .route("/notify/alive", axum::routing::post(notify_alive))
        .route("/notifications", get(notifications_list))
        .route("/apns", get(apns_show).put(apns_set))
        .route(
            "/devices/{name}/live-activity",
            get(live_show).put(live_set),
        )
        .route(
            "/devices/{name}/live-activity/tokens",
            axum::routing::post(live_token_add),
        )
        .route(
            "/devices/{name}/live-activity/tokens/{id}",
            axum::routing::delete(live_token_del),
        )
        .route("/live-activities/test", axum::routing::post(live_test))
        .fallback(not_found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_expose_no_pairing_or_tls_surface() {
        for r in ROUTES {
            assert!(!r.path.contains("ticket"), "{}", r.path);
            assert!(!r.path.contains("/pair"), "{}", r.path);
            assert!(!r.path.contains("/confirm"), "{}", r.path);
        }
    }

    #[test]
    fn device_envelope_keeps_the_token_on_the_trusted_listener() {
        // The tailnet is the trust boundary: the one listener serializes
        // the APNs token (there is no redaction layer anymore).
        let d = model::Device {
            name: "phone".to_string(),
            apns_token: Some("tok".to_string()),
            created_ts: 1,
            state: "active".to_string(),
            apns_env: None,
            apns_topic: None,
            la_pts_token: Some("secret".to_string()),
            la_config: None,
            la_activity_id: None,
            la_started_ts: None,
        };
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["apns_token"], "tok");
        assert_eq!(v["apns_configured"], true);
        assert!(v.get("la_pts_token").is_none());
    }
}
