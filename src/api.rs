//! The HTTP surface: versioned JSON envelopes, same shape as every
//! EST CLI (`{"ok":…,"v":1,…}`). Success is 200 (creation: 201);
//! misuse is 400, unknown 404, conflicts 409 — all envelopes. The one
//! exception: a body that is not JSON at all gets axum's plain 400,
//! before any handler runs. No route here ever needs the vault: the
//! hub answers from its own SQLite state.

use std::collections::HashMap;
use std::path::PathBuf;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
};
use serde_json::{Value, json};

use crate::{db, model};

/// Shared across handlers: where the SQLite file lives. Handlers open
/// per request (microsecond calls at single-user scale).
#[derive(Clone)]
pub struct AppState {
    /// Where the SQLite file lives.
    pub db_path: PathBuf,
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
    let (name, pubkey, apns) = match model::validate_device(&body) {
        Ok(v) => v,
        Err(why) => return err(StatusCode::BAD_REQUEST, &why),
    };
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::device_add(&conn, &name, pubkey.as_deref(), apns.as_deref()) {
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
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let ts = body.ts.unwrap_or_else(model::now_epoch);
    match db::record_result(&conn, name, ok_flag, body.code, reason, ts) {
        Ok(flipped) => ok(
            StatusCode::OK,
            json!({"recorded": name, "flipped": flipped}),
        ),
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
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::result_list(&conn, name.trim(), limit) {
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
        Ok(a) => ok(StatusCode::CREATED, json!({"approval": a})),
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
        Ok(a) => ok(StatusCode::OK, json!({"approval": a})),
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
    let conn = match conn(&s) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match db::notification_list(&conn, limit) {
        Ok(notifications) => ok(StatusCode::OK, json!({"notifications": notifications})),
        Err(e) => db_err(e),
    }
}

/// Every route the hub serves. Grows one route per slice; each lands
/// with its CLI twin the same day (the control-plane rule).
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/ping", get(ping))
        .route("/devices", get(devices_list).post(devices_create))
        .route("/devices/{name}", get(devices_show).delete(devices_delete))
        .route("/checks", get(checks_list).post(checks_create))
        .route(
            "/checks/{name}",
            get(checks_show).put(checks_replace).delete(checks_delete),
        )
        .route("/checks/{name}/results", get(results_list))
        .route("/results", axum::routing::post(results_report))
        .route("/heartbeats", axum::routing::post(heartbeats_beat))
        .route("/approvals", get(approvals_list).post(approvals_create))
        .route("/approvals/{id}", get(approvals_show))
        .route(
            "/approvals/{id}/decision",
            axum::routing::post(approvals_decide),
        )
        .route("/notify", axum::routing::post(notify_send))
        .route("/notifications", get(notifications_list))
        .fallback(not_found)
        .with_state(state)
}
