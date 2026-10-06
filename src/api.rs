//! The HTTP surface: versioned JSON envelopes, same shape as every
//! EST CLI (`{"ok":…,"v":1,…}`). Success is 200 with `"ok":true`;
//! unknown routes are 404 with `"ok":false`. No route here ever needs
//! the vault: the hub answers from its own SQLite state.

use axum::{Json, Router, http::StatusCode, routing::get};
use serde::Serialize;

/// What `/ping` answers: alive, named, versioned.
#[derive(Serialize)]
struct Ping<'a> {
    ok: bool,
    v: u8,
    name: &'a str,
    version: &'a str,
}

async fn ping() -> Json<Ping<'static>> {
    Json(Ping {
        ok: true,
        v: 1,
        name: "est-hub",
        version: crate::VERSION,
    })
}

async fn not_found() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"ok": false, "v": 1, "error": "no such route"})),
    )
}

/// Every route the hub serves. Grows one route per slice; each lands
/// with its CLI twin the same day (the control-plane rule).
pub fn router() -> Router {
    Router::new().route("/ping", get(ping)).fallback(not_found)
}
