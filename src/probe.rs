//! The hub's own eyes: fetch `url`/`api` checks with stock-platform
//! TLS and evaluate `heartbeat` staleness, recording through the same
//! [`crate::db::record_result`] every other runner uses — flips and
//! flip notifications included. `balance` waits for P4. The serve loop
//! decides *when* (per-check `every_secs`); this module decides *how*.

use std::path::Path;

use crate::{db, model};

fn fetch_reason(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        return "timed out".to_string();
    }
    if e.is_connect() {
        return "connection refused".to_string();
    }
    if e.is_builder() || e.is_request() {
        return "bad request".to_string();
    }
    format!("fetch failed: {e}")
}

/// Probe one check by name: fetch or evaluate, record, log. Never
/// panics, never fails the loop — a broken check definition records a
/// failed probe instead of crashing the daemon.
pub async fn probe_check(client: &reqwest::Client, db_path: &Path, name: &str) {
    let conn = match db::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            est_core::log::error(&format!("probe {name}: {e}"));
            return;
        }
    };
    let check = match db::check_get(&conn, name) {
        Ok(c) => c,
        Err(_) => return, // Deleted between ticks: nothing to do.
    };
    let now = model::now_epoch();
    let (ok, code, reason) = match check.ctype.as_str() {
        "url" | "api" => fetch(client, &check).await,
        "heartbeat" => {
            // Grace: a beat-less check younger than its own window is
            // still setting up, not down.
            if check.state.last_beat == 0
                && now.saturating_sub(check.created_ts) < check.config.miss_after_secs
            {
                return;
            }
            let silent = now.saturating_sub(check.state.last_beat);
            if silent <= check.config.miss_after_secs {
                (true, None, format!("beat {}s ago", silent))
            } else {
                (false, None, format!("no beat for {silent}s"))
            }
        }
        _ => return, // balance and friends: evaluated elsewhere.
    };
    match db::record_result(&conn, name, ok, code, &reason, now) {
        Ok(flipped) => {
            if flipped {
                est_core::log::info(&format!(
                    "probe {name} flipped {}",
                    if ok { "up" } else { "down" }
                ));
            }
        }
        Err(e) => est_core::log::error(&format!("probe {name}: {e}")),
    }
    let _ = conn.close();
}

async fn fetch(client: &reqwest::Client, check: &model::Check) -> (bool, Option<u16>, String) {
    let res = match client
        .get(&check.target)
        .timeout(std::time::Duration::from_secs(check.timeout_secs))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return (false, None, fetch_reason(&e)),
    };
    let code = res.status().as_u16();
    if code != check.config.expect {
        return (
            false,
            Some(code),
            format!("HTTP {code} (want {})", check.config.expect),
        );
    }
    if let Some(needle) = check.config.contains.as_deref() {
        let body = res.text().await.unwrap_or_default();
        if !body.contains(needle) {
            return (false, Some(code), format!("HTTP {code} without {needle:?}"));
        }
    }
    (true, Some(code), format!("HTTP {code}"))
}
