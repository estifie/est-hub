//! One SQLite file: devices, checks, results, heartbeats, approvals,
//! notifications. Opened WAL for readers-don't-block-writers; the
//! directory is `0700`. Handlers open per request — microsecond calls
//! at single-user scale, no pool to babysit.

use std::path::Path;

use crate::model::{self, ValidCheck};

/// Opening or operating the store failed: why, in one human line.
#[derive(Debug)]
pub enum Error {
    /// The directory could not be made or entered.
    Io(String),
    /// SQLite itself refused.
    Sql(rusqlite::Error),
    /// A row with that key already lives here.
    Exists(String),
    /// No such row.
    Missing(String),
    /// The operation is legal SQL but refused (double decision…).
    Invalid(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(why) => write!(f, "cannot ready the store dir: {why}"),
            Error::Sql(e) => write!(f, "sqlite refused: {e}"),
            Error::Exists(what) => write!(f, "{what} already exists"),
            Error::Missing(what) => write!(f, "no such {what}"),
            Error::Invalid(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for Error {}

/// Results older than this die on the next record (Angel's retention
/// doctrine: budgets on everything the daemon keeps).
const RESULT_RETENTION_SECS: u64 = 30 * 86_400;
/// Flips inside this window mark a check flapping.
const FLAP_WINDOW_SECS: u64 = 3_600;
const FLAP_FLIPS: usize = 5;

/// Open (creating) the store: dirs made `0700`, WAL on, every table
/// present. Additive migrations only — `CREATE TABLE IF NOT EXISTS`
/// plus new tables per slice, never rewrites.
pub fn open(path: &Path) -> Result<rusqlite::Connection, Error> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|e| Error::Io(format!("{}: {e}", parent.display())))?;
    }
    let conn = rusqlite::Connection::open(path).map_err(Error::Sql)?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(Error::Sql)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
         CREATE TABLE IF NOT EXISTS devices (
           name TEXT PRIMARY KEY, pubkey TEXT, apns_token TEXT, created_ts INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS checks (
           name TEXT PRIMARY KEY, owner TEXT NOT NULL, ctype TEXT NOT NULL,
           target TEXT NOT NULL, every_secs INTEGER NOT NULL, timeout_secs INTEGER NOT NULL,
           severity TEXT NOT NULL, runner TEXT NOT NULL, source TEXT NOT NULL,
           config TEXT NOT NULL, created_ts INTEGER NOT NULL,
           last_ok INTEGER, fails INTEGER NOT NULL DEFAULT 0, changed_ts INTEGER NOT NULL DEFAULT 0,
           last_ts INTEGER NOT NULL DEFAULT 0, last_code INTEGER, last_reason TEXT NOT NULL DEFAULT '');
         CREATE TABLE IF NOT EXISTS results (
           id INTEGER PRIMARY KEY AUTOINCREMENT, checks TEXT NOT NULL,
           ts INTEGER NOT NULL, ok INTEGER NOT NULL, code INTEGER, reason TEXT NOT NULL DEFAULT '');
         CREATE INDEX IF NOT EXISTS idx_results_check_ts ON results (checks, ts);
         CREATE TABLE IF NOT EXISTS heartbeats (checks TEXT PRIMARY KEY, ts INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS approvals (
           id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
           body TEXT NOT NULL DEFAULT '', reply_to TEXT NOT NULL DEFAULT '',
           state TEXT NOT NULL DEFAULT 'pending', created_ts INTEGER NOT NULL,
           deadline_ts INTEGER NOT NULL, decided_ts INTEGER NOT NULL DEFAULT 0,
           decision TEXT NOT NULL DEFAULT '', decided_by TEXT NOT NULL DEFAULT '');
         CREATE TABLE IF NOT EXISTS notifications (
           id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
           topic TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL DEFAULT '',
           to_device TEXT NOT NULL DEFAULT '', delivered INTEGER NOT NULL DEFAULT 0);",
    )
    .map_err(Error::Sql)?;
    Ok(conn)
}

// ---------------------------------------------------------------- devices

/// Register a device. Refuses a name already taken.
pub fn device_add(
    conn: &rusqlite::Connection,
    name: &str,
    pubkey: Option<&str>,
    apns_token: Option<&str>,
) -> Result<model::Device, Error> {
    let created = model::now_epoch();
    let n = conn
        .execute(
            "INSERT INTO devices (name, pubkey, apns_token, created_ts) VALUES (?, ?, ?, ?)
             ON CONFLICT (name) DO NOTHING",
            rusqlite::params![name, pubkey, apns_token, created as i64],
        )
        .map_err(Error::Sql)?;
    if n == 0 {
        return Err(Error::Exists(format!("device {name}")));
    }
    Ok(model::Device {
        name: name.to_string(),
        pubkey: pubkey.map(str::to_string),
        apns_token: apns_token.map(str::to_string),
        created_ts: created,
    })
}

/// One device, or missing.
pub fn device_get(conn: &rusqlite::Connection, name: &str) -> Result<model::Device, Error> {
    conn.query_row(
        "SELECT name, pubkey, apns_token, created_ts FROM devices WHERE name = ?",
        [name],
        |r| {
            Ok(model::Device {
                name: r.get(0)?,
                pubkey: r.get(1)?,
                apns_token: r.get(2)?,
                created_ts: r.get::<_, i64>(3)? as u64,
            })
        },
    )
    .map_err(|_| Error::Missing(format!("device {name}")))
}

/// Every device, by name.
pub fn device_list(conn: &rusqlite::Connection) -> Result<Vec<model::Device>, Error> {
    let mut stmt = conn
        .prepare("SELECT name, pubkey, apns_token, created_ts FROM devices ORDER BY name")
        .map_err(Error::Sql)?;
    stmt.query_map([], |r| {
        Ok(model::Device {
            name: r.get(0)?,
            pubkey: r.get(1)?,
            apns_token: r.get(2)?,
            created_ts: r.get::<_, i64>(3)? as u64,
        })
    })
    .map_err(Error::Sql)?
    .collect::<Result<Vec<_>, _>>()
    .map_err(Error::Sql)
}

/// Revoke a device: delete its row. Gone means gone.
pub fn device_delete(conn: &rusqlite::Connection, name: &str) -> Result<(), Error> {
    let n = conn
        .execute("DELETE FROM devices WHERE name = ?", [name])
        .map_err(Error::Sql)?;
    if n == 0 {
        return Err(Error::Missing(format!("device {name}")));
    }
    Ok(())
}

// ---------------------------------------------------------------- checks

struct CheckRow {
    name: String,
    owner: String,
    ctype: String,
    target: String,
    every_secs: u64,
    timeout_secs: u64,
    severity: String,
    runner: String,
    source: String,
    config: String,
    created_ts: u64,
    last_ok: Option<bool>,
    fails: u32,
    changed_ts: u64,
    last_ts: u64,
    last_code: Option<u16>,
    last_reason: String,
}

fn get_row(conn: &rusqlite::Connection, name: &str) -> Result<CheckRow, Error> {
    conn.query_row(
        "SELECT name, owner, ctype, target, every_secs, timeout_secs, severity, runner,
                source, config, created_ts, last_ok, fails, changed_ts, last_ts, last_code, last_reason
         FROM checks WHERE name = ?",
        [name],
        |r| {
            Ok(CheckRow {
                name: r.get(0)?,
                owner: r.get(1)?,
                ctype: r.get(2)?,
                target: r.get(3)?,
                every_secs: r.get::<_, i64>(4)? as u64,
                timeout_secs: r.get::<_, i64>(5)? as u64,
                severity: r.get(6)?,
                runner: r.get(7)?,
                source: r.get(8)?,
                config: r.get(9)?,
                created_ts: r.get::<_, i64>(10)? as u64,
                last_ok: r.get::<_, Option<i64>>(11)?.map(|v| v != 0),
                fails: r.get::<_, i64>(12)? as u32,
                changed_ts: r.get::<_, i64>(13)? as u64,
                last_ts: r.get::<_, i64>(14)? as u64,
                last_code: r.get::<_, Option<i64>>(15)?.map(|v| v as u16),
                last_reason: r.get(16)?,
            })
        },
    )
    .map_err(|_| Error::Missing(format!("check {name}")))
}

fn list_rows(conn: &rusqlite::Connection) -> Result<Vec<CheckRow>, Error> {
    let mut stmt = conn
        .prepare(
            "SELECT name, owner, ctype, target, every_secs, timeout_secs, severity, runner,
                    source, config, created_ts, last_ok, fails, changed_ts, last_ts, last_code, last_reason
             FROM checks ORDER BY name",
        )
        .map_err(Error::Sql)?;
    stmt.query_map([], |r| {
        Ok(CheckRow {
            name: r.get(0)?,
            owner: r.get(1)?,
            ctype: r.get(2)?,
            target: r.get(3)?,
            every_secs: r.get::<_, i64>(4)? as u64,
            timeout_secs: r.get::<_, i64>(5)? as u64,
            severity: r.get(6)?,
            runner: r.get(7)?,
            source: r.get(8)?,
            config: r.get(9)?,
            created_ts: r.get::<_, i64>(10)? as u64,
            last_ok: r.get::<_, Option<i64>>(11)?.map(|v| v != 0),
            fails: r.get::<_, i64>(12)? as u32,
            changed_ts: r.get::<_, i64>(13)? as u64,
            last_ts: r.get::<_, i64>(14)? as u64,
            last_code: r.get::<_, Option<i64>>(15)?.map(|v| v as u16),
            last_reason: r.get(16)?,
        })
    })
    .map_err(Error::Sql)?
    .collect::<Result<Vec<_>, _>>()
    .map_err(Error::Sql)
}

fn last_beat(conn: &rusqlite::Connection, name: &str) -> u64 {
    conn.query_row("SELECT ts FROM heartbeats WHERE checks = ?", [name], |r| {
        r.get::<_, i64>(0)
    })
    .map(|v| v as u64)
    .unwrap_or(0)
}

/// Flips inside the window: five or more reads flapping.
fn flapping(conn: &rusqlite::Connection, name: &str, now: u64) -> bool {
    let since = now.saturating_sub(FLAP_WINDOW_SECS) as i64;
    let oks: Vec<i64> = conn
        .prepare("SELECT ok FROM results WHERE checks = ? AND ts >= ? ORDER BY ts, id")
        .and_then(|mut s| {
            s.query_map(rusqlite::params![name, since], |r| r.get(0))?
                .collect::<Result<Vec<_>, _>>()
        })
        .unwrap_or_default();
    let flips = oks.windows(2).filter(|w| w[0] != w[1]).count();
    flips >= FLAP_FLIPS
}

fn assemble(conn: &rusqlite::Connection, row: CheckRow) -> model::Check {
    let config: model::CheckConfig = serde_json::from_str(&row.config).unwrap_or_default();
    let status = match row.last_ok {
        Some(true) => "up",
        Some(false) => "down",
        None => "unknown",
    }
    .to_string();
    model::Check {
        name: row.name.clone(),
        owner: row.owner,
        ctype: row.ctype,
        target: row.target,
        every_secs: row.every_secs,
        timeout_secs: row.timeout_secs,
        severity: row.severity,
        runner: row.runner,
        source: row.source,
        config,
        created_ts: row.created_ts,
        state: model::CheckState {
            status,
            ok: row.last_ok,
            fails: row.fails,
            changed_ts: row.changed_ts,
            last_ts: row.last_ts,
            last_code: row.last_code,
            last_reason: row.last_reason,
            last_beat: last_beat(conn, &row.name),
            flapping: flapping(conn, &row.name, model::now_epoch()),
        },
    }
}

/// Define a check (validated upstream). Refuses a name taken.
pub fn check_add(conn: &rusqlite::Connection, c: &ValidCheck) -> Result<model::Check, Error> {
    let created = model::now_epoch();
    let config = serde_json::to_string(&c.config).map_err(|e| Error::Invalid(e.to_string()))?;
    let n = conn
        .execute(
            "INSERT INTO checks (name, owner, ctype, target, every_secs, timeout_secs,
                                 severity, runner, source, config, created_ts)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (name) DO NOTHING",
            rusqlite::params![
                c.name,
                c.owner,
                c.ctype.as_str(),
                c.target,
                c.every_secs as i64,
                c.timeout_secs as i64,
                c.severity,
                c.runner,
                c.source,
                config,
                created as i64,
            ],
        )
        .map_err(Error::Sql)?;
    if n == 0 {
        return Err(Error::Exists(format!("check {}", c.name)));
    }
    check_get(conn, &c.name)
}

/// One check with live state, or missing.
pub fn check_get(conn: &rusqlite::Connection, name: &str) -> Result<model::Check, Error> {
    Ok(assemble(conn, get_row(conn, name)?))
}

/// Every check with live state, by name.
pub fn check_list(conn: &rusqlite::Connection) -> Result<Vec<model::Check>, Error> {
    Ok(list_rows(conn)?
        .into_iter()
        .map(|r| assemble(conn, r))
        .collect())
}

/// Replace a check's definition (state columns survive).
pub fn check_replace(
    conn: &rusqlite::Connection,
    name: &str,
    c: &ValidCheck,
) -> Result<model::Check, Error> {
    let config = serde_json::to_string(&c.config).map_err(|e| Error::Invalid(e.to_string()))?;
    let n = conn
        .execute(
            "UPDATE checks SET owner = ?, ctype = ?, target = ?, every_secs = ?, timeout_secs = ?,
                              severity = ?, runner = ?, source = ?, config = ? WHERE name = ?",
            rusqlite::params![
                c.owner,
                c.ctype.as_str(),
                c.target,
                c.every_secs as i64,
                c.timeout_secs as i64,
                c.severity,
                c.runner,
                c.source,
                config,
                name,
            ],
        )
        .map_err(Error::Sql)?;
    if n == 0 {
        return Err(Error::Missing(format!("check {name}")));
    }
    check_get(conn, name)
}

/// Delete a check, its results, and its beats. No corpses.
pub fn check_delete(conn: &rusqlite::Connection, name: &str) -> Result<(), Error> {
    let n = conn
        .execute("DELETE FROM checks WHERE name = ?", [name])
        .map_err(Error::Sql)?;
    if n == 0 {
        return Err(Error::Missing(format!("check {name}")));
    }
    let _ = conn.execute("DELETE FROM results WHERE checks = ?", [name]);
    let _ = conn.execute("DELETE FROM heartbeats WHERE checks = ?", [name]);
    Ok(())
}

// ---------------------------------------------------------------- results

/// Record one probe: persist, prune past retention, update state, and on
/// a flip queue a `health.flip` notification. Unknown counts as up, so
/// a check that is down from birth still alerts. Returns flipped.
pub fn record_result(
    conn: &rusqlite::Connection,
    name: &str,
    ok: bool,
    code: Option<u16>,
    reason: &str,
    ts: u64,
) -> Result<bool, Error> {
    let row = get_row(conn, name)?;
    conn.execute(
        "INSERT INTO results (checks, ts, ok, code, reason) VALUES (?, ?, ?, ?, ?)",
        rusqlite::params![name, ts as i64, ok as i64, code.map(|c| c as i64), reason],
    )
    .map_err(Error::Sql)?;
    let cutoff = ts.saturating_sub(RESULT_RETENTION_SECS) as i64;
    let _ = conn.execute(
        "DELETE FROM results WHERE checks = ? AND ts < ?",
        rusqlite::params![name, cutoff],
    );
    let flipped = row.last_ok.is_none_or(|prev| prev != ok);
    let fails = if ok { 0 } else { row.fails + 1 };
    let changed = if flipped { ts } else { row.changed_ts };
    conn.execute(
        "UPDATE checks SET last_ok = ?, fails = ?, changed_ts = ?, last_ts = ?,
                            last_code = ?, last_reason = ? WHERE name = ?",
        rusqlite::params![
            ok as i64,
            fails as i64,
            changed as i64,
            ts as i64,
            code.map(|c| c as i64),
            reason,
            name,
        ],
    )
    .map_err(Error::Sql)?;
    if flipped {
        let title = if ok {
            format!("🟢 {name} is back up")
        } else {
            format!("🔴 {name} is DOWN — {reason}")
        };
        let _ = notification_push(conn, "", "health.flip", &title, &row.target);
    }
    Ok(flipped)
}

/// Newest-first probe history, capped (1000 hard ceiling).
pub fn result_list(
    conn: &rusqlite::Connection,
    name: &str,
    limit: u64,
) -> Result<Vec<model::StoredResult>, Error> {
    get_row(conn, name)?;
    let mut stmt = conn
        .prepare(
            "SELECT id, checks, ts, ok, code, reason FROM results
             WHERE checks = ? ORDER BY ts DESC, id DESC LIMIT ?",
        )
        .map_err(Error::Sql)?;
    stmt.query_map(rusqlite::params![name, limit.min(1000) as i64], |r| {
        Ok(model::StoredResult {
            id: r.get(0)?,
            check: r.get(1)?,
            ts: r.get::<_, i64>(2)? as u64,
            ok: r.get::<_, i64>(3)? != 0,
            code: r.get::<_, Option<i64>>(4)?.map(|v| v as u16),
            reason: r.get(5)?,
        })
    })
    .map_err(Error::Sql)?
    .collect::<Result<Vec<_>, _>>()
    .map_err(Error::Sql)
}

// ---------------------------------------------------------------- heartbeats

/// Stamp a heartbeat. The prober turns silence into down.
pub fn heartbeat_beat(conn: &rusqlite::Connection, name: &str, ts: u64) -> Result<(), Error> {
    get_row(conn, name)?;
    conn.execute(
        "INSERT INTO heartbeats (checks, ts) VALUES (?, ?)
         ON CONFLICT (checks) DO UPDATE SET ts = excluded.ts",
        rusqlite::params![name, ts as i64],
    )
    .map_err(Error::Sql)?;
    Ok(())
}

// ---------------------------------------------------------------- approvals

/// Ask something. Pending until decided or past its deadline.
pub fn approval_create(
    conn: &rusqlite::Connection,
    title: &str,
    body: &str,
    reply_to: &str,
    ttl_secs: u64,
) -> Result<model::Approval, Error> {
    if title.trim().is_empty() || title.len() > 256 {
        return Err(Error::Invalid("title is 1-256 chars".to_string()));
    }
    if body.len() > 4096 || reply_to.len() > 256 {
        return Err(Error::Invalid(
            "body is 4096 max, reply_to 256 max".to_string(),
        ));
    }
    if !(1..=7 * 86_400).contains(&ttl_secs) {
        return Err(Error::Invalid("ttl_secs is 1-604800".to_string()));
    }
    let created = model::now_epoch();
    conn.execute(
        "INSERT INTO approvals (title, body, reply_to, state, created_ts, deadline_ts)
         VALUES (?, ?, ?, 'pending', ?, ?)",
        rusqlite::params![
            title,
            body,
            reply_to,
            created as i64,
            (created + ttl_secs) as i64
        ],
    )
    .map_err(Error::Sql)?;
    approval_get(conn, conn.last_insert_rowid())
}

fn live_state(state: &str, deadline: u64, now: u64) -> String {
    if state == "pending" && now > deadline {
        "expired".to_string()
    } else {
        state.to_string()
    }
}

/// One ask with its live state (pending past deadline reads expired).
pub fn approval_get(conn: &rusqlite::Connection, id: i64) -> Result<model::Approval, Error> {
    let a: model::Approval = conn
        .query_row(
            "SELECT id, title, body, reply_to, state, created_ts, deadline_ts,
                    decided_ts, decision, decided_by FROM approvals WHERE id = ?",
            [id],
            |r| {
                Ok(model::Approval {
                    id: r.get(0)?,
                    title: r.get(1)?,
                    body: r.get(2)?,
                    reply_to: r.get(3)?,
                    state: r.get(4)?,
                    created_ts: r.get::<_, i64>(5)? as u64,
                    deadline_ts: r.get::<_, i64>(6)? as u64,
                    decided_ts: r.get::<_, i64>(7)? as u64,
                    decision: r.get(8)?,
                    decided_by: r.get(9)?,
                })
            },
        )
        .map_err(|_| Error::Missing(format!("approval {id}")))?;
    let state = live_state(&a.state, a.deadline_ts, model::now_epoch());
    Ok(model::Approval { state, ..a })
}

/// Asks newest-first, live states, optional state filter.
pub fn approval_list(
    conn: &rusqlite::Connection,
    want: Option<&str>,
) -> Result<Vec<model::Approval>, Error> {
    let mut stmt = conn
        .prepare(
            "SELECT id, title, body, reply_to, state, created_ts, deadline_ts,
                    decided_ts, decision, decided_by FROM approvals ORDER BY id DESC LIMIT 500",
        )
        .map_err(Error::Sql)?;
    let all: Vec<model::Approval> = stmt
        .query_map([], |r| {
            Ok(model::Approval {
                id: r.get(0)?,
                title: r.get(1)?,
                body: r.get(2)?,
                reply_to: r.get(3)?,
                state: r.get(4)?,
                created_ts: r.get::<_, i64>(5)? as u64,
                deadline_ts: r.get::<_, i64>(6)? as u64,
                decided_ts: r.get::<_, i64>(7)? as u64,
                decision: r.get(8)?,
                decided_by: r.get(9)?,
            })
        })
        .map_err(Error::Sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Error::Sql)?;
    let now = model::now_epoch();
    Ok(all
        .into_iter()
        .map(|a| {
            let state = live_state(&a.state, a.deadline_ts, now);
            model::Approval { state, ..a }
        })
        .filter(|a| want.is_none_or(|w| a.state == w))
        .collect())
}

/// Answer an ask. Anything but live-pending refuses.
pub fn approval_decide(
    conn: &rusqlite::Connection,
    id: i64,
    approve: bool,
    by: &str,
) -> Result<model::Approval, Error> {
    let a = approval_get(conn, id)?;
    if a.state != "pending" {
        return Err(Error::Invalid(format!("already {}", a.state)));
    }
    if by.len() > 64 {
        return Err(Error::Invalid("by is 64 max".to_string()));
    }
    let now = model::now_epoch();
    let (state, decision) = if approve {
        ("approved", "approved")
    } else {
        ("rejected", "rejected")
    };
    conn.execute(
        "UPDATE approvals SET state = ?, decided_ts = ?, decision = ?, decided_by = ? WHERE id = ?",
        rusqlite::params![state, now as i64, decision, by, id],
    )
    .map_err(Error::Sql)?;
    approval_get(conn, id)
}

// ---------------------------------------------------------------- notify

/// Queue a notification for the delivery drivers.
pub fn notification_push(
    conn: &rusqlite::Connection,
    to: &str,
    topic: &str,
    title: &str,
    body: &str,
) -> Result<model::Notification, Error> {
    if title.trim().is_empty() || title.len() > 512 {
        return Err(Error::Invalid("title is 1-512 chars".to_string()));
    }
    if topic.len() > 128 || body.len() > 4096 || to.len() > 64 {
        return Err(Error::Invalid(
            "topic 128, body 4096, to 64 max".to_string(),
        ));
    }
    let ts = model::now_epoch();
    conn.execute(
        "INSERT INTO notifications (ts, topic, title, body, to_device) VALUES (?, ?, ?, ?, ?)",
        rusqlite::params![ts as i64, topic, title, body, to],
    )
    .map_err(Error::Sql)?;
    let id = conn.last_insert_rowid();
    Ok(model::Notification {
        id,
        ts,
        topic: topic.to_string(),
        title: title.to_string(),
        body: body.to_string(),
        to_device: to.to_string(),
        delivered: false,
    })
}

/// Queued notifications newest-first, capped (500 hard ceiling).
pub fn notification_list(
    conn: &rusqlite::Connection,
    limit: u64,
) -> Result<Vec<model::Notification>, Error> {
    let mut stmt = conn
        .prepare(
            "SELECT id, ts, topic, title, body, to_device, delivered FROM notifications
             ORDER BY id DESC LIMIT ?",
        )
        .map_err(Error::Sql)?;
    stmt.query_map([limit.min(500) as i64], |r| {
        Ok(model::Notification {
            id: r.get(0)?,
            ts: r.get::<_, i64>(1)? as u64,
            topic: r.get(2)?,
            title: r.get(3)?,
            body: r.get(4)?,
            to_device: r.get(5)?,
            delivered: r.get::<_, i64>(6)? != 0,
        })
    })
    .map_err(Error::Sql)?
    .collect::<Result<Vec<_>, _>>()
    .map_err(Error::Sql)
}

/// A driver claimed a notification: mark it delivered.
pub fn notification_delivered(conn: &rusqlite::Connection, id: i64) -> Result<(), Error> {
    let n = conn
        .execute("UPDATE notifications SET delivered = 1 WHERE id = ?", [id])
        .map_err(Error::Sql)?;
    if n == 0 {
        return Err(Error::Missing(format!("notification {id}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::NewCheck;

    fn mem(name: &str) -> rusqlite::Connection {
        let dir = std::env::temp_dir().join(format!("est-hub-db-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        open(&dir.join("hub.sqlite")).unwrap()
    }

    fn url_check() -> ValidCheck {
        let c = NewCheck {
            name: Some("site".to_string()),
            owner: Some("estifie".to_string()),
            ctype: Some("url".to_string()),
            target: Some("https://example.com".to_string()),
            ..Default::default()
        };
        model::validate_check(&c).unwrap()
    }

    #[test]
    fn opens_wal_and_roundtrips_meta() {
        let dir = std::env::temp_dir().join(format!("est-hub-db-{}-wal", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let conn = open(&dir.join("hub.sqlite")).unwrap();
        let mode: String = conn
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
        conn.execute("INSERT INTO meta (key, value) VALUES ('k', 'v')", [])
            .unwrap();
        let back: String = conn
            .query_row("SELECT value FROM meta WHERE key = 'k'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(back, "v");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn checks_roundtrip_and_reject_dupes() {
        let conn = mem("roundtrip");
        let c = check_add(&conn, &url_check()).unwrap();
        assert_eq!(c.state.status, "unknown");
        assert!(check_add(&conn, &url_check()).is_err());
        assert_eq!(check_list(&conn).unwrap().len(), 1);
        check_delete(&conn, "site").unwrap();
        assert!(check_get(&conn, "site").is_err());
    }

    #[test]
    fn first_down_flips_and_queues_a_notification() {
        let conn = mem("flip");
        check_add(&conn, &url_check()).unwrap();
        assert!(record_result(&conn, "site", false, None, "refused", 1000).unwrap());
        assert!(!record_result(&conn, "site", false, None, "refused", 1001).unwrap());
        assert!(record_result(&conn, "site", true, Some(200), "HTTP 200", 1002).unwrap());
        let c = check_get(&conn, "site").unwrap();
        assert_eq!(c.state.status, "up");
        assert_eq!(c.state.fails, 0);
        let notes = notification_list(&conn, 10).unwrap();
        assert_eq!(notes.len(), 2);
        assert!(notes.iter().any(|n| n.topic == "health.flip"));
    }

    #[test]
    fn approvals_expire_and_refuse_late_decisions() {
        let conn = mem("approvals");
        let a = approval_create(&conn, "deploy?", "", "", 3600).unwrap();
        assert_eq!(a.state, "pending");
        let a = approval_decide(&conn, a.id, true, "estifie").unwrap();
        assert_eq!(a.state, "approved");
        assert!(approval_decide(&conn, a.id, false, "x").is_err());
        let b = approval_create(&conn, "old?", "", "", 1).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(2));
        let b = approval_get(&conn, b.id).unwrap();
        assert_eq!(b.state, "expired");
        assert!(approval_decide(&conn, b.id, true, "x").is_err());
    }
}
