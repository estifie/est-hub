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
/// Queued notifications older than this die on the next push: the
/// Activity inbox reads days back, never years, and the table would
/// otherwise grow one row per page forever.
const NOTIFICATION_RETENTION_SECS: u64 = 90 * 86_400;
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
         DROP TABLE IF EXISTS pair_tickets;
         DROP TABLE IF EXISTS certs;
         DROP TABLE IF EXISTS revoked_serials;
         CREATE TABLE IF NOT EXISTS devices (
           name TEXT PRIMARY KEY, apns_token TEXT, created_ts INTEGER NOT NULL);
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
           to_device TEXT NOT NULL DEFAULT '', delivered INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE IF NOT EXISTS la_tokens (
           activity_id TEXT PRIMARY KEY, device TEXT NOT NULL,
           push_token TEXT NOT NULL, updated_ts INTEGER NOT NULL,
           label TEXT NOT NULL DEFAULT '');
         CREATE INDEX IF NOT EXISTS idx_la_tokens_device ON la_tokens (device);
         CREATE TABLE IF NOT EXISTS projects (
           slug TEXT PRIMARY KEY, pgroup TEXT NOT NULL DEFAULT '',
           name TEXT NOT NULL DEFAULT '', bundle_id TEXT NOT NULL DEFAULT '',
           icon BLOB, icon_sha TEXT, updated_ts INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE IF NOT EXISTS silences (
           name TEXT NOT NULL, kind TEXT NOT NULL,
           until_ts INTEGER NOT NULL, note TEXT NOT NULL DEFAULT '',
           created_ts INTEGER NOT NULL,
           PRIMARY KEY (name, kind));
         CREATE TABLE IF NOT EXISTS secrets (
           project TEXT PRIMARY KEY, env TEXT NOT NULL,
           sha TEXT NOT NULL, updated_ts INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS secret_tokens (
           token_hash TEXT PRIMARY KEY, project TEXT NOT NULL,
           created_ts INTEGER NOT NULL, last_used_ts INTEGER NOT NULL DEFAULT 0);
         CREATE INDEX IF NOT EXISTS idx_secret_tokens_project ON secret_tokens (project);
         CREATE TABLE IF NOT EXISTS balances (
           provider TEXT PRIMARY KEY, label TEXT NOT NULL DEFAULT '',
           amount TEXT NOT NULL DEFAULT '', currency TEXT NOT NULL DEFAULT '',
           note TEXT NOT NULL DEFAULT '', updated_ts INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS agents (
           pane TEXT PRIMARY KEY, title TEXT NOT NULL DEFAULT '',
           cwd TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'unknown',
           space TEXT NOT NULL DEFAULT '', tab TEXT NOT NULL DEFAULT '',
           output TEXT NOT NULL DEFAULT '', updated_ts INTEGER NOT NULL,
           status_since_ts INTEGER NOT NULL DEFAULT 0);",
    )
    .map_err(Error::Sql)?;
    // Registry state: `active` for every row (pairing is gone; the
    // column stays so legacy DBs read uniformly).
    ensure_column(&conn, "devices", "state", "TEXT NOT NULL DEFAULT 'active'")?;
    ensure_column(&conn, "devices", "apns_env", "TEXT")?;
    // Part 4: per-device Live Activity state plus the optional
    // per-device `apns-topic` override. Legacy NULL rows read
    // unconfigured (off, no tokens, hub-wide topic) — no backfill.
    ensure_column(&conn, "devices", "la_pts_token", "TEXT")?;
    ensure_column(&conn, "devices", "la_config", "TEXT")?;
    ensure_column(&conn, "devices", "la_activity_id", "TEXT")?;
    ensure_column(&conn, "devices", "la_started_ts", "INTEGER")?;
    ensure_column(&conn, "devices", "apns_topic", "TEXT")?;
    // Incident cards: labeled token rows beside the status pointer.
    // Legacy rows read `""` (status) — no backfill.
    ensure_column(&conn, "la_tokens", "label", "TEXT NOT NULL DEFAULT ''")?;
    // Agent placing + output: the watcher fills these; rows pushed
    // before read blank until the next push — no backfill.
    ensure_column(&conn, "agents", "space", "TEXT NOT NULL DEFAULT ''")?;
    ensure_column(&conn, "agents", "tab", "TEXT NOT NULL DEFAULT ''")?;
    ensure_column(&conn, "agents", "output", "TEXT NOT NULL DEFAULT ''")?;
    // Agent status clock: `agent_set` heals legacy 0 rows to their
    // `updated_ts` on the next push — no open-time backfill.
    ensure_column(
        &conn,
        "agents",
        "status_since_ts",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    // Numeric readings on results and on the check's last state.
    // Existing rows predate values and read `null` — no backfill; a
    // value never outlives the result it came with.
    ensure_column(&conn, "results", "value", "REAL")?;
    ensure_column(&conn, "checks", "last_value", "REAL")?;
    Ok(conn)
}

/// Additive migration: one column when it is missing, else nothing.
fn ensure_column(
    conn: &rusqlite::Connection,
    table: &str,
    column: &str,
    ddl: &str,
) -> Result<(), Error> {
    let has: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?",
            rusqlite::params![table, column],
            |r| r.get(0),
        )
        .map_err(Error::Sql)?;
    if has == 0 {
        conn.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {ddl}"),
            [],
        )
        .map_err(Error::Sql)?;
    }
    Ok(())
}

// ---------------------------------------------------------------- meta

/// One durable key: server-cert expiry, future flags.
pub fn meta_set(conn: &rusqlite::Connection, key: &str, value: &str) -> Result<(), Error> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        rusqlite::params![key, value],
    )
    .map_err(Error::Sql)?;
    Ok(())
}

/// One durable value, or nothing stored yet.
pub fn meta_get(conn: &rusqlite::Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT value FROM meta WHERE key = ?", [key], |r| r.get(0))
        .ok()
}

/// Forget one durable key (`apns set` clearing an id). Missing keys
/// clear quietly — the end state is what matters.
pub fn meta_del(conn: &rusqlite::Connection, key: &str) -> Result<(), Error> {
    conn.execute("DELETE FROM meta WHERE key = ?", [key])
        .map_err(Error::Sql)?;
    Ok(())
}

// ---------------------------------------------------------------- devices

/// Register a device. Refuses a name already taken.
pub fn device_add(
    conn: &rusqlite::Connection,
    name: &str,
    apns_token: Option<&str>,
) -> Result<model::Device, Error> {
    let created = model::now_epoch();
    let n = conn
        .execute(
            "INSERT INTO devices (name, apns_token, created_ts) VALUES (?, ?, ?)
             ON CONFLICT (name) DO NOTHING",
            rusqlite::params![name, apns_token, created as i64],
        )
        .map_err(Error::Sql)?;
    if n == 0 {
        return Err(Error::Exists(format!("device {name}")));
    }
    Ok(model::Device {
        name: name.to_string(),
        apns_token: apns_token.map(str::to_string),
        created_ts: created,
        state: "active".to_string(),
        apns_env: None,
        apns_topic: None,
        la_pts_token: None,
        la_config: None,
        la_activity_id: None,
        la_started_ts: None,
    })
}

fn device_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<model::Device> {
    Ok(model::Device {
        name: r.get(0)?,
        apns_token: r.get(1)?,
        created_ts: r.get::<_, i64>(2)? as u64,
        state: r.get(3)?,
        apns_env: r.get(4)?,
        apns_topic: r.get(5)?,
        la_pts_token: r.get(6)?,
        la_config: r.get(7)?,
        la_activity_id: r.get(8)?,
        la_started_ts: r.get::<_, Option<i64>>(9)?.map(|v| v as u64),
    })
}

const DEVICE_COLS: &str = "name, apns_token, created_ts, state, apns_env, apns_topic, la_pts_token,
     la_config, la_activity_id, la_started_ts";

/// One device, or missing.
pub fn device_get(conn: &rusqlite::Connection, name: &str) -> Result<model::Device, Error> {
    conn.query_row(
        &format!("SELECT {DEVICE_COLS} FROM devices WHERE name = ?"),
        [name],
        device_from_row,
    )
    .map_err(|_| Error::Missing(format!("device {name}")))
}

/// Every device, by name.
pub fn device_list(conn: &rusqlite::Connection) -> Result<Vec<model::Device>, Error> {
    let mut stmt = conn
        .prepare(&format!("SELECT {DEVICE_COLS} FROM devices ORDER BY name"))
        .map_err(Error::Sql)?;
    stmt.query_map([], device_from_row)
        .map_err(Error::Sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Error::Sql)
}

/// Revoke a device: delete its row and drop its Live Activity tokens
/// and last-push stamp. Gone means gone.
pub fn device_delete(conn: &rusqlite::Connection, name: &str) -> Result<(), Error> {
    let n = conn
        .execute("DELETE FROM devices WHERE name = ?", [name])
        .map_err(Error::Sql)?;
    if n == 0 {
        return Err(Error::Missing(format!("device {name}")));
    }
    let _ = conn.execute("DELETE FROM la_tokens WHERE device = ?", [name]);
    let _ = conn.execute(
        "DELETE FROM meta WHERE key = ?",
        [format!("live.last_push.{name}")],
    );
    Ok(())
}

/// The app reported push state; the caller resolves absent-keeps
/// before calling (this writes exactly what it is given).
pub fn device_update_apns(
    conn: &rusqlite::Connection,
    name: &str,
    apns_token: Option<&str>,
    apns_env: Option<&str>,
    apns_topic: Option<&str>,
) -> Result<model::Device, Error> {
    device_get(conn, name)?;
    conn.execute(
        "UPDATE devices SET apns_token = ?, apns_env = ?, apns_topic = ? WHERE name = ?",
        rusqlite::params![apns_token, apns_env, apns_topic, name],
    )
    .map_err(Error::Sql)?;
    device_get(conn, name)
}

// ---------------------------------------------------------------- live activity

/// One device's Live Activity feed config: stored JSON, or the default
/// (off) when never set. Unknown devices stay missing.
pub fn la_config_get(conn: &rusqlite::Connection, name: &str) -> Result<model::LaConfig, Error> {
    Ok(device_get(conn, name)?.la_config_parsed())
}

/// Write one device's feed config (validated upstream). Unknown devices
/// stay missing.
pub fn la_config_set(
    conn: &rusqlite::Connection,
    name: &str,
    cfg: &model::LaConfig,
) -> Result<model::LaConfig, Error> {
    device_get(conn, name)?;
    let raw = serde_json::to_string(cfg).map_err(|e| Error::Invalid(e.to_string()))?;
    conn.execute(
        "UPDATE devices SET la_config = ? WHERE name = ?",
        rusqlite::params![raw, name],
    )
    .map_err(Error::Sql)?;
    Ok(cfg.clone())
}

/// Write (or clear, with `None`) one device's push-to-start token.
/// Unknown devices stay missing.
pub fn la_pts_set(conn: &rusqlite::Connection, name: &str, pts: Option<&str>) -> Result<(), Error> {
    device_get(conn, name)?;
    conn.execute(
        "UPDATE devices SET la_pts_token = ? WHERE name = ?",
        rusqlite::params![pts, name],
    )
    .map_err(Error::Sql)?;
    Ok(())
}

/// Point a device at its current activity (`None`/`None` clears after
/// an end or a token delete). Unknown devices stay missing.
pub fn la_activity_set(
    conn: &rusqlite::Connection,
    name: &str,
    activity_id: Option<&str>,
    started_ts: Option<u64>,
) -> Result<(), Error> {
    device_get(conn, name)?;
    conn.execute(
        "UPDATE devices SET la_activity_id = ?, la_started_ts = ? WHERE name = ?",
        rusqlite::params![activity_id, started_ts.map(|t| t as i64), name],
    )
    .map_err(Error::Sql)?;
    Ok(())
}

/// Upsert one activity push token (same id re-reported refreshes the
/// token and stamp). Unknown devices stay missing.
pub fn la_token_upsert(
    conn: &rusqlite::Connection,
    device: &str,
    activity_id: &str,
    push_token: &str,
    label: &str,
    now: u64,
) -> Result<model::LaToken, Error> {
    device_get(conn, device)?;
    if label.len() > 128 {
        return Err(Error::Invalid("label is 128 max".to_string()));
    }
    conn.execute(
        "INSERT INTO la_tokens (activity_id, device, push_token, label, updated_ts)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (activity_id) DO UPDATE
         SET device = excluded.device, push_token = excluded.push_token,
             label = excluded.label, updated_ts = excluded.updated_ts",
        rusqlite::params![activity_id, device, push_token, label, now as i64],
    )
    .map_err(Error::Sql)?;
    Ok(model::LaToken {
        activity_id: activity_id.to_string(),
        device: device.to_string(),
        push_token: push_token.to_string(),
        updated_ts: now,
        label: label.to_string(),
    })
}

/// Every token row carrying one label (the incident end round reads
/// `incident:{check}` here). Empty label reads the status rows.
pub fn la_tokens_for_label(
    conn: &rusqlite::Connection,
    label: &str,
) -> Result<Vec<model::LaToken>, Error> {
    let mut stmt = conn
        .prepare(
            "SELECT activity_id, device, push_token, updated_ts, label FROM la_tokens
             WHERE label = ? ORDER BY updated_ts, activity_id",
        )
        .map_err(Error::Sql)?;
    stmt.query_map([label], |r| {
        Ok(model::LaToken {
            activity_id: r.get(0)?,
            device: r.get(1)?,
            push_token: r.get(2)?,
            updated_ts: r.get::<_, i64>(3)? as u64,
            label: r.get(4)?,
        })
    })
    .map_err(Error::Sql)?
    .collect::<Result<Vec<_>, _>>()
    .map_err(Error::Sql)
}

/// True when a device already reported a live card for one label (the
/// incident start round skips those — the card is already up).
pub fn la_label_live(conn: &rusqlite::Connection, device: &str, label: &str) -> bool {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM la_tokens WHERE device = ? AND label = ?)",
        rusqlite::params![device, label],
        |r| r.get::<_, i64>(0).map(|v| v != 0),
    )
    .unwrap_or(false)
}

/// Every activity token a device reported, oldest first. Unknown
/// devices stay missing.
pub fn la_tokens_for_device(
    conn: &rusqlite::Connection,
    device: &str,
) -> Result<Vec<model::LaToken>, Error> {
    device_get(conn, device)?;
    let mut stmt = conn
        .prepare(
            "SELECT activity_id, device, push_token, updated_ts, label FROM la_tokens
             WHERE device = ? ORDER BY updated_ts, activity_id",
        )
        .map_err(Error::Sql)?;
    stmt.query_map([device], |r| {
        Ok(model::LaToken {
            activity_id: r.get(0)?,
            device: r.get(1)?,
            push_token: r.get(2)?,
            updated_ts: r.get::<_, i64>(3)? as u64,
            label: r.get(4)?,
        })
    })
    .map_err(Error::Sql)?
    .collect::<Result<Vec<_>, _>>()
    .map_err(Error::Sql)
}

/// Delete one activity token. The id must belong to this device —
/// anything else (unknown id, another device's id) reads missing, so
/// one device's delete never oracles another's ids.
pub fn la_token_delete(
    conn: &rusqlite::Connection,
    device: &str,
    activity_id: &str,
) -> Result<(), Error> {
    device_get(conn, device)?;
    let n = conn
        .execute(
            "DELETE FROM la_tokens WHERE activity_id = ? AND device = ?",
            rusqlite::params![activity_id, device],
        )
        .map_err(Error::Sql)?;
    if n == 0 {
        return Err(Error::Missing(format!("live activity token {activity_id}")));
    }
    Ok(())
}

/// Delete every activity token a device reported (disable ends them
/// all). Returns rows dropped; unknown devices stay missing.
pub fn la_tokens_delete_device(conn: &rusqlite::Connection, device: &str) -> Result<u64, Error> {
    device_get(conn, device)?;
    let n = conn
        .execute("DELETE FROM la_tokens WHERE device = ?", [device])
        .map_err(Error::Sql)?;
    Ok(n as u64)
}

/// When the hub last pushed a Live Activity update/start/end to this
/// device (`None` when never). Lives in `meta` — a stamp, not schema.
pub fn live_last_push_get(conn: &rusqlite::Connection, device: &str) -> Option<u64> {
    meta_get(conn, &format!("live.last_push.{device}"))?
        .parse::<u64>()
        .ok()
}

/// Stamp a Live Activity push to this device.
pub fn live_last_push_set(
    conn: &rusqlite::Connection,
    device: &str,
    now: u64,
) -> Result<(), Error> {
    meta_set(conn, &format!("live.last_push.{device}"), &now.to_string())
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
    last_value: Option<f64>,
}

fn get_row(conn: &rusqlite::Connection, name: &str) -> Result<CheckRow, Error> {
    conn.query_row(
        "SELECT name, owner, ctype, target, every_secs, timeout_secs, severity, runner,
                source, config, created_ts, last_ok, fails, changed_ts, last_ts, last_code, last_reason,
                last_value
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
                last_value: r.get::<_, Option<f64>>(17)?,
            })
        },
    )
    .map_err(|_| Error::Missing(format!("check {name}")))
}

fn list_rows(conn: &rusqlite::Connection) -> Result<Vec<CheckRow>, Error> {
    let mut stmt = conn
        .prepare(
            "SELECT name, owner, ctype, target, every_secs, timeout_secs, severity, runner,
                    source, config, created_ts, last_ok, fails, changed_ts, last_ts, last_code, last_reason,
                    last_value
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
            last_value: r.get::<_, Option<f64>>(17)?,
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
            last_value: row.last_value,
        },
        ack_until: silence_until(conn, &row.name, "ack", model::now_epoch()),
        mute_until: silence_until(conn, &row.name, "mute", model::now_epoch()),
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

// ---------------------------------------------------------------- projects

/// Create or replace a project's metadata (the icon survives).
pub fn project_upsert(
    conn: &rusqlite::Connection,
    p: &model::ValidProject,
) -> Result<model::Project, Error> {
    let ts = model::now_epoch() as i64;
    conn.execute(
        "INSERT INTO projects (slug, pgroup, name, bundle_id, updated_ts)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (slug) DO UPDATE SET pgroup = excluded.pgroup, name = excluded.name,
           bundle_id = excluded.bundle_id, updated_ts = excluded.updated_ts",
        rusqlite::params![p.slug, p.group, p.name, p.bundle_id, ts],
    )
    .map_err(Error::Sql)?;
    project_get(conn, &p.slug)
}

fn project_row(r: &rusqlite::Row) -> Result<model::Project, rusqlite::Error> {
    let icon: Option<Vec<u8>> = r.get(4)?;
    Ok(model::Project {
        slug: r.get(0)?,
        group: r.get(1)?,
        name: r.get(2)?,
        bundle_id: r.get(3)?,
        has_icon: icon.is_some(),
        icon_sha256: r.get(5)?,
        updated_ts: r.get::<_, i64>(6)? as u64,
    })
}

/// One project, or missing.
pub fn project_get(conn: &rusqlite::Connection, slug: &str) -> Result<model::Project, Error> {
    conn.query_row(
        "SELECT slug, pgroup, name, bundle_id, icon, icon_sha, updated_ts
         FROM projects WHERE slug = ?",
        [slug],
        project_row,
    )
    .map_err(|_| Error::Missing(format!("project {slug}")))
}

/// Every project, by group then slug.
pub fn project_list(conn: &rusqlite::Connection) -> Result<Vec<model::Project>, Error> {
    let mut stmt = conn
        .prepare(
            "SELECT slug, pgroup, name, bundle_id, icon, icon_sha, updated_ts
             FROM projects ORDER BY pgroup, slug",
        )
        .map_err(Error::Sql)?;
    stmt.query_map([], project_row)
        .map_err(Error::Sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Error::Sql)
}

/// Store a project's icon (validated upstream). Missing projects
/// refuse: metadata lands first, then the bytes.
pub fn project_set_icon(
    conn: &rusqlite::Connection,
    slug: &str,
    bytes: &[u8],
    sha: &str,
) -> Result<model::Project, Error> {
    let ts = model::now_epoch() as i64;
    let n = conn
        .execute(
            "UPDATE projects SET icon = ?, icon_sha = ?, updated_ts = ? WHERE slug = ?",
            rusqlite::params![bytes, sha, ts, slug],
        )
        .map_err(Error::Sql)?;
    if n == 0 {
        return Err(Error::Missing(format!("project {slug}")));
    }
    project_get(conn, slug)
}

/// A project's icon bytes, or missing (no row, or no icon yet).
pub fn project_icon(conn: &rusqlite::Connection, slug: &str) -> Result<Vec<u8>, Error> {
    conn.query_row("SELECT icon FROM projects WHERE slug = ?", [slug], |r| {
        r.get::<_, Option<Vec<u8>>>(0)
    })
    .map_err(|_| Error::Missing(format!("project {slug}")))?
    .ok_or_else(|| Error::Missing(format!("project {slug} has no icon")))
}

/// A balance reading against its thresholds: `Some((ok, suffix))`, or
/// `None` when there is nothing to evaluate (no value, or neither line
/// set — the reporter's `ok` stands). `crit_below` is the paging line
/// when set, else `warn_below`; an up result still below `warn_below`
/// carries a `(below warn …)` suffix for the human copy.
fn balance_verdict(config_json: &str, value: Option<f64>) -> Option<(bool, String)> {
    let value = value?;
    let config: serde_json::Value = serde_json::from_str(config_json).ok()?;
    let line = |key: &str| config.pointer(&format!("/{key}")).and_then(|v| v.as_f64());
    let (warn, crit) = (line("warn_below"), line("crit_below"));
    let down = match (warn, crit) {
        (_, Some(c)) => value < c,
        (Some(w), None) => value < w,
        (None, None) => return None,
    };
    let suffix = if !down && warn.is_some_and(|w| value < w) {
        format!("(below warn {})", warn.unwrap_or(0.0))
    } else {
        String::new()
    };
    Some((!down, suffix))
}

// ---------------------------------------------------------------- results

/// Record one probe: persist, prune past retention, update state, and on
/// a flip queue a `health.flip` notification. Unknown counts as up, so
/// a check that is down from birth still alerts. Returns flipped.
///
/// Balance checks derive `ok` from the value against their thresholds:
/// below `crit_below` (when set, else `warn_below`) reads down; without
/// a value or thresholds the reporter's `ok` stands. An up result that
/// still sits below `warn_below` keeps a `(below warn …)` suffix, so the
/// soft line stays visible in the human copy.
pub fn record_result(
    conn: &rusqlite::Connection,
    name: &str,
    ok: bool,
    code: Option<u16>,
    reason: &str,
    ts: u64,
    value: Option<f64>,
) -> Result<(bool, Option<model::Notification>), Error> {
    if let Some(v) = value
        && !v.is_finite()
    {
        return Err(Error::Invalid(
            "value is a finite JSON number or null".to_string(),
        ));
    }
    let row = get_row(conn, name)?;
    let (ok, reason) = if row.ctype == "balance" {
        match balance_verdict(&row.config, value) {
            Some((derived, suffix)) if !suffix.is_empty() => {
                (derived, format!("{reason} {suffix}"))
            }
            Some((derived, _)) => (derived, reason.to_string()),
            None => (ok, reason.to_string()),
        }
    } else {
        (ok, reason.to_string())
    };
    conn.execute(
        "INSERT INTO results (checks, ts, ok, code, reason, value) VALUES (?, ?, ?, ?, ?, ?)",
        rusqlite::params![
            name,
            ts as i64,
            ok as i64,
            code.map(|c| c as i64),
            reason,
            value
        ],
    )
    .map_err(Error::Sql)?;
    let cutoff = ts.saturating_sub(RESULT_RETENTION_SECS) as i64;
    let _ = conn.execute(
        "DELETE FROM results WHERE checks = ? AND ts < ?",
        rusqlite::params![name, cutoff],
    );
    // Birth never flips: only healthy↔dead transitions page. A
    // check born down just shows down (unlaunched apps, new watches);
    // buzzing for a state never observed healthy is noise.
    let flipped = row.last_ok.is_some_and(|prev| prev != ok);
    let fails = if ok { 0 } else { row.fails + 1 };
    let changed = if flipped { ts } else { row.changed_ts };
    conn.execute(
        "UPDATE checks SET last_ok = ?, fails = ?, changed_ts = ?, last_ts = ?,
                            last_code = ?, last_reason = ?, last_value = ? WHERE name = ?",
        rusqlite::params![
            ok as i64,
            fails as i64,
            changed as i64,
            ts as i64,
            code.map(|c| c as i64),
            reason,
            value,
            name,
        ],
    )
    .map_err(Error::Sql)?;
    if flipped && ok {
        // Recovery retires the ack (the page it quieted is over); the
        // mute survives — only time or unmute clears that.
        let _ = silence_clear(conn, name, "ack");
    }
    let row = if flipped {
        let title = if ok {
            format!("🟢 {name} is back up")
        } else {
            format!("🔴 {name} is DOWN — {reason}")
        };
        notification_push(conn, "", "health.flip", &title, &row.target).ok()
    } else {
        None
    };
    Ok((flipped, row))
}

/// Newest-first probe history, capped (1000 hard ceiling). `since`
/// floors by probe time (unix seconds, 0 = no floor) — the detail
/// screen's 7d/30d ranges read straight off this.
pub fn result_list(
    conn: &rusqlite::Connection,
    name: &str,
    limit: u64,
    since: u64,
) -> Result<Vec<model::StoredResult>, Error> {
    get_row(conn, name)?;
    let mut stmt = conn
        .prepare(
            "SELECT id, checks, ts, ok, code, reason, value FROM results
             WHERE checks = ? AND ts >= ? ORDER BY ts DESC, id DESC LIMIT ?",
        )
        .map_err(Error::Sql)?;
    stmt.query_map(
        rusqlite::params![name, since as i64, limit.min(1000) as i64],
        |r| {
            Ok(model::StoredResult {
                id: r.get(0)?,
                check: r.get(1)?,
                ts: r.get::<_, i64>(2)? as u64,
                ok: r.get::<_, i64>(3)? != 0,
                code: r.get::<_, Option<i64>>(4)?.map(|v| v as u16),
                reason: r.get(5)?,
                value: r.get::<_, Option<f64>>(6)?,
            })
        },
    )
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

// ---------------------------------------------------------------- silences

/// Set an ack or mute horizon. The check must exist; expired rows
/// prune on write so the table never fills with dead horizons.
pub fn silence_set(
    conn: &rusqlite::Connection,
    name: &str,
    kind: &str,
    until_ts: u64,
    note: &str,
    now: u64,
) -> Result<(), Error> {
    if kind != "ack" && kind != "mute" {
        return Err(Error::Invalid("kind is ack or mute".to_string()));
    }
    if note.len() > 256 {
        return Err(Error::Invalid("note is 256 max".to_string()));
    }
    get_row(conn, name)?;
    let _ = conn.execute(
        "DELETE FROM silences WHERE until_ts <= ?",
        rusqlite::params![now as i64],
    );
    conn.execute(
        "INSERT INTO silences (name, kind, until_ts, note, created_ts) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (name, kind) DO UPDATE
         SET until_ts = excluded.until_ts, note = excluded.note, created_ts = excluded.created_ts",
        rusqlite::params![name, kind, until_ts as i64, note, now as i64],
    )
    .map_err(Error::Sql)?;
    Ok(())
}

/// Clear one silence. Missing rows clear quietly (unmuting a quiet
/// check is a no-op, not an error).
pub fn silence_clear(conn: &rusqlite::Connection, name: &str, kind: &str) -> Result<(), Error> {
    conn.execute(
        "DELETE FROM silences WHERE name = ? AND kind = ?",
        rusqlite::params![name, kind],
    )
    .map_err(Error::Sql)?;
    Ok(())
}

/// The live horizon for one silence (0 = none): expired reads as
/// none, so readers never need to prune.
fn silence_until(conn: &rusqlite::Connection, name: &str, kind: &str, now: u64) -> u64 {
    conn.query_row(
        "SELECT until_ts FROM silences WHERE name = ? AND kind = ? AND until_ts > ?",
        rusqlite::params![name, kind, now as i64],
        |r| r.get::<_, i64>(0).map(|v| v as u64),
    )
    .unwrap_or(0)
}

/// True when a flip this direction stays quiet: mutes hush both,
/// acks hush only the down page (recovery always buzzes).
pub fn silenced(conn: &rusqlite::Connection, name: &str, went_down: bool, now: u64) -> bool {
    if silence_until(conn, name, "mute", now) > 0 {
        return true;
    }
    went_down && silence_until(conn, name, "ack", now) > 0
}

// ---------------------------------------------------------------- secrets

/// sha256 hex of a token or env blob. Tokens compare by hash (the
/// plaintext shows once, at mint); envs by sha (deploys skip writes).
fn sha_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    crate::util::hex(&Sha256::digest(bytes))
}

fn valid_project(project: &str) -> Result<(), Error> {
    if !model::valid_name(project) {
        return Err(Error::Invalid(
            "project must match [a-z][a-z0-9_-]{0,31}".to_string(),
        ));
    }
    Ok(())
}

/// Push one project's env (validated size, upsert). The hub stores
/// the blob as-is: this disk already holds the live `.env` files, so
/// the store and the deploys share one trust zone — documented, not
/// encrypted-theater.
pub fn secret_set(
    conn: &rusqlite::Connection,
    project: &str,
    env: &str,
    now: u64,
) -> Result<model::SecretMeta, Error> {
    let project = project.trim();
    valid_project(project)?;
    if env.len() > model::SECRET_ENV_MAX {
        return Err(Error::Invalid(format!(
            "env is {} bytes max",
            model::SECRET_ENV_MAX
        )));
    }
    let sha = sha_hex(env.as_bytes());
    conn.execute(
        "INSERT INTO secrets (project, env, sha, updated_ts) VALUES (?, ?, ?, ?)
         ON CONFLICT (project) DO UPDATE
         SET env = excluded.env, sha = excluded.sha, updated_ts = excluded.updated_ts",
        rusqlite::params![project, env, sha, now as i64],
    )
    .map_err(Error::Sql)?;
    secret_meta(conn, project)
}

/// One secret's public face (never the env).
pub fn secret_meta(conn: &rusqlite::Connection, project: &str) -> Result<model::SecretMeta, Error> {
    conn.query_row(
        "SELECT project, sha, updated_ts,
                EXISTS (SELECT 1 FROM secret_tokens WHERE project = secrets.project)
         FROM secrets WHERE project = ?",
        rusqlite::params![project],
        |r| {
            Ok(model::SecretMeta {
                project: r.get(0)?,
                sha: r.get(1)?,
                updated_ts: r.get::<_, i64>(2)? as u64,
                has_token: r.get::<_, i64>(3)? != 0,
            })
        },
    )
    .map_err(|_| Error::Missing(format!("no secret for {project}")))
}

/// Every secret's public face, by project.
pub fn secret_list(conn: &rusqlite::Connection) -> Result<Vec<model::SecretMeta>, Error> {
    let mut stmt = conn
        .prepare(
            "SELECT project, sha, updated_ts,
                    EXISTS (SELECT 1 FROM secret_tokens WHERE project = secrets.project)
             FROM secrets ORDER BY project",
        )
        .map_err(Error::Sql)?;
    stmt.query_map([], |r| {
        Ok(model::SecretMeta {
            project: r.get(0)?,
            sha: r.get(1)?,
            updated_ts: r.get::<_, i64>(2)? as u64,
            has_token: r.get::<_, i64>(3)? != 0,
        })
    })
    .map_err(Error::Sql)?
    .collect::<Result<Vec<_>, _>>()
    .map_err(Error::Sql)
}

/// Delete a secret and its pull token. Missing refuses (the DELETE
/// twin 404s, like checks).
pub fn secret_delete(conn: &rusqlite::Connection, project: &str) -> Result<(), Error> {
    secret_meta(conn, project)?;
    conn.execute(
        "DELETE FROM secret_tokens WHERE project = ?",
        rusqlite::params![project],
    )
    .map_err(Error::Sql)?;
    conn.execute(
        "DELETE FROM secrets WHERE project = ?",
        rusqlite::params![project],
    )
    .map_err(Error::Sql)?;
    Ok(())
}

/// Mint the project's pull token (one live token per project —
/// re-minting kills the old one). The project needs a pushed secret
/// first; the plaintext shows here once and never again.
pub fn secret_token_mint(
    conn: &rusqlite::Connection,
    project: &str,
    now: u64,
) -> Result<String, Error> {
    secret_meta(conn, project)?;
    let mut raw = [0u8; 24];
    crate::util::random_bytes(&mut raw)
        .map_err(|why| Error::Invalid(format!("no randomness: {why}")))?;
    use base64::Engine as _;
    let token = format!(
        "{}{}",
        model::SECRET_TOKEN_PREFIX,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
    );
    conn.execute(
        "DELETE FROM secret_tokens WHERE project = ?",
        rusqlite::params![project],
    )
    .map_err(Error::Sql)?;
    conn.execute(
        "INSERT INTO secret_tokens (token_hash, project, created_ts) VALUES (?, ?, ?)",
        rusqlite::params![sha_hex(token.as_bytes()), project, now as i64],
    )
    .map_err(Error::Sql)?;
    Ok(token)
}

/// Revoke a project's pull token. Quiet when none (revoking twice
/// is a no-op, not an error).
pub fn secret_token_revoke(conn: &rusqlite::Connection, project: &str) -> Result<(), Error> {
    conn.execute(
        "DELETE FROM secret_tokens WHERE project = ?",
        rusqlite::params![project],
    )
    .map_err(Error::Sql)?;
    Ok(())
}

/// True when the token pulls this project (stamping last use). Hash
/// compare, `==`: timing leaks are noise against 192-bit randoms.
pub fn secret_token_check(
    conn: &rusqlite::Connection,
    project: &str,
    token: &str,
    now: u64,
) -> bool {
    let hash = sha_hex(token.trim().as_bytes());
    let hit: bool = conn
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM secret_tokens WHERE token_hash = ? AND project = ?)",
            rusqlite::params![hash, project],
            |r| r.get::<_, i64>(0).map(|v| v != 0),
        )
        .unwrap_or(false);
    if hit {
        let _ = conn.execute(
            "UPDATE secret_tokens SET last_used_ts = ? WHERE token_hash = ?",
            rusqlite::params![now as i64, hash],
        );
    }
    hit
}

/// The stored env plus its sha, for a tokened pull.
pub fn secret_env(conn: &rusqlite::Connection, project: &str) -> Result<(String, String), Error> {
    conn.query_row(
        "SELECT env, sha FROM secrets WHERE project = ?",
        rusqlite::params![project],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .map_err(|_| Error::Missing(format!("no secret for {project}")))
}

// ---------------------------------------------------------------- balances

/// Upsert one balance row. Amounts are display strings (the hub never
/// computes money); everything caps low, provider follows the name rule.
pub fn balance_set(
    conn: &rusqlite::Connection,
    provider: &str,
    label: &str,
    amount: &str,
    currency: &str,
    note: &str,
    now: u64,
) -> Result<model::Balance, Error> {
    let provider = provider.trim();
    if !model::valid_name(provider) {
        return Err(Error::Invalid(
            "provider must match [a-z][a-z0-9_-]{0,31}".to_string(),
        ));
    }
    for (field, value, max) in [
        ("label", label, 64),
        ("amount", amount, 64),
        ("currency", currency, 16),
        ("note", note, 256),
    ] {
        if value.len() > max {
            return Err(Error::Invalid(format!("{field} is {max} max")));
        }
    }
    let label = if label.trim().is_empty() {
        provider
    } else {
        label.trim()
    };
    conn.execute(
        "INSERT INTO balances (provider, label, amount, currency, note, updated_ts)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (provider) DO UPDATE
         SET label = excluded.label, amount = excluded.amount,
             currency = excluded.currency, note = excluded.note,
             updated_ts = excluded.updated_ts",
        rusqlite::params![
            provider,
            label,
            amount.trim(),
            currency.trim(),
            note.trim(),
            now as i64
        ],
    )
    .map_err(Error::Sql)?;
    balance_get(conn, provider)
}

/// One balance row.
pub fn balance_get(conn: &rusqlite::Connection, provider: &str) -> Result<model::Balance, Error> {
    conn.query_row(
        "SELECT provider, label, amount, currency, note, updated_ts FROM balances WHERE provider = ?",
        rusqlite::params![provider],
        |r| {
            Ok(model::Balance {
                provider: r.get(0)?,
                label: r.get(1)?,
                amount: r.get(2)?,
                currency: r.get(3)?,
                note: r.get(4)?,
                updated_ts: r.get::<_, i64>(5)? as u64,
            })
        },
    )
    .map_err(|_| Error::Missing(format!("no balance for {provider}")))
}

/// Every balance row, by provider.
pub fn balance_list(conn: &rusqlite::Connection) -> Result<Vec<model::Balance>, Error> {
    let mut stmt = conn
        .prepare("SELECT provider, label, amount, currency, note, updated_ts FROM balances ORDER BY provider")
        .map_err(Error::Sql)?;
    stmt.query_map([], |r| {
        Ok(model::Balance {
            provider: r.get(0)?,
            label: r.get(1)?,
            amount: r.get(2)?,
            currency: r.get(3)?,
            note: r.get(4)?,
            updated_ts: r.get::<_, i64>(5)? as u64,
        })
    })
    .map_err(Error::Sql)?
    .collect::<Result<Vec<_>, _>>()
    .map_err(Error::Sql)
}

/// Delete one balance row. Missing refuses (the DELETE twin 404s).
pub fn balance_delete(conn: &rusqlite::Connection, provider: &str) -> Result<(), Error> {
    balance_get(conn, provider)?;
    conn.execute(
        "DELETE FROM balances WHERE provider = ?",
        rusqlite::params![provider],
    )
    .map_err(Error::Sql)?;
    Ok(())
}

// ---------------------------------------------------------------- agents

/// One snapshot push: the required fields plus the keep-on-absent
/// placing (a failed read must not wipe the last output).
pub struct AgentSnapshot<'a> {
    /// Stripped terminal title.
    pub title: &'a str,
    /// Working directory of the agent.
    pub cwd: &'a str,
    /// One of herdr's five verbs.
    pub status: &'a str,
    /// Workspace label (`None` keeps the stored value).
    pub space: Option<&'a str>,
    /// Tab label (`None` keeps the stored value).
    pub tab: Option<&'a str>,
    /// Output tail (`None` keeps the stored value).
    pub output: Option<&'a str>,
}

/// Upsert one agent snapshot. The pane follows the pane rule, the
/// status is one of herdr's five verbs, title/cwd cap low.
pub fn agent_set(
    conn: &rusqlite::Connection,
    pane: &str,
    snap: AgentSnapshot<'_>,
    now: u64,
) -> Result<model::Agent, Error> {
    let pane = pane.trim();
    if !model::valid_pane(pane) {
        return Err(Error::Invalid(
            "pane must match [A-Za-z0-9:_-]{1,64}".to_string(),
        ));
    }
    let status = snap.status.trim();
    if !model::valid_agent_status(status) {
        return Err(Error::Invalid(
            "status is one of: working, done, idle, blocked, unknown".to_string(),
        ));
    }
    let prev = agent_get(conn, pane, now).ok();
    // The status clock: new rows and flips stamp now, steady rows keep
    // it, legacy 0 rows heal to their last push (closest known truth).
    let since = match prev.as_ref() {
        None => now,
        Some(p) if p.status != status => now,
        Some(p) if p.status_since_ts == 0 => p.updated_ts,
        Some(p) => p.status_since_ts,
    };
    let keep = |next: Option<&str>, old: &str| -> String {
        next.map(str::trim).unwrap_or(old).to_string()
    };
    let prev_space = prev.as_ref().map(|a| a.space.as_str()).unwrap_or("");
    let prev_tab = prev.as_ref().map(|a| a.tab.as_str()).unwrap_or("");
    let prev_output = prev.as_ref().map(|a| a.output.as_str()).unwrap_or("");
    let (space, tab, output) = (
        keep(snap.space, prev_space),
        keep(snap.tab, prev_tab),
        keep(snap.output, prev_output),
    );
    for (field, value, max) in [
        ("title", snap.title, 256),
        ("cwd", snap.cwd, 512),
        ("space", &space, 64),
        ("tab", &tab, 64),
        ("output", &output, 4096),
    ] {
        if value.len() > max {
            return Err(Error::Invalid(format!("{field} is {max} max")));
        }
    }
    conn.execute(
        "INSERT INTO agents (pane, title, cwd, status, space, tab, output, updated_ts, status_since_ts)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (pane) DO UPDATE
         SET title = excluded.title, cwd = excluded.cwd,
             status = excluded.status, space = excluded.space,
             tab = excluded.tab, output = excluded.output,
             updated_ts = excluded.updated_ts,
             status_since_ts = excluded.status_since_ts",
        rusqlite::params![
            pane,
            snap.title.trim(),
            snap.cwd.trim(),
            status,
            space,
            tab,
            output,
            now as i64,
            since as i64
        ],
    )
    .map_err(Error::Sql)?;
    agent_get(conn, pane, now)
}

/// One agent row; `stale` is computed against `now`, never stored.
pub fn agent_get(conn: &rusqlite::Connection, pane: &str, now: u64) -> Result<model::Agent, Error> {
    conn.query_row(
        "SELECT pane, title, cwd, status, space, tab, output, updated_ts, status_since_ts FROM agents WHERE pane = ?",
        rusqlite::params![pane],
        |r| {
            let updated_ts = r.get::<_, i64>(7)? as u64;
            Ok(model::Agent {
                pane: r.get(0)?,
                title: r.get(1)?,
                cwd: r.get(2)?,
                status: r.get(3)?,
                space: r.get(4)?,
                tab: r.get(5)?,
                output: r.get(6)?,
                updated_ts,
                stale: now.saturating_sub(updated_ts) > model::AGENT_STALE_AFTER_SECS,
                status_since_ts: r.get::<_, i64>(8)? as u64,
            })
        },
    )
    .map_err(|_| Error::Missing(format!("no agent {pane}")))
}

/// Every agent row, working first, then by pane.
pub fn agent_list(conn: &rusqlite::Connection, now: u64) -> Result<Vec<model::Agent>, Error> {
    let mut stmt = conn
        .prepare(
            "SELECT pane, title, cwd, status, space, tab, output, updated_ts, status_since_ts FROM agents
             ORDER BY CASE status WHEN 'working' THEN 0 WHEN 'blocked' THEN 1 ELSE 2 END, pane",
        )
        .map_err(Error::Sql)?;
    stmt.query_map([], |r| {
        let updated_ts = r.get::<_, i64>(7)? as u64;
        Ok(model::Agent {
            pane: r.get(0)?,
            title: r.get(1)?,
            cwd: r.get(2)?,
            status: r.get(3)?,
            space: r.get(4)?,
            tab: r.get(5)?,
            output: r.get(6)?,
            updated_ts,
            stale: now.saturating_sub(updated_ts) > model::AGENT_STALE_AFTER_SECS,
            status_since_ts: r.get::<_, i64>(8)? as u64,
        })
    })
    .map_err(Error::Sql)?
    .collect::<Result<Vec<_>, _>>()
    .map_err(Error::Sql)
}

/// Delete one agent row. Missing refuses (the DELETE twin 404s).
pub fn agent_delete(conn: &rusqlite::Connection, pane: &str) -> Result<(), Error> {
    agent_get(conn, pane, u64::MAX)?;
    conn.execute("DELETE FROM agents WHERE pane = ?", rusqlite::params![pane])
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
) -> Result<(model::Approval, Option<model::Notification>), Error> {
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
    // The ask is itself news: queue it for the drivers (Part 3 folds
    // this in — approvals previously queued nothing). The id is read
    // first: the queue insert moves `last_insert_rowid`. The queued row
    // rides out for the push fan-out; a queue failure still leaves the
    // ask itself created.
    let id = conn.last_insert_rowid();
    let row = notification_push(conn, "", "approval.requested", title, body).ok();
    Ok((approval_get(conn, id)?, row))
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
    let cutoff = ts.saturating_sub(NOTIFICATION_RETENTION_SECS) as i64;
    let _ = conn.execute("DELETE FROM notifications WHERE ts < ?", [cutoff]);
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
    notification_list_filtered(conn, limit, None, None)
}

/// The queue with cheap refresh filters: `to` narrows to one device's
/// rows (exact match), `since_id` to rows past an id. Both absent
/// reads the whole queue.
pub fn notification_list_filtered(
    conn: &rusqlite::Connection,
    limit: u64,
    to: Option<&str>,
    since_id: Option<i64>,
) -> Result<Vec<model::Notification>, Error> {
    let mut sql =
        String::from("SELECT id, ts, topic, title, body, to_device, delivered FROM notifications");
    let mut conds = Vec::new();
    if to.is_some() {
        conds.push("to_device = ?");
    }
    if since_id.is_some() {
        conds.push("id > ?");
    }
    if !conds.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&conds.join(" AND "));
    }
    sql.push_str(" ORDER BY id DESC LIMIT ?");
    let limit = limit.min(500) as i64;
    let mut params: Vec<&dyn rusqlite::ToSql> = Vec::new();
    if let Some(t) = to.as_ref() {
        params.push(t);
    }
    if let Some(s) = since_id.as_ref() {
        params.push(s);
    }
    params.push(&limit);
    let mut stmt = conn.prepare(&sql).map_err(Error::Sql)?;
    stmt.query_map(params.as_slice(), |r| {
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

    fn balance_check(warn: Option<f64>, crit: Option<f64>) -> ValidCheck {
        let c = NewCheck {
            name: Some("credits".to_string()),
            owner: Some("sys".to_string()),
            ctype: Some("balance".to_string()),
            target: Some("openrouter".to_string()),
            warn_below: warn,
            crit_below: crit,
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
    fn dead_healthy_transition_flips_and_queues() {
        let conn = mem("flip");
        check_add(&conn, &url_check()).unwrap();
        // Birth is quiet even when down; only the recovery flips.
        assert!(
            !record_result(&conn, "site", false, None, "refused", 1000, None)
                .unwrap()
                .0
        );
        assert!(
            !record_result(&conn, "site", false, None, "refused", 1001, None)
                .unwrap()
                .0
        );
        assert!(
            record_result(&conn, "site", true, Some(200), "HTTP 200", 1002, None)
                .unwrap()
                .0
        );
        let c = check_get(&conn, "site").unwrap();
        assert_eq!(c.state.status, "up");
        assert_eq!(c.state.fails, 0);
        let notes = notification_list(&conn, 10).unwrap();
        assert_eq!(notes.len(), 1);
        assert!(notes.iter().any(|n| n.topic == "health.flip"));
    }

    #[test]
    fn silences_gate_by_kind_direction_and_expiry() {
        let conn = mem("silence");
        check_add(&conn, &url_check()).unwrap();
        let now = 10_000;
        // Neither set: nothing silenced.
        assert!(!silenced(&conn, "site", true, now));
        assert!(!silenced(&conn, "site", false, now));
        // Ack hushes the down page only.
        silence_set(&conn, "site", "ack", now + 100, "", now).unwrap();
        assert!(silenced(&conn, "site", true, now));
        assert!(!silenced(&conn, "site", false, now));
        // Mute hushes both.
        silence_set(&conn, "site", "mute", now + 100, "", now).unwrap();
        assert!(silenced(&conn, "site", true, now));
        assert!(silenced(&conn, "site", false, now));
        // Expiry reads as none.
        assert!(!silenced(&conn, "site", true, now + 101));
        assert!(!silenced(&conn, "site", false, now + 101));
        // Re-set then clear: quiet again, and clearing twice is fine.
        silence_set(&conn, "site", "mute", now + 500, "drill", now).unwrap();
        assert!(silenced(&conn, "site", false, now));
        silence_clear(&conn, "site", "mute").unwrap();
        silence_clear(&conn, "site", "mute").unwrap();
        assert!(!silenced(&conn, "site", false, now));
        // Unknown checks refuse; bad kinds and long notes refuse.
        assert!(silence_set(&conn, "ghost", "ack", now + 1, "", now).is_err());
        assert!(silence_set(&conn, "site", "nap", now + 1, "", now).is_err());
        assert!(silence_set(&conn, "site", "ack", now + 1, &"n".repeat(257), now).is_err());
    }

    #[test]
    fn recovery_retires_ack_and_keeps_mute() {
        let conn = mem("ack-clear");
        check_add(&conn, &url_check()).unwrap();
        record_result(&conn, "site", true, Some(200), "HTTP 200", 1000, None).unwrap();
        record_result(&conn, "site", false, None, "refused", 1001, None).unwrap();
        // Horizons live past real now: assemble reads against the clock.
        let horizon = model::now_epoch() + 3600;
        silence_set(&conn, "site", "ack", horizon, "", 1002).unwrap();
        silence_set(&conn, "site", "mute", horizon, "", 1002).unwrap();
        let c = check_get(&conn, "site").unwrap();
        assert_eq!(c.ack_until, horizon);
        assert_eq!(c.mute_until, horizon);
        // Recovery flips: the ack retires, the mute survives.
        let (flipped, _) =
            record_result(&conn, "site", true, Some(200), "HTTP 200", 1003, None).unwrap();
        assert!(flipped);
        let c = check_get(&conn, "site").unwrap();
        assert_eq!(c.ack_until, 0);
        assert_eq!(c.mute_until, horizon);
    }

    #[test]
    fn flip_titles_follow_the_parseable_contract() {
        // The app's Events feed reads the check back out of these
        // titles — the exact shapes are a wire contract.
        let conn = mem("flip-titles");
        check_add(&conn, &url_check()).unwrap();
        record_result(&conn, "site", true, Some(200), "HTTP 200", 1000, None).unwrap();
        let (_, row) = record_result(&conn, "site", false, None, "refused", 1001, None).unwrap();
        let row = row.unwrap();
        assert_eq!(row.topic, "health.flip");
        assert_eq!(row.title, "🔴 site is DOWN — refused");
        let (_, row) =
            record_result(&conn, "site", true, Some(200), "HTTP 200", 1002, None).unwrap();
        assert_eq!(row.unwrap().title, "🟢 site is back up");
    }

    #[test]
    fn result_values_roundtrip_and_clear_last_value() {
        let conn = mem("result-values");
        check_add(&conn, &url_check()).unwrap();
        // A value rides the result row and the check's last state.
        record_result(&conn, "site", true, Some(200), "HTTP 200", 1000, Some(42.5)).unwrap();
        let rows = result_list(&conn, "site", 10, 0).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].value, Some(42.5));
        assert_eq!(
            check_get(&conn, "site").unwrap().state.last_value,
            Some(42.5)
        );
        // A later result without a value clears the last state: a value
        // never outlives the result it came with.
        record_result(&conn, "site", true, Some(200), "HTTP 200", 1001, None).unwrap();
        let rows = result_list(&conn, "site", 10, 0).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].value, None);
        assert_eq!(rows[1].value, Some(42.5));
        assert_eq!(check_get(&conn, "site").unwrap().state.last_value, None);
        // Non-finite refuses.
        assert!(
            record_result(
                &conn,
                "site",
                true,
                Some(200),
                "x",
                1002,
                Some(f64::INFINITY)
            )
            .is_err()
        );
        assert!(record_result(&conn, "site", true, Some(200), "x", 1002, Some(f64::NAN)).is_err());
    }

    #[test]
    fn balance_values_derive_ok_from_thresholds() {
        let conn = mem("balance-eval");
        check_add(&conn, &balance_check(Some(5.0), Some(1.0))).unwrap();
        // Birth is quiet even below the lines.
        let (flipped, _) = record_result(
            &conn,
            "credits",
            true,
            None,
            "OpenRouter $0.50",
            1000,
            Some(0.5),
        )
        .unwrap();
        assert!(!flipped);
        assert_eq!(check_get(&conn, "credits").unwrap().state.status, "down");
        // Between crit and warn: up, but the soft line stays in the copy.
        record_result(
            &conn,
            "credits",
            true,
            None,
            "OpenRouter $3.00",
            1001,
            Some(3.0),
        )
        .unwrap();
        let c = check_get(&conn, "credits").unwrap();
        assert_eq!(c.state.status, "up");
        assert!(
            c.state.last_reason.contains("(below warn 5)"),
            "{}",
            c.state.last_reason
        );
        // Back under crit: flips down and queues the page.
        let (flipped, row) = record_result(
            &conn,
            "credits",
            true,
            None,
            "OpenRouter $0.20",
            1002,
            Some(0.2),
        )
        .unwrap();
        assert!(flipped);
        assert!(row.is_some_and(|n| n.topic == "health.flip"));
        // No thresholds on a sibling: the reporter's ok stands.
        let conn2 = mem("balance-passthrough");
        check_add(&conn2, &balance_check(None, None)).unwrap();
        record_result(&conn2, "credits", false, None, "manual", 1000, Some(9.0)).unwrap();
        assert_eq!(check_get(&conn2, "credits").unwrap().state.status, "down");
        record_result(&conn2, "credits", false, None, "manual", 1001, None).unwrap();
        assert_eq!(check_get(&conn2, "credits").unwrap().state.status, "down");
    }

    #[test]
    fn pre_value_tables_migrate_to_null() {
        // A database created before values existed opens and serves:
        // old rows read `null` on both surfaces.
        let dir =
            std::env::temp_dir().join(format!("est-hub-db-{}-values-migrate", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hub.sqlite");
        {
            let raw = rusqlite::Connection::open(&path).unwrap();
            raw.execute_batch(
                "CREATE TABLE checks (
                   name TEXT PRIMARY KEY, owner TEXT NOT NULL, ctype TEXT NOT NULL,
                   target TEXT NOT NULL, every_secs INTEGER NOT NULL, timeout_secs INTEGER NOT NULL,
                   severity TEXT NOT NULL, runner TEXT NOT NULL, source TEXT NOT NULL,
                   config TEXT NOT NULL, created_ts INTEGER NOT NULL,
                   last_ok INTEGER, fails INTEGER NOT NULL DEFAULT 0, changed_ts INTEGER NOT NULL DEFAULT 0,
                   last_ts INTEGER NOT NULL DEFAULT 0, last_code INTEGER, last_reason TEXT NOT NULL DEFAULT '');
                 CREATE TABLE results (
                   id INTEGER PRIMARY KEY AUTOINCREMENT, checks TEXT NOT NULL,
                   ts INTEGER NOT NULL, ok INTEGER NOT NULL, code INTEGER, reason TEXT NOT NULL DEFAULT '');
                 INSERT INTO checks (name, owner, ctype, target, every_secs, timeout_secs,
                   severity, runner, source, config, created_ts)
                   VALUES ('legacy', 'e', 'url', 'https://example.com', 60, 10,
                     'normal', 'hub', 'manual', '{}', 1000);
                 INSERT INTO results (checks, ts, ok, code, reason)
                   VALUES ('legacy', 1000, 1, 200, 'HTTP 200');",
            )
            .unwrap();
        }
        let conn = open(&path).unwrap();
        let c = check_get(&conn, "legacy").unwrap();
        assert_eq!(c.state.last_value, None);
        let rows = result_list(&conn, "legacy", 10, 0).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].value, None);
        // New writes land on the migrated schema.
        record_result(
            &conn,
            "legacy",
            true,
            Some(200),
            "HTTP 200",
            1001,
            Some(7.0),
        )
        .unwrap();
        assert_eq!(
            check_get(&conn, "legacy").unwrap().state.last_value,
            Some(7.0)
        );
    }

    #[test]
    fn assemble_carries_silence_horizons() {
        let conn = mem("horizons");
        check_add(&conn, &url_check()).unwrap();
        let c = check_get(&conn, "site").unwrap();
        assert_eq!((c.ack_until, c.mute_until), (0, 0));
        let now = model::now_epoch();
        silence_set(&conn, "site", "ack", now + 60, "", now).unwrap();
        let c = check_get(&conn, "site").unwrap();
        assert_eq!(c.ack_until, now + 60);
        assert_eq!(c.mute_until, 0);
    }

    #[test]
    fn secrets_push_pull_and_scope_tokens() {
        let conn = mem("secrets");
        let now = model::now_epoch();
        // Push, then the public face (sha, no env, no token yet).
        let meta = secret_set(&conn, "api", "K=V\n", now).unwrap();
        assert_eq!(meta.project, "api");
        assert_eq!(meta.sha.len(), 64);
        assert!(!meta.has_token);
        // Mint needs a pushed secret; the token shows once.
        assert!(secret_token_mint(&conn, "ghost", now).is_err());
        let token = secret_token_mint(&conn, "api", now).unwrap();
        assert!(token.starts_with(model::SECRET_TOKEN_PREFIX));
        assert!(secret_meta(&conn, "api").unwrap().has_token);
        // The token pulls its own project, stamps use, and pulls
        // nothing else.
        assert!(secret_token_check(&conn, "api", &token, now));
        assert!(!secret_token_check(&conn, "other", &token, now));
        assert!(!secret_token_check(&conn, "api", "est_s_nope", now));
        let (env, sha) = secret_env(&conn, "api").unwrap();
        assert_eq!(env, "K=V\n");
        assert_eq!(sha, meta.sha);
        // Re-mint kills the old token.
        let token2 = secret_token_mint(&conn, "api", now).unwrap();
        assert_ne!(token, token2);
        assert!(!secret_token_check(&conn, "api", &token, now));
        assert!(secret_token_check(&conn, "api", &token2, now));
        // Revoke kills pulls; delete kills the secret too.
        secret_token_revoke(&conn, "api").unwrap();
        assert!(!secret_token_check(&conn, "api", &token2, now));
        assert!(
            secret_list(&conn)
                .unwrap()
                .iter()
                .any(|m| m.project == "api")
        );
        secret_delete(&conn, "api").unwrap();
        assert!(secret_list(&conn).unwrap().is_empty());
        assert!(secret_delete(&conn, "api").is_err());
    }

    #[test]
    fn balances_upsert_list_and_delete() {
        let conn = mem("balances");
        let now = model::now_epoch();
        assert!(balance_list(&conn).unwrap().is_empty());
        let b = balance_set(&conn, "openai", "", "$12.34", "USD", "team plan", now).unwrap();
        assert_eq!(b.label, "openai"); // Blank labels default to the provider.
        balance_set(&conn, "anthropic", "Anthropic", "84%", "%", "", now).unwrap();
        let list = balance_list(&conn).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].provider, "anthropic"); // Ordered by provider.
        balance_set(&conn, "openai", "", "$9.00", "USD", "", now + 1).unwrap();
        let b = balance_get(&conn, "openai").unwrap();
        assert_eq!((b.amount.as_str(), b.updated_ts), ("$9.00", now + 1));
        balance_delete(&conn, "openai").unwrap();
        assert!(balance_delete(&conn, "openai").is_err());
        assert!(balance_set(&conn, "BAD", "", "1", "", "", now).is_err());
        assert!(balance_set(&conn, "x", "", &"a".repeat(65), "", "", now).is_err());
    }

    #[test]
    fn agents_upsert_list_stale_and_delete() {
        let conn = mem("agents");
        let now = model::now_epoch();
        let set = |pane: &str,
                   title: &str,
                   status: &str,
                   space: Option<&str>,
                   tab: Option<&str>,
                   output: Option<&str>,
                   at: u64| {
            agent_set(
                &conn,
                pane,
                AgentSnapshot {
                    title,
                    cwd: "/Users/x",
                    status,
                    space,
                    tab,
                    output,
                },
                at,
            )
        };
        assert!(agent_list(&conn, now).unwrap().is_empty());
        let a = set(
            "w7:p1P",
            "Release run-up",
            "working",
            Some("iOS"),
            Some("1"),
            Some("compiling…"),
            now,
        )
        .unwrap();
        assert!(!a.stale);
        assert_eq!((a.space.as_str(), a.tab.as_str()), ("iOS", "1"));
        set("w7:p1W", "Screenshots", "blocked", None, None, None, now).unwrap();
        set("wN:p1", "EST Hub", "done", None, None, None, now).unwrap();
        let list = agent_list(&conn, now).unwrap();
        assert_eq!(list.len(), 3);
        // Working first, blocked next, then the rest by pane.
        assert_eq!(list[0].pane, "w7:p1P");
        assert_eq!(list[1].pane, "w7:p1W");
        assert_eq!(list[2].pane, "wN:p1");
        // Stale is computed, never stored.
        let list = agent_list(&conn, now + model::AGENT_STALE_AFTER_SECS + 1).unwrap();
        assert!(list.iter().all(|a| a.stale));
        assert!(!agent_list(&conn, now).unwrap().iter().any(|a| a.stale));
        // Re-push refreshes the stamp; omitted space/tab/output keep.
        set(
            "w7:p1P",
            "Release run-up",
            "idle",
            None,
            None,
            None,
            now + 10,
        )
        .unwrap();
        let a = agent_get(&conn, "w7:p1P", now + 10).unwrap();
        assert_eq!((a.status.as_str(), a.updated_ts), ("idle", now + 10));
        assert_eq!(a.output.as_str(), "compiling…");
        // Present replaces, even with blank.
        set(
            "w7:p1P",
            "Release run-up",
            "idle",
            Some(""),
            Some("2"),
            Some("done."),
            now + 11,
        )
        .unwrap();
        let a = agent_get(&conn, "w7:p1P", now + 11).unwrap();
        assert_eq!(
            (a.space.as_str(), a.tab.as_str(), a.output.as_str()),
            ("", "2", "done.")
        );
        agent_delete(&conn, "w7:p1P").unwrap();
        assert!(agent_delete(&conn, "w7:p1P").is_err());
        assert!(agent_get(&conn, "w7:p1P", now).is_err());
        assert!(set("w 7", "t", "working", None, None, None, now).is_err());
        assert!(set("w7:p1P", "t", "napping", None, None, None, now).is_err());
        assert!(set("w7:p1P", &"t".repeat(257), "working", None, None, None, now).is_err());
        assert!(
            set(
                "w7:p1P",
                "t",
                "working",
                None,
                None,
                Some(&"o".repeat(4097)),
                now
            )
            .is_err()
        );
    }

    #[test]
    fn agent_status_since_flips_heals_and_migrates() {
        let conn = mem("agents-since");
        let now = model::now_epoch();
        let set = |pane: &str, status: &str, at: u64| {
            agent_set(
                &conn,
                pane,
                AgentSnapshot {
                    title: "t",
                    cwd: "/x",
                    status,
                    space: None,
                    tab: None,
                    output: None,
                },
                at,
            )
            .unwrap()
        };
        // New rows stamp now; steady pushes keep it; flips re-stamp.
        let a = set("w1:p1", "working", now);
        assert_eq!(a.status_since_ts, now);
        let a = set("w1:p1", "working", now + 10);
        assert_eq!((a.updated_ts, a.status_since_ts), (now + 10, now));
        let a = set("w1:p1", "done", now + 20);
        assert_eq!(a.status_since_ts, now + 20);
        // Legacy 0 rows heal to their last push on the next set.
        conn.execute(
            "INSERT INTO agents (pane, title, cwd, status, updated_ts, status_since_ts)
             VALUES ('w1:p2', 't', '/x', 'working', ?1, 0)",
            rusqlite::params![now as i64],
        )
        .unwrap();
        let a = set("w1:p2", "working", now + 5);
        assert_eq!(a.status_since_ts, now);
        // Pre-migration tables (no column at all) open and serve.
        let dir =
            std::env::temp_dir().join(format!("est-hub-db-{}-agents-migrate", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hub.sqlite");
        {
            let raw = rusqlite::Connection::open(&path).unwrap();
            raw.execute_batch(
                "CREATE TABLE agents (
                   pane TEXT PRIMARY KEY, title TEXT NOT NULL DEFAULT '',
                   cwd TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'unknown',
                   space TEXT NOT NULL DEFAULT '', tab TEXT NOT NULL DEFAULT '',
                   output TEXT NOT NULL DEFAULT '', updated_ts INTEGER NOT NULL);",
            )
            .unwrap();
        }
        let migrated = open(&path).unwrap();
        let a = agent_set(
            &migrated,
            "w1:p9",
            AgentSnapshot {
                title: "t",
                cwd: "/x",
                status: "working",
                space: None,
                tab: None,
                output: None,
            },
            now,
        )
        .unwrap();
        assert_eq!(a.status_since_ts, now);
    }

    #[test]
    fn secrets_validate_names_and_size() {
        let conn = mem("secrets-valid");
        let now = model::now_epoch();
        assert!(secret_set(&conn, "Upper", "K=V", now).is_err());
        assert!(secret_set(&conn, "", "K=V", now).is_err());
        let big = "K=".to_string() + &"V".repeat(model::SECRET_ENV_MAX);
        assert!(secret_set(&conn, "api", &big, now).is_err());
    }

    #[test]
    fn birth_is_quiet_both_ways() {
        let conn = mem("birth-quiet");
        check_add(&conn, &url_check()).unwrap();
        let (flipped, row) =
            record_result(&conn, "site", true, Some(200), "HTTP 200", 1000, None).unwrap();
        assert!(!flipped);
        assert!(row.is_none());
        assert!(notification_list(&conn, 10).unwrap().is_empty());
        let conn2 = mem("birth-down");
        check_add(&conn2, &url_check()).unwrap();
        let (flipped, row) =
            record_result(&conn2, "site", false, None, "refused", 1000, None).unwrap();
        assert!(!flipped);
        assert!(row.is_none());
        assert!(notification_list(&conn2, 10).unwrap().is_empty());
        let c = check_get(&conn2, "site").unwrap();
        assert_eq!(c.state.status, "down");
    }

    #[test]
    fn projects_upsert_icon_and_list() {
        let conn = mem("projects");
        let p = model::ValidProject {
            slug: "daysleft".to_string(),
            group: "ios".to_string(),
            name: "Days Left".to_string(),
            bundle_id: "com.estifie.daysleft".to_string(),
        };
        let got = project_upsert(&conn, &p).unwrap();
        assert_eq!(got.slug, "daysleft");
        assert!(!got.has_icon);
        assert!(project_icon(&conn, "daysleft").is_err());
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00];
        let got = project_set_icon(&conn, "daysleft", &png, "abc").unwrap();
        assert!(got.has_icon);
        assert_eq!(got.icon_sha256.as_deref(), Some("abc"));
        assert_eq!(project_icon(&conn, "daysleft").unwrap(), png);
        // Metadata rewrites keep the icon.
        let got = project_upsert(&conn, &p).unwrap();
        assert!(got.has_icon);
        assert_eq!(project_list(&conn).unwrap().len(), 1);
        assert!(project_set_icon(&conn, "ghost", &png, "abc").is_err());
    }

    #[test]
    fn old_devices_table_migrates_to_active() {
        // The prod db predates the registration reshuffle: a legacy
        // `pubkey` column and no pairing tables.
        let dir = std::env::temp_dir().join(format!("est-hub-db-{}-migrate", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hub.sqlite");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE devices (
                   name TEXT PRIMARY KEY, pubkey TEXT, apns_token TEXT, created_ts INTEGER NOT NULL);
                 INSERT INTO devices (name, pubkey, apns_token, created_ts)
                 VALUES ('legacy', NULL, NULL, 1000);",
            )
            .unwrap();
        }
        let conn = open(&path).unwrap();
        let d = device_get(&conn, "legacy").unwrap();
        assert_eq!(d.state, "active");
        assert_eq!(d.apns_env, None);
        // Part 4 columns arrive null: unconfigured, off, hub-wide topic.
        assert_eq!(d.apns_topic, None);
        assert_eq!(d.la_pts_token, None);
        assert_eq!(d.la_config, None);
        assert_eq!(d.la_activity_id, None);
        assert_eq!(d.la_started_ts, None);
        assert_eq!(
            la_config_get(&conn, "legacy").unwrap(),
            model::LaConfig::default()
        );
        assert!(la_tokens_for_device(&conn, "legacy").unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn approvals_queue_an_approval_requested_row() {
        let conn = mem("approval-row");
        // A prior queue row first: the tables run out of lockstep, so
        // a `last_insert_rowid` mixup reads back the wrong approval.
        notification_push(&conn, "", "notify", "old", "").unwrap();
        let (a, row) = approval_create(&conn, "deploy?", "the body", "", 3600).unwrap();
        assert_eq!(a.id, 1);
        assert_eq!(a.title, "deploy?");
        assert_eq!(a.state, "pending");
        // The queued row rides out for the push fan-out.
        let row = row.unwrap();
        assert_eq!(row.topic, "approval.requested");
        assert_eq!(row.title, "deploy?");
        assert_eq!(row.body, "the body");
        let notes = notification_list(&conn, 10).unwrap();
        assert_eq!(notes.len(), 2);
        assert_eq!(notes[0].topic, "approval.requested");
        assert_eq!(notes[0].title, "deploy?");
        assert_eq!(notes[0].body, "the body");
        assert_eq!(notes[0].to_device, "");
        assert!(!notes[0].delivered);
    }

    #[test]
    fn apns_410_clears_the_token_and_keeps_the_env() {
        // The exact call `apns::deliver_to` makes on Unregistered.
        let conn = mem("apns-clear");
        device_add(&conn, "phone", Some("tok")).unwrap();
        device_update_apns(
            &conn,
            "phone",
            Some("tok"),
            Some("production"),
            Some("com.estifie.app"),
        )
        .unwrap();
        device_update_apns(
            &conn,
            "phone",
            None,
            Some("production"),
            Some("com.estifie.app"),
        )
        .unwrap();
        let d = device_get(&conn, "phone").unwrap();
        assert_eq!(d.apns_token, None);
        assert_eq!(d.apns_env.as_deref(), Some("production"));
        assert_eq!(d.apns_topic.as_deref(), Some("com.estifie.app"));
        assert!(!d.apns_configured());
        // The topic clears on its own: null writes null, the rest stays.
        device_update_apns(&conn, "phone", None, Some("production"), None).unwrap();
        let d = device_get(&conn, "phone").unwrap();
        assert_eq!(d.apns_topic, None);
        assert_eq!(d.apns_env.as_deref(), Some("production"));
    }

    #[test]
    fn live_storage_roundtrips_config_pts_activity_and_tokens() {
        let conn = mem("live-store");
        device_add(&conn, "phone", None).unwrap();
        device_add(&conn, "watch", None).unwrap();
        // Fresh devices read the default config (off), no PTS, no stamp.
        assert_eq!(
            la_config_get(&conn, "phone").unwrap(),
            model::LaConfig::default()
        );
        assert_eq!(device_get(&conn, "phone").unwrap().la_pts_token, None);
        assert_eq!(live_last_push_get(&conn, "phone"), None);
        assert!(la_tokens_for_device(&conn, "phone").unwrap().is_empty());
        // Config writes and reads back whole.
        let cfg = model::LaConfig {
            enabled: true,
            checks: Some(vec!["b".to_string(), "a".to_string()]),
            min_severity: "high".to_string(),
            approvals: false,
            alert_on_down: true,
        };
        assert_eq!(la_config_set(&conn, "phone", &cfg).unwrap(), cfg);
        assert_eq!(la_config_get(&conn, "phone").unwrap(), cfg);
        // PTS sets and clears.
        la_pts_set(&conn, "phone", Some("ab12")).unwrap();
        assert_eq!(
            device_get(&conn, "phone").unwrap().la_pts_token.as_deref(),
            Some("ab12")
        );
        la_pts_set(&conn, "phone", None).unwrap();
        assert_eq!(device_get(&conn, "phone").unwrap().la_pts_token, None);
        // Activity points and clears.
        la_activity_set(&conn, "phone", Some("act-1"), Some(1000)).unwrap();
        let d = device_get(&conn, "phone").unwrap();
        assert_eq!(d.la_activity_id.as_deref(), Some("act-1"));
        assert_eq!(d.la_started_ts, Some(1000));
        la_activity_set(&conn, "phone", None, None).unwrap();
        let d = device_get(&conn, "phone").unwrap();
        assert_eq!(d.la_activity_id, None);
        assert_eq!(d.la_started_ts, None);
        // Tokens upsert per id, list oldest-first, delete by owner.
        la_token_upsert(&conn, "phone", "act-1", "tok-1", "", 100).unwrap();
        la_token_upsert(&conn, "phone", "act-2", "tok-2", "", 200).unwrap();
        la_token_upsert(&conn, "phone", "act-1", "tok-1b", "", 300).unwrap();
        let tokens = la_tokens_for_device(&conn, "phone").unwrap();
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0].activity_id, "act-2"); // oldest first
        assert_eq!(tokens[1].activity_id, "act-1");
        assert_eq!(tokens[1].push_token, "tok-1b");
        assert_eq!(tokens[1].updated_ts, 300);
        // Another device's id is not this device's to delete.
        assert!(la_token_delete(&conn, "watch", "act-1").is_err());
        assert!(la_token_delete(&conn, "phone", "nope").is_err());
        la_token_delete(&conn, "phone", "act-1").unwrap();
        assert_eq!(la_tokens_for_device(&conn, "phone").unwrap().len(), 1);
        assert_eq!(la_tokens_delete_device(&conn, "phone").unwrap(), 1);
        assert!(la_tokens_for_device(&conn, "phone").unwrap().is_empty());
        // Unknown devices stay missing everywhere.
        assert!(la_config_get(&conn, "ghost").is_err());
        assert!(la_config_set(&conn, "ghost", &cfg).is_err());
        assert!(la_pts_set(&conn, "ghost", Some("x")).is_err());
        assert!(la_activity_set(&conn, "ghost", Some("a"), Some(1)).is_err());
        assert!(la_token_upsert(&conn, "ghost", "a", "t", "", 1).is_err());
        assert!(la_tokens_for_device(&conn, "ghost").is_err());
        assert!(la_token_delete(&conn, "ghost", "a").is_err());
        assert!(la_tokens_delete_device(&conn, "ghost").is_err());
        // The last-push stamp writes and reads.
        live_last_push_set(&conn, "phone", 4242).unwrap();
        assert_eq!(live_last_push_get(&conn, "phone"), Some(4242));
        // Revoke takes the tokens and the stamp with the row.
        la_token_upsert(&conn, "phone", "act-9", "tok-9", "", 400).unwrap();
        device_delete(&conn, "phone").unwrap();
        device_add(&conn, "phone", None).unwrap();
        assert!(la_tokens_for_device(&conn, "phone").unwrap().is_empty());
        assert_eq!(live_last_push_get(&conn, "phone"), None);
    }

    #[test]
    fn notification_filters_narrow_to_and_since() {
        let conn = mem("notif-filters");
        let a = notification_push(&conn, "phone", "notify", "one", "").unwrap();
        let b = notification_push(&conn, "watch", "notify", "two", "").unwrap();
        let c = notification_push(&conn, "phone", "health.flip", "three", "").unwrap();
        assert!(a.id < b.id && b.id < c.id);
        let all = notification_list_filtered(&conn, 10, None, None).unwrap();
        assert_eq!(all.len(), 3);
        let phone = notification_list_filtered(&conn, 10, Some("phone"), None).unwrap();
        assert_eq!(phone.len(), 2);
        assert!(phone.iter().all(|n| n.to_device == "phone"));
        let fresh = notification_list_filtered(&conn, 10, None, Some(b.id)).unwrap();
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].id, c.id);
        let both = notification_list_filtered(&conn, 10, Some("phone"), Some(a.id)).unwrap();
        assert_eq!(both.len(), 1);
        assert_eq!(both[0].id, c.id);
        let none = notification_list_filtered(&conn, 10, Some("nope"), None).unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn notifications_prune_past_retention_on_push() {
        let conn = mem("notif-prune");
        let old = model::now_epoch().saturating_sub(NOTIFICATION_RETENTION_SECS + 1) as i64;
        conn.execute(
            "INSERT INTO notifications (ts, topic, title, body, to_device) VALUES (?, ?, ?, ?, ?)",
            rusqlite::params![old, "notify", "ancient", "", ""],
        )
        .unwrap();
        let fresh = notification_push(&conn, "", "notify", "today", "").unwrap();
        let notes = notification_list(&conn, 10).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].id, fresh.id);
    }

    #[test]
    fn approvals_expire_and_refuse_late_decisions() {
        let conn = mem("approvals");
        let (a, _) = approval_create(&conn, "deploy?", "", "", 3600).unwrap();
        assert_eq!(a.state, "pending");
        let a = approval_decide(&conn, a.id, true, "estifie").unwrap();
        assert_eq!(a.state, "approved");
        assert!(approval_decide(&conn, a.id, false, "x").is_err());
        let (b, _) = approval_create(&conn, "old?", "", "", 1).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(2));
        let b = approval_get(&conn, b.id).unwrap();
        assert_eq!(b.state, "expired");
        assert!(approval_decide(&conn, b.id, true, "x").is_err());
    }
}
