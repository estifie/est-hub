//! Hub-driven Live Activity triggers: per-device state recompute,
//! update/start/end fan-out, and the 6h refresh.
//!
//! Each enabled device watches a feed (all checks or a subset, at or
//! above a floor severity, plus optionally pending approvals). On every
//! flip, approval change, config change, and 6h tick, the hub recomputes
//! the feed and converges the card: update the running activity (loud
//! at 10 on a fresh down, quiet at 5 otherwise), push-to-start one via
//! the PTS token when there is news and no card, or end the card when
//! everything cleared. A 410/`BadDeviceToken` deletes the dead token
//! and queues one throttled `live.stale` notice — the same 1/hour
//! pattern as `device.blocked`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// The `device.blocked` throttle map, shared: `live:{device}` keys sit
/// beside fingerprint keys (the `:` keeps them disjoint).
pub type Throttle = Arc<Mutex<HashMap<String, u64>>>;

/// Refresh cadence: re-push (and restart aging cards) this often, well
/// before Apple's ~8h auto-end.
pub const REFRESH_SECS: u64 = 6 * 3600;
/// A running card with no push inside this reads stale.
pub const STALE_AFTER_SECS: u64 = 8 * 3600;
/// One `live.stale` notice per device per hour, like `device.blocked`.
pub const STALE_ALERT_SECS: u64 = 3600;
/// Ended cards dismiss this long after the end (the owner sees the
/// all-clear, then it goes away on its own).
pub const END_DISMISS_AFTER_SECS: u64 = 3600;
/// The card's title attribute, and the default alert title.
pub const CARD_TITLE: &str = "EST status";

/// What a converge needs beyond the db path: the shared push client,
/// the explicit APNs key path, the stale-notice throttle, and (tests
/// only) a mock Apple host.
#[derive(Clone)]
pub struct Ctx {
    /// The shared push client.
    pub client: reqwest::Client,
    /// Explicit `--apns-key` path (`None` falls back as usual).
    pub apns_key: Option<PathBuf>,
    /// The `live.stale` throttle (shared with `device.blocked`).
    pub throttle: Throttle,
    /// Test override for the Apple host; always `None` in prod.
    pub apns_base: Option<String>,
}

impl Ctx {
    /// A production context: real Apple hosts.
    pub fn new(client: reqwest::Client, apns_key: Option<PathBuf>, throttle: Throttle) -> Self {
        Ctx {
            client,
            apns_key,
            throttle,
            apns_base: None,
        }
    }
}

/// Severity floor, `low` < `normal` < `high`. Unknown reads `normal`.
pub fn severity_rank(sev: &str) -> u8 {
    match sev.trim() {
        "low" => 0,
        "high" => 2,
        _ => 1,
    }
}

/// One device's recomputed card state.
pub struct LiveState {
    /// Watched checks currently down.
    pub down_count: u32,
    /// Worst severity among them (`low` when clear — the wire shape
    /// always carries a severity).
    pub worst: String,
    /// Pending approvals (0 when the device opted out).
    pub pending_approvals: u32,
}

impl LiveState {
    /// Nothing to show: no downs, no pending approvals.
    pub fn clear(&self) -> bool {
        self.down_count == 0 && self.pending_approvals == 0
    }

    /// One human line for alert bodies: `2 checks down · 1 approval
    /// pending`, or `all clear`.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if self.down_count > 0 {
            parts.push(format!(
                "{} check{} down",
                self.down_count,
                if self.down_count == 1 { "" } else { "s" }
            ));
        }
        if self.pending_approvals > 0 {
            parts.push(format!(
                "{} approval{} pending",
                self.pending_approvals,
                if self.pending_approvals == 1 { "" } else { "s" }
            ));
        }
        if parts.is_empty() {
            "all clear".to_string()
        } else {
            parts.join(" · ")
        }
    }

    /// The pinned content-state object (exact keys, epoch seconds).
    pub fn content_state(&self, now: u64) -> serde_json::Value {
        crate::apns::live_content_state(self.down_count, &self.worst, self.pending_approvals, now)
    }
}

/// Recompute one device's card from its feed: watched checks that are
/// down at or above the floor severity, plus pending approvals when the
/// device counts them.
pub fn recompute(conn: &rusqlite::Connection, cfg: &crate::model::LaConfig) -> LiveState {
    let floor = severity_rank(&cfg.min_severity);
    let mut down_count = 0u32;
    let mut worst_rank = 0u8;
    for c in crate::db::check_list(conn).unwrap_or_default() {
        if c.state.status != "down" {
            continue;
        }
        if let Some(want) = cfg.checks.as_ref()
            && !want.iter().any(|w| w == &c.name)
        {
            continue;
        }
        let rank = severity_rank(&c.severity);
        if rank < floor {
            continue;
        }
        down_count += 1;
        worst_rank = worst_rank.max(rank);
    }
    let worst = ["low", "normal", "high"][worst_rank.min(2) as usize].to_string();
    let pending_approvals = if cfg.approvals {
        crate::db::approval_list(conn, Some("pending"))
            .map(|a| a.len() as u32)
            .unwrap_or(0)
    } else {
        0
    };
    LiveState {
        down_count,
        worst,
        pending_approvals,
    }
}

/// One device's card status: `off` (disabled), `pending` (enabled, no
/// activity yet — the app has not reported a token), `active`, or
/// `stale` (running, but no push inside ~8h, so Apple likely ended it).
pub fn status_of(
    enabled: bool,
    activity_id: Option<&str>,
    started_ts: Option<u64>,
    last_push_ts: Option<u64>,
    now: u64,
) -> &'static str {
    if !enabled {
        return "off";
    }
    if activity_id.is_none() {
        return "pending";
    }
    let fresh = last_push_ts.is_some_and(|t| now.saturating_sub(t) <= STALE_AFTER_SECS)
        || last_push_ts.is_none()
            && started_ts.is_some_and(|t| now.saturating_sub(t) <= STALE_AFTER_SECS);
    if fresh { "active" } else { "stale" }
}

/// The sender identity, or `None` when pushes cannot run (unconfigured
/// hubs converge to nothing — tests and dev unaffected). Half-configured
/// hubs log the one-line fix, like `POST /notify` does.
fn load_cfg(ctx: &Ctx, db_path: &Path) -> Option<crate::apns::Config> {
    let conn = crate::db::open(db_path).ok()?;
    match crate::apns::load(ctx.apns_key.as_deref(), db_path, &conn) {
        Ok(cfg) => cfg,
        Err(why) => {
            est_core::log::info(&format!("apns skipped: {why}"));
            None
        }
    }
}

/// One Live Activity POST on a device's resolved topic.
async fn push_live(
    ctx: &Ctx,
    cfg: &crate::apns::Config,
    device: &crate::model::Device,
    token: &str,
    priority: u8,
    payload: &serde_json::Value,
) -> crate::apns::SendOutcome {
    let base = crate::apns::resolve_topic(device.apns_topic.as_deref(), &cfg.topic);
    let topic = crate::apns::live_topic(&base);
    let bytes = serde_json::to_vec(payload).unwrap_or_default();
    let send = crate::apns::LiveSend {
        token,
        env: device.apns_env.as_deref(),
        topic: &topic,
        priority,
        payload: &bytes,
        base_override: ctx.apns_base.as_deref(),
    };
    crate::apns::send_live(&ctx.client, cfg, &send).await
}

/// Flip pushes page at most this often per check: a flapping check
/// still queues every flip and refreshes cards, but buzzes rarely.
const FLIP_PUSH_SECS: u64 = 300;

/// True once per [`FLIP_PUSH_SECS`] per check (first call always).
fn flip_push_due(throttle: &Throttle, check: &str) -> bool {
    let now = crate::model::now_epoch();
    let key = format!("flip-push:{check}");
    let mut guard = throttle.lock().unwrap_or_else(|e| e.into_inner());
    if now.saturating_sub(guard.get(&key).copied().unwrap_or(0)) >= FLIP_PUSH_SECS {
        guard.insert(key, now);
        true
    } else {
        false
    }
}

/// A dead token's notice: one throttled `live.stale` row per device per
/// hour, mirroring the `device.blocked` throttle exactly.
pub fn stale_notice(conn: &rusqlite::Connection, throttle: &Throttle, device: &str, what: &str) {
    let now = crate::model::now_epoch();
    let key = format!("live:{device}");
    let mut guard = throttle.lock().unwrap_or_else(|e| e.into_inner());
    if now.saturating_sub(guard.get(&key).copied().unwrap_or(0)) >= STALE_ALERT_SECS {
        guard.insert(key, now);
        let _ = crate::db::notification_push(
            conn,
            device,
            "live.stale",
            &format!("live activity went stale on {device}"),
            what,
        );
    }
}

/// Converge one device's card to its recomputed feed: update the running
/// activity (priority 10 + alert on a fresh down the device wants loud,
/// silent 5 otherwise), push-to-start via PTS when there is news and no
/// card, or end the card when everything cleared. `note` names the fresh
/// down for alert titles (`None` reads [`CARD_TITLE`]). Disabled devices
/// and unknown names converge to nothing.
pub async fn converge_device(
    ctx: &Ctx,
    db_path: &Path,
    device_name: &str,
    newly_down: bool,
    note: Option<&str>,
) {
    let Some(cfg) = load_cfg(ctx, db_path) else {
        return;
    };
    // Read everything first: the connection never crosses an await.
    let read = crate::db::open(db_path).ok().and_then(|conn| {
        let device = crate::db::device_get(&conn, device_name).ok()?;
        let feed = device.la_config_parsed();
        if !feed.enabled {
            return None;
        }
        let state = recompute(&conn, &feed);
        let live_token = device.la_activity_id.as_deref().and_then(|id| {
            crate::db::la_tokens_for_device(&conn, device_name)
                .unwrap_or_default()
                .into_iter()
                .find(|t| t.activity_id == id)
                .map(|t| t.push_token)
        });
        Some((device, feed, state, live_token))
    });
    let Some((device, feed, state, live_token)) = read else {
        return;
    };
    let now = crate::model::now_epoch();
    match live_token {
        Some(token) if state.clear() => {
            let payload = crate::apns::live_end_payload(
                &state.content_state(now),
                now + END_DISMISS_AFTER_SECS,
                now,
            );
            let outcome = push_live(ctx, &cfg, &device, &token, 10, &payload).await;
            let landed = outcome.sent();
            if let Ok(conn) = crate::db::open(db_path) {
                end_local(&conn, device_name, outcome, ctx);
            }
            if landed {
                mark_pushed(db_path, device_name, now);
            }
        }
        Some(token) => {
            let summary = state.summary();
            let alert = (newly_down && feed.alert_on_down)
                .then(|| (note.unwrap_or(CARD_TITLE), summary.as_str()));
            let payload = crate::apns::live_update_payload(&state.content_state(now), alert, now);
            let outcome = push_live(
                ctx,
                &cfg,
                &device,
                &token,
                crate::apns::live_update_priority(newly_down),
                &payload,
            )
            .await;
            match outcome {
                crate::apns::SendOutcome::Sent { .. } => mark_pushed(db_path, device_name, now),
                crate::apns::SendOutcome::Unregistered => {
                    if let Ok(conn) = crate::db::open(db_path) {
                        end_local(&conn, device_name, outcome, ctx);
                    }
                }
                _ => {}
            }
        }
        None => {
            if state.clear() {
                return;
            }
            let Some(pts) = device.la_pts_token.as_deref().filter(|t| !t.is_empty()) else {
                return;
            };
            let payload = crate::apns::live_start_payload(
                device_name,
                CARD_TITLE,
                &state.content_state(now),
                note.unwrap_or(CARD_TITLE),
                &state.summary(),
                now,
            );
            match push_live(ctx, &cfg, &device, pts, 10, &payload).await {
                crate::apns::SendOutcome::Sent { .. } => mark_pushed(db_path, device_name, now),
                crate::apns::SendOutcome::Unregistered => {
                    // The PTS token died: clear it, once, throttled.
                    if let Ok(conn) = crate::db::open(db_path) {
                        let _ = crate::db::la_pts_set(&conn, device_name, None);
                        stale_notice(
                            &conn,
                            &ctx.throttle,
                            device_name,
                            "Apple rejected the push-to-start token (410/BadDeviceToken); it was cleared",
                        );
                    }
                }
                _ => {}
            }
        }
    }
}

/// After an end push (or a dead activity token): forget the token and
/// the current activity, and on `Unregistered` queue the throttled
/// notice. Rejections and transport failures keep everything — the next
/// trigger retries.
fn end_local(
    conn: &rusqlite::Connection,
    device: &str,
    outcome: crate::apns::SendOutcome,
    ctx: &Ctx,
) {
    match outcome {
        crate::apns::SendOutcome::Sent { .. } => {
            forget_activity(conn, device);
        }
        crate::apns::SendOutcome::Unregistered => {
            forget_activity(conn, device);
            stale_notice(
                conn,
                &ctx.throttle,
                device,
                "Apple rejected the activity token (410/BadDeviceToken); it was deleted",
            );
        }
        _ => {}
    }
}

/// Forget one device's current activity: its token row (when known by
/// id) plus the pointer. The next converge starts over.
fn forget_activity(conn: &rusqlite::Connection, device: &str) {
    if let Ok(d) = crate::db::device_get(conn, device)
        && let Some(id) = d.la_activity_id.as_deref()
    {
        let _ = crate::db::la_token_delete(conn, device, id);
    }
    let _ = crate::db::la_activity_set(conn, device, None, None);
}

/// Stamp a landed Live Activity push.
fn mark_pushed(db_path: &Path, device: &str, now: u64) {
    if let Ok(conn) = crate::db::open(db_path) {
        let _ = crate::db::live_last_push_set(&conn, device, now);
    }
}

/// The token label pinning one incident card: `incident:{check}`. The
/// app reports it with the push-started card's token; the hub reads it
/// back to skip duplicate starts and to end on recovery.
pub fn incident_label(check: &str) -> String {
    format!("incident:{check}")
}

/// The human reason out of a down note (`🔴 {name} is DOWN — {reason}`),
/// or `""` when the note is not that shape (the card still pins — the
/// check name carries it).
fn down_reason(note: &str, name: &str) -> String {
    note.strip_prefix(&format!("🔴 {name} is DOWN — "))
        .unwrap_or("")
        .to_string()
}

/// Pin or drop the incident card beside the status card: down flips
/// push-to-start one per watching device (skipping cards already live),
/// recovery ends every labeled row. Runs past the silence gate — a
/// muted check pins nothing. No refresh loop yet: Apple retires an
/// un-updated card after ~8h, so multi-day outages lose the pin until
/// the next flip (V2 re-pushes on the refresh tick).
async fn incident_round(ctx: &Ctx, db_path: &Path, check_name: &str, went_down: bool, note: &str) {
    let label = incident_label(check_name);
    if went_down {
        incident_start(ctx, db_path, check_name, &label, note).await;
    } else {
        incident_end(ctx, db_path, &label).await;
    }
}

/// Push-to-start the incident card on every watching device that has a
/// PTS token and no live card for this check yet.
async fn incident_start(ctx: &Ctx, db_path: &Path, check_name: &str, label: &str, note: &str) {
    let Some(cfg) = load_cfg(ctx, db_path) else {
        return;
    };
    let jobs: Vec<(crate::model::Device, String)> = crate::db::open(db_path)
        .ok()
        .and_then(|conn| {
            let check = crate::db::check_get(&conn, check_name).ok()?;
            let rank = severity_rank(&check.severity);
            let devices = crate::db::device_list(&conn).unwrap_or_default();
            Some(
                devices
                    .into_iter()
                    .filter(|d| {
                        let feed = d.la_config_parsed();
                        feed.enabled
                            && feed
                                .checks
                                .as_ref()
                                .is_none_or(|want| want.iter().any(|w| w == check_name))
                            && rank >= severity_rank(&feed.min_severity)
                    })
                    .filter(|d| !crate::db::la_label_live(&conn, &d.name, label))
                    .filter_map(|d| {
                        let pts = d.la_pts_token.clone().filter(|t| !t.trim().is_empty())?;
                        Some((d, pts))
                    })
                    .collect(),
            )
        })
        .unwrap_or_default();
    if jobs.is_empty() {
        return;
    }
    let now = crate::model::now_epoch();
    let reason = down_reason(note, check_name);
    let payload = crate::apns::incident_start_payload(check_name, &reason, now, now);
    for (device, pts) in jobs {
        if matches!(
            push_live(ctx, &cfg, &device, &pts, 10, &payload).await,
            crate::apns::SendOutcome::Unregistered
        ) && let Ok(conn) = crate::db::open(db_path)
        {
            let _ = crate::db::la_pts_set(&conn, &device.name, None);
            stale_notice(
                &conn,
                &ctx.throttle,
                &device.name,
                "Apple rejected the push-to-start token (410/BadDeviceToken); it was cleared",
            );
        }
    }
}

/// End every card labeled for this check, dropping the rows as they
/// land (or as Apple reports them dead). A transport failure keeps the
/// row — the next recovery retries; worst case Apple retires the card.
async fn incident_end(ctx: &Ctx, db_path: &Path, label: &str) {
    let tokens: Vec<crate::model::LaToken> = crate::db::open(db_path)
        .ok()
        .and_then(|conn| crate::db::la_tokens_for_label(&conn, label).ok())
        .unwrap_or_default();
    if tokens.is_empty() {
        return;
    }
    let Some(cfg) = load_cfg(ctx, db_path) else {
        return;
    };
    let now = crate::model::now_epoch();
    for t in tokens {
        let device = crate::db::open(db_path)
            .ok()
            .and_then(|conn| crate::db::device_get(&conn, &t.device).ok());
        let Some(device) = device else {
            // The device is gone: drop its orphan row.
            if let Ok(conn) = crate::db::open(db_path) {
                let _ = crate::db::la_token_delete(&conn, &t.device, &t.activity_id);
            }
            continue;
        };
        let payload = crate::apns::incident_end_payload("recovered", t.updated_ts, now);
        match push_live(ctx, &cfg, &device, &t.push_token, 10, &payload).await {
            crate::apns::SendOutcome::Sent { .. } | crate::apns::SendOutcome::Unregistered => {
                if let Ok(conn) = crate::db::open(db_path) {
                    let _ = crate::db::la_token_delete(&conn, &t.device, &t.activity_id);
                }
            }
            _ => {}
        }
    }
}

/// The token label pinning one fleet card per device: `fleet`. The
/// app reports it with the push-started card's token; the hub reads it
/// back to update instead of re-starting, and to end when nothing is
/// live.
pub const FLEET_LABEL: &str = "fleet";
/// Rows per card: the Lock Screen fits about six; the hub order
/// (working, blocked, then the settled) picks the survivors.
pub const FLEET_MAX_ROWS: usize = 6;
/// Settled rows linger this long, so a finish stays visible before the
/// card drops it (or ends, when nothing else is live).
pub const FLEET_RECENT_SECS: u64 = 900;
/// How long an unanswered push-to-start pins the card. The app uploads a
/// card's per-activity token only once it next runs, so until that token
/// comes back the hub cannot update the card — and starting again would
/// stack a *second* card on the Lock Screen instead. Apple retires a
/// card 8h after it starts, so past this window a fresh start is safe
/// (the old card is gone).
pub const FLEET_START_HOLD_SECS: u64 = 8 * 3600;
/// The start banner's title (Apple mandates an alert on every start).
pub const FLEET_START_TITLE: &str = "Agents live";

/// One device's recomputed fleet card: the rows plus the freshest
/// mirror stamp (the widget's "updated ago").
pub struct FleetState {
    /// The card's rows, hub order, capped.
    pub rows: Vec<crate::model::FleetRow>,
    /// Freshest mirror stamp across the rows, unix seconds.
    pub updated_ts: u64,
}

/// Display name mirroring the app's row title: `space * tab` placing
/// first (terminal titles go stale — the placing never lies), then the
/// title, the cwd leaf, the pane.
pub fn agent_display_name(space: &str, tab: &str, title: &str, cwd: &str, pane: &str) -> String {
    let placing: Vec<&str> = [space.trim(), tab.trim()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
    if !placing.is_empty() {
        return placing.join(" * ");
    }
    let title = title.trim();
    if !title.is_empty() {
        return title.to_string();
    }
    if let Some(leaf) = cwd
        .trim()
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|l| !l.is_empty())
    {
        return leaf.to_string();
    }
    pane.to_string()
}

/// The card's rows: live agents (working/blocked) plus agents settled
/// inside [`FLEET_RECENT_SECS`], hub order, capped. Stale panes (mirror
/// quiet) never render — a frozen "working" is a lie.
pub fn fleet_rows(conn: &rusqlite::Connection, now: u64) -> FleetState {
    let mut rows = Vec::new();
    let mut freshest = 0u64;
    for a in crate::db::agent_list(conn, now).unwrap_or_default() {
        if a.stale {
            continue;
        }
        let live = a.status == "working" || a.status == "blocked";
        let recent = now.saturating_sub(a.updated_ts) <= FLEET_RECENT_SECS;
        if !live && !recent {
            continue;
        }
        freshest = freshest.max(a.updated_ts);
        rows.push(crate::model::FleetRow {
            pane: a.pane.clone(),
            name: agent_display_name(&a.space, &a.tab, &a.title, &a.cwd, &a.pane),
            status: a.status.clone(),
        });
        if rows.len() >= FLEET_MAX_ROWS {
            break;
        }
    }
    FleetState {
        rows,
        updated_ts: freshest,
    }
}

/// One human line for the start banner: `2 working · 1 needs input`.
pub fn fleet_summary(rows: &[crate::model::FleetRow]) -> String {
    let (mut working, mut blocked, mut settled) = (0u32, 0u32, 0u32);
    for r in rows {
        match r.status.as_str() {
            "working" => working += 1,
            "blocked" => blocked += 1,
            _ => settled += 1,
        }
    }
    let mut parts = Vec::new();
    if working > 0 {
        parts.push(format!("{working} working"));
    }
    if blocked > 0 {
        parts.push(if blocked == 1 {
            "1 needs input".to_string()
        } else {
            format!("{blocked} need input")
        });
    }
    if settled > 0 {
        parts.push(format!("{settled} done"));
    }
    if parts.is_empty() {
        "all clear".to_string()
    } else {
        parts.join(" · ")
    }
}

/// The durable last-pushed rows per device (canonical JSON). Durable,
/// not memory: a deploy restart must not re-push (or re-start) every
/// card.
fn fleet_pushed_key(device: &str) -> String {
    format!("fleet.pushed.{device}")
}

/// True when these rows differ from the last pushed ones. The
/// `updated_ts` rides every push but never joins the diff — the mirror
/// stamps every round, and diffing it would push 4/min forever.
fn fleet_rows_changed(
    conn: &rusqlite::Connection,
    device: &str,
    rows: &[crate::model::FleetRow],
) -> bool {
    let canon = serde_json::to_string(rows).unwrap_or_default();
    crate::db::meta_get(conn, &fleet_pushed_key(device)).as_deref() != Some(canon.as_str())
}

fn fleet_rows_stored(conn: &rusqlite::Connection, device: &str, rows: &[crate::model::FleetRow]) {
    let canon = serde_json::to_string(rows).unwrap_or_default();
    let _ = crate::db::meta_set(conn, &fleet_pushed_key(device), &canon);
}

/// When this device's fleet card was push-started, unix seconds. Present
/// while a start is outstanding (the card's token never came back), so
/// the hub holds instead of stacking a second card. Cleared with the
/// rows — on a 410 or an end, the card is gone and a start is safe.
fn fleet_started_key(device: &str) -> String {
    format!("fleet.started.{device}")
}

fn fleet_rows_forget(conn: &rusqlite::Connection, device: &str) {
    let _ = crate::db::meta_del(conn, &fleet_pushed_key(device));
    let _ = crate::db::meta_del(conn, &fleet_started_key(device));
}

/// Agents changed (mirror write or delete): converge every enabled
/// device's fleet card. No live rows ends every labeled card; live
/// rows update the labeled card when the rows moved (silent, priority
/// 5) or push-to-start via PTS when no card does. The mirror writes
/// every 15s per pane — the diff gate is what keeps that quiet. A
/// push-to-start is then held until its token comes back (or Apple's 8h
/// cap), so a closed app never stacks a second card.
pub async fn on_agents_changed(ctx: &Ctx, db_path: &Path) {
    let state = crate::db::open(db_path)
        .ok()
        .map(|conn| fleet_rows(&conn, crate::model::now_epoch()))
        .unwrap_or(FleetState {
            rows: Vec::new(),
            updated_ts: 0,
        });
    if state.rows.is_empty() {
        fleet_end_all(ctx, db_path).await;
        return;
    }
    let devices: Vec<String> = crate::db::open(db_path)
        .ok()
        .map(|conn| {
            crate::db::device_list(&conn)
                .unwrap_or_default()
                .into_iter()
                .filter(|d| d.la_config_parsed().enabled)
                .map(|d| d.name)
                .collect()
        })
        .unwrap_or_default();
    for name in devices {
        fleet_converge_device(ctx, db_path, &name, &state).await;
    }
}

/// Converge one device's fleet card to the recomputed rows.
async fn fleet_converge_device(ctx: &Ctx, db_path: &Path, device_name: &str, state: &FleetState) {
    let Some(cfg) = load_cfg(ctx, db_path) else {
        return;
    };
    // Read everything first: the connection never crosses an await.
    let read = crate::db::open(db_path).ok().and_then(|conn| {
        let device = crate::db::device_get(&conn, device_name).ok()?;
        if !device.la_config_parsed().enabled {
            return None;
        }
        let token = crate::db::la_tokens_for_label(&conn, FLEET_LABEL)
            .unwrap_or_default()
            .into_iter()
            .find(|t| t.device == device_name)
            .map(|t| (t.activity_id, t.push_token));
        let changed = fleet_rows_changed(&conn, device_name, &state.rows);
        let pts = device.la_pts_token.clone().filter(|t| !t.trim().is_empty());
        let started = crate::db::meta_get(&conn, &fleet_started_key(device_name))
            .and_then(|s| s.parse::<u64>().ok());
        Some((device, token, changed, pts, started))
    });
    let Some((device, token, changed, pts, started)) = read else {
        return;
    };
    let now = crate::model::now_epoch();
    let content = crate::apns::fleet_content_state(&state.rows, state.updated_ts);
    match (token, changed) {
        (Some((id, push_token)), true) => {
            let payload = crate::apns::live_update_payload(&content, None, now);
            match push_live(ctx, &cfg, &device, &push_token, 5, &payload).await {
                crate::apns::SendOutcome::Sent { .. } => {
                    if let Ok(conn) = crate::db::open(db_path) {
                        fleet_rows_stored(&conn, device_name, &state.rows);
                    }
                }
                crate::apns::SendOutcome::Unregistered => {
                    // The card died: drop its row (the next change starts
                    // over via PTS) and say so once, throttled.
                    if let Ok(conn) = crate::db::open(db_path) {
                        let _ = crate::db::la_token_delete(&conn, device_name, &id);
                        fleet_rows_forget(&conn, device_name);
                        stale_notice(
                            &conn,
                            &ctx.throttle,
                            device_name,
                            "Apple rejected the fleet card token (410/BadDeviceToken); it was deleted",
                        );
                    }
                }
                _ => {}
            }
        }
        (Some(_), false) => {} // Rows unmoved: the 15s mirror stays quiet.
        // No card yet: start only when the rows moved since the last
        // start — otherwise a device whose app never reports the token
        // (old build, closed app) would eat a start every 15s.
        (None, false) => {}
        // A start is already outstanding and the app has not run since it
        // landed (its token never came back): hold. The card is live and
        // showing the last rows; starting again would stack a duplicate.
        (None, true) if started.is_some_and(|t| now.saturating_sub(t) < FLEET_START_HOLD_SECS) => {}
        (None, true) => {
            let Some(pts) = pts else {
                return;
            };
            let payload = crate::apns::fleet_start_payload(
                &content,
                FLEET_START_TITLE,
                &fleet_summary(&state.rows),
                now,
            );
            match push_live(ctx, &cfg, &device, &pts, 10, &payload).await {
                crate::apns::SendOutcome::Sent { .. } => {
                    if let Ok(conn) = crate::db::open(db_path) {
                        fleet_rows_stored(&conn, device_name, &state.rows);
                        let _ = crate::db::meta_set(
                            &conn,
                            &fleet_started_key(device_name),
                            &now.to_string(),
                        );
                    }
                }
                crate::apns::SendOutcome::Unregistered => {
                    if let Ok(conn) = crate::db::open(db_path) {
                        let _ = crate::db::la_pts_set(&conn, device_name, None);
                        fleet_rows_forget(&conn, device_name);
                        stale_notice(
                            &conn,
                            &ctx.throttle,
                            device_name,
                            "Apple rejected the push-to-start token (410/BadDeviceToken); it was cleared",
                        );
                    }
                }
                _ => {}
            }
        }
    }
}

/// End every labeled fleet card, dropping the rows as they land (or as
/// Apple reports them dead). A transport failure keeps the row — the
/// next trigger retries; worst case Apple retires the card.
async fn fleet_end_all(ctx: &Ctx, db_path: &Path) {
    let tokens = crate::db::open(db_path)
        .ok()
        .and_then(|conn| crate::db::la_tokens_for_label(&conn, FLEET_LABEL).ok())
        .unwrap_or_default();
    if tokens.is_empty() {
        return;
    }
    let Some(cfg) = load_cfg(ctx, db_path) else {
        return;
    };
    let now = crate::model::now_epoch();
    let payload = crate::apns::fleet_end_payload(&crate::apns::fleet_content_state(&[], now), now);
    for t in tokens {
        let device = crate::db::open(db_path)
            .ok()
            .and_then(|conn| crate::db::device_get(&conn, &t.device).ok());
        let Some(device) = device else {
            // The device is gone: drop its orphan row.
            if let Ok(conn) = crate::db::open(db_path) {
                let _ = crate::db::la_token_delete(&conn, &t.device, &t.activity_id);
            }
            continue;
        };
        match push_live(ctx, &cfg, &device, &t.push_token, 10, &payload).await {
            crate::apns::SendOutcome::Sent { .. } | crate::apns::SendOutcome::Unregistered => {
                if let Ok(conn) = crate::db::open(db_path) {
                    let _ = crate::db::la_token_delete(&conn, &t.device, &t.activity_id);
                    fleet_rows_forget(&conn, &t.device);
                }
            }
            _ => {}
        }
    }
}

/// A check flipped: every enabled device watching it (feed membership +
/// floor severity) converges — loud at 10 when it went down, quiet at 5
/// on recovery. `note` is the one-line down description for alerts.
/// A check flipped: page every device once (throttled per check, so
/// a flapping check buzzes at most every [`FLIP_PUSH_SECS`]) and
/// refresh every watching card. `row` is the queued `health.flip` row
/// the push delivers; `None` skips the push but still converges the
/// cards (tests, backfills, queue-write failures).
pub async fn on_flip(
    ctx: &Ctx,
    db_path: &Path,
    check_name: &str,
    went_down: bool,
    note: &str,
    row: Option<&crate::model::Notification>,
) {
    // Silence quiets the buzz, not the record: the queued row stays
    // for history, but neither the push nor the card trigger fires.
    if let Ok(conn) = crate::db::open(db_path)
        && crate::db::silenced(&conn, check_name, went_down, crate::model::now_epoch())
    {
        return;
    }
    // The incident card pins beside the status card: down push-to-starts
    // it per watching device, recovery ends every labeled row.
    incident_round(ctx, db_path, check_name, went_down, note).await;
    if let Some(row) = row
        && flip_push_due(&ctx.throttle, check_name)
        && let Some(cfg) = load_cfg(ctx, db_path)
    {
        let _ = crate::apns::deliver(&ctx.client, db_path, &cfg, row).await;
    }
    let targets: Vec<String> = crate::db::open(db_path)
        .ok()
        .and_then(|conn| {
            let check = crate::db::check_get(&conn, check_name).ok()?;
            let rank = severity_rank(&check.severity);
            let devices = crate::db::device_list(&conn).unwrap_or_default();
            Some(
                devices
                    .into_iter()
                    .filter(|d| {
                        let feed = d.la_config_parsed();
                        feed.enabled
                            && feed
                                .checks
                                .as_ref()
                                .is_none_or(|want| want.iter().any(|w| w == check_name))
                            && rank >= severity_rank(&feed.min_severity)
                    })
                    .map(|d| d.name)
                    .collect(),
            )
        })
        .unwrap_or_default();
    for name in targets {
        converge_device(ctx, db_path, &name, went_down, Some(note)).await;
    }
}

/// Approvals changed (asked or decided): every enabled device counting
/// them converges, quietly — counts are info, never a buzz.
pub async fn on_approvals_changed(ctx: &Ctx, db_path: &Path) {
    let targets: Vec<String> = crate::db::open(db_path)
        .ok()
        .map(|conn| {
            crate::db::device_list(&conn)
                .unwrap_or_default()
                .into_iter()
                .filter(|d| {
                    let feed = d.la_config_parsed();
                    feed.enabled && feed.approvals
                })
                .map(|d| d.name)
                .collect()
        })
        .unwrap_or_default();
    for name in targets {
        converge_device(ctx, db_path, &name, false, None).await;
    }
}

/// Disable's half: best-effort end the running card with its final
/// state, then forget the activity and every token — the stop is local
/// and unconditional, so it holds even unconfigured.
pub async fn disable_device(ctx: &Ctx, db_path: &Path, device_name: &str) {
    let end = load_cfg(ctx, db_path).and_then(|cfg| {
        crate::db::open(db_path).ok().and_then(|conn| {
            let device = crate::db::device_get(&conn, device_name).ok()?;
            let token = device.la_activity_id.as_deref().and_then(|id| {
                crate::db::la_tokens_for_device(&conn, device_name)
                    .unwrap_or_default()
                    .into_iter()
                    .find(|t| t.activity_id == id)
                    .map(|t| t.push_token)
            })?;
            let state = recompute(&conn, &device.la_config_parsed());
            Some((cfg, device, token, state))
        })
    });
    if let Some((cfg, device, token, state)) = end {
        let now = crate::model::now_epoch();
        let payload = crate::apns::live_end_payload(
            &state.content_state(now),
            now + END_DISMISS_AFTER_SECS,
            now,
        );
        // Best effort: the rows below die whatever Apple says.
        let _ = push_live(ctx, &cfg, &device, &token, 10, &payload).await;
    }
    if let Ok(conn) = crate::db::open(db_path) {
        let _ = crate::db::la_activity_set(&conn, device_name, None, None);
        let _ = crate::db::la_tokens_delete_device(&conn, device_name);
        // The fleet rows die too: a re-enable with identical rows must
        // still start the card over.
        fleet_rows_forget(&conn, device_name);
    }
}

/// The 6h refresh: every enabled device converges (self-healing when a
/// start never landed), and cards older than the refresh window restart
/// — end dismissed at once, fresh start — before Apple's ~8h auto-end.
/// The fleet card converges too (diff-gated, so usually quiet): this is
/// what ends a card the mirror abandoned overnight.
pub async fn refresh_all(ctx: &Ctx, db_path: &Path) {
    let devices: Vec<crate::model::Device> = crate::db::open(db_path)
        .ok()
        .and_then(|conn| crate::db::device_list(&conn).ok())
        .unwrap_or_default();
    let now = crate::model::now_epoch();
    for device in devices {
        if !device.la_config_parsed().enabled {
            continue;
        }
        let old = device.la_activity_id.is_some()
            && device
                .la_started_ts
                .is_some_and(|t| now.saturating_sub(t) > REFRESH_SECS);
        let pts = device
            .la_pts_token
            .as_deref()
            .is_some_and(|t| !t.is_empty());
        if old && pts {
            restart_device(ctx, db_path, &device.name).await;
        } else {
            converge_device(ctx, db_path, &device.name, false, None).await;
        }
    }
    on_agents_changed(ctx, db_path).await;
}

/// Restart one aging card: end (dismissed at once — the replacement is
/// incoming), then push-to-start the recomputed state. A clear feed
/// ends without a start; failures keep the old card for the next tick.
async fn restart_device(ctx: &Ctx, db_path: &Path, device_name: &str) {
    let Some(cfg) = load_cfg(ctx, db_path) else {
        return;
    };
    let read = crate::db::open(db_path).ok().and_then(|conn| {
        let device = crate::db::device_get(&conn, device_name).ok()?;
        let token = device.la_activity_id.as_deref().and_then(|id| {
            crate::db::la_tokens_for_device(&conn, device_name)
                .unwrap_or_default()
                .into_iter()
                .find(|t| t.activity_id == id)
                .map(|t| t.push_token)
        })?;
        let feed = device.la_config_parsed();
        if !feed.enabled {
            return None;
        }
        let state = recompute(&conn, &feed);
        let pts = device.la_pts_token.clone().filter(|t| !t.is_empty())?;
        Some((device, token, state, pts))
    });
    let Some((device, token, state, pts)) = read else {
        return;
    };
    let now = crate::model::now_epoch();
    let end = crate::apns::live_end_payload(&state.content_state(now), now, now);
    match push_live(ctx, &cfg, &device, &token, 10, &end).await {
        crate::apns::SendOutcome::Sent { .. } => {}
        crate::apns::SendOutcome::Unregistered => {
            if let Ok(conn) = crate::db::open(db_path) {
                forget_activity(&conn, device_name);
                stale_notice(
                    &conn,
                    &ctx.throttle,
                    device_name,
                    "Apple rejected the activity token (410/BadDeviceToken); it was deleted",
                );
            }
            return;
        }
        _ => return, // Keep the old card; the next tick retries.
    }
    if state.clear() {
        if let Ok(conn) = crate::db::open(db_path) {
            forget_activity(&conn, device_name);
        }
        mark_pushed(db_path, device_name, now);
        return;
    }
    let start = crate::apns::live_start_payload(
        device_name,
        CARD_TITLE,
        &state.content_state(now),
        CARD_TITLE,
        &state.summary(),
        now,
    );
    match push_live(ctx, &cfg, &device, &pts, 10, &start).await {
        crate::apns::SendOutcome::Sent { .. } => {
            if let Ok(conn) = crate::db::open(db_path) {
                // The old activity ended; the new id arrives via the
                // tokens route when the app reports it.
                forget_activity(&conn, device_name);
            }
            mark_pushed(db_path, device_name, now);
        }
        crate::apns::SendOutcome::Unregistered => {
            if let Ok(conn) = crate::db::open(db_path) {
                forget_activity(&conn, device_name);
                let _ = crate::db::la_pts_set(&conn, device_name, None);
                stale_notice(
                    &conn,
                    &ctx.throttle,
                    device_name,
                    "Apple rejected the push-to-start token (410/BadDeviceToken); it was cleared",
                );
            }
        }
        _ => {
            // The end landed but the start did not: forget anyway (the
            // old card is gone) and let the next tick start over.
            if let Ok(conn) = crate::db::open(db_path) {
                forget_activity(&conn, device_name);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use std::collections::VecDeque;

    // ---------------------------------------------------------------- harness

    /// One request the mock Apple saw: headers, token, and body.
    struct Captured {
        topic: String,
        push_type: String,
        priority: String,
        expiration: String,
        authed: bool,
        token: String,
        body: serde_json::Value,
    }

    /// One scripted mock response: status, body, and apns-id.
    type Scripted = VecDeque<(u16, serde_json::Value, Option<String>)>;

    #[derive(Clone)]
    struct MockState {
        captures: Arc<Mutex<Vec<Captured>>>,
        script: Arc<Mutex<Scripted>>,
    }

    async fn mock_push(
        axum::extract::State(st): axum::extract::State<MockState>,
        axum::extract::Path(token): axum::extract::Path<String>,
        headers: axum::http::HeaderMap,
        body: axum::body::Bytes,
    ) -> impl axum::response::IntoResponse {
        let get = |n: &str| {
            headers
                .get(n)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        };
        st.captures.lock().unwrap().push(Captured {
            topic: get("apns-topic"),
            push_type: get("apns-push-type"),
            priority: get("apns-priority"),
            expiration: get("apns-expiration"),
            authed: headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.starts_with("bearer ")),
            token,
            body: serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
        });
        let (status, payload, apns_id) = st.script.lock().unwrap().pop_front().unwrap_or((
            200,
            serde_json::json!({}),
            Some("mock-apns-id".to_string()),
        ));
        let mut res = (
            axum::http::StatusCode::from_u16(status).unwrap(),
            axum::Json(payload),
        )
            .into_response();
        if let Some(id) = apns_id {
            res.headers_mut().insert("apns-id", id.parse().unwrap());
        }
        res
    }

    /// A mock Apple on an ephemeral port: scripted (status, body,
    /// apns-id) triples, popped per request (default: 200 + id).
    async fn spawn_mock() -> (MockState, String) {
        let st = MockState {
            captures: Arc::new(Mutex::new(Vec::new())),
            script: Arc::new(Mutex::new(VecDeque::new())),
        };
        let app = axum::Router::new()
            .route("/3/device/{token}", axum::routing::post(mock_push))
            .with_state(st.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (st, base)
    }

    /// A fresh hub dir + db, APNs-configured (key + ids), with the ctx
    /// pointing at the mock host.
    struct Setup {
        dir: PathBuf,
        db_path: PathBuf,
        ctx: Ctx,
    }

    fn test_key_der() -> Vec<u8> {
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
        let rng = aws_lc_rs::rand::SystemRandom::new();
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .unwrap()
            .as_ref()
            .to_vec()
    }

    fn setup(name: &str, base: &str) -> Setup {
        let dir = std::env::temp_dir().join(format!("est-hub-live-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db_path = dir.join("hub.sqlite");
        let conn = crate::db::open(&db_path).unwrap();
        // The `.p8` (0600) plus the three ids: a configured hub.
        let key_path = dir.join("apns.p8");
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, test_key_der())
        );
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&key_path)
                .unwrap()
                .write_all(pem.as_bytes())
                .unwrap();
        }
        crate::db::meta_set(&conn, crate::apns::META_KEY_ID, "KEY1").unwrap();
        crate::db::meta_set(&conn, crate::apns::META_TEAM_ID, "TEAM1").unwrap();
        crate::db::meta_set(&conn, crate::apns::META_TOPIC, "com.estifie.app").unwrap();
        let ctx = Ctx {
            client: reqwest::Client::new(),
            apns_key: Some(key_path),
            throttle: Arc::new(Mutex::new(HashMap::new())),
            apns_base: Some(base.to_string()),
        };
        Setup { dir, db_path, ctx }
    }

    impl Drop for Setup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn enabled(
        conn: &rusqlite::Connection,
        device: &str,
        checks: Option<Vec<String>>,
        min_severity: &str,
        approvals: bool,
        alert_on_down: bool,
    ) {
        crate::db::device_add(conn, device, None).unwrap();
        crate::db::la_config_set(
            conn,
            device,
            &crate::model::LaConfig {
                enabled: true,
                checks,
                min_severity: min_severity.to_string(),
                approvals,
                alert_on_down,
            },
        )
        .unwrap();
    }

    fn add_check(conn: &rusqlite::Connection, name: &str, severity: &str) {
        let c = crate::model::NewCheck {
            name: Some(name.to_string()),
            owner: Some("estifie".to_string()),
            ctype: Some("url".to_string()),
            target: Some("https://example.com".to_string()),
            severity: Some(severity.to_string()),
            ..Default::default()
        };
        let valid = crate::model::validate_check(&c).unwrap();
        crate::db::check_add(conn, &valid).unwrap();
    }

    fn down(conn: &rusqlite::Connection, name: &str) {
        crate::db::record_result(conn, name, false, None, "refused", 1000, None).unwrap();
    }

    fn up(conn: &rusqlite::Connection, name: &str) {
        crate::db::record_result(conn, name, true, Some(200), "HTTP 200", 1001, None).unwrap();
    }

    fn running(conn: &rusqlite::Connection, device: &str, id: &str, token: &str, started: u64) {
        crate::db::la_token_upsert(conn, device, id, token, "", started).unwrap();
        crate::db::la_activity_set(conn, device, Some(id), Some(started)).unwrap();
    }

    /// The exact key set of an object.
    fn keys(v: &serde_json::Value) -> Vec<&str> {
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        keys
    }

    // ---------------------------------------------------------------- pure

    #[test]
    fn flip_push_throttles_per_check() {
        let throttle: Throttle = Arc::new(Mutex::new(HashMap::new()));
        assert!(flip_push_due(&throttle, "site"));
        assert!(!flip_push_due(&throttle, "site"));
        assert!(flip_push_due(&throttle, "other"));
    }

    #[test]
    fn recompute_respects_feed_severity_and_approvals() {
        let dir =
            std::env::temp_dir().join(format!("est-hub-live-{}-recompute", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let conn = crate::db::open(&dir.join("hub.sqlite")).unwrap();
        add_check(&conn, "site", "high");
        add_check(&conn, "blog", "low");
        add_check(&conn, "api", "normal");
        down(&conn, "site");
        down(&conn, "blog");
        up(&conn, "api");
        crate::db::approval_create(&conn, "deploy?", "", "", 3600).unwrap();
        // All checks, floor low, approvals on: everything counts.
        let cfg = crate::model::LaConfig {
            enabled: true,
            ..Default::default()
        };
        let s = recompute(&conn, &cfg);
        assert_eq!(s.down_count, 2);
        assert_eq!(s.worst, "high");
        assert_eq!(s.pending_approvals, 1);
        assert!(!s.clear());
        // A subset watches only itself.
        let cfg = crate::model::LaConfig {
            checks: Some(vec!["blog".to_string()]),
            ..cfg.clone()
        };
        let s = recompute(&conn, &cfg);
        assert_eq!(s.down_count, 1);
        assert_eq!(s.worst, "low");
        // The floor drops the low check.
        let cfg = crate::model::LaConfig {
            min_severity: "normal".to_string(),
            ..cfg.clone()
        };
        let s = recompute(&conn, &cfg);
        assert_eq!(s.down_count, 0);
        assert!(!s.clear()); // the approval still pends
        let cfg = crate::model::LaConfig {
            approvals: false,
            ..cfg.clone()
        };
        let s = recompute(&conn, &cfg);
        assert_eq!(s.pending_approvals, 0);
        assert!(s.clear());
        assert_eq!(s.worst, "low"); // the clear baseline
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn statuses_and_summaries_read() {
        let now = crate::model::now_epoch();
        assert_eq!(
            status_of(false, Some("a"), Some(now), Some(now), now),
            "off"
        );
        assert_eq!(status_of(true, None, None, None, now), "pending");
        assert_eq!(
            status_of(true, Some("a"), Some(now), Some(now), now),
            "active"
        );
        // Just reported, never pushed: active on the started grace.
        assert_eq!(status_of(true, Some("a"), Some(now), None, now), "active");
        assert_eq!(
            status_of(
                true,
                Some("a"),
                Some(now - 9 * 3600),
                Some(now - 9 * 3600),
                now
            ),
            "stale"
        );
        assert_eq!(
            status_of(true, Some("a"), Some(now - 9 * 3600), None, now),
            "stale"
        );
        let s = LiveState {
            down_count: 0,
            worst: "low".to_string(),
            pending_approvals: 0,
        };
        assert!(s.clear());
        assert_eq!(s.summary(), "all clear");
        let s = LiveState {
            down_count: 1,
            worst: "high".to_string(),
            pending_approvals: 0,
        };
        assert_eq!(s.summary(), "1 check down");
        let s = LiveState {
            down_count: 2,
            worst: "high".to_string(),
            pending_approvals: 1,
        };
        assert_eq!(s.summary(), "2 checks down · 1 approval pending");
        assert_eq!(severity_rank("low"), 0);
        assert_eq!(severity_rank("normal"), 1);
        assert_eq!(severity_rank("high"), 2);
        assert_eq!(severity_rank("weird"), 1);
    }

    // ---------------------------------------------------------------- fleet pure

    fn push_agent(
        conn: &rusqlite::Connection,
        pane: &str,
        title: &str,
        cwd: &str,
        status: &str,
        now: u64,
    ) {
        crate::db::agent_set(
            conn,
            pane,
            crate::db::AgentSnapshot {
                title,
                cwd,
                status,
                space: None,
                tab: None,
                output: None,
            },
            now,
        )
        .unwrap();
    }

    fn fleet_db(name: &str) -> rusqlite::Connection {
        let dir = std::env::temp_dir().join(format!("est-hub-live-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        crate::db::open(&dir.join("hub.sqlite")).unwrap()
    }

    #[test]
    fn display_name_prefers_placing_then_title_leaf_pane() {
        assert_eq!(
            agent_display_name("iOS", "SYSTEM", "Stale title", "/x", "w1:p1"),
            "iOS * SYSTEM"
        );
        assert_eq!(
            agent_display_name("iOS", "", "Export", "/x/y", "w1:p1"),
            "iOS"
        );
        assert_eq!(
            agent_display_name("", "", "Export", "/x/y", "w1:p1"),
            "Export"
        );
        assert_eq!(
            agent_display_name("", "", "  ", "/Users/x/Desktop/iOS", "w1:p1"),
            "iOS"
        );
        assert_eq!(
            agent_display_name("", "", "", "/Users/x/Desktop/iOS/", "w1:p1"),
            "iOS"
        );
        assert_eq!(agent_display_name("", "", "", "", "w1:p1"), "w1:p1");
        assert_eq!(agent_display_name("", "", "", "/", "w1:p1"), "w1:p1");
    }

    #[test]
    fn fleet_rows_live_recent_stale_and_cap() {
        let conn = fleet_db("fleet-rows");
        let now = crate::model::now_epoch();
        push_agent(&conn, "w1:p1", "Export", "/x/est", "working", now);
        push_agent(&conn, "w1:p2", "", "/x/ios", "blocked", now);
        push_agent(&conn, "w1:p3", "Old", "/x", "done", now - 100);
        push_agent(&conn, "w1:p4", "Ancient", "/x", "idle", now - 1000);
        push_agent(&conn, "w1:p5", "Ghost", "/x", "working", now - 700);
        let state = fleet_rows(&conn, now);
        // Live + recent render; old-settled and stale never do.
        assert_eq!(state.rows.len(), 3);
        assert_eq!(state.rows[0].pane, "w1:p1");
        assert_eq!(state.rows[0].name, "Export");
        assert_eq!(state.rows[0].status, "working");
        assert_eq!(state.rows[1].name, "ios");
        assert_eq!(state.rows[1].status, "blocked");
        assert_eq!(state.rows[2].status, "done");
        assert_eq!(state.updated_ts, now);
        // The cap keeps the Lock Screen readable.
        for i in 6..13 {
            push_agent(&conn, &format!("w2:p{i}"), "Agent", "/x", "working", now);
        }
        assert_eq!(fleet_rows(&conn, now).rows.len(), FLEET_MAX_ROWS);
    }

    #[test]
    fn fleet_summary_counts() {
        let row = |status: &str| crate::model::FleetRow {
            pane: "w1:p1".to_string(),
            name: "A".to_string(),
            status: status.to_string(),
        };
        assert_eq!(fleet_summary(&[]), "all clear");
        assert_eq!(
            fleet_summary(&[row("working"), row("working"), row("blocked")]),
            "2 working · 1 needs input"
        );
        assert_eq!(
            fleet_summary(&[row("blocked"), row("blocked"), row("done")]),
            "2 need input · 1 done"
        );
    }

    #[test]
    fn fleet_diff_gate_round_trip() {
        let conn = fleet_db("fleet-diff");
        let rows = vec![crate::model::FleetRow {
            pane: "w1:p1".to_string(),
            name: "A".to_string(),
            status: "working".to_string(),
        }];
        assert!(fleet_rows_changed(&conn, "phone", &rows));
        fleet_rows_stored(&conn, "phone", &rows);
        assert!(!fleet_rows_changed(&conn, "phone", &rows));
        let moved = vec![crate::model::FleetRow {
            status: "done".to_string(),
            ..rows[0].clone()
        }];
        assert!(fleet_rows_changed(&conn, "phone", &moved));
        fleet_rows_forget(&conn, "phone");
        assert!(fleet_rows_changed(&conn, "phone", &rows));
    }

    // ---------------------------------------------------------------- wire

    #[tokio::test]
    async fn flip_down_updates_loud_at_10() {
        let (mock, base) = spawn_mock().await;
        let t = setup("loud", &base);
        let conn = crate::db::open(&t.db_path).unwrap();
        enabled(&conn, "phone", None, "low", true, true);
        add_check(&conn, "site", "high");
        down(&conn, "site");
        running(&conn, "phone", "act-1", "tok-1", crate::model::now_epoch());
        drop(conn);
        converge_device(&t.ctx, &t.db_path, "phone", true, Some("site is DOWN")).await;
        let caps = mock.captures.lock().unwrap();
        assert_eq!(caps.len(), 1);
        let c = &caps[0];
        assert_eq!(c.token, "tok-1");
        assert_eq!(c.topic, "com.estifie.app.push-type.liveactivity");
        assert_eq!(c.push_type, "liveactivity");
        assert_eq!(c.priority, "10");
        assert_eq!(c.expiration, "0");
        assert!(c.authed);
        assert_eq!(c.body["aps"]["event"], "update");
        assert_eq!(
            keys(&c.body["aps"]["content-state"]),
            ["down_count", "pending_approvals", "updated_ts", "worst"]
        );
        assert_eq!(c.body["aps"]["content-state"]["down_count"], 1);
        assert_eq!(c.body["aps"]["content-state"]["worst"], "high");
        assert_eq!(c.body["aps"]["alert"]["title"], "site is DOWN");
        assert_eq!(c.body["aps"]["alert"]["body"], "1 check down");
        // The push stamped last-push.
        let conn = crate::db::open(&t.db_path).unwrap();
        assert!(crate::db::live_last_push_get(&conn, "phone").unwrap() > 1_700_000_000);
    }

    #[tokio::test]
    async fn fleet_starts_updates_silent_and_ends() {
        let (mock, base) = spawn_mock().await;
        let t = setup("fleet", &base);
        let conn = crate::db::open(&t.db_path).unwrap();
        enabled(&conn, "phone", None, "low", false, false);
        crate::db::la_pts_set(&conn, "phone", Some("pts-1")).unwrap();
        let now = crate::model::now_epoch();
        push_agent(&conn, "w1:p1", "Export", "/x/est", "working", now);
        drop(conn);
        // No card: push-to-start via PTS, loud (Apple mandates the alert).
        on_agents_changed(&t.ctx, &t.db_path).await;
        {
            let caps = mock.captures.lock().unwrap();
            assert_eq!(caps.len(), 1);
            assert_eq!(caps[0].token, "pts-1");
            assert_eq!(caps[0].priority, "10");
            assert_eq!(caps[0].body["aps"]["event"], "start");
            assert_eq!(
                caps[0].body["aps"]["attributes-type"],
                crate::apns::FLEET_ATTRIBUTES_TYPE
            );
            assert_eq!(caps[0].body["aps"]["attributes"], serde_json::json!({}));
            assert_eq!(
                keys(&caps[0].body["aps"]["content-state"]),
                ["rows", "updated_ts"]
            );
            assert_eq!(
                keys(&caps[0].body["aps"]["content-state"]["rows"][0]),
                ["name", "pane", "status"]
            );
            assert_eq!(
                caps[0].body["aps"]["content-state"]["rows"][0]["name"],
                "Export"
            );
            assert_eq!(caps[0].body["aps"]["alert"]["title"], FLEET_START_TITLE);
        }
        // The app reports the card's token, labeled: the next change
        // updates it silently instead of starting over.
        let conn = crate::db::open(&t.db_path).unwrap();
        crate::db::la_token_upsert(&conn, "phone", "act-f", "tok-f", FLEET_LABEL, now).unwrap();
        push_agent(&conn, "w1:p1", "Export", "/x/est", "done", now);
        drop(conn);
        on_agents_changed(&t.ctx, &t.db_path).await;
        {
            let caps = mock.captures.lock().unwrap();
            assert_eq!(caps.len(), 2);
            assert_eq!(caps[1].token, "tok-f");
            assert_eq!(caps[1].priority, "5");
            assert_eq!(caps[1].body["aps"]["event"], "update");
            assert!(caps[1].body["aps"].get("alert").is_none());
            assert_eq!(
                caps[1].body["aps"]["content-state"]["rows"][0]["status"],
                "done"
            );
        }
        // Same rows again (a fresh mirror stamp, nothing moved): quiet.
        let conn = crate::db::open(&t.db_path).unwrap();
        push_agent(&conn, "w1:p1", "Export", "/x/est", "done", now);
        drop(conn);
        on_agents_changed(&t.ctx, &t.db_path).await;
        assert_eq!(mock.captures.lock().unwrap().len(), 2);
        // Nothing live: end the card and drop its row.
        let conn = crate::db::open(&t.db_path).unwrap();
        crate::db::agent_delete(&conn, "w1:p1").unwrap();
        drop(conn);
        on_agents_changed(&t.ctx, &t.db_path).await;
        {
            let caps = mock.captures.lock().unwrap();
            assert_eq!(caps.len(), 3);
            assert_eq!(caps[2].token, "tok-f");
            assert_eq!(caps[2].body["aps"]["event"], "end");
            assert!(caps[2].body["aps"].get("dismissal-date").is_some());
        }
        let conn = crate::db::open(&t.db_path).unwrap();
        assert!(!crate::db::la_label_live(&conn, "phone", FLEET_LABEL));
    }

    #[tokio::test]
    async fn fleet_start_storms_nothing_without_a_token() {
        // The app never reports the card's token (closed app / old build):
        // repeated converges — and moved rows too — must not re-start, since
        // a fresh start could only stack a second card the hub can't end.
        let (mock, base) = spawn_mock().await;
        let t = setup("fleet-storm", &base);
        let conn = crate::db::open(&t.db_path).unwrap();
        enabled(&conn, "phone", None, "low", false, false);
        crate::db::la_pts_set(&conn, "phone", Some("pts-1")).unwrap();
        let now = crate::model::now_epoch();
        push_agent(&conn, "w1:p1", "Export", "/x/est", "working", now);
        drop(conn);
        on_agents_changed(&t.ctx, &t.db_path).await;
        on_agents_changed(&t.ctx, &t.db_path).await;
        on_agents_changed(&t.ctx, &t.db_path).await;
        assert_eq!(mock.captures.lock().unwrap().len(), 1);
        // Rows move before the token comes back: still one card, no stack.
        let conn = crate::db::open(&t.db_path).unwrap();
        push_agent(&conn, "w1:p1", "Export", "/x/est", "blocked", now);
        drop(conn);
        on_agents_changed(&t.ctx, &t.db_path).await;
        assert_eq!(mock.captures.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn fleet_restarts_once_the_hold_window_passes() {
        // The hold only lasts while the first card can still be live; past
        // Apple's 8h cap the old card is gone, so a fresh start is safe.
        let (mock, base) = spawn_mock().await;
        let t = setup("fleet-hold", &base);
        let conn = crate::db::open(&t.db_path).unwrap();
        enabled(&conn, "phone", None, "low", false, false);
        crate::db::la_pts_set(&conn, "phone", Some("pts-1")).unwrap();
        let now = crate::model::now_epoch();
        push_agent(&conn, "w1:p1", "Export", "/x/est", "working", now);
        drop(conn);
        on_agents_changed(&t.ctx, &t.db_path).await;
        assert_eq!(mock.captures.lock().unwrap().len(), 1);
        // Age the outstanding start past the hold window; rows move: start.
        let conn = crate::db::open(&t.db_path).unwrap();
        crate::db::meta_set(
            &conn,
            &fleet_started_key("phone"),
            &(now - FLEET_START_HOLD_SECS - 1).to_string(),
        )
        .unwrap();
        push_agent(&conn, "w1:p1", "Export", "/x/est", "blocked", now);
        drop(conn);
        on_agents_changed(&t.ctx, &t.db_path).await;
        assert_eq!(mock.captures.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn fleet_ignores_disabled_devices() {
        let (mock, base) = spawn_mock().await;
        let t = setup("fleet-off", &base);
        let conn = crate::db::open(&t.db_path).unwrap();
        crate::db::device_add(&conn, "phone", None).unwrap();
        crate::db::la_pts_set(&conn, "phone", Some("pts-1")).unwrap();
        push_agent(
            &conn,
            "w1:p1",
            "Export",
            "/x",
            "working",
            crate::model::now_epoch(),
        );
        drop(conn);
        on_agents_changed(&t.ctx, &t.db_path).await;
        assert!(mock.captures.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn recovery_updates_silent_at_5() {
        let (mock, base) = spawn_mock().await;
        let t = setup("quiet", &base);
        let conn = crate::db::open(&t.db_path).unwrap();
        enabled(&conn, "phone", None, "low", false, true);
        add_check(&conn, "site", "normal");
        add_check(&conn, "blog", "normal");
        down(&conn, "site");
        down(&conn, "blog");
        up(&conn, "blog"); // one recovers, one still down
        running(&conn, "phone", "act-1", "tok-1", crate::model::now_epoch());
        drop(conn);
        converge_device(&t.ctx, &t.db_path, "phone", false, None).await;
        let caps = mock.captures.lock().unwrap();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].priority, "5");
        assert_eq!(caps[0].body["aps"]["event"], "update");
        assert!(caps[0].body["aps"].get("alert").is_none());
        assert_eq!(caps[0].body["aps"]["content-state"]["down_count"], 1);
    }

    #[tokio::test]
    async fn clear_card_ends_with_final_state() {
        let (mock, base) = spawn_mock().await;
        let t = setup("end", &base);
        let conn = crate::db::open(&t.db_path).unwrap();
        enabled(&conn, "phone", None, "low", false, true);
        add_check(&conn, "site", "normal");
        up(&conn, "site");
        running(&conn, "phone", "act-1", "tok-1", crate::model::now_epoch());
        drop(conn);
        converge_device(&t.ctx, &t.db_path, "phone", false, None).await;
        let caps = mock.captures.lock().unwrap();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].body["aps"]["event"], "end");
        assert_eq!(caps[0].body["aps"]["content-state"]["down_count"], 0);
        assert_eq!(
            keys(&caps[0].body["aps"]["content-state"]),
            ["down_count", "pending_approvals", "updated_ts", "worst"]
        );
        let ts = caps[0].body["aps"]["timestamp"].as_u64().unwrap();
        assert_eq!(
            caps[0].body["aps"]["dismissal-date"],
            ts + END_DISMISS_AFTER_SECS
        );
        // The end forgot the activity and its token.
        let conn = crate::db::open(&t.db_path).unwrap();
        assert_eq!(
            crate::db::device_get(&conn, "phone")
                .unwrap()
                .la_activity_id,
            None
        );
        assert!(
            crate::db::la_tokens_for_device(&conn, "phone")
                .unwrap()
                .is_empty()
        );
        assert!(crate::db::live_last_push_get(&conn, "phone").is_some());
    }

    #[tokio::test]
    async fn no_card_push_to_starts_via_pts() {
        let (mock, base) = spawn_mock().await;
        let t = setup("start", &base);
        let conn = crate::db::open(&t.db_path).unwrap();
        enabled(&conn, "phone", None, "low", true, true);
        crate::db::la_pts_set(&conn, "phone", Some("pts-1")).unwrap();
        add_check(&conn, "site", "normal");
        down(&conn, "site");
        drop(conn);
        converge_device(&t.ctx, &t.db_path, "phone", true, Some("site is DOWN")).await;
        let caps = mock.captures.lock().unwrap();
        assert_eq!(caps.len(), 1);
        let c = &caps[0];
        assert_eq!(c.token, "pts-1");
        assert_eq!(c.priority, "10");
        assert_eq!(c.body["aps"]["event"], "start");
        assert_eq!(
            c.body["aps"]["attributes-type"],
            crate::apns::LA_ATTRIBUTES_TYPE
        );
        assert_eq!(keys(&c.body["aps"]["attributes"]), ["device_name", "title"]);
        assert_eq!(c.body["aps"]["attributes"]["device_name"], "phone");
        assert_eq!(c.body["aps"]["content-state"]["down_count"], 1);
        // The alert is required on start.
        assert_eq!(c.body["aps"]["alert"]["title"], "site is DOWN");
        assert!(!c.body["aps"]["alert"]["body"].as_str().unwrap().is_empty());
        // The activity id stays unknown until the app reports it.
        let conn = crate::db::open(&t.db_path).unwrap();
        assert_eq!(
            crate::db::device_get(&conn, "phone")
                .unwrap()
                .la_activity_id,
            None
        );
        assert!(crate::db::live_last_push_get(&conn, "phone").is_some());
    }

    #[tokio::test]
    async fn clear_or_unreachable_sends_nothing() {
        let (mock, base) = spawn_mock().await;
        let t = setup("nothing", &base);
        let conn = crate::db::open(&t.db_path).unwrap();
        // Clear with PTS: no start for an empty card.
        enabled(&conn, "clear", None, "low", false, true);
        crate::db::la_pts_set(&conn, "clear", Some("pts-1")).unwrap();
        add_check(&conn, "site", "normal");
        up(&conn, "site");
        // Down with neither token nor PTS: unreachable.
        enabled(
            &conn,
            "bare",
            Some(vec!["site".to_string()]),
            "low",
            false,
            true,
        );
        // Disabled with everything: off means off.
        crate::db::device_add(&conn, "off", None).unwrap();
        crate::db::la_pts_set(&conn, "off", Some("pts-2")).unwrap();
        drop(conn);
        converge_device(&t.ctx, &t.db_path, "clear", false, None).await;
        converge_device(&t.ctx, &t.db_path, "bare", true, Some("x")).await;
        converge_device(&t.ctx, &t.db_path, "off", true, Some("x")).await;
        converge_device(&t.ctx, &t.db_path, "ghost", true, Some("x")).await;
        assert!(mock.captures.lock().unwrap().is_empty());
        // Down but unreachable stays unstamped.
        let conn = crate::db::open(&t.db_path).unwrap();
        assert_eq!(crate::db::live_last_push_get(&conn, "bare"), None);
    }

    #[tokio::test]
    async fn unregistered_deletes_and_throttles_the_notice() {
        let (mock, base) = spawn_mock().await;
        let t = setup("gone", &base);
        let conn = crate::db::open(&t.db_path).unwrap();
        enabled(&conn, "phone", None, "low", false, true);
        add_check(&conn, "site", "normal");
        down(&conn, "site");
        running(&conn, "phone", "act-1", "tok-1", crate::model::now_epoch());
        drop(conn);
        // First 410: the token dies, one notice queues.
        mock.script.lock().unwrap().push_back((
            410,
            serde_json::json!({"reason": "Unregistered"}),
            None,
        ));
        converge_device(&t.ctx, &t.db_path, "phone", true, Some("x")).await;
        let conn = crate::db::open(&t.db_path).unwrap();
        assert!(
            crate::db::la_tokens_for_device(&conn, "phone")
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            crate::db::device_get(&conn, "phone")
                .unwrap()
                .la_activity_id,
            None
        );
        let stale = |conn: &rusqlite::Connection| {
            crate::db::notification_list(conn, 50)
                .unwrap()
                .iter()
                .filter(|n| n.topic == "live.stale")
                .count()
        };
        assert_eq!(stale(&conn), 1);
        // Re-report, fail again: the throttle holds at one notice.
        running(&conn, "phone", "act-2", "tok-2", crate::model::now_epoch());
        drop(conn);
        mock.script.lock().unwrap().push_back((
            400,
            serde_json::json!({"reason": "BadDeviceToken"}),
            None,
        ));
        converge_device(&t.ctx, &t.db_path, "phone", true, Some("x")).await;
        let conn = crate::db::open(&t.db_path).unwrap();
        assert!(
            crate::db::la_tokens_for_device(&conn, "phone")
                .unwrap()
                .is_empty()
        );
        assert_eq!(stale(&conn), 1);
        let note = crate::db::notification_list(&conn, 50)
            .unwrap()
            .into_iter()
            .find(|n| n.topic == "live.stale")
            .unwrap();
        assert_eq!(note.to_device, "phone");
        // A dead PTS token clears the same way (throttle shared).
        crate::db::la_pts_set(&conn, "phone", Some("pts-1")).unwrap();
        drop(conn);
        mock.script.lock().unwrap().push_back((
            410,
            serde_json::json!({"reason": "Unregistered"}),
            None,
        ));
        converge_device(&t.ctx, &t.db_path, "phone", true, Some("x")).await;
        let conn = crate::db::open(&t.db_path).unwrap();
        assert_eq!(
            crate::db::device_get(&conn, "phone").unwrap().la_pts_token,
            None
        );
        assert_eq!(stale(&conn), 1);
    }

    #[tokio::test]
    async fn topics_override_then_fall_back() {
        let (mock, base) = spawn_mock().await;
        let t = setup("topics", &base);
        let conn = crate::db::open(&t.db_path).unwrap();
        enabled(&conn, "custom", None, "low", false, true);
        enabled(&conn, "plain", None, "low", false, true);
        crate::db::device_update_apns(&conn, "custom", None, None, Some("com.owner.sidecar"))
            .unwrap();
        add_check(&conn, "site", "normal");
        down(&conn, "site");
        running(&conn, "custom", "act-c", "tok-c", crate::model::now_epoch());
        running(&conn, "plain", "act-p", "tok-p", crate::model::now_epoch());
        drop(conn);
        converge_device(&t.ctx, &t.db_path, "custom", true, Some("x")).await;
        converge_device(&t.ctx, &t.db_path, "plain", true, Some("x")).await;
        let caps = mock.captures.lock().unwrap();
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0].topic, "com.owner.sidecar.push-type.liveactivity");
        assert_eq!(caps[1].topic, "com.estifie.app.push-type.liveactivity");
    }

    #[tokio::test]
    async fn flip_fans_out_only_to_watchers() {
        let (mock, base) = spawn_mock().await;
        let t = setup("fanout", &base);
        let conn = crate::db::open(&t.db_path).unwrap();
        enabled(
            &conn,
            "watcher",
            Some(vec!["site".to_string()]),
            "low",
            false,
            true,
        );
        enabled(
            &conn,
            "other",
            Some(vec!["blog".to_string()]),
            "low",
            false,
            true,
        );
        enabled(&conn, "picky", None, "high", false, true);
        add_check(&conn, "site", "normal");
        add_check(&conn, "blog", "normal");
        down(&conn, "site");
        down(&conn, "blog");
        let now = crate::model::now_epoch();
        running(&conn, "watcher", "act-w", "tok-w", now);
        running(&conn, "other", "act-o", "tok-o", now);
        running(&conn, "picky", "act-p", "tok-p", now);
        drop(conn);
        // `site` (normal) flipped down: its watcher hears it; the blog
        // watcher and the high-floor device hear nothing.
        on_flip(&t.ctx, &t.db_path, "site", true, "site is DOWN", None).await;
        let caps = mock.captures.lock().unwrap();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].token, "tok-w");
        assert_eq!(caps[0].priority, "10");
    }

    #[tokio::test]
    async fn silenced_flips_send_nothing() {
        let (mock, base) = spawn_mock().await;
        let t = setup("silence-fanout", &base);
        let conn = crate::db::open(&t.db_path).unwrap();
        enabled(
            &conn,
            "watcher",
            Some(vec!["site".to_string()]),
            "low",
            false,
            true,
        );
        add_check(&conn, "site", "normal");
        down(&conn, "site");
        let now = crate::model::now_epoch();
        running(&conn, "watcher", "act-w", "tok-w", now);
        crate::db::silence_set(&conn, "site", "mute", now + 3600, "", now).unwrap();
        crate::db::la_pts_set(&conn, "watcher", Some("pts-w")).unwrap();
        drop(conn);
        // Muted: neither the down page, the status converge, nor the
        // incident start fires — even with a PTS token ready.
        on_flip(&t.ctx, &t.db_path, "site", true, "site is DOWN", None).await;
        on_flip(&t.ctx, &t.db_path, "site", false, "site is back up", None).await;
        assert!(mock.captures.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn ack_hushes_the_page_but_not_the_recovery() {
        let (mock, base) = spawn_mock().await;
        let t = setup("silence-ack", &base);
        let conn = crate::db::open(&t.db_path).unwrap();
        enabled(
            &conn,
            "watcher",
            Some(vec!["site".to_string()]),
            "low",
            false,
            true,
        );
        add_check(&conn, "site", "normal");
        down(&conn, "site");
        let now = crate::model::now_epoch();
        running(&conn, "watcher", "act-w", "tok-w", now);
        crate::db::silence_set(&conn, "site", "ack", now + 3600, "", now).unwrap();
        drop(conn);
        on_flip(&t.ctx, &t.db_path, "site", true, "site is DOWN", None).await;
        assert!(mock.captures.lock().unwrap().is_empty());
        // Recovery still converges the card: the ack quiets the page,
        // never the good news.
        on_flip(&t.ctx, &t.db_path, "site", false, "site is back up", None).await;
        let caps = mock.captures.lock().unwrap();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].token, "tok-w");
    }

    #[test]
    fn down_reason_strips_the_note_or_empty() {
        assert_eq!(down_reason("🔴 site is DOWN — refused", "site"), "refused");
        assert_eq!(down_reason("🟢 site is back up", "site"), "");
        assert_eq!(down_reason("garbage", "site"), "");
    }

    #[tokio::test]
    async fn down_flip_starts_one_incident_card_per_watcher() {
        let (mock, base) = spawn_mock().await;
        let t = setup("incident-start", &base);
        let conn = crate::db::open(&t.db_path).unwrap();
        enabled(
            &conn,
            "watcher",
            Some(vec!["site".to_string()]),
            "low",
            false,
            true,
        );
        enabled(
            &conn,
            "other",
            Some(vec!["blog".to_string()]),
            "low",
            false,
            true,
        );
        crate::db::la_pts_set(&conn, "watcher", Some("pts-w")).unwrap();
        crate::db::la_pts_set(&conn, "other", Some("pts-o")).unwrap();
        add_check(&conn, "site", "normal");
        add_check(&conn, "blog", "normal");
        down(&conn, "site");
        drop(conn);
        on_flip(
            &t.ctx,
            &t.db_path,
            "site",
            true,
            "🔴 site is DOWN — refused",
            None,
        )
        .await;
        let caps = mock.captures.lock().unwrap();
        // Two cards, one device: the incident pins first, then the
        // status card starts (it has news and no card yet). The blog
        // watcher hears nothing.
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0].token, "pts-w");
        assert_eq!(caps[0].body["aps"]["event"], "start");
        assert_eq!(
            caps[0].body["aps"]["attributes-type"],
            "ESTIncidentAttributes"
        );
        assert_eq!(caps[0].body["aps"]["attributes"]["check_name"], "site");
        assert_eq!(caps[0].body["aps"]["content-state"]["reason"], "refused");
        assert!(
            caps[0].body["aps"]["content-state"]["since_ts"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(caps[1].token, "pts-w");
        assert_eq!(
            caps[1].body["aps"]["attributes-type"],
            "ESTStatusAttributes"
        );
    }

    #[tokio::test]
    async fn live_incident_cards_skip_restart_and_end_on_recovery() {
        let (mock, base) = spawn_mock().await;
        let t = setup("incident-end", &base);
        let conn = crate::db::open(&t.db_path).unwrap();
        enabled(&conn, "watcher", None, "low", false, true);
        crate::db::la_pts_set(&conn, "watcher", Some("pts-w")).unwrap();
        add_check(&conn, "site", "normal");
        down(&conn, "site");
        let now = crate::model::now_epoch();
        // The app reported the push-started card (label included).
        crate::db::la_token_upsert(&conn, "watcher", "act-i", "tok-i", "incident:site", now)
            .unwrap();
        assert!(crate::db::la_label_live(&conn, "watcher", "incident:site"));
        drop(conn);
        // A repeat down flip restarts no incident (the status card
        // still converges — it has news and no card yet).
        on_flip(
            &t.ctx,
            &t.db_path,
            "site",
            true,
            "🔴 site is DOWN — refused",
            None,
        )
        .await;
        {
            let caps = mock.captures.lock().unwrap();
            assert!(
                caps.iter()
                    .all(|c| { c.body["aps"]["attributes-type"] != "ESTIncidentAttributes" }),
                "incident restarted despite the live label"
            );
        }
        // Recovery ends the labeled card and drops the row.
        on_flip(
            &t.ctx,
            &t.db_path,
            "site",
            false,
            "🟢 site is back up",
            None,
        )
        .await;
        let caps = mock.captures.lock().unwrap();
        let ends: Vec<_> = caps
            .iter()
            .filter(|c| c.body["aps"]["event"] == "end" && c.token == "tok-i")
            .collect();
        assert_eq!(ends.len(), 1);
        assert!(ends[0].body["aps"]["dismissal-date"].as_u64().unwrap() > 0);
        let conn = crate::db::open(&t.db_path).unwrap();
        assert!(!crate::db::la_label_live(&conn, "watcher", "incident:site"));
    }

    #[tokio::test]
    async fn approvals_change_converges_quietly() {
        let (mock, base) = spawn_mock().await;
        let t = setup("counts", &base);
        let conn = crate::db::open(&t.db_path).unwrap();
        enabled(&conn, "phone", None, "low", true, true);
        enabled(&conn, "nocount", None, "low", false, true);
        running(&conn, "phone", "act-1", "tok-1", crate::model::now_epoch());
        running(
            &conn,
            "nocount",
            "act-2",
            "tok-2",
            crate::model::now_epoch(),
        );
        crate::db::approval_create(&conn, "deploy?", "", "", 3600).unwrap();
        drop(conn);
        on_approvals_changed(&t.ctx, &t.db_path).await;
        let caps = mock.captures.lock().unwrap();
        // Only the counting device; a quiet info update.
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].token, "tok-1");
        assert_eq!(caps[0].priority, "5");
        assert!(caps[0].body["aps"].get("alert").is_none());
        assert_eq!(caps[0].body["aps"]["content-state"]["pending_approvals"], 1);
    }

    #[tokio::test]
    async fn refresh_restarts_old_cards_and_updates_young_ones() {
        let (mock, base) = spawn_mock().await;
        let t = setup("refresh", &base);
        let conn = crate::db::open(&t.db_path).unwrap();
        let now = crate::model::now_epoch();
        enabled(&conn, "old", None, "low", false, true);
        enabled(&conn, "young", None, "low", false, true);
        crate::db::la_pts_set(&conn, "old", Some("pts-old")).unwrap();
        add_check(&conn, "site", "normal");
        down(&conn, "site");
        running(&conn, "old", "act-old", "tok-old", now - 7 * 3600);
        running(&conn, "young", "act-young", "tok-young", now);
        drop(conn);
        refresh_all(&t.ctx, &t.db_path).await;
        let caps = mock.captures.lock().unwrap();
        // Alphabetical: old restarts (end + start), young updates.
        assert_eq!(caps.len(), 3);
        assert_eq!(caps[0].token, "tok-old");
        assert_eq!(caps[0].body["aps"]["event"], "end");
        assert_eq!(
            caps[0].body["aps"]["dismissal-date"],
            caps[0].body["aps"]["timestamp"]
        );
        assert_eq!(caps[1].token, "pts-old");
        assert_eq!(caps[1].body["aps"]["event"], "start");
        assert_eq!(caps[2].token, "tok-young");
        assert_eq!(caps[2].body["aps"]["event"], "update");
        assert_eq!(caps[2].priority, "5");
        // The old activity is forgotten; the new id arrives via tokens.
        let conn = crate::db::open(&t.db_path).unwrap();
        assert_eq!(
            crate::db::device_get(&conn, "old").unwrap().la_activity_id,
            None
        );
        assert!(crate::db::live_last_push_get(&conn, "old").is_some());
    }

    #[tokio::test]
    async fn disable_ends_and_stops_even_unconfigured() {
        let (mock, base) = spawn_mock().await;
        let t = setup("disable", &base);
        let conn = crate::db::open(&t.db_path).unwrap();
        enabled(&conn, "phone", None, "low", false, true);
        add_check(&conn, "site", "normal");
        down(&conn, "site");
        running(&conn, "phone", "act-1", "tok-1", crate::model::now_epoch());
        drop(conn);
        disable_device(&t.ctx, &t.db_path, "phone").await;
        {
            let caps = mock.captures.lock().unwrap();
            assert_eq!(caps.len(), 1);
            assert_eq!(caps[0].body["aps"]["event"], "end");
            assert_eq!(caps[0].body["aps"]["content-state"]["down_count"], 1);
        }
        let conn = crate::db::open(&t.db_path).unwrap();
        assert_eq!(
            crate::db::device_get(&conn, "phone")
                .unwrap()
                .la_activity_id,
            None
        );
        assert!(
            crate::db::la_tokens_for_device(&conn, "phone")
                .unwrap()
                .is_empty()
        );
        drop(conn);
        // Unconfigured (key + ids gone): no push, but the stop holds.
        let conn = crate::db::open(&t.db_path).unwrap();
        running(&conn, "phone", "act-2", "tok-2", crate::model::now_epoch());
        crate::db::meta_del(&conn, crate::apns::META_KEY_ID).unwrap();
        std::fs::remove_file(t.dir.join("apns.p8")).unwrap();
        drop(conn);
        disable_device(&t.ctx, &t.db_path, "phone").await;
        assert_eq!(mock.captures.lock().unwrap().len(), 1);
        let conn = crate::db::open(&t.db_path).unwrap();
        assert!(
            crate::db::la_tokens_for_device(&conn, "phone")
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn unconfigured_converges_to_nothing() {
        let (_mock, base) = spawn_mock().await;
        let t = setup("unconf", &base);
        // No key, no ids: flips are silent (queue-only hubs unaffected).
        std::fs::remove_file(t.dir.join("apns.p8")).unwrap();
        let conn = crate::db::open(&t.db_path).unwrap();
        crate::db::meta_del(&conn, crate::apns::META_KEY_ID).unwrap();
        crate::db::meta_del(&conn, crate::apns::META_TEAM_ID).unwrap();
        crate::db::meta_del(&conn, crate::apns::META_TOPIC).unwrap();
        enabled(&conn, "phone", None, "low", false, true);
        add_check(&conn, "site", "normal");
        down(&conn, "site");
        running(&conn, "phone", "act-1", "tok-1", crate::model::now_epoch());
        drop(conn);
        converge_device(&t.ctx, &t.db_path, "phone", true, Some("x")).await;
        on_flip(&t.ctx, &t.db_path, "site", true, "x", None).await;
        refresh_all(&t.ctx, &t.db_path).await;
        // Nothing pushed, nothing stamped, tokens kept.
        let conn = crate::db::open(&t.db_path).unwrap();
        assert_eq!(crate::db::live_last_push_get(&conn, "phone"), None);
        assert_eq!(
            crate::db::la_tokens_for_device(&conn, "phone")
                .unwrap()
                .len(),
            1
        );
    }
}
