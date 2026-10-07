//! Shapes the hub stores and serves: devices, checks, results,
//! approvals, notifications. Validation lives here so the API and the
//! CLI reject the same things the same way.

use serde::{Deserialize, Serialize};

/// `[a-z][a-z0-9_-]{0,31}`: check names, device names, reporter ids.
/// Same rule as Herdr agent names, so reporters translate 1:1.
pub fn valid_name(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=32).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// A herdr pane id (`w7:p1P`): short, no spaces, no slashes (it
/// rides a path segment). Uppercase and `:` are legal here — this is
/// deliberately wider than [`valid_name`].
pub fn valid_pane(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=64).contains(&b.len())
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b':' || *c == b'_' || *c == b'-')
}

/// The five herdr lifecycle states, mirrored verbatim: the hub stores
/// what herdr reports, never its own vocabulary.
pub fn valid_agent_status(s: &str) -> bool {
    matches!(s, "working" | "done" | "idle" | "blocked" | "unknown")
}

/// Past this many quiet seconds an agent row reads `stale` (the
/// watcher pushes every ~15s; ten silent minutes means it is dead,
/// not the agent). Display-only — stale never pages.
pub const AGENT_STALE_AFTER_SECS: u64 = 600;

fn valid_url(s: &str) -> bool {
    (s.starts_with("http://") || s.starts_with("https://"))
        && s.len() <= 2048
        && !s.chars().any(char::is_whitespace)
}

// ---------------------------------------------------------------- devices

/// A known device. Access is Tailscale membership, so a device is just
/// a name plus whatever push state the app has reported.
#[derive(Clone)]
pub struct Device {
    /// Device address, `[a-z][a-z0-9_-]{0,31}`.
    pub name: String,
    /// APNs device token, once the app registers it.
    pub apns_token: Option<String>,
    /// When it first registered, unix seconds.
    pub created_ts: u64,
    /// Always `active` (kept so legacy rows read uniformly).
    pub state: String,
    /// `development` or `production`, once the app reports it.
    pub apns_env: Option<String>,
    /// Per-device `apns-topic` override (a bundle id); `None` reads the
    /// hub-wide `apns.topic` from `meta`. Bundle ids are public.
    pub apns_topic: Option<String>,
    /// Push-to-start token, once the app reports it. Hub-only (it starts
    /// activities), so never serialized — like `apns_token`.
    pub la_pts_token: Option<String>,
    /// Live Activity feed config as JSON ([`LaConfig`]); `None` reads
    /// the default (off). Never serialized; the live-activity routes
    /// serve the parsed shape instead.
    pub la_config: Option<String>,
    /// The current Live Activity id, once the app reports its token.
    /// Never serialized.
    pub la_activity_id: Option<String>,
    /// When the current activity started, unix seconds. Never serialized.
    pub la_started_ts: Option<u64>,
}

/// Ack quiets the down page this long unless the check recovers first
/// (recovery clears the ack and always buzzes, unless muted).
pub const ACK_DEFAULT_SECS: u64 = 2 * 3600;
/// Ack never outlives a day: a forgotten ack must not hide an outage.
pub const ACK_MAX_SECS: u64 = 24 * 3600;
/// Mute quiets both directions this long unless told otherwise.
pub const MUTE_DEFAULT_SECS: u64 = 24 * 3600;
/// Mute never outlives a month: silence must be re-earned.
pub const MUTE_MAX_SECS: u64 = 30 * 86400;

impl Device {
    /// True when a non-empty APNs token is stored. Clients read this
    /// bit; only the hub ever needs the token itself.
    pub fn apns_configured(&self) -> bool {
        self.apns_token.as_deref().is_some_and(|t| !t.is_empty())
    }

    /// The parsed Live Activity config: stored JSON, or the default
    /// when unset or unreadable (a corrupt row reads off, never loud).
    pub fn la_config_parsed(&self) -> LaConfig {
        self.la_config
            .as_deref()
            .and_then(|raw| serde_json::from_str(raw).ok())
            .unwrap_or_default()
    }
}

// Manual so serialization carries the derived `apns_configured` bit
// beside the stored fields (additive: every old field keeps its shape).
// The `la_*` fields stay out: the PTS token is hub-only, and the rest
// rides the live-activity routes, not the device object.
impl Serialize for Device {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("Device", 7)?;
        st.serialize_field("name", &self.name)?;
        st.serialize_field("apns_token", &self.apns_token)?;
        st.serialize_field("created_ts", &self.created_ts)?;
        st.serialize_field("state", &self.state)?;
        st.serialize_field("apns_env", &self.apns_env)?;
        st.serialize_field("apns_topic", &self.apns_topic)?;
        st.serialize_field("apns_configured", &self.apns_configured())?;
        st.end()
    }
}

/// What `POST /devices` takes.
#[derive(Deserialize)]
pub struct NewDevice {
    /// Device address (required).
    pub name: Option<String>,
    /// APNs device token, if known yet.
    pub apns_token: Option<String>,
}

/// Name plus optional token, or why the device is unacceptable.
pub fn validate_device(d: &NewDevice) -> Result<(String, Option<String>), String> {
    let name = d.name.as_deref().unwrap_or("").trim();
    if !valid_name(name) {
        return Err("name must match [a-z][a-z0-9_-]{0,31}".to_string());
    }
    if d.apns_token.as_deref().unwrap_or("").len() > 512 {
        return Err("apns_token is too long (512 max)".to_string());
    }
    Ok((
        name.to_string(),
        d.apns_token.clone().filter(|s| !s.trim().is_empty()),
    ))
}

// ---------------------------------------------------------------- live activity

/// The default `min_severity`: `low`, so every severity passes.
fn default_min_severity() -> String {
    "low".to_string()
}

/// Serde default for the toggles that start on.
fn default_true() -> bool {
    true
}

/// One device's Live Activity feed: which checks the hub watches for
/// it, how severe they must be to count, and how loud to be. Stored as
/// one JSON blob on the device row; unset reads the default (off, so
/// no pushes until the owner opts in).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct LaConfig {
    /// Master switch. Off until set — the hub never pushes uninvited.
    #[serde(default)]
    pub enabled: bool,
    /// Feed: `None` watches every check, `Some` watches exactly these.
    /// Writes normalize an empty list to `None` (the app sends [] for
    /// its "All checks" toggle), so `Some` is never empty on disk.
    #[serde(default)]
    pub checks: Option<Vec<String>>,
    /// Floor severity: `low`, `normal`, or `high`. A down check counts
    /// only at or above this (default `low` = everything counts).
    #[serde(default = "default_min_severity")]
    pub min_severity: String,
    /// Fold pending approvals into the card's count (default on).
    #[serde(default = "default_true")]
    pub approvals: bool,
    /// Buzz when a watched check goes down (default on). Recoveries
    /// update silently; starts always alert (Apple requires it).
    #[serde(default = "default_true")]
    pub alert_on_down: bool,
}

impl Default for LaConfig {
    fn default() -> Self {
        LaConfig {
            enabled: false,
            checks: None,
            min_severity: "low".to_string(),
            approvals: true,
            alert_on_down: true,
        }
    }
}

/// One reported Live Activity push token: the app starts (or resumes)
/// an activity, then upserts its id + token here so hub pushes reach it.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LaToken {
    /// Apple's activity id (the row key).
    pub activity_id: String,
    /// The device that reported it.
    pub device: String,
    /// The activity push token (hub-only secret, never served).
    pub push_token: String,
    /// When reported, unix seconds.
    pub updated_ts: u64,
    /// Card kind: `""` for the status card, `incident:{check}` for an
    /// incident card. Only status tokens move the device's activity
    /// pointer — incident rows ride beside it, never through it.
    pub label: String,
}

// ---------------------------------------------------------------- checks

/// What a check probes. `url`/`api` are fetched by a runner; `heartbeat`
/// is pushed by the reporter (missing beats read as down); `balance`
/// derives its answer from each reported value against `warn_below` /
/// `crit_below` (evaluated on record).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CheckType {
    /// Plain URL probe: status plus optional body substring.
    Url,
    /// API probe: same fetch, JSON-assertion flavor (P2b extends it).
    Api,
    /// Dead-man's switch: the reporter beats, silence reads down.
    Heartbeat,
    /// Balance threshold: warn/crit below reported values (P4).
    Balance,
}

impl CheckType {
    /// `url`, `api`, `heartbeat`, `balance` — anything else is None.
    pub fn parse(s: &str) -> Option<CheckType> {
        match s.trim() {
            "url" => Some(CheckType::Url),
            "api" => Some(CheckType::Api),
            "heartbeat" => Some(CheckType::Heartbeat),
            "balance" => Some(CheckType::Balance),
            _ => None,
        }
    }

    /// The wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            CheckType::Url => "url",
            CheckType::Api => "api",
            CheckType::Heartbeat => "heartbeat",
            CheckType::Balance => "balance",
        }
    }
}

/// `low`, `normal`, `high` — anything else is None.
pub fn parse_severity(s: &str) -> Option<&'static str> {
    match s.trim() {
        "low" => Some("low"),
        "normal" => Some("normal"),
        "high" => Some("high"),
        _ => None,
    }
}

/// `hub`, `mac`, `both` — anything else is None.
pub fn parse_runner(s: &str) -> Option<&'static str> {
    match s.trim() {
        "hub" => Some("hub"),
        "mac" => Some("mac"),
        "both" => Some("both"),
        _ => None,
    }
}

/// `auto`, `manual` — anything else is None.
pub fn parse_source(s: &str) -> Option<&'static str> {
    match s.trim() {
        "auto" => Some("auto"),
        "manual" => Some("manual"),
        _ => None,
    }
}

/// Flat per-type knobs, stored as one JSON blob. Only the fields the
/// type reads matter; the rest ride along ignored.
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct CheckConfig {
    /// Wanted HTTP status for `url`/`api` (default 200).
    #[serde(default)]
    pub expect: u16,
    /// Wanted body substring for `url`/`api`, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contains: Option<String>,
    /// Silence past this reads down for `heartbeat` (default 300).
    #[serde(default)]
    pub miss_after_secs: u64,
    /// Warn below this for `balance`, if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warn_below: Option<f64>,
    /// Crit below this for `balance`, if set (sits under warn).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crit_below: Option<f64>,
}

/// What `POST /checks` (and `PUT`) takes. Only the four keys are
/// required; everything else falls back to sane defaults.
#[derive(Deserialize, Default)]
pub struct NewCheck {
    /// Check address (required).
    pub name: Option<String>,
    /// Who owns it: human or app slug (required).
    pub owner: Option<String>,
    /// `url`, `api`, `heartbeat`, `balance` (required).
    #[serde(rename = "type")]
    pub ctype: Option<String>,
    /// URL for `url`/`api`, reporter label otherwise (required).
    pub target: Option<String>,
    /// Probe cadence, 10-86400 (default 60).
    pub every_secs: Option<u64>,
    /// Per-probe budget, 1-300 and within `every_secs` (default 10).
    pub timeout_secs: Option<u64>,
    /// `low`, `normal`, `high` (default `normal`).
    pub severity: Option<String>,
    /// `hub`, `mac`, `both` (default `hub`).
    pub runner: Option<String>,
    /// `auto`, `manual` (default `manual`).
    pub source: Option<String>,
    /// Wanted HTTP status (default 200).
    pub expect: Option<u16>,
    /// Wanted body substring, if any.
    pub contains: Option<String>,
    /// Heartbeat silence budget (default 300).
    pub miss_after_secs: Option<u64>,
    /// Balance warn line, if any.
    pub warn_below: Option<f64>,
    /// Balance crit line, if any.
    pub crit_below: Option<f64>,
}

/// A check after validation, ready to store.
pub struct ValidCheck {
    /// Check address.
    pub name: String,
    /// Who owns it.
    pub owner: String,
    /// Parsed type.
    pub ctype: CheckType,
    /// URL or reporter label.
    pub target: String,
    /// Probe cadence.
    pub every_secs: u64,
    /// Per-probe budget.
    pub timeout_secs: u64,
    /// Severity.
    pub severity: &'static str,
    /// Runner.
    pub runner: &'static str,
    /// Source.
    pub source: &'static str,
    /// Type knobs.
    pub config: CheckConfig,
}

/// Every rule in one place, or the first refusal as a human line.
pub fn validate_check(c: &NewCheck) -> Result<ValidCheck, String> {
    let name = c.name.as_deref().unwrap_or("").trim();
    if !valid_name(name) {
        return Err("name must match [a-z][a-z0-9_-]{0,31}".to_string());
    }
    let owner = c.owner.as_deref().unwrap_or("").trim();
    if owner.is_empty() || owner.len() > 64 {
        return Err("owner names the human or app responsible (1-64 chars)".to_string());
    }
    let ctype = c
        .ctype
        .as_deref()
        .and_then(CheckType::parse)
        .ok_or("type is one of: url, api, heartbeat, balance")?;
    let target = c.target.as_deref().unwrap_or("").trim();
    match ctype {
        CheckType::Url | CheckType::Api => {
            if !valid_url(target) {
                return Err("target is an http(s) URL (2048 max, no spaces)".to_string());
            }
        }
        CheckType::Heartbeat | CheckType::Balance => {
            if target.is_empty() || target.len() > 64 {
                return Err("target names the reporter or account (1-64 chars)".to_string());
            }
        }
    }
    let every_secs = c.every_secs.unwrap_or(60);
    if !(10..=86_400).contains(&every_secs) {
        return Err("every_secs is 10-86400".to_string());
    }
    let timeout_secs = c.timeout_secs.unwrap_or(10);
    if !(1..=300).contains(&timeout_secs) {
        return Err("timeout_secs is 1-300".to_string());
    }
    if timeout_secs > every_secs {
        return Err("timeout_secs cannot outrun every_secs".to_string());
    }
    let severity = c
        .severity
        .as_deref()
        .map(parse_severity)
        .unwrap_or(Some("normal"))
        .ok_or("severity is one of: low, normal, high")?;
    let runner = c
        .runner
        .as_deref()
        .map(parse_runner)
        .unwrap_or(Some("hub"))
        .ok_or("runner is one of: hub, mac, both")?;
    let source = c
        .source
        .as_deref()
        .map(parse_source)
        .unwrap_or(Some("manual"))
        .ok_or("source is one of: auto, manual")?;
    let expect = c.expect.unwrap_or(200);
    if !(100..=599).contains(&expect) {
        return Err("expect is an HTTP status 100-599".to_string());
    }
    if c.contains.as_deref().unwrap_or("").len() > 512 {
        return Err("contains is 512 chars max".to_string());
    }
    let miss_after_secs = c.miss_after_secs.unwrap_or(300);
    if !(30..=86_400).contains(&miss_after_secs) {
        return Err("miss_after_secs is 30-86400".to_string());
    }
    for (label, v) in [("warn_below", c.warn_below), ("crit_below", c.crit_below)] {
        if let Some(f) = v
            && !(f.is_finite() && f >= 0.0)
        {
            return Err(format!("{label} is a finite number >= 0"));
        }
    }
    if let (Some(w), Some(cb)) = (c.warn_below, c.crit_below)
        && cb >= w
    {
        return Err("crit_below sits below warn_below".to_string());
    }
    Ok(ValidCheck {
        name: name.to_string(),
        owner: owner.to_string(),
        ctype,
        target: target.to_string(),
        every_secs,
        timeout_secs,
        severity,
        runner,
        source,
        config: CheckConfig {
            expect,
            contains: c.contains.clone().filter(|s| !s.is_empty()),
            miss_after_secs,
            warn_below: c.warn_below,
            crit_below: c.crit_below,
        },
    })
}

/// Current state, served with every check. `status` is `up`, `down`,
/// or `unknown`; heartbeats read stale beats as down on serve.
#[derive(Serialize, Clone)]
pub struct CheckState {
    /// `up`, `down`, or `unknown`.
    pub status: String,
    /// Last probe's answer, if any probe ran.
    pub ok: Option<bool>,
    /// Consecutive failures (zeroed by any success).
    pub fails: u32,
    /// When the status last flipped, unix seconds.
    pub changed_ts: u64,
    /// When the last probe ran, unix seconds.
    pub last_ts: u64,
    /// Last probe's HTTP status, if one arrived.
    pub last_code: Option<u16>,
    /// Last probe's human reason.
    pub last_reason: String,
    /// Last heartbeat, unix seconds (0 when never).
    pub last_beat: u64,
    /// Five-plus flips in the last hour.
    pub flapping: bool,
    /// Numeric value of the latest result, when that result carried
    /// one (`null` when it did not — a value never outlives the
    /// result it came with).
    pub last_value: Option<f64>,
}

/// A check with its live state: what `GET /checks` serves.
#[derive(Serialize, Clone)]
pub struct Check {
    /// Check address.
    pub name: String,
    /// Who owns it.
    pub owner: String,
    /// Check type.
    #[serde(rename = "type")]
    pub ctype: String,
    /// URL or reporter label.
    pub target: String,
    /// Probe cadence.
    pub every_secs: u64,
    /// Per-probe budget.
    pub timeout_secs: u64,
    /// Severity.
    pub severity: String,
    /// Runner.
    pub runner: String,
    /// Source.
    pub source: String,
    /// Type knobs.
    pub config: CheckConfig,
    /// When it was defined, unix seconds.
    pub created_ts: u64,
    /// Live state.
    pub state: CheckState,
    /// Ack horizon, unix seconds (0 = none): the down page stays
    /// quiet until this, or until recovery clears it — whichever
    /// comes first.
    pub ack_until: u64,
    /// Mute horizon, unix seconds (0 = none): both directions stay
    /// quiet until this. Nothing clears a mute but time or unmute.
    pub mute_until: u64,
}

// ---------------------------------------------------------------- projects

/// What `PUT /projects/{name}` takes: the Mac sync owns every key.
/// Group and name ride every write; the bundle id is optional (not
/// every project ships an app).
#[derive(Deserialize, Default)]
pub struct NewProject {
    /// Display group (`ios`, ...).
    pub group: Option<String>,
    /// Human name.
    pub name: Option<String>,
    /// Bundle id, when the project has one.
    pub bundle_id: Option<String>,
}

/// A project after validation, ready to store.
pub struct ValidProject {
    /// Project address (the app slug).
    pub slug: String,
    /// Display group.
    pub group: String,
    /// Human name.
    pub name: String,
    /// Bundle id (`""` when none).
    pub bundle_id: String,
}

/// Every rule in one place, or the first refusal as a human line.
pub fn validate_project(slug: &str, p: &NewProject) -> Result<ValidProject, String> {
    let slug = slug.trim();
    if !valid_name(slug) {
        return Err("slug must match [a-z][a-z0-9_-]{0,31}".to_string());
    }
    let group = p.group.as_deref().unwrap_or("").trim();
    if group.is_empty() || group.len() > 32 {
        return Err("group names the display group (1-32 chars)".to_string());
    }
    let name = p.name.as_deref().unwrap_or("").trim();
    if name.is_empty() || name.len() > 128 {
        return Err("name is the human name (1-128 chars)".to_string());
    }
    let bundle_id = p.bundle_id.as_deref().unwrap_or("").trim();
    if bundle_id.len() > 128 {
        return Err("bundle_id is 128 max".to_string());
    }
    Ok(ValidProject {
        slug: slug.to_string(),
        group: group.to_string(),
        name: name.to_string(),
        bundle_id: bundle_id.to_string(),
    })
}

/// A stored project: ecosystem metadata the Mac sync owns. Health
/// rolls up at serve time (owner == slug), so this stores no status —
/// only identity plus the icon bytes.
#[derive(Serialize, Clone)]
pub struct Project {
    /// Project address.
    pub slug: String,
    /// Display group.
    pub group: String,
    /// Human name.
    pub name: String,
    /// Bundle id (`""` when none).
    pub bundle_id: String,
    /// True when icon bytes are stored.
    pub has_icon: bool,
    /// sha256 hex of the icon, when one is stored (sync skips re-upload).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_sha256: Option<String>,
    /// Last metadata/icon write, unix seconds.
    pub updated_ts: u64,
}

/// Health rollup over one project's checks.
#[derive(Serialize, Clone)]
pub struct ProjectHealth {
    /// Checks currently up.
    pub up: u32,
    /// Checks currently down.
    pub down: u32,
    /// Checks never probed (or unreadable).
    pub unknown: u32,
    /// All three.
    pub total: u32,
}

/// One project's env blob, cap: 64KB covers any `.env` without
/// inviting binary dumps.
pub const SECRET_ENV_MAX: usize = 65536;

/// Project-token prefix: `est_s_…` reads as a secret at a glance
/// (and greps out of logs when it leaks into one).
pub const SECRET_TOKEN_PREFIX: &str = "est_s_";

/// A stored secret's public face: identity plus the sha deploys
/// compare — the env itself only ever leaves via a tokened pull.
#[derive(Serialize, Clone)]
pub struct SecretMeta {
    /// Project address (the deploy slug).
    pub project: String,
    /// sha256 hex of the stored env (deploys skip unchanged writes).
    pub sha: String,
    /// Last push, unix seconds.
    pub updated_ts: u64,
    /// True when a pull token is minted for this project.
    pub has_token: bool,
}

/// One API balance row: a display amount plus when it was read.
/// Amounts are strings (`"$12.34"`, `"84%"`) — providers format
/// variously, and the hub displays, never computes.
#[derive(Serialize, Clone)]
pub struct Balance {
    /// Provider key (`openai`, `anthropic`, …).
    pub provider: String,
    /// Human label (defaults to the provider).
    pub label: String,
    /// Display amount.
    pub amount: String,
    /// Currency/unit hint (`USD`, `%`, `credits`).
    pub currency: String,
    /// Free note (plan, reset date, …).
    pub note: String,
    /// When read, unix seconds.
    pub updated_ts: u64,
}

/// One herdr agent snapshot: the mirror of what herdr shows —
/// title, directory, lifecycle state, workspace/tab placing, last
/// output, and when the watcher last saw it. `stale` is computed at
/// serve time (never stored).
#[derive(Serialize, Clone)]
pub struct Agent {
    /// herdr pane id (`w7:p1P`), the row key.
    pub pane: String,
    /// Stripped terminal title (`EST Hub App Delivery`).
    pub title: String,
    /// Working directory of the agent.
    pub cwd: String,
    /// One of `working|done|idle|blocked|unknown`.
    pub status: String,
    /// herdr workspace label (`iOS`, `EST`), 64 max.
    pub space: String,
    /// herdr tab label inside the space, 64 max.
    pub tab: String,
    /// Tail of the pane's recent output (~2KB), 4096 max.
    pub output: String,
    /// Last watcher push, unix seconds.
    pub updated_ts: u64,
    /// True past [`AGENT_STALE_AFTER_SECS`] quiet seconds.
    pub stale: bool,
    /// When the status last flipped, unix seconds (the row's elapsed
    /// clock — the app's "working 12m" reads this, not `updated_ts`).
    pub status_since_ts: u64,
}

/// One fleet-card row: the pane, its display name (title, cwd leaf,
/// pane — the app's `displayTitle` order), and herdr's own status
/// verb. Serialized into the card's content state, never served.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct FleetRow {
    /// herdr pane id, the row key.
    pub pane: String,
    /// Display name (title, cwd leaf, pane).
    pub name: String,
    /// herdr's own status verb.
    pub status: String,
}

/// A project with its live rollup: what the project GETs serve. Flat
/// (not nested): the app binds rows straight to it.
#[derive(Serialize, Clone)]
pub struct ProjectLive {
    /// The stored identity.
    #[serde(flatten)]
    pub project: Project,
    /// The rollup over owner == slug.
    pub health: ProjectHealth,
    /// `up`, `down`, or `unknown` (down wins, then unknown, then up;
    /// zero checks reads unknown).
    pub state: String,
}

impl Project {
    /// Roll this project's checks (owner == slug) into its live shape.
    pub fn live(&self, checks: &[Check]) -> ProjectLive {
        let (mut up, mut down, mut unknown) = (0u32, 0u32, 0u32);
        for c in checks.iter().filter(|c| c.owner == self.slug) {
            match c.state.status.as_str() {
                "up" => up += 1,
                "down" => down += 1,
                _ => unknown += 1,
            }
        }
        let total = up + down + unknown;
        let state = if down > 0 {
            "down"
        } else if total == 0 || unknown > 0 {
            "unknown"
        } else {
            "up"
        };
        ProjectLive {
            project: self.clone(),
            health: ProjectHealth {
                up,
                down,
                unknown,
                total,
            },
            state: state.to_string(),
        }
    }
}

// ---------------------------------------------------------------- results

/// What `POST /results` takes: a runner reporting one probe.
#[derive(Deserialize)]
pub struct NewResult {
    /// Check address (required).
    pub check: Option<String>,
    /// The probe's answer (required).
    pub ok: Option<bool>,
    /// HTTP status, when one arrived.
    pub code: Option<u16>,
    /// Human reason.
    pub reason: Option<String>,
    /// Probe time; now when absent (lets runners backfill).
    pub ts: Option<u64>,
    /// Numeric reading (optional): disk/mem percent, load score, TLS
    /// days-left. Absent or `null` means no value; a JSON number must
    /// be finite, anything else is a 400.
    pub value: Option<serde_json::Value>,
}

/// Validate the optional `value` on a result report: absent or `null`
/// reads `None`; a finite JSON number reads `Some`; anything else
/// (strings, bools, non-finite) refuses with a human line.
pub fn parse_result_value(v: Option<&serde_json::Value>) -> Result<Option<f64>, String> {
    match v {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(n)) => match n.as_f64() {
            Some(f) if f.is_finite() => Ok(Some(f)),
            _ => Err("value is a finite JSON number or null".to_string()),
        },
        Some(_) => Err("value is a finite JSON number or null".to_string()),
    }
}

/// One recorded probe.
#[derive(Serialize, Clone)]
pub struct StoredResult {
    /// Row id.
    pub id: i64,
    /// Check address.
    pub check: String,
    /// Probe time, unix seconds.
    pub ts: u64,
    /// The probe's answer.
    pub ok: bool,
    /// HTTP status, when one arrived.
    pub code: Option<u16>,
    /// Human reason.
    pub reason: String,
    /// Numeric reading, when the probe carried one.
    pub value: Option<f64>,
}

// ---------------------------------------------------------------- approvals

/// What `POST /approvals` takes.
#[derive(Deserialize)]
pub struct NewApproval {
    /// The ask, one line (required).
    pub title: Option<String>,
    /// Detail, if any.
    pub body: Option<String>,
    /// Correlation id for the requester, if any.
    pub reply_to: Option<String>,
    /// Seconds until expiry (default 3600).
    pub ttl_secs: Option<u64>,
}

/// An ask and its answer. `state` is `pending`, `approved`, `rejected`,
/// or `expired` (pending past its deadline reads expired, and a
/// decision then refuses).
#[derive(Serialize, Clone)]
pub struct Approval {
    /// Ask id.
    pub id: i64,
    /// The ask.
    pub title: String,
    /// Detail.
    pub body: String,
    /// Requester's correlation id.
    pub reply_to: String,
    /// Live state.
    pub state: String,
    /// When asked, unix seconds.
    pub created_ts: u64,
    /// When pending rots, unix seconds.
    pub deadline_ts: u64,
    /// When decided, unix seconds (0 when open).
    pub decided_ts: u64,
    /// `approved`/`rejected`, empty when open.
    pub decision: String,
    /// Who decided, empty when open.
    pub decided_by: String,
}

/// What `POST /approvals/{id}/decision` takes.
#[derive(Deserialize)]
pub struct Decision {
    /// True approves, false rejects (required).
    pub approve: Option<bool>,
    /// Who decided.
    pub by: Option<String>,
}

// ---------------------------------------------------------------- notify

/// What `POST /notify` takes.
#[derive(Deserialize)]
pub struct NewNotification {
    /// Device address, empty for broadcast.
    pub to: Option<String>,
    /// Topic (`notify`, `health.flip`, …).
    pub topic: Option<String>,
    /// One line (required).
    pub title: Option<String>,
    /// Detail, if any.
    pub body: Option<String>,
}

/// A queued notification. Delivery drivers (Telegram now, APNs later)
/// drain this table; until one runs, clients poll it.
#[derive(Serialize, Clone)]
pub struct Notification {
    /// Queue id.
    pub id: i64,
    /// When queued, unix seconds.
    pub ts: u64,
    /// Topic.
    pub topic: String,
    /// One line.
    pub title: String,
    /// Detail.
    pub body: String,
    /// Device address, empty for broadcast.
    pub to_device: String,
    /// A driver claimed it.
    pub delivered: bool,
}

/// Unix seconds, or 0 when the clock is unreadable.
pub fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_follow_the_rule() {
        assert!(valid_name("api-prod"));
        assert!(valid_name("a"));
        assert!(valid_name("x9_y-z"));
        assert!(!valid_name(""));
        assert!(!valid_name("Upper"));
        assert!(!valid_name("9lives"));
        assert!(!valid_name("has space"));
        assert!(!valid_name("toolong-0123456789-0123456789-0123"));
    }

    fn check(ctype: &str, target: &str) -> NewCheck {
        NewCheck {
            name: Some("probe-1".to_string()),
            owner: Some("estifie".to_string()),
            ctype: Some(ctype.to_string()),
            target: Some(target.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn url_checks_want_urls_and_sane_budgets() {
        assert!(validate_check(&check("url", "https://example.com/x")).is_ok());
        assert!(validate_check(&check("url", "notaurl")).is_err());
        let mut c = check("url", "https://example.com");
        c.every_secs = Some(5);
        assert!(validate_check(&c).is_err());
        let mut c = check("url", "https://example.com");
        c.timeout_secs = Some(61);
        assert!(validate_check(&c).is_err());
        let mut c = check("url", "https://example.com");
        c.ctype = Some("nope".to_string());
        assert!(validate_check(&c).is_err());
    }

    #[test]
    fn heartbeat_and_balance_targets_are_labels() {
        assert!(validate_check(&check("heartbeat", "nightly-job")).is_ok());
        assert!(validate_check(&check("heartbeat", "")).is_err());
        let mut c = check("balance", "OPENROUTER");
        c.warn_below = Some(5.0);
        c.crit_below = Some(1.0);
        assert!(validate_check(&c).is_ok());
        c.crit_below = Some(9.0);
        assert!(validate_check(&c).is_err());
    }

    fn device_with_token(token: Option<&str>) -> Device {
        Device {
            name: "phone".to_string(),
            apns_token: token.map(str::to_string),
            created_ts: 1_700_000_000,
            state: "active".to_string(),
            apns_env: Some("production".to_string()),
            apns_topic: None,
            la_pts_token: None,
            la_config: None,
            la_activity_id: None,
            la_started_ts: None,
        }
    }

    #[test]
    fn apns_configured_tracks_a_non_empty_token() {
        assert!(device_with_token(Some("tok")).apns_configured());
        assert!(!device_with_token(None).apns_configured());
        assert!(!device_with_token(Some("")).apns_configured());
    }

    #[test]
    fn devices_serialize_the_configured_bit() {
        let v = serde_json::to_value(device_with_token(Some("tok"))).unwrap();
        assert_eq!(v["apns_token"], "tok");
        assert_eq!(v["apns_configured"], true);
        // Stored fields keep their shape beside the bit.
        assert_eq!(v["name"], "phone");
        let v = serde_json::to_value(device_with_token(None)).unwrap();
        assert!(v["apns_token"].is_null());
        assert_eq!(v["apns_configured"], false);
    }

    #[test]
    fn devices_serialize_topic_but_never_live_secrets() {
        let mut d = device_with_token(Some("tok"));
        d.apns_topic = Some("com.estifie.app2".to_string());
        d.la_pts_token = Some("pts-secret".to_string());
        d.la_config = Some(r#"{"enabled":true}"#.to_string());
        d.la_activity_id = Some("act-1".to_string());
        d.la_started_ts = Some(1_700_000_001);
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["apns_topic"], "com.estifie.app2");
        for key in [
            "la_pts_token",
            "la_config",
            "la_activity_id",
            "la_started_ts",
        ] {
            assert!(v.get(key).is_none(), "{v}");
        }
        assert!(!v.to_string().contains("pts-secret"));
        // Unset topic serializes null, beside the configured bit.
        let v = serde_json::to_value(device_with_token(None)).unwrap();
        assert!(v["apns_topic"].is_null());
        assert_eq!(v["apns_configured"], false);
    }

    #[test]
    fn live_configs_default_off_and_parse_leniently() {
        let fresh = device_with_token(None);
        assert_eq!(fresh.la_config_parsed(), LaConfig::default());
        assert!(!LaConfig::default().enabled);
        assert_eq!(LaConfig::default().min_severity, "low");
        assert!(LaConfig::default().approvals);
        // Corrupt rows read off, never loud.
        let mut d = device_with_token(None);
        d.la_config = Some("not json".to_string());
        assert_eq!(d.la_config_parsed(), LaConfig::default());
        // Partial blobs fill the rest with defaults.
        d.la_config = Some(r#"{"enabled":true}"#.to_string());
        let parsed = d.la_config_parsed();
        assert!(parsed.enabled);
        assert_eq!(parsed.checks, None);
        assert_eq!(parsed.min_severity, "low");
    }

    #[test]
    fn devices_need_names_only() {
        let d = NewDevice {
            name: Some("iphone".to_string()),
            apns_token: None,
        };
        assert!(validate_device(&d).is_ok());
        let d = NewDevice {
            name: Some("Nope!".to_string()),
            apns_token: None,
        };
        assert!(validate_device(&d).is_err());
    }

    #[test]
    fn result_values_take_finite_numbers_or_null() {
        assert_eq!(parse_result_value(None).unwrap(), None);
        assert_eq!(
            parse_result_value(Some(&serde_json::Value::Null)).unwrap(),
            None
        );
        assert_eq!(
            parse_result_value(Some(&serde_json::json!(42.5))).unwrap(),
            Some(42.5)
        );
        assert_eq!(
            parse_result_value(Some(&serde_json::json!(0))).unwrap(),
            Some(0.0)
        );
        assert!(parse_result_value(Some(&serde_json::json!("42"))).is_err());
        assert!(parse_result_value(Some(&serde_json::json!(true))).is_err());
        assert!(parse_result_value(Some(&serde_json::json!([1]))).is_err());
        // Non-finite has no JSON spelling: an overflow exponent does not
        // even parse as JSON, so the transport refuses before validation.
        assert!(serde_json::from_str::<serde_json::Value>("1e999").is_err());
    }
}
