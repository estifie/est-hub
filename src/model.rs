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

fn valid_url(s: &str) -> bool {
    (s.starts_with("http://") || s.starts_with("https://"))
        && s.len() <= 2048
        && !s.chars().any(char::is_whitespace)
}

// ---------------------------------------------------------------- devices

/// A known device. Registry only until mTLS (P3) enforces it.
#[derive(Serialize, Clone)]
pub struct Device {
    /// Device address, `[a-z][a-z0-9_-]{0,31}`.
    pub name: String,
    /// X25519 public key (base64), once pairing issues it.
    pub pubkey: Option<String>,
    /// APNs device token, once the app registers it.
    pub apns_token: Option<String>,
    /// When it paired, unix seconds.
    pub created_ts: u64,
}

/// What `POST /devices` takes.
#[derive(Deserialize)]
pub struct NewDevice {
    /// Device address (required).
    pub name: Option<String>,
    /// X25519 public key, if known yet.
    pub pubkey: Option<String>,
    /// APNs device token, if known yet.
    pub apns_token: Option<String>,
}

/// Name plus optional keys, or why the device is unacceptable.
pub fn validate_device(d: &NewDevice) -> Result<(String, Option<String>, Option<String>), String> {
    let name = d.name.as_deref().unwrap_or("").trim();
    if !valid_name(name) {
        return Err("name must match [a-z][a-z0-9_-]{0,31}".to_string());
    }
    for (label, v) in [("pubkey", &d.pubkey), ("apns_token", &d.apns_token)] {
        if v.as_deref().unwrap_or("").len() > 512 {
            return Err(format!("{label} is too long (512 max)"));
        }
    }
    Ok((
        name.to_string(),
        d.pubkey.clone().filter(|s| !s.trim().is_empty()),
        d.apns_token.clone().filter(|s| !s.trim().is_empty()),
    ))
}

// ---------------------------------------------------------------- checks

/// What a check probes. `url`/`api` are fetched by a runner; `heartbeat`
/// is pushed by the reporter (missing beats read as down); `balance`
/// compares a reported value against thresholds (evaluation lands P4).
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

    #[test]
    fn devices_need_names_only() {
        let d = NewDevice {
            name: Some("iphone".to_string()),
            pubkey: None,
            apns_token: None,
        };
        assert!(validate_device(&d).is_ok());
        let d = NewDevice {
            name: Some("Nope!".to_string()),
            pubkey: None,
            apns_token: None,
        };
        assert!(validate_device(&d).is_err());
    }
}
