//! `checks sync`: the ecosystem's own repos are the source of truth for
//! what health watches, so a new app (or a moved URL) shows up without
//! anyone hand-adding a check.
//!
//! iOS legal URLs come from each app's `INFOPLIST_KEY_EC*` build
//! settings — the values Xcode stamps into the app's Info.plist EC
//! keys at build time — with a `*Config*.swift` fallback for older
//! apps that still carry `Config.privacyURL`/`termsURL`, plus
//! `support_url` from `.estifie/asc/general.yaml`. Backend apps come
//! from the `internal/apps` directory names. Pure scan/parse here;
//! the CLI layer upserts through the checks routes.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// One check the scan wants to exist. Type is always `url`, runner
/// always `hub`, source always `auto` — the CLI fills those in.
pub struct Want {
    /// Check address (`ios-<slug>-privacy`, `backend-live`, ...).
    pub name: String,
    /// Owner: the app slug, or `backend`.
    pub owner: String,
    /// The probed URL.
    pub target: String,
    /// Probe cadence, seconds.
    pub every_secs: u64,
    /// Per-probe budget, seconds.
    pub timeout_secs: u64,
    /// `low`, `normal`, or `high`.
    pub severity: String,
    /// Wanted HTTP status.
    pub expect: u16,
}

impl Want {
    fn url(
        name: String,
        owner: &str,
        target: String,
        every_secs: u64,
        timeout_secs: u64,
        severity: &str,
        expect: u16,
    ) -> Self {
        Want {
            name,
            owner: owner.to_string(),
            target,
            every_secs,
            timeout_secs,
            severity: severity.to_string(),
            expect,
        }
    }
}

/// What a scan found, plus the human-readable gaps (apps without
/// URLs, unreadable files) the CLI reports as warnings.
pub struct Scan {
    /// Checks that should exist.
    pub wants: Vec<Want>,
    /// Gaps the operator (or AI) should close.
    pub warnings: Vec<String>,
}

/// The hub probes http(s); anything else never leaves the scan.
pub fn is_http_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

/// Strip one pair of matching single/double quotes.
fn strip_quotes(v: &str) -> &str {
    let b = v.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        &v[1..b.len() - 1]
    } else {
        v
    }
}

/// Every distinct `KEY = value;` in pbxproj text, in order.
fn pbxproj_values(text: &str, key: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some((left, right)) = line.split_once('=') else {
            continue;
        };
        if left.trim() != key {
            continue;
        }
        let v = right.trim();
        let v = strip_quotes(v.strip_suffix(';').unwrap_or(v).trim());
        if !out.iter().any(|f| f == v) {
            out.push(v.to_string());
        }
    }
    out
}

/// One `KEY = value;` out of pbxproj text: the value plus whether the
/// key carried distinct values (Debug vs Release disagreeing). First
/// distinct URL wins; non-URL values are ignored (placeholders).
fn pbxproj_value(text: &str, key: &str) -> (Option<String>, bool) {
    let urls: Vec<String> = pbxproj_values(text, key)
        .into_iter()
        .filter(|v| is_http_url(v))
        .collect();
    let mut found = None;
    let mut conflict = false;
    for v in urls {
        match &found {
            None => found = Some(v),
            Some(f) if *f == v => {}
            Some(_) => conflict = true,
        }
    }
    (found, conflict)
}

/// The app target's bundle id out of pbxproj text: test, UI-test,
/// widget, and extension targets carry their own ids, so values
/// mentioning `test`/`widget` lose, unresolved `$(...)` values lose
/// next, and longer ids (extensions) lose after that; file order
/// breaks every remaining tie (stable sort).
pub fn pick_bundle_id(text: &str) -> Option<String> {
    let values: Vec<String> = pbxproj_values(text, "PRODUCT_BUNDLE_IDENTIFIER")
        .into_iter()
        .filter(|v| !v.is_empty())
        .collect();
    let mut cands: Vec<&String> = values.iter().collect();
    cands.sort_by_key(|v| {
        let low = v.to_lowercase();
        let ext = low.contains("test") || low.contains("widget");
        let dirty = v.contains("$(");
        (ext as u8, dirty as u8, v.split('.').count())
    });
    cands.first().cloned().cloned()
}

/// Legal URLs from pbxproj text: `(privacy, terms, notes)`. Notes name
/// config disagreements; the caller prefixes the app slug.
pub fn parse_pbxproj_legal(text: &str) -> (Option<String>, Option<String>, Vec<String>) {
    let mut notes = Vec::new();
    let (privacy, p_conflict) = pbxproj_value(text, "INFOPLIST_KEY_ECPrivacyURL");
    let (terms, t_conflict) = pbxproj_value(text, "INFOPLIST_KEY_ECTermsURL");
    if p_conflict {
        notes.push(
            "INFOPLIST_KEY_ECPrivacyURL differs between configs; using the first".to_string(),
        );
    }
    if t_conflict {
        notes.push("INFOPLIST_KEY_ECTermsURL differs between configs; using the first".to_string());
    }
    (privacy, terms, notes)
}

/// First http(s) literal on the line (`"https://..."`, `URL(string:
/// "https://...")`), if any.
fn first_http_literal(line: &str) -> Option<String> {
    let mut rest = line;
    loop {
        let at = rest.find("http")?;
        let cand = &rest[at..];
        if !cand.starts_with("http://") && !cand.starts_with("https://") {
            rest = &rest[at + 4..];
            continue;
        }
        let end = cand
            .find(|c: char| {
                c == '"' || c == '\'' || c.is_whitespace() || c == ')' || c == ';' || c == ','
            })
            .unwrap_or(cand.len());
        return Some(cand[..end].to_string());
    }
}

/// Legal URLs from older apps' `Config.privacyURL`/`termsURL` Swift:
/// `(privacy, terms)`. Only http(s) literals on matching lines count.
pub fn parse_swift_config_urls(text: &str) -> (Option<String>, Option<String>) {
    let mut privacy = None;
    let mut terms = None;
    for line in text.lines() {
        let low = line.to_lowercase();
        let is_privacy = low.contains("privacyurl");
        let is_terms = low.contains("termsurl") || low.contains("termsofuseurl");
        if !is_privacy && !is_terms {
            continue;
        }
        let Some(u) = first_http_literal(line) else {
            continue;
        };
        if is_privacy && privacy.is_none() {
            privacy = Some(u.clone());
        }
        if is_terms && terms.is_none() {
            terms = Some(u);
        }
    }
    (privacy, terms)
}

/// `support_url` out of `.estifie/asc/general.yaml`. Absent or empty
/// reads `None` — most apps have no support page, and that is fine.
pub fn parse_support_url(text: &str) -> Option<String> {
    for line in text.lines() {
        let Some(after) = line.trim().strip_prefix("support_url:") else {
            continue;
        };
        let v = after.trim();
        let v = v.split_once(" #").map(|(h, _)| h).unwrap_or(v).trim();
        let v = strip_quotes(v);
        return is_http_url(v).then(|| v.to_string());
    }
    None
}

/// `<slug>/*.xcodeproj/project.pbxproj`, first hit.
fn find_pbxproj(app_dir: &Path) -> Option<PathBuf> {
    let entries = fs::read_dir(app_dir).ok()?;
    for e in entries.filter_map(|e| e.ok()) {
        if !e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".xcodeproj") {
            continue;
        }
        let pbx = e.path().join("project.pbxproj");
        if pbx.is_file() {
            return Some(pbx);
        }
    }
    None
}

/// `*Config*.swift` files under the app dir (depth 4 max, build and
/// hidden dirs skipped): where older apps keep their legal URLs.
fn find_config_swifts(app_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![(app_dir.to_path_buf(), 0u8)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > 4 || out.len() >= 50 {
            continue;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.filter_map(|e| e.ok()) {
            let name = e.file_name().to_string_lossy().into_owned();
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                if name.starts_with('.') || name == "build" || name == "DerivedData" {
                    continue;
                }
                stack.push((e.path(), depth + 1));
            } else if name.contains("Config") && name.ends_with(".swift") {
                out.push(e.path());
            }
        }
    }
    out.sort();
    out
}

/// Scan `<root>/apps/*` for legal/support URLs. Every app yields up to
/// three `url` checks (`ios-<slug>-privacy|terms|support`, owner
/// `<slug>`): explicit URLs first (`INFOPLIST_KEY_EC*`, then
/// `*Config*.swift`), then `site/apps.yaml` completes served-but-unpinned
/// apps under the proven site pattern (see [`legal_base_from`]).
/// Gaps warn — the pinned keys are required for the App Store too, so
/// those warnings pull double duty.
pub fn scan_ios_apps(root: &Path, every_secs: u64, timeout_secs: u64) -> Scan {
    let mut scan = Scan {
        wants: Vec::new(),
        warnings: Vec::new(),
    };
    let apps_dir = root.join("apps");
    let Ok(entries) = fs::read_dir(&apps_dir) else {
        scan.warnings
            .push(format!("ios: cannot read {}", apps_dir.display()));
        return scan;
    };
    let mut slugs: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with('.'))
        .collect();
    slugs.sort();
    let mut explicit: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();
    for slug in &slugs {
        let dir = apps_dir.join(slug);
        let (p, t) = scan_one_app(&dir, slug, every_secs, timeout_secs, &mut scan);
        if let Some(u) = &p {
            push_legal(
                &mut scan,
                slug,
                "privacy",
                u.clone(),
                every_secs,
                timeout_secs,
            );
        }
        if let Some(u) = &t {
            push_legal(
                &mut scan,
                slug,
                "terms",
                u.clone(),
                every_secs,
                timeout_secs,
            );
        }
        explicit.insert(slug.clone(), (p, t));
    }
    derive_registry_legal(root, &explicit, every_secs, timeout_secs, &mut scan);
    scan
}

/// One app's explicit legal URLs (pbxproj `INFOPLIST_KEY_EC*`, then
/// `*Config*.swift` literals). Support goes straight to wants; legal
/// returns for the registry pass to complete.
fn scan_one_app(
    dir: &Path,
    slug: &str,
    every_secs: u64,
    timeout_secs: u64,
    scan: &mut Scan,
) -> (Option<String>, Option<String>) {
    let mut privacy = None;
    let mut terms = None;
    if let Some(pbx) = find_pbxproj(dir) {
        match fs::read_to_string(&pbx) {
            Ok(text) => {
                let (p, t, notes) = parse_pbxproj_legal(&text);
                privacy = p;
                terms = t;
                for n in notes {
                    scan.warnings.push(format!("ios {slug}: {n}"));
                }
            }
            Err(_) => scan
                .warnings
                .push(format!("ios {slug}: unreadable {}", pbx.display())),
        }
    }
    if privacy.is_none() || terms.is_none() {
        for f in find_config_swifts(dir) {
            let Ok(text) = fs::read_to_string(&f) else {
                continue;
            };
            let (p, t) = parse_swift_config_urls(&text);
            if privacy.is_none() {
                privacy = p;
            }
            if terms.is_none() {
                terms = t;
            }
            if privacy.is_some() && terms.is_some() {
                break;
            }
        }
    }
    if let Ok(text) = fs::read_to_string(dir.join(".estifie/asc/general.yaml"))
        && let Some(u) = parse_support_url(&text)
    {
        scan.wants.push(Want::url(
            format!("ios-{slug}-support"),
            slug,
            u,
            every_secs,
            timeout_secs,
            "normal",
            200,
        ));
    }
    (privacy, terms)
}

fn push_legal(
    scan: &mut Scan,
    slug: &str,
    kind: &str,
    url: String,
    every_secs: u64,
    timeout_secs: u64,
) {
    scan.wants.push(Want::url(
        format!("ios-{slug}-{kind}"),
        slug,
        url,
        every_secs,
        timeout_secs,
        "normal",
        200,
    ));
}

/// One `site/apps.yaml` entry: every app the legal site serves.
/// `generated` renders from the app's own `.estifie/legal/`; `legacy`
/// serves frozen `legacy/` copies; `retired` is deliberately unserved.
#[derive(Debug, PartialEq, Clone)]
pub struct AppEntry {
    /// Registry slug.
    pub slug: String,
    /// Human name (`""` when the registry does not say).
    pub name: String,
    /// `generated`, `legacy`, or `retired`.
    pub state: String,
}

/// The registry out of `site/apps.yaml`.
pub fn parse_apps_yaml(text: &str) -> Vec<AppEntry> {
    let mut out = Vec::new();
    let mut slug: Option<String> = None;
    let mut name = String::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("- slug:") {
            slug = Some(strip_quotes(rest.trim()).to_string());
            name.clear();
        } else if let Some(rest) = t.strip_prefix("name:") {
            name = strip_quotes(rest.trim()).to_string();
        } else if let Some(rest) = t.strip_prefix("state:")
            && let Some(s) = slug.take()
        {
            out.push(AppEntry {
                slug: s,
                name: std::mem::take(&mut name),
                state: strip_quotes(rest.trim()).to_string(),
            });
        }
    }
    out
}

/// The legal site's base (`https://estifie.com/apps`) proven by an
/// explicit app URL: the value minus its `/<slug>/privacy-policy`
/// (or `/terms-of-use`) tail. `None` when no explicit value matches
/// its own slug — derivation without a proven pattern is guessing.
pub fn legal_base_from(
    explicit: &HashMap<String, (Option<String>, Option<String>)>,
) -> Option<String> {
    let mut slugs: Vec<&String> = explicit.keys().collect();
    slugs.sort();
    for slug in slugs {
        let (p, t) = &explicit[slug];
        for u in [p, t].into_iter().flatten() {
            for tail in [
                format!("/{slug}/privacy-policy"),
                format!("/{slug}/terms-of-use"),
            ] {
                if let Some(base) = u.strip_suffix(tail.as_str()) {
                    return Some(base.to_string());
                }
            }
        }
    }
    None
}

/// Complete legal coverage from `site/apps.yaml`: served-but-unpinned
/// apps get derived checks under the proven base. `retired` stays
/// out — unserving was deliberate. Every derived check warns:
/// pinning the app's own keys is one AI edit and removes the guess.
fn derive_registry_legal(
    root: &Path,
    explicit: &HashMap<String, (Option<String>, Option<String>)>,
    every_secs: u64,
    timeout_secs: u64,
    scan: &mut Scan,
) {
    let registry = match fs::read_to_string(root.join("site/apps.yaml")) {
        Ok(t) => parse_apps_yaml(&t),
        Err(_) => {
            scan.warnings
                .push("ios: site/apps.yaml missing; cannot derive legal URLs".to_string());
            Vec::new()
        }
    };
    let base = legal_base_from(explicit);
    if !registry.is_empty() && base.is_none() {
        scan.warnings.push(
            "ios: no explicit legal URL pins the site pattern; add INFOPLIST_KEY_EC* to one app"
                .to_string(),
        );
    }
    let served: HashMap<&str, &str> = registry
        .iter()
        .map(|e| (e.slug.as_str(), e.state.as_str()))
        .collect();
    let mut slugs: Vec<&String> = explicit.keys().collect();
    slugs.sort();
    for slug in slugs {
        let (p, t) = &explicit[slug];
        let state = served.get(slug.as_str()).copied();
        let derivable = state.is_some_and(|st| st != "retired") && base.is_some();
        if p.is_none() || t.is_none() {
            if derivable {
                let b = base.as_deref().unwrap_or("");
                if p.is_none() {
                    push_legal(
                        scan,
                        slug,
                        "privacy",
                        format!("{b}/{slug}/privacy-policy"),
                        every_secs,
                        timeout_secs,
                    );
                }
                if t.is_none() {
                    push_legal(
                        scan,
                        slug,
                        "terms",
                        format!("{b}/{slug}/terms-of-use"),
                        every_secs,
                        timeout_secs,
                    );
                }
                scan.warnings.push(format!(
                    "ios {slug}: legal URLs derived from the site registry; add INFOPLIST_KEY_EC* to pin"
                ));
            } else if p.is_none() && t.is_none() {
                if state.is_none() {
                    scan.warnings.push(format!(
                        "ios {slug}: no legal URLs and not in site/apps.yaml"
                    ));
                } else if state == Some("retired") {
                    scan.warnings.push(format!(
                        "ios {slug}: no legal URLs and retired in site/apps.yaml"
                    ));
                } else {
                    scan.warnings.push(format!(
                        "ios {slug}: no legal URLs (needs INFOPLIST_KEY_ECPrivacyURL/ECTermsURL or Config URLs)"
                    ));
                }
            } else if p.is_none() {
                scan.warnings.push(format!(
                    "ios {slug}: privacy URL missing (needs INFOPLIST_KEY_ECPrivacyURL)"
                ));
            } else {
                scan.warnings.push(format!(
                    "ios {slug}: terms URL missing (needs INFOPLIST_KEY_ECTermsURL)"
                ));
            }
        }
    }
    for entry in &registry {
        if entry.state == "retired" || explicit.contains_key(&entry.slug) {
            continue;
        }
        let Some(b) = &base else { continue };
        let slug = &entry.slug;
        push_legal(
            scan,
            slug,
            "privacy",
            format!("{b}/{slug}/privacy-policy"),
            every_secs,
            timeout_secs,
        );
        push_legal(
            scan,
            slug,
            "terms",
            format!("{b}/{slug}/terms-of-use"),
            every_secs,
            timeout_secs,
        );
        scan.warnings.push(format!(
            "ios {slug}: legacy app, legal URLs derived from the site registry"
        ));
    }
}

/// Backend app keys: `<root>/internal/apps` subdirectory names.
pub fn scan_backend_apps(root: &Path) -> (Vec<String>, Vec<String>) {
    let apps_dir = root.join("internal/apps");
    let Ok(entries) = fs::read_dir(&apps_dir) else {
        return (
            vec![],
            vec![format!("backend: cannot read {}", apps_dir.display())],
        );
    };
    let mut keys: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with('.'))
        .collect();
    keys.sort();
    (keys, vec![])
}

/// Backend checks against a deployed base URL: `/health/live` plus
/// `/health/ready` (the process and its DB pool, owner `backend`) plus
/// one `/v1/<app>/access` per app (owner is the app key, so the probe
/// rolls into the app's project and page like its iOS probes).
/// Access is bearer-gated, so per-app checks expect 401 — the auth
/// challenge proves routing plus the app's module is alive (a
/// kill-switch flip reads as a flip).
pub fn backend_wants(
    base_url: &str,
    keys: &[String],
    every_secs: u64,
    timeout_secs: u64,
) -> Vec<Want> {
    let base = base_url.trim_end_matches('/');
    let mut wants = vec![
        Want::url(
            "backend-live".to_string(),
            "backend",
            format!("{base}/health/live"),
            every_secs,
            timeout_secs,
            "high",
            200,
        ),
        Want::url(
            "backend-ready".to_string(),
            "backend",
            format!("{base}/health/ready"),
            every_secs,
            timeout_secs,
            "high",
            200,
        ),
    ];
    for key in keys {
        wants.push(Want::url(
            format!("backend-app-{key}"),
            key,
            format!("{base}/v1/{key}/access"),
            every_secs,
            timeout_secs,
            "normal",
            401,
        ));
    }
    wants
}

/// Whether a sync run owns a stored check for prune/stale purposes:
/// `source=auto` plus the run's scanned prefixes. A backend-only run
/// must not call the iOS checks gone (and vice versa).
pub fn sync_manages(name: &str, source: &str, scans_ios: bool, scans_backend: bool) -> bool {
    source == "auto"
        && ((scans_ios && name.starts_with("ios-"))
            || (scans_backend && name.starts_with("backend-")))
}

/// The first `AppIcon.appiconset/Contents.json` under the app dir
/// (depth 4 max, build and hidden dirs skipped).
fn find_appicon_contents(app_dir: &Path) -> Option<PathBuf> {
    let mut stack = vec![(app_dir.to_path_buf(), 0u8)];
    let mut hits = Vec::new();
    while let Some((dir, depth)) = stack.pop() {
        if depth > 4 {
            continue;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.filter_map(|e| e.ok()) {
            let name = e.file_name().to_string_lossy().into_owned();
            if !e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            if name.starts_with('.') || name == "build" || name == "DerivedData" {
                continue;
            }
            if name == "AppIcon.appiconset" {
                let c = e.path().join("Contents.json");
                if c.is_file() {
                    hits.push(c);
                }
            } else {
                stack.push((e.path(), depth + 1));
            }
        }
    }
    hits.sort();
    hits.into_iter().next()
}

/// Pick the icon file out of an `AppIcon.appiconset/Contents.json`:
/// the largest `size` wins (the 1024 store icon in practice), and
/// missing files never win.
pub fn pick_app_icon_file(contents: &serde_json::Value, dir: &Path) -> Option<PathBuf> {
    let images = contents.pointer("/images")?.as_array()?;
    let mut best: Option<(u32, PathBuf)> = None;
    for img in images {
        // Inherited variants (dark/tinted) carry no filename: skip
        // the entry, never the whole set.
        let Some(file) = img.pointer("/filename").and_then(|f| f.as_str()) else {
            continue;
        };
        let area = img
            .pointer("/size")
            .and_then(|s| s.as_str())
            .and_then(|s| {
                let (w, h) = s.split_once('x')?;
                w.trim()
                    .parse::<u32>()
                    .ok()?
                    .checked_mul(h.trim().parse::<u32>().ok()?)
            })
            .unwrap_or(0);
        let path = dir.join(file);
        if !path.is_file() {
            continue;
        }
        if best.as_ref().is_none_or(|(a, _)| area > *a) {
            best = Some((area, path));
        }
    }
    best.map(|(_, p)| p)
}

/// The app icon PNG for a sync upload, if the project has one.
pub fn scan_app_icon(app_dir: &Path) -> Option<PathBuf> {
    let contents = find_appicon_contents(app_dir)?;
    let text = fs::read_to_string(&contents).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    let dir = contents.parent().unwrap_or(app_dir);
    pick_app_icon_file(&v, dir)
}

/// Identity for one project row: what the sync uploads as metadata.
pub struct ProjectMeta {
    /// Project address.
    pub slug: String,
    /// Display group.
    pub group: String,
    /// Human name.
    pub name: String,
    /// Bundle id (`""` when none).
    pub bundle_id: String,
    /// Local icon PNG, when the project has one.
    pub icon_path: Option<PathBuf>,
}

/// Workspace app slugs, sorted (`[]` when `apps/` is unreadable).
fn app_slugs(root: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(root.join("apps")) else {
        return Vec::new();
    };
    let mut slugs: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with('.'))
        .collect();
    slugs.sort();
    slugs
}

/// Project metadata for every workspace app plus served-but-external
/// registry entries (legacy apps): names from `site/apps.yaml` (the
/// slug when the registry does not say), bundle ids from the app
/// target's `PRODUCT_BUNDLE_IDENTIFIER`, icons from the
/// `AppIcon.appiconset`. Retired entries stay out.
pub fn scan_ios_projects(root: &Path) -> (Vec<ProjectMeta>, Vec<String>) {
    let mut warnings = Vec::new();
    let registry = fs::read_to_string(root.join("site/apps.yaml"))
        .map(|t| parse_apps_yaml(&t))
        .unwrap_or_default();
    let names: HashMap<&str, &AppEntry> = registry.iter().map(|e| (e.slug.as_str(), e)).collect();
    let slugs = app_slugs(root);
    let mut metas = Vec::new();
    for slug in &slugs {
        let dir = root.join("apps").join(slug);
        let entry = names.get(slug.as_str()).copied();
        if entry.is_some_and(|e| e.state == "retired") {
            continue;
        }
        let name = entry
            .map(|e| e.name.clone())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| slug.clone());
        let bundle_id = find_pbxproj(&dir)
            .and_then(|p| fs::read_to_string(p).ok())
            .and_then(|t| pick_bundle_id(&t))
            .unwrap_or_default();
        if bundle_id.is_empty() {
            warnings.push(format!("ios {slug}: no PRODUCT_BUNDLE_IDENTIFIER found"));
        }
        metas.push(ProjectMeta {
            slug: slug.clone(),
            group: "ios".to_string(),
            name,
            bundle_id,
            icon_path: scan_app_icon(&dir),
        });
    }
    for entry in &registry {
        if entry.state == "retired" || slugs.contains(&entry.slug) {
            continue;
        }
        metas.push(ProjectMeta {
            slug: entry.slug.clone(),
            group: "ios".to_string(),
            name: if entry.name.is_empty() {
                entry.slug.clone()
            } else {
                entry.name.clone()
            },
            bundle_id: String::new(),
            icon_path: None,
        });
    }
    metas.sort_by(|a, b| a.slug.cmp(&b.slug));
    (metas, warnings)
}

/// PNG magic: what an uploadable icon starts with.
const PNG_MAGIC: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

/// sha256 hex of bytes, for the icon skip-if-same check.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    crate::util::hex(&Sha256::digest(bytes))
}

/// Bytes to upload for an icon: PNGs pass through, anything else
/// converts via `sips` (macOS ships it; the sync only runs on Macs),
/// capped at 512px — the phone renders icons small, and a 1024
/// photo-JPEG would otherwise explode past the hub's 1MB cap as PNG.
/// The hub stays PNG-only; the app decodes one format.
pub fn png_upload_bytes(path: &Path) -> Result<Vec<u8>, String> {
    let bytes = fs::read(path).map_err(|e| format!("cannot read icon: {e}"))?;
    if bytes.len() >= PNG_MAGIC.len() && bytes[..PNG_MAGIC.len()] == PNG_MAGIC {
        return Ok(bytes);
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let out = std::env::temp_dir().join(format!("est-icon-{}-{nanos}.png", std::process::id()));
    let status = std::process::Command::new("sips")
        .args(["-Z", "512", "-s", "format", "png"])
        .arg(path)
        .args(["--out"])
        .arg(&out)
        .output()
        .map_err(|e| format!("sips missing: {e}"))?;
    if !status.status.success() {
        let _ = fs::remove_file(&out);
        return Err(format!("sips refused {}", path.display()));
    }
    let converted = fs::read(&out).map_err(|e| format!("sips wrote nothing: {e}"))?;
    let _ = fs::remove_file(&out);
    if converted.len() < PNG_MAGIC.len() || converted[..PNG_MAGIC.len()] != PNG_MAGIC {
        return Err("sips output is not PNG".to_string());
    }
    Ok(converted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbxproj_reads_quoted_urls_and_skips_placeholders() {
        let text = "INFOPLIST_KEY_ECPrivacyURL = \"https://estifie.com/apps/x/privacy-policy\";\nINFOPLIST_KEY_ECTermsURL = \"https://estifie.com/apps/x/terms-of-use\";\nINFOPLIST_KEY_ECAPIKey = appl_xxx;\n";
        let (p, t, notes) = parse_pbxproj_legal(text);
        assert_eq!(
            p.as_deref(),
            Some("https://estifie.com/apps/x/privacy-policy")
        );
        assert_eq!(
            t.as_deref(),
            Some("https://estifie.com/apps/x/terms-of-use")
        );
        assert!(notes.is_empty());
    }

    #[test]
    fn pbxproj_first_wins_on_config_conflict() {
        let text = "INFOPLIST_KEY_ECPrivacyURL = \"https://a.example/p\";\nINFOPLIST_KEY_ECPrivacyURL = \"https://b.example/p\";\n";
        let (p, _, notes) = parse_pbxproj_legal(text);
        assert_eq!(p.as_deref(), Some("https://a.example/p"));
        assert_eq!(notes.len(), 1);
    }

    #[test]
    fn swift_config_urls_read_literals() {
        let text = "static let privacyURL = URL(string: \"https://example.com/p\")!\nstatic let termsURL = URL(string: \"https://example.com/t\")!\n";
        let (p, t) = parse_swift_config_urls(text);
        assert_eq!(p.as_deref(), Some("https://example.com/p"));
        assert_eq!(t.as_deref(), Some("https://example.com/t"));
    }

    #[test]
    fn swift_ignores_computed_urls() {
        let (p, t) = parse_swift_config_urls(
            "static var privacyURL: URL? { host.appending(path: \"p\") }\n",
        );
        assert!(p.is_none() && t.is_none());
    }

    #[test]
    fn support_url_shapes() {
        assert_eq!(
            parse_support_url("support_url: \"https://x.example/s\"\n").as_deref(),
            Some("https://x.example/s")
        );
        assert_eq!(
            parse_support_url("support_url: https://x.example/s # main\n").as_deref(),
            Some("https://x.example/s")
        );
        assert!(parse_support_url("support_url: \"\"\n").is_none());
        assert!(parse_support_url("marketing_url: \"https://x.example\"\n").is_none());
    }

    #[test]
    fn backend_wants_shape() {
        let wants = backend_wants(
            "https://api.example.com/",
            &["songcreator".to_string()],
            300,
            15,
        );
        assert_eq!(wants.len(), 3);
        assert_eq!(wants[0].name, "backend-live");
        assert_eq!(wants[0].target, "https://api.example.com/health/live");
        assert_eq!(wants[0].expect, 200);
        assert_eq!(wants[2].name, "backend-app-songcreator");
        assert_eq!(wants[2].owner, "songcreator");
        assert_eq!(
            wants[2].target,
            "https://api.example.com/v1/songcreator/access"
        );
        assert_eq!(wants[2].expect, 401);
    }

    fn fixture_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("est-sync-test-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn ios_scan_finds_pbxproj_swift_and_support() {
        let root = fixture_root("ios");
        let a1 = root.join("apps/a1/A.xcodeproj");
        fs::create_dir_all(&a1).unwrap();
        fs::write(
            a1.join("project.pbxproj"),
            "INFOPLIST_KEY_ECPrivacyURL = \"https://x.example/a1p\";\nINFOPLIST_KEY_ECTermsURL = \"https://x.example/a1t\";\n",
        )
        .unwrap();
        let asc = root.join("apps/a1/.estifie/asc");
        fs::create_dir_all(&asc).unwrap();
        fs::write(
            asc.join("general.yaml"),
            "support_url: \"https://x.example/a1s\"\n",
        )
        .unwrap();
        let a2 = root.join("apps/a2");
        fs::create_dir_all(&a2).unwrap();
        fs::write(
            a2.join("AppConfig.swift"),
            "static let privacyURL = URL(string: \"https://x.example/a2p\")!\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("apps/a3")).unwrap();

        let scan = scan_ios_apps(&root, 300, 15);
        let names: Vec<_> = scan.wants.iter().map(|w| w.name.as_str()).collect();
        assert!(names.contains(&"ios-a1-privacy"));
        assert!(names.contains(&"ios-a1-terms"));
        assert!(names.contains(&"ios-a1-support"));
        assert!(names.contains(&"ios-a2-privacy"));
        assert!(!names.iter().any(|n| n.contains("a3")));
        assert_eq!(scan.wants.len(), 4);
        assert!(
            scan.warnings
                .iter()
                .any(|w| w.contains("a2") && w.contains("terms"))
        );
        assert!(
            scan.warnings
                .iter()
                .any(|w| w.contains("a3") && w.contains("no legal URLs"))
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn bundle_id_prefers_the_app_target() {
        let text = "PRODUCT_BUNDLE_IDENTIFIER = com.estifie.xTests;\nPRODUCT_BUNDLE_IDENTIFIER = com.estifie.x;\nPRODUCT_BUNDLE_IDENTIFIER = com.estifie.x.widgets;\n";
        assert_eq!(pick_bundle_id(text).as_deref(), Some("com.estifie.x"));
        let ext = "PRODUCT_BUNDLE_IDENTIFIER = com.estifie.y.Share;\nPRODUCT_BUNDLE_IDENTIFIER = com.estifie.y;\n";
        assert_eq!(pick_bundle_id(ext).as_deref(), Some("com.estifie.y"));
        assert!(pick_bundle_id("PRODUCT_BUNDLE_IDENTIFIER = ;\n").is_none());
        assert!(pick_bundle_id("PRODUCT_BUNDLE_IDENTIFIER = com.estifie.nothing;\n").is_some());
    }

    #[test]
    fn app_icon_prefers_largest_size() {
        let root = fixture_root("appicon");
        let set = root.join("A.xcassets/AppIcon.appiconset");
        fs::create_dir_all(&set).unwrap();
        fs::write(
            set.join("Contents.json"),
            r#"{"images":[
              {"size":"60x60","filename":"small.png"},
              {"size":"1024x1024","filename":"big.png"},
              {"size":"2048x2048","filename":"ghost.png"},
              {"size":"512x512"}]}"#,
        )
        .unwrap();
        fs::write(set.join("small.png"), b"small").unwrap();
        fs::write(set.join("big.png"), b"big").unwrap();
        // ghost.png is missing and the last entry inherits (no
        // filename): neither may kill the pick.
        assert_eq!(scan_app_icon(&root), Some(set.join("big.png")));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn sha256_hex_matches_the_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn png_upload_passes_png_through_and_refuses_garbage() {
        let root = fixture_root("pngup");
        let png = root.join("a.png");
        let mut bytes = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        bytes.extend([0u8; 16]);
        fs::write(&png, &bytes).unwrap();
        assert_eq!(png_upload_bytes(&png).unwrap(), bytes);
        let garbage = root.join("b.jpg");
        fs::write(&garbage, b"definitely not an image").unwrap();
        assert!(png_upload_bytes(&garbage).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn ios_projects_collect_metadata() {
        let root = fixture_root("projects");
        let a1 = root.join("apps/a1");
        fs::create_dir_all(a1.join("A.xcodeproj")).unwrap();
        fs::write(
            a1.join("A.xcodeproj/project.pbxproj"),
            "PRODUCT_BUNDLE_IDENTIFIER = com.estifie.a1Tests;\nPRODUCT_BUNDLE_IDENTIFIER = com.estifie.a1;\n",
        )
        .unwrap();
        let set = a1.join("A.xcassets/AppIcon.appiconset");
        fs::create_dir_all(&set).unwrap();
        fs::write(
            set.join("Contents.json"),
            r#"{"images":[{"size":"1024x1024","filename":"i.png"}]}"#,
        )
        .unwrap();
        fs::write(set.join("i.png"), b"png").unwrap();
        fs::create_dir_all(root.join("apps/a3")).unwrap();
        let site = root.join("site");
        fs::create_dir_all(&site).unwrap();
        fs::write(
            site.join("apps.yaml"),
            "apps:\n  - slug: a1\n    name: \"Ay One\"\n    state: generated\n  - slug: a9\n    name: \"Ay Nine\"\n    state: legacy\n",
        )
        .unwrap();
        let (metas, warnings) = scan_ios_projects(&root);
        assert_eq!(metas.len(), 3);
        let a1m = metas.iter().find(|m| m.slug == "a1").unwrap();
        assert_eq!(a1m.name, "Ay One");
        assert_eq!(a1m.bundle_id, "com.estifie.a1");
        assert_eq!(a1m.icon_path, Some(set.join("i.png")));
        assert_eq!(a1m.group, "ios");
        let a9m = metas.iter().find(|m| m.slug == "a9").unwrap();
        assert_eq!(a9m.name, "Ay Nine");
        assert!(a9m.bundle_id.is_empty() && a9m.icon_path.is_none());
        assert!(warnings.iter().any(|w| w.contains("a3")));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn backend_scan_lists_app_dirs() {
        let root = fixture_root("backend");
        fs::create_dir_all(root.join("internal/apps/bb")).unwrap();
        fs::create_dir_all(root.join("internal/apps/aa")).unwrap();
        fs::write(root.join("internal/apps/registry_gen.go"), "package apps\n").unwrap();
        let (keys, warnings) = scan_backend_apps(&root);
        assert_eq!(keys, vec!["aa".to_string(), "bb".to_string()]);
        assert!(warnings.is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn sync_manages_only_scanned_prefixes() {
        assert!(sync_manages("ios-a-privacy", "auto", true, false));
        assert!(sync_manages("backend-live", "auto", false, true));
        assert!(sync_manages("ios-a-privacy", "auto", true, true));
        assert!(!sync_manages("ios-a-privacy", "auto", false, true));
        assert!(!sync_manages("backend-live", "auto", true, false));
        assert!(!sync_manages("ios-a-privacy", "manual", true, false));
        assert!(!sync_manages("site", "auto", true, true));
    }

    #[test]
    fn apps_yaml_lists_slugs_and_states() {
        let text = "# comment\napps:\n  - slug: aa\n    name: \"Ay\"\n    state: generated\n  - slug: \"bb\"\n    state: legacy\n";
        assert_eq!(
            parse_apps_yaml(text),
            vec![
                AppEntry {
                    slug: "aa".to_string(),
                    name: "Ay".to_string(),
                    state: "generated".to_string(),
                },
                AppEntry {
                    slug: "bb".to_string(),
                    name: "".to_string(),
                    state: "legacy".to_string(),
                },
            ]
        );
    }

    #[test]
    fn legal_base_needs_a_proven_pattern() {
        let mut explicit = HashMap::new();
        explicit.insert(
            "freq".to_string(),
            (
                Some("https://estifie.com/apps/freq/privacy-policy".to_string()),
                None,
            ),
        );
        assert_eq!(
            legal_base_from(&explicit).as_deref(),
            Some("https://estifie.com/apps")
        );
        let mut other = HashMap::new();
        other.insert(
            "x".to_string(),
            (Some("https://else.example/legal".to_string()), None),
        );
        assert!(legal_base_from(&other).is_none());
        assert!(legal_base_from(&HashMap::new()).is_none());
    }

    #[test]
    fn ios_scan_derives_registry_legal() {
        let root = fixture_root("derived");
        let a1 = root.join("apps/a1/A.xcodeproj");
        fs::create_dir_all(&a1).unwrap();
        fs::write(
            a1.join("project.pbxproj"),
            "INFOPLIST_KEY_ECPrivacyURL = \"https://x.example/apps/a1/privacy-policy\";\nINFOPLIST_KEY_ECTermsURL = \"https://x.example/apps/a1/terms-of-use\";\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("apps/a3")).unwrap();
        let site = root.join("site");
        fs::create_dir_all(&site).unwrap();
        fs::write(
            site.join("apps.yaml"),
            "apps:\n  - slug: a1\n    state: generated\n  - slug: a3\n    state: generated\n  - slug: a4\n    state: legacy\n  - slug: a5\n    state: retired\n",
        )
        .unwrap();

        let scan = scan_ios_apps(&root, 300, 15);
        let names: Vec<_> = scan.wants.iter().map(|w| w.name.as_str()).collect();
        assert_eq!(scan.wants.len(), 6);
        assert!(names.contains(&"ios-a1-privacy"));
        assert!(names.contains(&"ios-a3-terms"));
        assert!(names.contains(&"ios-a4-privacy"));
        assert!(!names.iter().any(|n| n.contains("a5")));
        let a3 = scan
            .wants
            .iter()
            .find(|w| w.name == "ios-a3-privacy")
            .unwrap();
        assert_eq!(a3.target, "https://x.example/apps/a3/privacy-policy");
        assert!(
            scan.warnings
                .iter()
                .any(|w| w.contains("a3") && w.contains("derived"))
        );
        assert!(
            scan.warnings
                .iter()
                .any(|w| w.contains("a4") && w.contains("legacy"))
        );
        let _ = fs::remove_dir_all(&root);
    }
}
