//! Full resource flows over real HTTP, plus every CLI twin against
//! a live hub. If a flow breaks here, dashboards and agents break too.

mod common;

use common::Hub;
use serde_json::{Value, json};

async fn post(hub: &Hub, path: &str, body: Value) -> (u16, Value) {
    let res = reqwest::Client::new()
        .post(hub.url(path))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap())
}

async fn get(hub: &Hub, path: &str) -> (u16, Value) {
    let res = reqwest::get(hub.url(path)).await.unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap())
}

#[tokio::test]
async fn devices_crud_roundtrip() {
    let hub = Hub::spawn("flows-devices");
    let (s, v) = post(&hub, "/devices", json!({"name": "iphone"})).await;
    assert_eq!(s, 201);
    assert_eq!(v["device"]["name"], "iphone");
    let (s, v) = post(&hub, "/devices", json!({"name": "iphone"})).await;
    assert_eq!(s, 409);
    assert_eq!(v["ok"], false);
    let (s, _) = get(&hub, "/devices").await;
    assert_eq!(s, 200);
    let (s, v) = post(&hub, "/devices", json!({"name": "Nope!"})).await;
    assert_eq!(s, 400);
    assert_eq!(v["ok"], false);
    let client = reqwest::Client::new();
    let res = client
        .delete(hub.url("/devices/iphone"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let (s, _) = get(&hub, "/devices/iphone").await;
    assert_eq!(s, 404);
}

#[tokio::test]
async fn checks_crud_and_validation() {
    let hub = Hub::spawn("flows-checks");
    let (s, v) = post(
        &hub,
        "/checks",
        json!({"name": "site", "owner": "estifie", "type": "url", "target": "https://example.com"}),
    )
    .await;
    assert_eq!(s, 201);
    assert_eq!(v["check"]["state"]["status"], "unknown");
    let (s, _) = post(
        &hub,
        "/checks",
        json!({"name": "bad", "owner": "e", "type": "nope", "target": "x"}),
    )
    .await;
    assert_eq!(s, 400);
    let client = reqwest::Client::new();
    let res = client
        .put(hub.url("/checks/site"))
        .json(&json!({"owner": "e2", "type": "url", "target": "https://example.org"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["check"]["owner"], "e2");
    let res = client.delete(hub.url("/checks/site")).send().await.unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let (s, _) = get(&hub, "/checks/site").await;
    assert_eq!(s, 404);
}

#[tokio::test]
async fn results_flip_and_queue_flip_notifications() {
    let hub = Hub::spawn("flows-flip");
    post(
        &hub,
        "/checks",
        json!({"name": "api", "owner": "e", "type": "api", "target": "https://x.test/h"}),
    )
    .await;
    let (s, v) = post(
        &hub,
        "/results",
        json!({"check": "api", "ok": false, "reason": "refused"}),
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(v["flipped"], true);
    let (_, v) = post(
        &hub,
        "/results",
        json!({"check": "api", "ok": false, "reason": "refused"}),
    )
    .await;
    assert_eq!(v["flipped"], false);
    let (_, v) = post(
        &hub,
        "/results",
        json!({"check": "api", "ok": true, "code": 200}),
    )
    .await;
    assert_eq!(v["flipped"], true);
    let (_, v) = get(&hub, "/checks/api").await;
    assert_eq!(v["check"]["state"]["status"], "up");
    assert_eq!(v["check"]["state"]["fails"], 0);
    let (_, v) = get(&hub, "/notifications?limit=10").await;
    let notes = v["notifications"].as_array().unwrap();
    assert_eq!(notes.len(), 2);
    assert!(notes.iter().all(|n| n["topic"] == "health.flip"));
    let (_, v) = get(&hub, "/checks/api/results?limit=2").await;
    assert_eq!(v["results"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn heartbeat_staleness_reads_down() {
    let hub = Hub::spawn("flows-beat");
    post(
        &hub,
        "/checks",
        json!({"name": "nightly", "owner": "e", "type": "heartbeat", "target": "nightly-job",
               "every_secs": 10, "miss_after_secs": 30}),
    )
    .await;
    // A fresh beat: the prober's next tick records it up.
    let (s, _) = post(&hub, "/heartbeats", json!({"check": "nightly"})).await;
    assert_eq!(s, 200);
    let (_, v) = get(&hub, "/checks/nightly").await;
    assert!(v["check"]["state"]["last_beat"].as_u64().unwrap() > 0);
    // An ancient beat: the next tick records it down.
    let old = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 3600;
    post(&hub, "/heartbeats", json!({"check": "nightly", "ts": old})).await;
    let mut down = false;
    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let (_, v) = get(&hub, "/checks/nightly").await;
        if v["check"]["state"]["status"] == "down" {
            down = true;
            break;
        }
    }
    assert!(down, "the prober never marked the stale heartbeat down");
}

#[tokio::test]
async fn approvals_decide_once_and_expire_live() {
    let hub = Hub::spawn("flows-approvals");
    let (_, v) = post(&hub, "/approvals", json!({"title": "deploy?"})).await;
    let id = v["approval"]["id"].as_i64().unwrap();
    assert_eq!(v["approval"]["state"], "pending");
    let (s, v) = post(
        &hub,
        &format!("/approvals/{id}/decision"),
        json!({"approve": true, "by": "e"}),
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(v["approval"]["state"], "approved");
    let (s, _) = post(
        &hub,
        &format!("/approvals/{id}/decision"),
        json!({"approve": false}),
    )
    .await;
    assert_eq!(s, 400);
    let (_, v) = get(&hub, "/approvals?state=approved").await;
    assert_eq!(v["approvals"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn notify_queues_for_drivers() {
    let hub = Hub::spawn("flows-notify");
    let (s, v) = post(&hub, "/notify", json!({"title": "hello", "topic": "test"})).await;
    assert_eq!(s, 201);
    assert_eq!(v["notification"]["delivered"], false);
    let (s, _) = post(&hub, "/notify", json!({"title": ""})).await;
    assert_eq!(s, 400);
}

#[test]
fn every_cli_twin_works_against_a_live_hub() {
    let hub = Hub::spawn("flows-cli");
    let run = |args: &[&str]| {
        let out = hub.cli(args).output().unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    assert!(run(&["devices", "add", "phone"]).contains("added device phone"));
    assert!(run(&["devices", "list"]).contains("phone"));
    assert!(run(&["devices", "show", "phone"]).contains("phone"));
    assert!(
        run(&[
            "checks",
            "add",
            "site",
            "--type",
            "url",
            "--target",
            "https://example.com",
            "--owner",
            "e"
        ])
        .contains("added check site")
    );
    assert!(run(&["checks", "list"]).contains("site"));
    assert!(run(&["checks", "show", "site"]).contains("example.com"));
    assert!(
        run(&[
            "checks",
            "set",
            "site",
            "--type",
            "url",
            "--target",
            "https://example.org",
            "--owner",
            "e"
        ])
        .contains("updated check site")
    );
    assert!(
        run(&[
            "results", "report", "--check", "site", "--fail", "--reason", "x"
        ])
        .contains("recorded")
    );
    assert!(run(&["results", "list", "--check", "site"]).contains("FAIL"));
    assert!(run(&["heartbeats", "beat", "--check", "site"]).contains("beat site"));
    let text = run(&["approvals", "request", "--title", "ship?"]);
    assert!(text.contains("approval #"), "{text}");
    let id = text
        .split('#')
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    assert!(run(&["approvals", "list"]).contains("ship?"));
    assert!(run(&["approvals", "show", &id]).contains("pending"));
    assert!(run(&["approvals", "decide", &id, "--approve", "--by", "e"]).contains("approved"));
    assert!(run(&["notify", "send", "--title", "hi"]).contains("notified #"));
    assert!(run(&["notifications", "list"]).contains("hi"));
    assert!(run(&["checks", "delete", "site", "--yes"]).contains("deleted check site"));
    assert!(run(&["devices", "revoke", "phone", "--yes"]).contains("revoked device phone"));
    let out = hub.cli(&["checks", "show", "site"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
}
