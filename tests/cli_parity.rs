//! The control-plane rule as a gate: every route in [`est_hub::api::ROUTES`]
//! answers with a versioned envelope, and every route names the CLI twin
//! that appears in `est-hub help`. A route merged without its twin —
//! or a twin missing from help — fails here.

mod common;

use common::Hub;
use est_hub::api::ROUTES;

#[test]
fn every_route_names_a_twin_in_help() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_est-hub"))
        .arg("help")
        .output()
        .unwrap();
    let help = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(!help.is_empty());
    for r in ROUTES {
        assert!(help.contains(r.cli), "help lacks the {:?} twin", r.cli);
    }
}

#[tokio::test]
async fn every_route_answers_envelopes() {
    let hub = Hub::spawn("parity");
    let client = reqwest::Client::new();
    for r in ROUTES {
        let path = r
            .path
            .replace("{name}", "__parity__")
            .replace("{id}", "999999");
        let req = match r.method {
            "GET" => client.get(hub.url(&path)),
            "DELETE" => client.delete(hub.url(&path)),
            "POST" => client.post(hub.url(&path)).json(&serde_json::json!({})),
            "PUT" => client.put(hub.url(&path)).json(&serde_json::json!({})),
            m => panic!("unknown method {m}"),
        };
        let res = req.send().await.unwrap();
        let body = res.text().await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&body)
            .unwrap_or_else(|_| panic!("{} {} is not JSON: {body:?}", r.method, path));
        assert_eq!(v["v"], 1, "{} {} lacks the version", r.method, path);
        assert!(
            v.get("ok").and_then(|o| o.as_bool()).is_some(),
            "{} {} lacks ok",
            r.method,
            path
        );
    }
}
