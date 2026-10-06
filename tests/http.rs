//! The hub over real TCP: spawn `serve` on an ephemeral port, read
//! the address it prints, and assert the envelopes. The child is killed
//! on drop; the address read is bounded (15s) so a broken binary fails
//! the test instead of hanging it.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Hub {
    child: Child,
    addr: String,
}

impl Hub {
    fn spawn(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("est-hub-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_est-hub"))
            .args(["serve", "--port", "0", "--db"])
            .arg(dir.join("hub.sqlite"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let out = BufReader::new(child.stdout.take().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let mut out = out;
            let _ = out.read_line(&mut line);
            let _ = tx.send(line);
        });
        let line = rx
            .recv_timeout(Duration::from_secs(15))
            .expect("the hub did not print its address");
        let value: serde_json::Value = serde_json::from_str(&line).expect("not JSON");
        assert_eq!(value["ok"], true);
        let addr = value["listening"].as_str().unwrap().to_string();
        Hub { child, addr }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

impl Drop for Hub {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test]
async fn ping_answers_the_versioned_envelope() {
    let hub = Hub::spawn("ping");
    let res = reqwest::get(hub.url("/ping")).await.unwrap();
    assert!(res.status().is_success());
    let value: serde_json::Value = res.json().await.unwrap();
    assert_eq!(value["ok"], true);
    assert_eq!(value["v"], 1);
    assert_eq!(value["name"], "est-hub");
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn unknown_routes_are_404_envelopes() {
    let hub = Hub::spawn("404");
    let res = reqwest::get(hub.url("/nope")).await.unwrap();
    assert_eq!(res.status().as_u16(), 404);
    let value: serde_json::Value = res.json().await.unwrap();
    assert_eq!(value["ok"], false);
    assert_eq!(value["v"], 1);
}

#[test]
fn ping_command_reports_liveness() {
    let hub = Hub::spawn("cli");
    let out = Command::new(env!("CARGO_BIN_EXE_est-hub"))
        .args(["ping", "--hub"])
        .arg(format!("http://{}", hub.addr))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(text.starts_with("hub ok (est-hub "), "{text}");
}
