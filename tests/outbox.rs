//! The outbox: what a decision asks to deliver (webhooks to the application,
//! module actions) leaves the engine's transaction as rows, and a worker
//! delivers them, retries them, and gives up after the last attempt.

use openfraud::config::Config;

type Received = (Vec<(String, String)>, String);
use openfraud::engine::{Engine, Options};
use openfraud::outbox::{Handler, Workers, run_outbox};
use openfraud::webhook::{Delivery, generate_secret, verify};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

/// An HTTP server answering each request with the next status of `statuses`,
/// and sending back (headers, body).
fn receiver(statuses: Vec<u16>) -> (String, mpsc::Receiver<Received>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for status in statuses {
            let Ok((stream, _)) = listener.accept() else { return };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut headers = Vec::new();
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let line = line.trim_end().to_owned();
                if line.is_empty() {
                    break;
                }
                if let Some((k, v)) = line.split_once(':') {
                    let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_owned());
                    if k == "content-length" {
                        length = v.parse().unwrap();
                    }
                    headers.push((k, v));
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let mut stream = stream;
            write!(stream, "HTTP/1.1 {status} X\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").unwrap();
            tx.send((headers, String::from_utf8(body).unwrap())).unwrap();
        }
    });
    (url, rx)
}

fn engine(url: &str) -> Engine {
    let config = format!(
        r#"
[safety]
require_replay = false

[webhooks]
url = "{url}"
max_attempts = 2
events = ["decision.quarantine", "actor.status_changed"]

[workflows.w]
events = ["message.send_requested"]
quarantine_at = 50
on_quarantine = {{ actions = ["suspend_feature:email"] }}

[[workflows.w.rules]]
id = "always"
when = "true"
score = 60
reason = "Always"
"#
    );
    Engine::open(
        Config::parse(&config, Path::new(".")).unwrap(),
        b"outbox-test-key-outbox-test-key!".to_vec(),
        None,
    )
    .unwrap()
}

fn block_event(e: &Engine, now: u64) {
    let raw = serde_json::from_value(json!({"type": "message.send_requested", "actor_id": "u1", "at": now})).unwrap();
    e.process(
        raw,
        Options {
            dry_run: false,
            now: Some(now),
        },
    )
    .unwrap();
}

#[test]
fn a_decision_and_a_status_change_reach_the_application_signed() {
    let (url, rx) = receiver(vec![200, 200]);
    let e = engine(&url);
    let secret = generate_secret();
    let now = 1_800_000_000;
    block_event(&e, now);
    let report = run_outbox(&e, &Workers::new(&secret), now, 10);
    assert_eq!(report.len(), 2, "{report:?}");
    let mut types = Vec::new();
    for _ in 0..2 {
        let (headers, body) = rx.recv().unwrap();
        let get = |name: &str| headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone()).unwrap_or_default();
        let ts: u64 = get("webhook-timestamp").parse().unwrap();
        verify(&secret, &get("webhook-id"), ts, &get("webhook-signature"), body.as_bytes(), ts).unwrap();
        let v: Value = serde_json::from_str(&body).unwrap();
        types.push(v["type"].as_str().unwrap().to_owned());
        if v["type"] == "decision.quarantine" {
            let actions = v["data"]["actions"].as_array().unwrap();
            assert!(
                actions.contains(&json!({"action": "suspend_feature:email", "target": "actor", "id": "u1"})),
                "the decision carries its actions: {v}"
            );
            assert_eq!(v["data"]["actor"]["status"], "quarantined");
        }
    }
    types.sort();
    assert_eq!(types, vec!["actor.status_changed", "decision.quarantine"]);
    assert!(
        run_outbox(&e, &Workers::new(&secret), now + 1, 10).is_empty(),
        "nothing left to deliver"
    );
}

#[test]
fn a_failed_delivery_is_retried_then_given_up() {
    let (url, rx) = receiver(vec![503, 503, 503, 503]);
    let e = engine(&url);
    let secret = generate_secret();
    let now = 1_800_000_000;
    block_event(&e, now);
    let first = run_outbox(&e, &Workers::new(&secret), now, 10);
    assert_eq!(first.len(), 2);
    assert!(first.iter().all(|r| r.contains("retry")), "{first:?}");
    assert!(
        run_outbox(&e, &Workers::new(&secret), now + 1, 10).is_empty(),
        "not before its retry time"
    );
    let second = run_outbox(&e, &Workers::new(&secret), now + 10, 10);
    assert!(
        second.iter().all(|r| r.contains("failed")),
        "max_attempts = 2: given up: {second:?}"
    );
    assert!(run_outbox(&e, &Workers::new(&secret), now + 100_000, 10).is_empty());
    drop(rx);
}

struct Recorder(Arc<Mutex<Vec<String>>>);

impl Handler for Recorder {
    fn handle(&self, _engine: &Engine, payload: &str) -> Delivery {
        self.0.lock().unwrap().push(payload.to_owned());
        Delivery::Done
    }
}

#[test]
fn a_module_action_goes_to_its_handler() {
    let config = r#"
[safety]
require_replay = false

[stripe]
enabled = true
actions = true

[workflows.w]
events = ["subscription.trial_started"]
quarantine_at = 50
on_quarantine = { actions = ["stripe.cancel_subscriptions"] }

[[workflows.w.rules]]
id = "always"
when = "true"
score = 60
reason = "Always"
"#;
    let e = Engine::open(
        Config::parse(config, Path::new(".")).unwrap(),
        b"outbox-test-key-outbox-test-key!".to_vec(),
        None,
    )
    .unwrap();
    let raw = serde_json::from_value(json!({"type": "subscription.trial_started", "actor_id": "u9", "at": 100})).unwrap();
    e.process(
        raw,
        Options {
            dry_run: false,
            now: Some(100),
        },
    )
    .unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut workers = Workers::new("whsec_AAAA");
    workers.handlers.insert("stripe".into(), Box::new(Recorder(seen.clone())));
    let report = run_outbox(&e, &workers, 100, 10);
    assert_eq!(report.len(), 1, "only the stripe.* action goes to the module: {report:?}");
    let payload: Value = serde_json::from_str(&seen.lock().unwrap()[0]).unwrap();
    assert_eq!(payload["action"], "stripe.cancel_subscriptions");
    assert_eq!(payload["user"], "u9");
}
