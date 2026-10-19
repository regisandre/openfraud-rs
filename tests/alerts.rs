//! Alerts to people: each notifier gets what reaches its minimum severity,
//! now or gathered in a digest; critical alerts never wait.

mod support;

use openfraud::alerts::{Alerts, flush_digests};
use openfraud::config::{Config, Severity};
use openfraud::engine::{Engine, queue_alert};
use openfraud::outbox::{Workers, run_outbox};
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

fn engine(text: &str) -> Engine {
    Engine::open(
        Config::parse(text, Path::new(".")).unwrap(),
        b"alerts-test-key-alerts-test-key!".to_vec(),
        None,
    )
    .unwrap()
}

fn alert(e: &Engine, severity: Severity, title: &str, at: u64) {
    let config = e.assembled();
    e.with_store(|s| queue_alert(s, &config, severity, title, "details", at)).unwrap();
}

fn workers(e: &Engine) -> Workers {
    let mut w = Workers::new("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");
    w.handlers.insert(
        "alert".into(),
        Box::new(Alerts::new(&e.assembled(), "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")),
    );
    w
}

#[test]
fn each_notifier_gets_the_severities_it_asked_for() {
    let (slack, slack_rx) = support::serve(vec![(200, "ok".into()); 4]);
    let (hook, hook_rx) = support::serve(vec![(200, "{}".into()); 4]);
    let (tg, tg_rx) = support::serve(vec![(200, r#"{"ok":true}"#.into()); 4]);
    // SAFETY: tests in this file do not read this variable concurrently.
    unsafe { std::env::set_var("OPENFRAUD_TEST_TG_TOKEN", "123:abc") };
    let e = engine(&format!(
        r#"
[[alerts]]
kind = "slack"
url = "{slack}/services/x"
min_severity = "warning"

[[alerts]]
kind = "webhook"
url = "{hook}/alerts"
min_severity = "info"

[[alerts]]
kind = "telegram"
api_base = "{tg}"
bot_token_env = "OPENFRAUD_TEST_TG_TOKEN"
chat_id = "-100"
min_severity = "critical"
"#
    ));
    alert(&e, Severity::Info, "Case opened", 1_000);
    alert(&e, Severity::Warning, "Account quarantined", 1_000);
    alert(&e, Severity::Critical, "Safety brake engaged", 1_000);
    let report = run_outbox(&e, &workers(&e), 1_000, 50);
    assert_eq!(report.len(), 6, "1 + 2 + 3 deliveries: {report:#?}");
    assert!(report.iter().all(|r| r.ends_with("done")), "{report:#?}");

    let wait = |rx: &mpsc::Receiver<support::Received>| -> Vec<support::Received> { rx.try_iter().collect() };
    std::thread::sleep(Duration::from_millis(50));
    let slack = wait(&slack_rx);
    assert_eq!(slack.len(), 2, "warning and critical");
    let text: Value = serde_json::from_str(&slack[0].body).unwrap();
    assert!(text["text"].as_str().unwrap().contains("Account quarantined"), "{text}");
    let hooks = wait(&hook_rx);
    assert_eq!(hooks.len(), 3);
    assert!(
        hooks.iter().all(|h| h.header("webhook-signature").starts_with("v1,")),
        "the webhook is signed"
    );
    let tg = wait(&tg_rx);
    assert_eq!(tg.len(), 1);
    assert_eq!(tg[0].path, "/bot123:abc/sendMessage");
    let body: Value = serde_json::from_str(&tg[0].body).unwrap();
    assert_eq!(body["chat_id"], "-100");
    assert!(body["text"].as_str().unwrap().contains("Safety brake engaged"));
}

#[test]
fn a_digest_gathers_alerts_and_critical_ones_go_at_once() {
    let (slack, rx) = support::serve(vec![(200, "ok".into()); 3]);
    let e = engine(&format!(
        "[[alerts]]\nkind = \"slack\"\nurl = \"{slack}/x\"\nmin_severity = \"info\"\ndigest = \"1h\"\n"
    ));
    alert(&e, Severity::Info, "Case opened", 1_000);
    alert(&e, Severity::Warning, "Account quarantined", 1_200);
    run_outbox(&e, &workers(&e), 1_200, 50);
    alert(&e, Severity::Critical, "Safety brake engaged", 1_300);
    run_outbox(&e, &workers(&e), 1_300, 50);
    std::thread::sleep(Duration::from_millis(50));
    let now: Vec<_> = rx.try_iter().collect();
    assert_eq!(now.len(), 1, "only the critical alert went out");
    assert!(now[0].body.contains("Safety brake engaged"));

    flush_digests(&e, 2_000);
    run_outbox(&e, &workers(&e), 2_000, 50);
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(rx.try_iter().count(), 0, "not before the digest period");
    flush_digests(&e, 1_000 + 3_600);
    run_outbox(&e, &workers(&e), 1_000 + 3_600, 50);
    std::thread::sleep(Duration::from_millis(50));
    let digest: Vec<_> = rx.try_iter().collect();
    assert_eq!(digest.len(), 1, "one message for the period");
    assert!(
        digest[0].body.contains("Case opened") && digest[0].body.contains("Account quarantined"),
        "{}",
        digest[0].body
    );
    flush_digests(&e, 1_000 + 7_200);
    assert!(
        run_outbox(&e, &workers(&e), 1_000 + 7_200, 50).is_empty(),
        "an empty digest sends nothing"
    );
}

/// A minimal SMTP server: accepts one message and hands back its DATA.
fn smtp() -> (u16, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else { return };
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut out = stream;
        writeln!(out, "220 test ESMTP\r").unwrap();
        let mut data = String::new();
        let mut in_data = false;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            if in_data {
                if line == ".\r\n" {
                    in_data = false;
                    write!(out, "250 queued\r\n").unwrap();
                } else {
                    data.push_str(&line);
                }
                continue;
            }
            let cmd = line.to_ascii_uppercase();
            if cmd.starts_with("EHLO") {
                write!(out, "250-test\r\n250 OK\r\n").unwrap();
            } else if cmd.starts_with("DATA") {
                in_data = true;
                write!(out, "354 go\r\n").unwrap();
            } else if cmd.starts_with("QUIT") {
                write!(out, "221 bye\r\n").unwrap();
                break;
            } else {
                write!(out, "250 OK\r\n").unwrap();
            }
        }
        tx.send(data).unwrap();
    });
    (port, rx)
}

#[test]
fn an_email_alert_goes_through_smtp() {
    let (port, rx) = smtp();
    let e = engine(&format!(
        "[[alerts]]\nkind = \"email\"\nsmtp_host = \"127.0.0.1\"\nsmtp_port = {port}\nsmtp_tls = \"none\"\nfrom = \"openfraud@example.com\"\nto = [\"oncall@example.com\"]\nmin_severity = \"warning\"\n"
    ));
    alert(&e, Severity::Warning, "Account quarantined", 1_000);
    let report = run_outbox(&e, &workers(&e), 1_000, 50);
    assert!(report.iter().all(|r| r.ends_with("done")), "{report:#?}");
    let data = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(data.contains("Subject: [openfraud] warning: Account quarantined"), "{data}");
    assert!(data.contains("To: oncall@example.com"), "{data}");
}

#[test]
fn an_alert_without_a_notifier_is_not_queued() {
    let e = engine("");
    alert(&e, Severity::Critical, "Safety brake engaged", 1_000);
    assert!(e.with_store(|s| s.outbox_recent(10)).unwrap().is_empty());
}
