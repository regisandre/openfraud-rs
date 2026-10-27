//! Webhooks: signed with the Standard Webhooks scheme, delivered from the
//! outbox, retried with backoff, and given up on when the receiver says the
//! endpoint is gone.
#![allow(clippy::type_complexity)]

use openfraud::webhook::{Delivery, deliver, download, generate_secret, global_address, redirect_allowed, retry_delay, sign, verify};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

#[test]
fn a_signature_matches_the_standard_webhooks_test_vector() {
    let sig = sign(
        "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw",
        "msg_p5jXN8AQM9LWM0D4loKWxJek",
        1_614_265_330,
        br#"{"test": 2432232314}"#,
    )
    .unwrap();
    assert_eq!(sig, "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=");
}

#[test]
fn a_receiver_accepts_only_a_fresh_untouched_message() {
    let secret = generate_secret();
    assert!(secret.starts_with("whsec_"), "{secret}");
    let body = br#"{"type":"decision.block"}"#;
    let sig = sign(&secret, "msg_1", 10_000, body).unwrap();
    // (case, secret, id, timestamp, signature header, body, now, accepted)
    let other = generate_secret();
    let cases: Vec<(&str, &str, &str, u64, String, &[u8], u64, bool)> = vec![
        ("the message as sent", &secret, "msg_1", 10_000, sig.clone(), body, 10_100, true),
        (
            "one of several signatures",
            &secret,
            "msg_1",
            10_000,
            format!("v1,bm90IGl0 {sig}"),
            body,
            10_100,
            true,
        ),
        (
            "a changed body",
            &secret,
            "msg_1",
            10_000,
            sig.clone(),
            br#"{"type":"decision.allow"}"#,
            10_100,
            false,
        ),
        ("another message id", &secret, "msg_2", 10_000, sig.clone(), body, 10_100, false),
        ("another secret", &other, "msg_1", 10_000, sig.clone(), body, 10_100, false),
        ("too old", &secret, "msg_1", 10_000, sig.clone(), body, 10_400, false),
        ("from the future", &secret, "msg_1", 10_000, sig.clone(), body, 9_600, false),
        ("no signature", &secret, "msg_1", 10_000, String::new(), body, 10_100, false),
    ];
    let mut failures = Vec::new();
    for (case, secret, id, ts, header, body, now, want) in cases {
        let got = verify(secret, id, ts, &header, body, now).is_ok();
        if got != want {
            failures.push(format!("{case}: accepted {got}, want {want}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_failed_delivery_is_retried_later_and_later() {
    let delays: Vec<u64> = (0..14).map(retry_delay).collect();
    assert_eq!(delays[0], 5, "first retry after 5 seconds");
    assert!(delays.windows(2).all(|w| w[0] <= w[1]), "never sooner: {delays:?}");
    assert_eq!(*delays.last().unwrap(), 86_400, "at most a day apart: {delays:?}");
    let total: u64 = delays[..12].iter().sum();
    assert!(total >= 3 * 86_400, "12 attempts cover about three days or more: {total}s");
}

/// A one-shot HTTP server answering `status`; returns what it received.
fn receiver(status: u16) -> (String, mpsc::Receiver<(Vec<String>, String)>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
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
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap();
                }
                headers.push(line);
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

#[test]
fn a_delivery_outcome_follows_the_receiver_answer() {
    let secret = generate_secret();
    // (case, status, outcome)
    let cases: Vec<(&str, u16, &str)> = vec![
        ("accepted", 200, "done"),
        ("accepted without content", 204, "done"),
        ("a server error is retried", 503, "retry"),
        ("a rate limit is retried", 429, "retry"),
        ("a client error is retried: the receiver may be fixed", 400, "retry"),
        ("gone stops for good", 410, "gone"),
    ];
    let mut failures = Vec::new();
    for (case, status, want) in cases {
        let (url, rx) = receiver(status);
        let body = r#"{"type":"decision.block","timestamp":"2026-10-19T12:44:00Z","data":{}}"#;
        let got = deliver(&url, &secret, "msg_42", 1_792_414_000, body, 2_000);
        let got = match got {
            Delivery::Done => "done",
            Delivery::Retry(_) => "retry",
            Delivery::Gone => "gone",
        };
        if got != want {
            failures.push(format!("{case}: {got}, want {want}"));
        }
        let (headers, received) = rx.recv().unwrap();
        let header = |name: &str| {
            headers
                .iter()
                .find_map(|h| {
                    h.split_once(':')
                        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
                        .map(|(_, v)| v.trim().to_owned())
                })
                .unwrap_or_default()
        };
        if received != body {
            failures.push(format!("{case}: the body changed on the way"));
        }
        if header("webhook-id") != "msg_42" || header("webhook-timestamp") != "1792414000" {
            failures.push(format!("{case}: id and timestamp headers missing: {headers:?}"));
        }
        if verify(
            &secret,
            "msg_42",
            1_792_414_000,
            &header("webhook-signature"),
            received.as_bytes(),
            1_792_414_010,
        )
        .is_err()
        {
            failures.push(format!("{case}: the signature does not verify"));
        }
    }
    let unreachable = deliver("http://127.0.0.1:9/hook", &secret, "msg_1", 1, "{}", 500);
    assert!(matches!(unreachable, Delivery::Retry(_)), "an unreachable receiver is retried");
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn only_an_address_on_the_internet_is_global() {
    // (address, global)
    let cases = [
        ("8.8.8.8", true),
        ("10.1.2.3", false),
        ("172.16.0.1", false),
        ("192.168.1.1", false),
        ("127.0.0.1", false),
        ("169.254.169.254", false),
        ("100.64.0.1", false),
        ("0.0.0.0", false),
        ("255.255.255.255", false),
        ("192.0.2.1", false),
        ("198.18.0.1", false),
        ("224.0.0.1", false),
        ("240.0.0.1", false),
        ("2606:4700::1111", true),
        ("::1", false),
        ("::", false),
        ("fc00::1", false),
        ("fe80::1", false),
        ("ff02::1", false),
        ("2001:db8::1", false),
        ("::ffff:10.0.0.1", false),
        ("::ffff:8.8.8.8", true),
        ("64:ff9b::a00:1", false),
    ];
    let failures: Vec<String> = cases
        .iter()
        .filter(|(ip, want)| global_address(ip.parse().unwrap()) != *want)
        .map(|(ip, want)| format!("{ip}: want global {want}"))
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_download_follows_a_redirect_only_where_its_first_address_could_lead() {
    // (case, from, to, followed)
    let cases = [
        ("https to https", "https://lists.example/a", "https://cdn.example/a", true),
        ("https down to plain http", "https://lists.example/a", "http://cdn.example/a", false),
        ("into a private range", "https://lists.example/a", "https://10.0.0.1/a", false),
        ("onto the host itself", "https://lists.example/a", "https://127.0.0.1/a", false),
        ("onto the IPv6 loopback", "https://lists.example/a", "https://[::1]/a", false),
        (
            "to the cloud metadata address",
            "https://lists.example/a",
            "http://169.254.169.254/latest",
            false,
        ),
        (
            "to an internal name",
            "https://lists.example/a",
            "https://metadata.google.internal/",
            false,
        ),
        ("to a single-label name", "https://lists.example/a", "https://mirror/a", false),
        ("to localhost", "https://lists.example/a", "https://localhost/a", false),
        ("within the private network", "http://mirror.internal/a", "http://10.0.0.7/a", true),
        (
            "from the private network out over https",
            "http://10.0.0.5/a",
            "https://lists.example/a",
            true,
        ),
        (
            "from the private network out over http",
            "http://10.0.0.5/a",
            "http://lists.example/a",
            false,
        ),
        ("not a URL", "https://lists.example/a", "ftp://lists.example/a", false),
    ];
    let failures: Vec<String> = cases
        .iter()
        .filter(|(_, from, to, want)| redirect_allowed(from, to) != *want)
        .map(|(case, _, _, want)| format!("{case}: want followed {want}"))
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}

/// An HTTP server answering every request from `route` until the test ends.
fn site(route: fn(&str) -> String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut first = String::new();
            reader.read_line(&mut first).unwrap();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 || line.trim_end().is_empty() {
                    break;
                }
            }
            let path = first.split(' ').nth(1).unwrap_or_default().to_owned();
            let mut stream = stream;
            let _ = stream.write_all(route(&path).as_bytes());
        }
    });
    base
}

#[test]
fn a_download_refuses_a_redirect_it_must_not_follow() {
    fn route(path: &str) -> String {
        let (head, body) = match path {
            "/list" => ("200 OK", "a\nb\n"),
            "/moved" => ("302 Found\r\nlocation: /list", ""),
            "/out" => ("302 Found\r\nlocation: http://lists.example/list", ""),
            "/loop" => ("302 Found\r\nlocation: /loop", ""),
            _ => ("404 Not Found", ""),
        };
        format!(
            "HTTP/1.1 {head}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
    }
    let base = site(route);
    // (case, path, the list read)
    let cases = [
        ("a list", "/list", Some("a\nb\n")),
        ("a list moved on the same host", "/moved", Some("a\nb\n")),
        ("a redirect to plain http on the internet", "/out", None),
        ("a redirect without end", "/loop", None),
        ("a missing list", "/missing", None),
    ];
    let mut failures = Vec::new();
    for (case, path, want) in cases {
        let got = download(&format!("{base}{path}"), 2_000, 1 << 20).ok();
        let got = got.as_deref().map(|b| std::str::from_utf8(b).unwrap());
        if got != want {
            failures.push(format!("{case}: {got:?}, want {want:?}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
