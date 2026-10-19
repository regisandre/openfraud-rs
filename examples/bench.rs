//! Decide latency with every pack on and acting, on a database file.
//!
//! cargo run --release --example bench -- [warm events] [measured events]
//!
//! Warms the engine with a mixed history (sign-ups, logins, trials, cards,
//! messages, payouts, API usage, content), then times `process` for each
//! measured event and prints p50, p95, p99 and the maximum. One thread, as
//! one request: the engine serializes decisions behind one lock.

use openfraud::config::Config;
use openfraud::engine::{Engine, Options};
use serde_json::{Value, json};
use std::path::Path;
use std::time::Instant;

const PACKS: &str = r#"packs = ["free-tier-and-trial", "card-and-payments", "messaging", "marketplace-and-payouts", "api-and-compute", "hosting-and-content"]

[safety]
require_replay = false
max_auto_per_hour = 1000000

"#;

/// A cheap deterministic generator: the same history on every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn event(rng: &mut Rng, i: u64, at: u64) -> Value {
    let actor = format!("u{}", rng.below(20_000));
    let ip = format!("198.51.{}.{}", rng.below(200), rng.below(250));
    let card = format!("fp_{}", rng.below(30_000));
    let mailbox = ["gmail.com", "yahoo.com", "outlook.com", "icloud.com", "example.org"];
    let to: Vec<String> = (0..rng.below(6) + 1)
        .map(|k| format!("c{}{k}@{}", rng.below(1000), mailbox[rng.below(5) as usize]))
        .collect();
    let country = ["BE", "FR", "DE", "US", "MA"][rng.below(5) as usize];
    let device = format!("d{}", rng.below(25_000));
    let email = format!("{actor}@{}", mailbox[rng.below(5) as usize]);
    let base = json!({"id": format!("e{i}"), "at": at, "actor_id": actor, "ip": ip, "device": device, "country": country, "email": email});
    let (kind, attrs) = match rng.below(10) {
        0 => ("account.created", json!({"username": format!("name{}", rng.below(1000))})),
        1 => ("session.login", json!({})),
        2 => (
            "subscription.trial_started",
            json!({"card_fingerprint": card, "card_country": "FR"}),
        ),
        3 => (
            "payment.method_added",
            json!({"card_fingerprint": card, "card_country": "BE", "card_funding": "credit"}),
        ),
        4 => ("payment.failed", json!({"card_fingerprint": card, "amount": rng.below(500)})),
        5 => ("message.send_requested", json!({"recipients": to})),
        6 => ("message.contacts_imported", json!({"recipients": to, "count": to.len()})),
        7 => (
            "payout.requested",
            json!({"amount": rng.below(5_000), "payout_destination": format!("iban{}", rng.below(5_000))}),
        ),
        8 => (
            "usage.recorded",
            json!({"units": rng.below(100), "api_key": format!("k{}", rng.below(3_000))}),
        ),
        _ => ("content.published", json!({"links": rng.below(20), "text": "hello"})),
    };
    let mut e = base;
    e["type"] = json!(kind);
    e["attrs"] = attrs;
    e
}

fn main() {
    let args: Vec<u64> = std::env::args().skip(1).filter_map(|a| a.parse().ok()).collect();
    let warm = args.first().copied().unwrap_or(50_000);
    let measured = args.get(1).copied().unwrap_or(20_000);
    let mut config = Config::parse(PACKS, Path::new(".")).unwrap();
    let assembled = config.assemble().unwrap();
    for wf in assembled.workflows.values() {
        for rule in &wf.rules {
            config.overrides.entry(rule.id.clone()).or_default().mode = Some(openfraud::config::Mode::Act);
        }
    }
    let db = std::env::temp_dir().join(format!("openfraud-bench-{}.db", openfraud::event::random_hex(4)));
    let engine = Engine::open(config, b"bench-key-bench-key-bench-key-be".to_vec(), Some(&db)).unwrap();
    // As `serve` does: checkpoints on their own thread.
    let wal = db.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let _ = openfraud::store::Store::checkpoint(&wal);
        }
    });
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let start = 1_800_000_000;
    let total = warm + measured;
    let started = Instant::now();
    let mut times = Vec::with_capacity(measured as usize);
    for i in 0..total {
        // About 3 events a second of history.
        let at = start + i / 3;
        let raw = serde_json::from_value(event(&mut rng, i, at)).unwrap();
        let t = Instant::now();
        engine
            .process(
                raw,
                Options {
                    dry_run: false,
                    now: Some(at),
                },
            )
            .unwrap();
        if i >= warm {
            times.push(t.elapsed().as_micros() as u64);
        }
        if i + 1 == warm {
            eprintln!("warmed with {warm} events in {:.1}s", started.elapsed().as_secs_f64());
        }
    }
    times.sort_unstable();
    let p = |q: f64| times[((times.len() as f64 * q) as usize).min(times.len() - 1)] as f64 / 1000.0;
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0);
    println!(
        "{measured} decisions, every pack acting, database file, {cores} cores: p50 {:.2} ms, p95 {:.2} ms, p99 {:.2} ms, max {:.2} ms",
        p(0.50),
        p(0.95),
        p(0.99),
        *times.last().unwrap() as f64 / 1000.0
    );
    drop(engine);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", db.display()));
    }
}
