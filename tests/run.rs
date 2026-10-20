//! The running server: a configuration edited by hand is applied without a
//! restart, and a broken edit leaves the running one in place.

use openfraud::config::Config;
use openfraud::engine::Engine;
use openfraud::run::Watch;
use std::time::{Duration, SystemTime};

const RULE: &str = "\n[workflows.w]\nevents = [\"account.created\"]\n[[workflows.w.rules]]\nid = \"edited_by_hand\"\nwhen = \"true\"\nscore = 1\nreason = \"x\"\n";

fn touch(path: &std::path::Path, text: &str, at: SystemTime) {
    std::fs::write(path, text).unwrap();
    std::fs::File::options().write(true).open(path).unwrap().set_modified(at).unwrap();
}

#[test]
fn a_configuration_edited_by_hand_is_applied() {
    let dir = std::env::temp_dir().join(format!("openfraud-run-{}", openfraud::event::random_hex(4)));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("openfraud.toml");
    let t0 = SystemTime::now() - Duration::from_secs(60);
    touch(&path, "", t0);
    let engine = Engine::open(Config::load(&path).unwrap(), b"run-test-key-run-test-key-run-te".to_vec(), None).unwrap();
    let mut watch = Watch::new(&path);
    let has_rule = |e: &Engine| e.config().workflows.contains_key("w");

    // (case, new text or none, outcome expected, rule present after)
    assert!(watch.check(&engine).is_none(), "unchanged: nothing to do");
    touch(&path, RULE, t0 + Duration::from_secs(10));
    assert_eq!(watch.check(&engine).map(|r| r.is_ok()), Some(true), "an edit is applied");
    assert!(has_rule(&engine));
    touch(&path, "[workflows.w]\nevents = [\"not a type\"]\n", t0 + Duration::from_secs(20));
    assert_eq!(watch.check(&engine).map(|r| r.is_ok()), Some(false), "a broken edit is reported");
    assert!(has_rule(&engine), "and the running configuration stays");
    assert!(watch.check(&engine).is_none(), "the same broken file is reported once");
}

#[test]
fn the_write_ahead_log_stays_bounded_while_the_engine_writes_without_pause() {
    let dir = std::env::temp_dir().join(format!("openfraud-wal-{}", openfraud::event::random_hex(4)));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("openfraud.db");
    let wal = dir.join("openfraud.db-wal");
    let config = Config::parse("[safety]\nrequire_replay = false\n", &dir).unwrap();
    let engine = Engine::open(config, b"run-test-key-run-test-key-run-te".to_vec(), Some(&db)).unwrap();
    let size = || std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
    let stop = std::sync::atomic::AtomicBool::new(false);
    let mut largest = 0;
    std::thread::scope(|s| {
        // The engine writes one event after another, as under steady load.
        s.spawn(|| {
            let mut i = 0u64;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let raw: openfraud::event::RawEvent = serde_json::from_value(serde_json::json!({
                    "type": "session.login", "actor_id": format!("u{}", i % 5_000), "ip": format!("198.51.{}.{}", i % 200, i % 250),
                    "device": format!("d{i}"), "email": format!("u{}@example.com", i % 5_000),
                }))
                .unwrap();
                engine.process(raw, openfraud::engine::Options::default()).unwrap();
                i += 1;
            }
        });
        // The server's checkpoint thread, meanwhile.
        let began = std::time::Instant::now();
        while began.elapsed() < Duration::from_secs(8) {
            std::thread::sleep(Duration::from_millis(200));
            openfraud::run::checkpoint(&engine, &db).unwrap();
            largest = largest.max(size());
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
    });
    openfraud::run::checkpoint(&engine, &db).unwrap();
    let mb = |b: u64| b / (1 << 20);
    assert!(
        largest < openfraud::store::WAL_LIMIT + (32 << 20) && size() <= openfraud::store::WAL_LIMIT,
        "the log reached {} MB and ends at {} MB",
        mb(largest),
        mb(size())
    );
    let _ = std::fs::remove_dir_all(&dir);
}
