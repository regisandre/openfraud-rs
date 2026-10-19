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
