//! The command line: what each command prints and how it exits.
#![allow(clippy::type_complexity)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("openfraud-cli-{}", openfraud::event::random_hex(4)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn run(config: &Path, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_openfraud"))
        .arg("-c")
        .arg(config)
        .args(args)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn each_command_answers_and_exits_as_documented() {
    let d = dir();
    let shipped = Path::new(env!("CARGO_MANIFEST_DIR")).join("openfraud.toml");
    let with_packs = d.join("packs.toml");
    std::fs::write(&with_packs, "packs = [\"free-tier-and-trial\"]\n").unwrap();
    let broken = d.join("broken.toml");
    std::fs::write(&broken, "[workflows.w]\nevents = [\"x.unknown\"]\n").unwrap();
    let good = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/scenarios/trial-farming.jsonl");
    let wrong = d.join("wrong.jsonl");
    std::fs::write(
        &wrong,
        "{\"event\": {\"type\": \"account.created\", \"actor_id\": \"a\"}, \"expect\": {\"decision\": \"block\"}}\n",
    )
    .unwrap();
    let good = good.to_str().unwrap();
    let wrong = wrong.to_str().unwrap();

    // (case, config, args, succeeds, words in stdout, words in stderr)
    let cases: Vec<(&str, &Path, Vec<&str>, bool, &str, &str)> = vec![
        (
            "the shipped configuration is valid",
            &shipped,
            vec!["validate"],
            true,
            "is valid",
            "",
        ),
        (
            "a pack with year-long counters is warned about",
            &with_packs,
            vec!["validate"],
            true,
            "is valid",
            "warning: counter",
        ),
        ("a mistake is refused and named", &broken, vec!["validate"], false, "", "x.unknown"),
        ("the packs are listed", &shipped, vec!["packs"], true, "hosting-and-content", ""),
        ("a scenario that holds passes", &shipped, vec!["simulate", good], true, "ok", ""),
        (
            "a scenario that does not hold fails",
            &shipped,
            vec!["simulate", wrong],
            false,
            "MISMATCH",
            "1 mismatches",
        ),
    ];
    let mut failures = Vec::new();
    for (case, config, args, succeeds, stdout, stderr) in cases {
        let (ok, out, err) = run(config, &args);
        if ok != succeeds || !out.contains(stdout) || !err.contains(stderr) {
            failures.push(format!("{case}: ok={ok}\nstdout: {out}\nstderr: {err}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

#[test]
fn api_keys_are_created_listed_and_revoked() {
    let d = dir();
    let config = d.join("openfraud.toml");
    std::fs::write(&config, "").unwrap();
    let (ok, key, _) = run(&config, &["key", "add", "backend"]);
    assert!(ok && key.trim().len() > 20, "a key is printed once: {key}");
    let (_, list, _) = run(&config, &["key", "list"]);
    assert!(
        list.contains("backend") && !list.contains(key.trim()),
        "the list shows the name, never the key: {list}"
    );
    let id = list.split_whitespace().next().unwrap().to_owned();
    assert!(run(&config, &["key", "revoke", &id]).0);
    assert!(!run(&config, &["key", "list"]).1.contains("backend"));
    assert!(!run(&config, &["key", "revoke", &id]).0, "revoking twice fails");
    let (ok, token, _) = run(&config, &["admin-token"]);
    assert!(ok && token.trim().len() > 20);
}
