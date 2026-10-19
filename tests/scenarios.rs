//! The scenario files in examples/scenarios, run against the shipped
//! configuration. Each line is an event and what openfraud must answer.
//! `trial-probe.jsonl` is a real attack on an event platform: it must end
//! blocked, with the account quarantined, before the first mail leaves.

use openfraud::config::{Config, DEFAULT_CONFIG};
use openfraud::scenario::run_scenario;
use std::path::Path;

#[test]
fn every_scenario_gets_the_answers_it_expects() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/scenarios");
    let mut files: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).collect();
    files.sort();
    assert!(files.len() >= 4, "the scenarios are missing: {files:?}");
    let mut failures = Vec::new();
    for file in files {
        let config = Config::parse(DEFAULT_CONFIG, Path::new(".")).unwrap();
        let text = std::fs::read_to_string(&file).unwrap();
        let report = run_scenario(config, &text).unwrap();
        for mismatch in report.mismatches() {
            failures.push(format!("{}: {mismatch}", file.file_name().unwrap().to_string_lossy()));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
