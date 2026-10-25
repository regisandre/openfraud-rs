//! The network table: which operator (autonomous system) announces an
//! address, and the country it is registered in, from the IPtoASN dataset.

#![allow(clippy::type_complexity)]

use openfraud::networks::NetworkTable;

const TSV: &str = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n\
1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n\
198.51.100.0\t198.51.100.255\t64500\tBE\tEXAMPLE-ISP Example Telecom\n\
198.51.101.0\t198.51.101.127\t64501\tFR\tOTHER-NET\n\
2001:db8::\t2001:db8:ffff:ffff:ffff:ffff:ffff:ffff\t64502\tDE\tV6-NET\n\
not a line\n";

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("openfraud-{name}-{}", openfraud::event::random_hex(4)));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn an_address_is_found_in_the_network_that_announces_it() {
    let text = NetworkTable::parse(TSV);
    assert_eq!(text.len(), 4, "the unrouted range and the broken line are skipped");
    assert!(!text.is_mapped(), "a table read from text lives in memory");
    let dir = temp_dir("networks-lookup");
    let file = dir.join("networks.bin");
    std::fs::write(&file, text.compiled()).unwrap();
    let mapped = NetworkTable::open(&file).unwrap();
    assert!(mapped.is_mapped(), "a compiled file is mapped, not copied");
    let copied = NetworkTable::from_bytes(text.compiled()).unwrap();
    assert!(
        NetworkTable::from_bytes(&text.compiled()[..text.compiled().len() - 1]).is_err(),
        "a truncated compiled table is an error"
    );
    // (source, table)
    let sources = [("text", &text), ("compiled bytes", &copied), ("mapped file", &mapped)];
    // (case, address, expected (asn, country, org))
    let cases: [(&str, &str, Option<(u32, &str, &str)>); 7] = [
        (
            "first address of a range",
            "198.51.100.0",
            Some((64500, "BE", "EXAMPLE-ISP Example Telecom")),
        ),
        (
            "last address of a range",
            "198.51.100.255",
            Some((64500, "BE", "EXAMPLE-ISP Example Telecom")),
        ),
        ("a smaller range", "198.51.101.5", Some((64501, "FR", "OTHER-NET"))),
        ("just past a range", "198.51.101.128", None),
        ("unrouted", "1.0.2.1", None),
        ("IPv6", "2001:db8::42", Some((64502, "DE", "V6-NET"))),
        ("outside every range", "203.0.113.9", None),
    ];
    let mut failures = Vec::new();
    for (source, table) in sources {
        if table.len() != 4 {
            failures.push(format!("{source}: {} ranges, want 4", table.len()));
        }
        for (case, ip, want) in cases {
            let got = table.lookup(ip.parse().unwrap());
            let got = got.as_ref().map(|n| (n.asn, n.country.as_str(), n.org.as_str()));
            if got != want {
                failures.push(format!("{source}, {case}: {ip} gave {got:?}, want {want:?}"));
            }
        }
    }
    drop(mapped);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_file_replaced_by_a_rename_is_seen_as_a_new_version() {
    use openfraud::networks::version;
    let dir = temp_dir("networks-version");
    let file = dir.join("networks.bin");
    assert_eq!(version(&file), None, "a missing file has no version");
    std::fs::write(&file, NetworkTable::parse(TSV).compiled()).unwrap();
    let first = version(&file);
    assert!(first.is_some(), "a file has a version");
    assert_eq!(version(&file), first, "an untouched file keeps its version");
    let next = dir.join("networks.bin.tmp");
    std::fs::write(
        &next,
        NetworkTable::parse(
            "10.0.0.0	10.0.0.255	64999	BE	LOCAL
",
        )
        .compiled(),
    )
    .unwrap();
    std::fs::rename(&next, &file).unwrap();
    assert_ne!(version(&file), first, "a file renamed over the old one is a new version");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_gzipped_download_is_read_like_the_text() {
    use std::io::Write;
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(TSV.as_bytes()).unwrap();
    let bytes = gz.finish().unwrap();
    let table = NetworkTable::from_bytes(&bytes).unwrap();
    assert_eq!(table.len(), 4);
    assert!(
        NetworkTable::from_bytes(b"\x1f\x8bnot gzip").is_err(),
        "a broken archive is an error"
    );
    assert!(
        NetworkTable::from_bytes(b"").is_err(),
        "an empty download is an error, not an empty table"
    );
}

#[test]
fn the_table_comes_from_a_file_a_fresh_cache_or_a_download() {
    use openfraud::config::Networks;
    use openfraud::networks::load;
    use std::cell::Cell;
    let dir = std::env::temp_dir().join(format!("openfraud-networks-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cache = dir.join("networks.tsv.gz");
    let local = dir.join("mine.tsv");
    std::fs::write(&local, "10.0.0.0\t10.0.0.255\t64999\tBE\tLOCAL\n").unwrap();
    let calls = Cell::new(0);
    let ok = |_: &str| -> anyhow::Result<Vec<u8>> {
        calls.set(calls.get() + 1);
        Ok(TSV.as_bytes().to_vec())
    };
    let down = |_: &str| -> anyhow::Result<Vec<u8>> {
        calls.set(calls.get() + 1);
        anyhow::bail!("offline")
    };
    let on = |file: Option<&std::path::Path>| Networks {
        enabled: true,
        file: file.map(|f| f.to_path_buf()),
        ..Networks::default()
    };
    let size = |t: Option<openfraud::networks::NetworkTable>| t.map(|t| t.len());

    // (case, settings, fetch allowed, downloader, expected ranges or error, downloads made)
    assert_eq!(
        size(load(&Networks::default(), &cache, true, 24, &ok).unwrap()),
        None,
        "off by default"
    );
    assert_eq!(calls.get(), 0, "off: nothing downloaded");
    assert_eq!(
        size(load(&on(Some(&local)), &cache, true, 24, &ok).unwrap()),
        Some(1),
        "a file of your own"
    );
    assert_eq!(calls.get(), 0, "a file: nothing downloaded");
    let compiled = dir.join("mine.bin");
    std::fs::write(&compiled, NetworkTable::parse(TSV).compiled()).unwrap();
    let mapped = load(&on(Some(&compiled)), &cache, true, 24, &ok).unwrap().unwrap();
    assert!(mapped.is_mapped() && mapped.len() == 4, "a compiled file of your own is mapped");
    drop(mapped);
    assert_eq!(calls.get(), 0, "a compiled file: nothing downloaded");
    assert!(
        load(&on(None), &cache, false, 24, &ok).is_err(),
        "no file and downloads off: an error that says so"
    );
    assert_eq!(size(load(&on(None), &cache, true, 24, &ok).unwrap()), Some(4), "downloaded");
    assert!(cache.exists(), "the download is cached");
    assert_eq!(
        size(load(&on(None), &cache, true, 24, &ok).unwrap()),
        Some(4),
        "a fresh cache is read"
    );
    assert_eq!(calls.get(), 1, "a fresh cache is not downloaded again");
    assert_eq!(
        size(load(&on(None), &cache, true, 0, &down).unwrap()),
        Some(4),
        "a failed refresh keeps the stale cache"
    );
    assert_eq!(calls.get(), 2, "a stale cache is downloaded again");
    let _ = std::fs::remove_dir_all(&dir);
}
