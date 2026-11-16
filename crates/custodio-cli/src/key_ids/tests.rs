use std::time::{Duration, Instant};

use custodio_client::Kind;

use super::*;

fn key(id: &str) -> KeyEntry {
    KeyEntry {
        id: id.into(),
        key_type: "ecdsa-p256".into(),
        kind: Kind::Tpm,
        certificate: Vec::new(),
    }
}

fn keys(ids: &[&str]) -> Vec<KeyEntry> {
    ids.iter().map(|i| key(i)).collect()
}

#[test]
fn ids_are_sorted_one_per_line() {
    assert_eq!(
        render(&keys(&["work", "a", "Zed", "b_1-x"])),
        "Zed\na\nb_1-x\nwork\n"
    );
}

#[test]
fn ids_outside_the_grammar_are_dropped() {
    let long = "a".repeat(60);
    let ok = "a".repeat(59);
    let hostile = [
        "",
        "$(touch MARK)",
        "`id`",
        "a;b",
        "a b",
        "*",
        "a\nb",
        "a\x1b[31m",
        "é",
        "a.b",
        &long,
    ];
    let mut all = keys(&hostile);
    all.push(key(&ok));
    all.push(key("fine"));
    assert_eq!(render(&all), format!("{ok}\nfine\n"));
}

#[test]
fn no_keys_print_nothing() {
    assert_eq!(render(&[]), "");
}

#[test]
fn a_call_that_answers_is_returned() {
    assert_eq!(within(Duration::from_secs(5), || Some(3)), Some(3));
}

#[test]
fn a_call_that_fails_is_none() {
    assert_eq!(within::<u8, _>(Duration::from_secs(5), || None), None);
}

#[test]
fn a_call_that_never_answers_is_none_at_the_limit() {
    let start = Instant::now();
    let got = within::<u8, _>(Duration::from_millis(200), || {
        std::thread::sleep(Duration::from_secs(30));
        Some(1)
    });
    assert_eq!(got, None);
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[test]
fn a_call_that_panics_is_none() {
    assert_eq!(
        within::<u8, _>(Duration::from_secs(5), || panic!("boom")),
        None
    );
}
