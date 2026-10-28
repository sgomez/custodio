use super::journal::{check_sent, send_fields};
use super::*;
use std::error::Error;
use std::io::ErrorKind;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

type TestResult = Result<(), Box<dyn Error>>;

const ID_LITERAL: &str = "29c3d30e6c4242406c6db3f120d36401";

fn key(s: &str) -> Result<KeyId, InvalidKeyId> {
    KeyId::new(s)
}

fn entry(o: Outcome, m: Option<AuditMechanism>) -> Result<Entry, InvalidKeyId> {
    Ok(Entry::new(
        o,
        Caller {
            uid: 1_234_567,
            pid: 7_654_321,
        },
        key("key-1_A")?,
        m,
    ))
}

fn socket() -> Result<Socket, Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("j.sock");
    let s = UnixDatagram::bind(&path)?;
    s.set_read_timeout(Some(Duration::from_secs(2)))?;
    Ok((dir, path, s))
}

fn recv(s: &UnixDatagram) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut buf = vec![0u8; 65536];
    let n = s.recv(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

type Field = (String, Vec<u8>);
type Socket = (tempfile::TempDir, PathBuf, UnixDatagram);

/// Independent decoder of the Native Journal Protocol.
fn decode(mut b: &[u8]) -> Result<Vec<Field>, Box<dyn Error>> {
    let bad = || Box::<dyn Error>::from("bad datagram");
    let mut out = Vec::new();
    while !b.is_empty() {
        let nl = b.iter().position(|&c| c == b'\n').ok_or_else(bad)?;
        let eq = b.iter().position(|&c| c == b'=');
        if let Some(e) = eq.filter(|&e| e < nl) {
            let name = String::from_utf8(b.get(..e).ok_or_else(bad)?.to_vec())?;
            out.push((name, b.get(e + 1..nl).ok_or_else(bad)?.to_vec()));
            b = b.get(nl + 1..).ok_or_else(bad)?;
        } else {
            let name = String::from_utf8(b.get(..nl).ok_or_else(bad)?.to_vec())?;
            let len = u64::from_le_bytes(b.get(nl + 1..nl + 9).ok_or_else(bad)?.try_into()?);
            let end = nl + 9 + usize::try_from(len)?;
            out.push((name, b.get(nl + 9..end).ok_or_else(bad)?.to_vec()));
            assert_eq!(b.get(end), Some(&b'\n'));
            b = b.get(end + 1..).ok_or_else(bad)?;
        }
    }
    Ok(out)
}

fn would_block(s: &UnixDatagram) -> TestResult {
    s.set_nonblocking(true)?;
    let mut buf = [0u8; 8];
    assert!(matches!(s.recv(&mut buf), Err(e) if e.kind() == ErrorKind::WouldBlock));
    Ok(())
}

#[test]
fn memory_sink_records_entries() -> TestResult {
    let sink = MemorySink::default();
    let dynsink: &dyn AuditSink = &sink;
    let a = entry(Outcome::Signed, None)?;
    let b = entry(Outcome::Denied, Some(AuditMechanism::Ecdsa))?;
    dynsink.record(&a)?;
    assert_eq!(sink.entries(), vec![a.clone()]);
    dynsink.record(&b)?;
    assert_eq!(sink.entries(), vec![a, b.clone()]);
    assert_eq!(b.mechanism(), Some(AuditMechanism::Ecdsa));
    assert_eq!(entry(Outcome::Signed, None)?.mechanism(), None);
    Ok(())
}

#[test]
fn failing_sink_returns_error() -> TestResult {
    let sink: &dyn AuditSink = &FailingSink;
    assert!(sink.record(&entry(Outcome::Signed, None)?).is_err());
    Ok(())
}

#[test]
fn key_id_rejects_bad_strings() {
    let long = "a".repeat(65);
    for bad in [
        "",
        long.as_str(),
        "a\nb",
        "a=b",
        "a b",
        "a\0b",
        "clé",
        ".",
        "../x",
        "a.b",
    ] {
        let err = KeyId::new(bad).err();
        assert!(err.is_some(), "accepted {bad:?}");
        let err = err.unwrap_or(InvalidKeyId);
        // The error is a unit value: nothing of the input can be in it.
        assert_eq!(format!("{err:?}{err}"), "InvalidKeyIdinvalid key id");
    }
    assert!(KeyId::new(&"a".repeat(64)).is_ok());
}

#[test]
fn key_id_matches_store_rule() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = crate::store::KeyStore::open(dir.path().join("s"))?;
    let long = "b".repeat(65);
    let ok64 = "b".repeat(64);
    for s in [
        "", "a", "A-b_9", "a.b", "../x", "a b", "a\n", "é", &long, &ok64, "a/b", "a\0",
    ] {
        let rejected = matches!(store.get(s), Err(crate::store::StoreError::InvalidId));
        assert_eq!(KeyId::new(s).is_ok(), !rejected, "{s:?}");
    }
    Ok(())
}

#[test]
fn mechanism_names_are_distinct_and_fixed() {
    let all = [
        (AuditMechanism::RsaPkcs, "rsa_pkcs"),
        (AuditMechanism::RsaPkcsPssSha256, "rsa_pkcs_pss_sha256"),
        (AuditMechanism::RsaPkcsPssSha384, "rsa_pkcs_pss_sha384"),
        (AuditMechanism::RsaPkcsPssSha512, "rsa_pkcs_pss_sha512"),
        (AuditMechanism::Ecdsa, "ecdsa"),
    ];
    for (m, n) in all {
        assert_eq!(m.name(), n);
    }
}

#[test]
fn every_sign_mechanism_has_a_name() {
    let mut ms = vec![Mechanism::RsaPkcs, Mechanism::Ecdsa];
    for hash in [PssHash::Sha256, PssHash::Sha384, PssHash::Sha512] {
        ms.push(Mechanism::RsaPkcsPss { hash, salt_len: 20 });
    }
    let names: Vec<_> = ms.iter().map(|m| AuditMechanism::from(m).name()).collect();
    assert!(names.iter().all(|n| !n.is_empty()));
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len());
}

#[test]
fn message_text_per_outcome() -> TestResult {
    let c = Caller { uid: 10, pid: 20 };
    let msg = |o| Ok::<_, InvalidKeyId>(Entry::new(o, c, key("k9")?, None).message());
    assert_eq!(
        msg(Outcome::Signed)?,
        "signature made: uid 10 pid 20 key k9"
    );
    assert_eq!(
        msg(Outcome::Denied)?,
        "signature denied: uid 10 pid 20 key k9"
    );
    assert_eq!(
        msg(Outcome::SigningFailed)?,
        "signing failed after approval: uid 10 pid 20 key k9"
    );
    assert_eq!(
        msg(Outcome::AuthorizationUnavailable)?,
        "authorization unavailable, no signature: uid 10 pid 20 key k9"
    );
    Ok(())
}

#[test]
fn debug_prints_only_typed_fields() -> TestResult {
    let e = entry(Outcome::Signed, Some(AuditMechanism::Ecdsa))?;
    let d = format!("{e:?}");
    assert!(d.contains("key-1_A") && d.contains("1234567") && d.contains("7654321"));
    for err in [
        AuditError::Io(ErrorKind::NotFound),
        AuditError::TooLarge,
        AuditError::ShortSend {
            sent: 3,
            expected: 9,
        },
    ] {
        let d = format!("{err:?}{err}");
        assert!(!d.contains("sock") && !d.contains('/'));
    }
    assert_eq!(
        AuditError::Io(ErrorKind::NotFound).to_string(),
        "audit entry not recorded: entity not found"
    );
    assert_eq!(AuditError::TooLarge.to_string(), "audit entry too large");
    assert_eq!(
        AuditError::ShortSend {
            sent: 3,
            expected: 9
        }
        .to_string(),
        "audit entry sent partially: 3 of 9 bytes"
    );
    Ok(())
}

#[test]
fn default_socket_path() {
    assert_eq!(DEFAULT_JOURNAL_SOCKET, "/run/systemd/journal/socket");
    assert_eq!(
        JournalSink::default().path(),
        Path::new("/run/systemd/journal/socket")
    );
}

#[test]
fn wire_plain_fields() -> TestResult {
    let (_d, path, s) = socket()?;
    JournalSink::new(&path).record(&entry(
        Outcome::Signed,
        Some(AuditMechanism::RsaPkcsPssSha256),
    )?)?;
    let expected = b"MESSAGE=signature made: uid 1234567 pid 7654321 key key-1_A\n\
MESSAGE_ID=29c3d30e6c4242406c6db3f120d36401\n\
PRIORITY=6\n\
SYSLOG_IDENTIFIER=custodiod\n\
CUSTODIO_UID=1234567\n\
CUSTODIO_PID=7654321\n\
CUSTODIO_KEY_ID=key-1_A\n\
CUSTODIO_OUTCOME=signed\n\
CUSTODIO_MECHANISM=rsa_pkcs_pss_sha256\n";
    assert_eq!(recv(&s)?, expected);
    Ok(())
}

#[test]
fn wire_value_with_newline() -> TestResult {
    let (_d, path, s) = socket()?;
    let cases: [(&str, &[u8]); 4] = [
        ("a\nb", b"N\n\x03\0\0\0\0\0\0\0a\nb\n"),
        ("ab\n", b"N\n\x03\0\0\0\0\0\0\0ab\n\n"),
        ("\n", b"N\n\x01\0\0\0\0\0\0\0\n\n"),
        ("", b"N=\n"),
    ];
    for (v, want) in cases {
        send_fields(&path, MAX_DATAGRAM, &[("N", v.to_owned())])?;
        assert_eq!(recv(&s)?, want);
    }
    let mut exp = b"NAME\n".to_vec();
    exp.extend_from_slice(&3u64.to_le_bytes());
    exp.extend_from_slice(b"a\nb\n");
    send_fields(&path, MAX_DATAGRAM, &[("NAME", "a\nb".to_owned())])?;
    assert_eq!(recv(&s)?, exp);
    Ok(())
}

#[test]
fn all_entries_decode_to_expected_fields() -> TestResult {
    let (_d, path, s) = socket()?;
    let sink = JournalSink::new(&path);
    let outcomes = [
        Outcome::Signed,
        Outcome::SigningFailed,
        Outcome::Denied,
        Outcome::AuthorizationUnavailable,
    ];
    let mechs = [
        None,
        Some(AuditMechanism::RsaPkcs),
        Some(AuditMechanism::RsaPkcsPssSha384),
        Some(AuditMechanism::RsaPkcsPssSha512),
        Some(AuditMechanism::Ecdsa),
    ];
    for o in outcomes {
        for m in mechs {
            for k in ["a", "key-1_A", &"z".repeat(64)] {
                let e = Entry::new(
                    o,
                    Caller {
                        uid: 0,
                        pid: u32::MAX,
                    },
                    key(k)?,
                    m,
                );
                sink.record(&e)?;
                let got = decode(&recv(&s)?)?;
                let mut want: Vec<Field> = vec![
                    ("MESSAGE".into(), e.message().into_bytes()),
                    ("MESSAGE_ID".into(), ID_LITERAL.into()),
                    ("PRIORITY".into(), o.priority().to_string().into_bytes()),
                    ("SYSLOG_IDENTIFIER".into(), b"custodiod".to_vec()),
                    ("CUSTODIO_UID".into(), b"0".to_vec()),
                    ("CUSTODIO_PID".into(), u32::MAX.to_string().into_bytes()),
                    ("CUSTODIO_KEY_ID".into(), k.into()),
                    ("CUSTODIO_OUTCOME".into(), o.name().into()),
                ];
                if let Some(m) = m {
                    want.push(("CUSTODIO_MECHANISM".into(), m.name().into()));
                }
                assert_eq!(got, want);
            }
        }
    }
    Ok(())
}

#[test]
fn message_id_is_32_hex_and_in_every_entry() -> TestResult {
    assert_eq!(MESSAGE_ID, ID_LITERAL);
    assert!(
        MESSAGE_ID
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_ne!(MESSAGE_ID, "0".repeat(32));
    let (_d, path, s) = socket()?;
    for o in [
        Outcome::Signed,
        Outcome::SigningFailed,
        Outcome::Denied,
        Outcome::AuthorizationUnavailable,
    ] {
        JournalSink::new(&path).record(&entry(o, None)?)?;
        let got = String::from_utf8(recv(&s)?)?;
        assert!(got.contains(&format!("\nMESSAGE_ID={ID_LITERAL}\n")));
    }
    Ok(())
}

#[test]
fn fields_per_outcome() -> TestResult {
    let (_d, path, s) = socket()?;
    let table = [
        (Outcome::Signed, "6", "signed"),
        (Outcome::SigningFailed, "3", "signing_failed"),
        (Outcome::Denied, "5", "denied"),
        (
            Outcome::AuthorizationUnavailable,
            "4",
            "authorization_unavailable",
        ),
    ];
    for (o, prio, name) in table {
        for m in [None, Some(AuditMechanism::Ecdsa)] {
            JournalSink::new(&path).record(&entry(o, m)?)?;
            let got = decode(&recv(&s)?)?;
            let get = |n: &str| got.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
            assert_eq!(get("PRIORITY"), Some(prio.into()));
            assert_eq!(get("CUSTODIO_OUTCOME"), Some(name.into()));
            assert_eq!(get("CUSTODIO_UID"), Some(b"1234567".to_vec()));
            assert_eq!(get("CUSTODIO_PID"), Some(b"7654321".to_vec()));
            assert_eq!(get("CUSTODIO_KEY_ID"), Some(b"key-1_A".to_vec()));
            assert_eq!(get("CUSTODIO_MECHANISM"), m.map(|_| b"ecdsa".to_vec()));
        }
    }
    Ok(())
}

#[test]
fn one_datagram_per_call() -> TestResult {
    let (_d, path, s) = socket()?;
    let sink = JournalSink::new(&path);
    for _ in 0..3 {
        sink.record(&entry(Outcome::Denied, None)?)?;
    }
    for _ in 0..3 {
        assert_eq!(decode(&recv(&s)?)?.len(), 8);
    }
    would_block(&s)?;
    Ok(())
}

#[test]
fn missing_socket_is_an_error() -> TestResult {
    let dir = tempfile::tempdir()?;
    let r = JournalSink::new(dir.path().join("none")).record(&entry(Outcome::Signed, None)?);
    assert_eq!(r, Err(AuditError::Io(ErrorKind::NotFound)));
    Ok(())
}

#[test]
fn refusing_socket_is_an_error() -> TestResult {
    let (_d, path, s) = socket()?;
    drop(s);
    let r = JournalSink::new(&path).record(&entry(Outcome::Signed, None)?);
    assert_eq!(r, Err(AuditError::Io(ErrorKind::ConnectionRefused)));
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("f");
    std::fs::write(&file, b"x")?;
    assert!(matches!(
        JournalSink::new(&file).record(&entry(Outcome::Signed, None)?),
        Err(AuditError::Io(_))
    ));
    Ok(())
}

#[test]
fn full_socket_is_an_error_without_blocking() -> TestResult {
    let (_d, path, s) = socket()?;
    let filler = UnixDatagram::unbound()?;
    filler.set_nonblocking(true)?;
    let block = vec![0u8; 8192];
    while filler.send_to(&block, &path).is_ok() {}
    let (tx, rx) = mpsc::channel();
    let e = entry(Outcome::Signed, None)?;
    let p = path.clone();
    std::thread::spawn(move || {
        let _ = tx.send(JournalSink::new(p).record(&e));
    });
    let r = rx.recv_timeout(Duration::from_secs(1))?;
    assert_eq!(r, Err(AuditError::Io(ErrorKind::WouldBlock)));
    drop(s);
    Ok(())
}

#[test]
fn short_send_is_an_error() {
    assert_eq!(check_sent(5, 5), Ok(()));
    assert_eq!(
        check_sent(4, 5),
        Err(AuditError::ShortSend {
            sent: 4,
            expected: 5
        })
    );
}

#[test]
fn oversize_entry_is_too_large() -> TestResult {
    let (_d, path, s) = socket()?;
    let r = JournalSink::with_max(&path, 64).record(&entry(Outcome::Signed, None)?);
    assert_eq!(r, Err(AuditError::TooLarge));
    would_block(&s)?;
    Ok(())
}

#[test]
fn size_limit_is_exact() -> TestResult {
    assert_eq!(MAX_DATAGRAM, 16384);
    let (_d, path, s) = socket()?;
    let e = entry(Outcome::Signed, None)?;
    JournalSink::new(&path).record(&e)?;
    let len = recv(&s)?.len();
    JournalSink::with_max(&path, len).record(&e)?;
    assert_eq!(recv(&s)?.len(), len);
    let r = JournalSink::with_max(&path, len - 1).record(&e);
    assert_eq!(r, Err(AuditError::TooLarge));
    would_block(&s)?;
    Ok(())
}

#[test]
fn without_caller_entry_has_no_uid_or_pid() -> TestResult {
    let (_d, path, s) = socket()?;
    let e = Entry::without_caller(key("k9")?, Some(AuditMechanism::Ecdsa));
    assert_eq!(e.outcome(), Outcome::AuthorizationUnavailable);
    assert_eq!(e.caller(), None);
    assert_eq!(e.key_id().as_str(), "k9");
    assert_eq!(e.mechanism(), Some(AuditMechanism::Ecdsa));
    assert_eq!(
        e.message(),
        "authorization unavailable, no signature: uid unknown pid unknown key k9"
    );
    JournalSink::new(&path).record(&e)?;
    let got = decode(&recv(&s)?)?;
    let names: Vec<&str> = got.iter().map(|(k, _)| k.as_str()).collect();
    assert!(!names.contains(&"CUSTODIO_UID") && !names.contains(&"CUSTODIO_PID"));
    let get = |n: &str| got.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(get("PRIORITY"), Some(b"4".to_vec()));
    assert_eq!(get("CUSTODIO_KEY_ID"), Some(b"k9".to_vec()));
    assert_eq!(
        get("CUSTODIO_OUTCOME"),
        Some(b"authorization_unavailable".to_vec())
    );
    Ok(())
}

#[test]
fn entry_with_caller_exposes_it() -> TestResult {
    let e = entry(Outcome::Denied, None)?;
    assert_eq!(
        e.caller(),
        Some(Caller {
            uid: 1_234_567,
            pid: 7_654_321
        })
    );
    Ok(())
}
