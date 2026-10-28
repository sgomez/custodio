//! Multi-part signing through the built module: what the service receives, that the signatures
//! verify with code that shares nothing with the module, and that nothing outlives a call.

use super::composed::{check_recorded, check_run, check_signature, expected_input, printed};
use super::multipart_child::worker_message;
use super::*;

/// The certificate of `label`, as the child printed it.
fn cert_of(out: &str, label: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    printed(out, "CERT")
        .into_iter()
        .find(|(l, _, _)| l == label)
        .map(|(_, _, c)| c)
        .ok_or_else(|| format!("no certificate for {label}").into())
}

#[test]
fn multipart_equivalence() -> TestResult {
    let f = Fixture::start(true, true)?;
    let (ok, out) = f.run("multipart_equivalence")?;
    assert!(ok);
    // 12 signatures, each checked against what the service was sent and by an independent
    // verifier; the pairs are single-part then multi-part.
    check_run(&f, &out, &message(100_000), 12)?;
    let sigs = printed(&out, "SIG");
    for pair in sigs.chunks(2) {
        if pair[0].1.starts_with("rsa") {
            assert_eq!(
                pair[0].2, pair[1].2,
                "{}: PKCS#1 v1.5 is deterministic",
                pair[0].1
            );
        }
    }
    Ok(())
}

#[test]
fn multipart_large() -> TestResult {
    let f = Fixture::start(true, true)?;
    let (ok, out) = f.run("multipart_large")?;
    assert!(ok);
    check_run(&f, &out, &message(LARGE_LEN), 2)
}

#[test]
fn multipart_retry() -> TestResult {
    let f = Fixture::start(true, true)?;
    let (ok, out) = f.run("multipart_retry")?;
    assert!(ok);
    // Two mechanisms; the queries and the short buffer asked nothing.
    check_run(&f, &out, &message(COMPOSED_LEN), 2)
}

#[test]
fn multipart_raw() -> TestResult {
    let f = Fixture::start(true, true)?;
    assert!(f.run("multipart_raw")?.0);
    assert_eq!(f.asked(), 1);
    assert_eq!(f.signs(1)?.len(), 1);
    Ok(())
}

#[test]
fn multipart_sign_after_update() -> TestResult {
    let f = Fixture::start(true, true)?;
    assert!(f.run("multipart_sign_after_update")?.0);
    assert_eq!(f.asked(), 0);
    assert!(f.signs(0)?.is_empty());
    Ok(())
}

#[test]
fn multipart_denied() -> TestResult {
    let f = Fixture::start(false, true)?;
    let (ok, out) = f.run("multipart_denied")?;
    assert!(ok);
    assert_eq!(lines(&out, "UNTOUCHED").count(), 2);
    assert!(lines(&out, "UNTOUCHED").all(|l| l[0] == "true"), "{out}");
    assert_eq!(f.asked(), 2);
    // Polkit allows from now on: a third full attempt signs.
    f.approve(true);
    let (ok, out) = f.run("multipart_allowed")?;
    assert!(ok);
    assert_eq!(f.asked(), 3);
    let recorded = f.signs(3)?;
    assert_eq!(recorded.len(), 3);
    let sig = printed(&out, "SIG");
    let msg = b"first second";
    check_recorded(&recorded[2], "ec", "ecdsa-sha256", msg);
    check_signature(&cert_of(&out, "ec")?, "ecdsa-sha256", msg, &sig[0].2)
}

#[test]
fn multipart_tasks() -> TestResult {
    let f = Fixture::start(true, true)?;
    let (ok, out) = f.run("multipart_tasks")?;
    assert!(ok, "{out}");
    for tag in ["TASKS", "FDS"] {
        let seen = lines(&out, tag).collect::<Vec<_>>();
        assert_eq!(seen.len(), 2, "{tag}: {out}");
        for l in seen {
            assert_eq!(l[1], l[2], "{tag} {}: changed by the call: {out}", l[0]);
            assert_eq!(l[1], l[3], "{tag} {}: changed later: {out}", l[0]);
        }
    }
    assert_eq!(f.asked(), 1);
    Ok(())
}

#[test]
fn multipart_forks() -> TestResult {
    let f = Fixture::start(true, true)?;
    let (ok, out) = f.run("multipart_forks")?;
    assert!(ok, "{out}");
    let msg = message(400);
    // 5 children x (single + multi) and the parent's own.
    assert_eq!(f.asked(), 11);
    let recorded = f.signs(11)?;
    assert_eq!(recorded.len(), 11);
    let wanted = expected_input("ecdsa-sha256", &msg);
    assert_eq!(recorded.iter().filter(|r| r.data == wanted).count(), 1);
    let sig = printed(&out, "SIG");
    check_signature(&cert_of(&out, "ec")?, "ecdsa-sha256", &msg, &sig[0].2)
}

#[test]
fn multipart_threads() -> TestResult {
    let f = Fixture::start(true, true)?;
    let (ok, out) = f.run("multipart_threads")?;
    assert!(ok, "{out}");
    // A 1 + workers 24 + race 50.
    assert_eq!(f.asked(), 75);
    let recorded = f.signs(75)?;
    assert_eq!(recorded.len(), 75);
    let cert = cert_of(&out, "ec")?;
    let a = message(300);
    let asig = lines(&out, "ASIG").next().ok_or("no ASIG")?;
    check_signature(&cert, "ecdsa-sha256", &a, &unhex_str(asig[0]))?;
    let count = |msg: &[u8]| {
        let wanted = expected_input("ecdsa-sha256", msg);
        recorded.iter().filter(|r| r.data == wanted).count()
    };
    assert_eq!(count(&a), 1);
    assert_eq!(count(&message(77)), 50);
    let workers = lines(&out, "WSIG").collect::<Vec<_>>();
    assert_eq!(workers.len(), 24);
    for l in workers {
        let (w, r): (usize, usize) = (l[0].parse()?, l[1].parse()?);
        let msg = worker_message(w, r);
        check_signature(&cert, "ecdsa-sha256", &msg, &unhex_str(l[2]))?;
        assert_eq!(count(&msg), 1);
    }
    Ok(())
}

fn unhex_str(s: &str) -> Vec<u8> {
    super::composed::unhex(s)
}
