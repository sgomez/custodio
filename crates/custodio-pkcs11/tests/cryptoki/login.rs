//! `C_Login` and `C_Logout` through the built module: they contact nothing, change nothing, and a
//! signature after them asks polkit as before.

use super::composed::{check_recorded, check_run, check_signature, printed};
use super::*;

#[test]
fn login_does_not_contact_service() -> TestResult {
    let f = Fixture::start(true, true)?;
    assert!(f.run("login_baseline")?.0);
    let baseline = f.settled_service_calls();
    assert!(baseline > 0, "the counter must see the setup");
    assert!(f.run("login_variants")?.0);
    let after_variants = f.settled_service_calls();
    // The second run repeats the setup, so it adds exactly the baseline: the logins add nothing.
    assert_eq!(after_variants - baseline, baseline);
    assert_eq!(f.asked(), 0);
    Ok(())
}

#[test]
fn login_logout_cryptoki() -> TestResult {
    let f = Fixture::start(true, true)?;
    assert!(f.run("login_variants")?.0);
    assert_eq!(f.asked(), 0);
    Ok(())
}

#[test]
fn login_changes_no_flags() -> TestResult {
    let f = Fixture::start(true, true)?;
    assert!(f.run("login_flags")?.0);
    assert_eq!(f.asked(), 0);
    Ok(())
}

#[test]
fn sign_after_login_asks_polkit() -> TestResult {
    let f = Fixture::start(true, true)?;
    let (ok, out) = f.run("login_sign")?;
    assert!(ok);
    // Three signatures per token; every one asked polkit once.
    check_run(&f, &out, &message(COMPOSED_LEN), 6)
}

#[test]
fn login_keeps_the_open_operation() -> TestResult {
    let f = Fixture::start(true, true)?;
    let (ok, out) = f.run("login_open_operation")?;
    assert!(ok);
    let msg = message(COMPOSED_LEN);
    let sigs = printed(&out, "SIG");
    assert_eq!(sigs.len(), 2);
    assert_eq!(sigs[0].2, sigs[1].2, "PKCS#1 v1.5 is deterministic");
    let cert = printed(&out, "CERT")
        .into_iter()
        .find(|(l, _, _)| l == "rsa")
        .ok_or("no rsa certificate")?
        .2;
    check_signature(&cert, "rsa-sha256", &msg, &sigs[1].2)?;
    let recorded = f.signs(2)?;
    assert_eq!(recorded.len(), 2);
    for r in &recorded {
        check_recorded(r, "rsa", "rsa-sha256", &msg);
    }
    assert_eq!(f.asked(), 2);
    Ok(())
}

#[test]
fn denied_after_login_still_fails() -> TestResult {
    let f = Fixture::start(false, true)?;
    let (ok, out) = f.run("login_denied")?;
    assert!(ok);
    assert_eq!(lines(&out, "UNTOUCHED").count(), 2);
    assert!(lines(&out, "UNTOUCHED").all(|l| l[0] == "true"), "{out}");
    assert_eq!(f.asked(), 2);
    Ok(())
}
