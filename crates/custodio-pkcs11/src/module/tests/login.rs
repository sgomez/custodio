//! What `C_Login` and `C_Logout` ask of the module: only whether the session exists.

use super::composed::{calls, rec_module};
use super::*;

const SENTINEL: &[u8] = b"sentinel-pin-7731";

fn sign_state(m: &Module<Fake>, s: CK_SESSION_HANDLE) -> (CK_SLOT_ID, bool, String) {
    let state = m.lock();
    let session = &state.sessions[&s];
    (
        session.slot,
        session.find.is_some(),
        format!("{:?}", session.sign),
    )
}

#[test]
fn checking_the_session_leaves_it_unchanged() {
    let (m, s) = module(Ok(vec![0; 64]));
    assert_eq!(m.sign_init(s, Mechanism::Ecdsa, KEY_HANDLE), Ok(()));
    let before = sign_state(&m, s);
    // The credential never reaches the module: its only call takes the handle.
    assert_eq!(m.check_session(s), Ok(()));
    assert_eq!(sign_state(&m, s), before);
    let text = &before.2;
    assert!(!text.contains(std::str::from_utf8(SENTINEL).unwrap_or("?")));
    assert!(!text.contains(&format!("{:?}", SENTINEL.to_vec())));
    assert!(!text.contains("[115, 101"));
}

#[test]
fn login_does_not_reach_the_backend() {
    let (m, s) = module(Ok(vec![0; 64]));
    let counts = |m: &Module<Fake>| {
        (
            m.backend.signed.load(Ordering::SeqCst),
            m.backend.listed.load(Ordering::SeqCst),
        )
    };
    let before = counts(&m);
    assert_eq!(before.1, 1, "the slot list asked once");
    for _ in 0..3 {
        assert_eq!(m.check_session(s), Ok(()));
    }
    assert_eq!(m.check_session(s + 1), Err(CKR_SESSION_HANDLE_INVALID));
    assert_eq!(counts(&m), before);
}

#[test]
fn login_keeps_the_open_operation() {
    let run = |login: bool| {
        let (m, s) = rec_module(super::composed::RSA_CERT, Ok(vec![7; 256]));
        let ckm = cryptoki_sys::CKM_SHA256_RSA_PKCS;
        let mech = Mechanism::new(ckm, None).unwrap_or(Mechanism::RsaPkcs);
        assert_eq!(m.sign_init(s, mech, KEY_HANDLE), Ok(()));
        assert_eq!(m.sign_update(s, b"ab"), Ok(()));
        if login {
            assert_eq!(m.check_session(s), Ok(()));
        }
        assert_eq!(m.sign_update(s, b"c"), Ok(()));
        assert!(m.sign_final(s, Some(256)).is_ok());
        calls(&m)[0].2.clone()
    };
    assert_eq!(run(true), run(false));
}
