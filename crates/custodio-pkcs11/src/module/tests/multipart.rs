//! Multi-part signing through `Module`, against the recording backend of the composed tests.

use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

use cryptoki_sys::{
    CK_MECHANISM_TYPE, CKG_MGF1_SHA256, CKM_ECDSA, CKM_ECDSA_SHA256, CKM_RSA_PKCS,
    CKM_RSA_PKCS_PSS, CKM_SHA256, CKM_SHA256_RSA_PKCS, CKR_DATA_INVALID, CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED, CKR_OPERATION_ACTIVE, CKR_OPERATION_NOT_INITIALIZED,
    CKR_SESSION_HANDLE_INVALID,
};
use sha2::{Digest, Sha256};

use super::composed::{EC_MECHS, RSA_CERT, RSA_MECHS, Rec, calls, rec_module, unhex};
use super::signing::hash_part;
use super::*;
use crate::composed::DigestHasher;

const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SHA256_PREFIX: &str = "3031300d060960864801650304020105000420";

fn mech(ckm: CK_MECHANISM_TYPE) -> Mechanism {
    Mechanism::new(ckm, None).unwrap_or(Mechanism::RsaPkcs)
}

/// A module on an RSA or P-256 token with a canned signature of the right size.
fn module_for(cert: &'static [u8]) -> (Arc<Module<Rec>>, CK_SESSION_HANDLE, usize) {
    let size = token(cert).signature_len();
    let (m, s) = rec_module(cert, Ok(vec![7; size]));
    (m, s, size)
}

fn token(cert: &[u8]) -> Token {
    Token::parse("key", cert).unwrap_or_else(|| unreachable!("fixture parses"))
}

fn all_mechanisms() -> Vec<(&'static [u8], CK_MECHANISM_TYPE)> {
    RSA_MECHS
        .into_iter()
        .map(|m| (RSA_CERT, m))
        .chain(EC_MECHS.into_iter().map(|m| (EC_CERT, m)))
        .collect()
}

/// What a single-part `sign` of `message` sends, on a module of its own.
fn single_part_input(cert: &'static [u8], ckm: CK_MECHANISM_TYPE, message: &[u8]) -> Vec<u8> {
    let (m, s, size) = module_for(cert);
    assert_eq!(m.sign_init(s, mech(ckm), KEY_HANDLE), Ok(()));
    assert!(m.sign(s, message, Some(size)).is_ok());
    calls(&m)[0].2.clone()
}

fn multipart(
    m: &Module<Rec>,
    s: CK_SESSION_HANDLE,
    size: usize,
    parts: &[&[u8]],
) -> Rv<SignOutcome> {
    for part in parts {
        m.sign_update(s, part)?;
    }
    m.sign_final(s, Some(size))
}

#[test]
fn multipart_sends_digest_of_concatenation() {
    let message: Vec<u8> = (0..200u8).collect();
    let ones: Vec<u8> = (0..if cfg!(miri) { 50 } else { 1000 })
        .map(|i| u8::try_from(i % 251).unwrap_or_default())
        .collect();
    for (cert, ckm) in all_mechanisms() {
        let rsa = cert == RSA_CERT;
        // "abc" with an empty part in the middle, against the literal answer.
        let (m, s, size) = module_for(cert);
        assert_eq!(m.sign_init(s, mech(ckm), KEY_HANDLE), Ok(()));
        assert!(multipart(&m, s, size, &[b"a", b"", b"bc"]).is_ok());
        assert_eq!(calls(&m).len(), 1);
        if ckm == CKM_ECDSA_SHA256 {
            assert_eq!(calls(&m)[0].2, unhex(ABC_SHA256));
        }
        if ckm == CKM_SHA256_RSA_PKCS {
            assert_eq!(
                calls(&m)[0].2,
                unhex(&format!("{SHA256_PREFIX}{ABC_SHA256}"))
            );
        }
        assert_eq!(calls(&m)[0].2, single_part_input(cert, ckm, b"abc"));

        // A split at a non-block boundary.
        let (m, s, size) = module_for(cert);
        assert_eq!(m.sign_init(s, mech(ckm), KEY_HANDLE), Ok(()));
        let parts = [&message[..37], &message[37..101], &message[101..]];
        assert!(multipart(&m, s, size, &parts).is_ok());
        assert_eq!(calls(&m).len(), 1);
        assert_eq!(calls(&m)[0].2, single_part_input(cert, ckm, &message));

        // One byte at a time.
        let (m, s, size) = module_for(cert);
        assert_eq!(m.sign_init(s, mech(ckm), KEY_HANDLE), Ok(()));
        let singles: Vec<&[u8]> = ones.chunks(1).collect();
        assert!(multipart(&m, s, size, &singles).is_ok());
        assert_eq!(calls(&m).len(), 1);
        assert_eq!(calls(&m)[0].2, single_part_input(cert, ckm, &ones));

        // No update: the hash of the empty message.
        let (m, s, size) = module_for(cert);
        assert_eq!(m.sign_init(s, mech(ckm), KEY_HANDLE), Ok(()));
        assert!(multipart(&m, s, size, &[]).is_ok());
        if ckm == CKM_ECDSA_SHA256 {
            assert_eq!(calls(&m)[0].2, unhex(EMPTY_SHA256));
        }
        assert_eq!(calls(&m)[0].2, single_part_input(cert, ckm, b""));
        // The service is asked for the raw mechanism only.
        let raw = if rsa { CKM_RSA_PKCS } else { CKM_ECDSA };
        assert_eq!(
            calls(&m)[0].1.mechanism,
            u32::try_from(raw).unwrap_or_default()
        );
    }
}

#[test]
// Two sessions named `a` and `b`, as in the contract.
#[allow(clippy::many_single_char_names)]
fn multipart_state_is_per_session() {
    let (m, a, size) = module_for(EC_CERT);
    let slot = m.session_slot(a).unwrap_or_default();
    let b = m.open_session(slot).unwrap_or_default();
    for s in [a, b] {
        assert_eq!(m.sign_init(s, mech(CKM_ECDSA_SHA256), KEY_HANDLE), Ok(()));
    }
    assert_eq!(m.sign_update(a, b"first "), Ok(()));
    assert_eq!(m.sign_update(b, b"other "), Ok(()));
    assert_eq!(m.sign_update(a, b"message"), Ok(()));
    assert_eq!(m.sign_update(b, b"message!"), Ok(()));
    assert!(m.sign_final(b, Some(size)).is_ok());
    assert!(m.sign_final(a, Some(size)).is_ok());
    let sent = calls(&m);
    assert_eq!(sent[0].2, Sha256::digest(b"other message!").to_vec());
    assert_eq!(sent[1].2, Sha256::digest(b"first message").to_vec());

    // A session closed in the middle.
    let c = m.open_session(slot).unwrap_or_default();
    assert_eq!(m.sign_init(c, mech(CKM_ECDSA_SHA256), KEY_HANDLE), Ok(()));
    assert_eq!(m.sign_update(c, b"x"), Ok(()));
    assert_eq!(m.close_session(c), Ok(()));
    assert_eq!(m.sign_final(c, Some(size)), Err(CKR_SESSION_HANDLE_INVALID));
    assert_eq!(m.sign_update(c, b"x"), Err(CKR_SESSION_HANDLE_INVALID));
    let d = m.open_session(slot).unwrap_or_default();
    assert_eq!(
        m.sign_final(d, Some(size)),
        Err(CKR_OPERATION_NOT_INITIALIZED)
    );
    assert_eq!(calls(&m).len(), 2);
}

#[test]
fn multipart_leaves_the_lock_free() {
    let (m, a, _) = module_for(EC_CERT);
    assert_eq!(m.sign_init(a, mech(CKM_ECDSA_SHA256), KEY_HANDLE), Ok(()));
    assert_eq!(m.sign_update(a, b"part"), Ok(()));
    let (tx, rx) = channel();
    let other = Arc::clone(&m);
    let worker = thread::spawn(move || {
        let slots = other.slot_list().unwrap_or_default();
        let b = other.open_session(slots[0]).unwrap_or_default();
        let r = other.sign_init(b, mech(CKM_ECDSA_SHA256), KEY_HANDLE);
        let _ = tx.send(r);
    });
    assert_eq!(rx.recv_timeout(Duration::from_secs(10)), Ok(Ok(())));
    assert!(worker.join().is_ok());
    // An update never reaches the service.
    assert_eq!(calls(&m).len(), 0);
}

#[test]
fn multipart_update_busy() {
    // Each of update, final and sign meets a part in flight, in a fresh run.
    for call in 0..3 {
        let (m, a, size) = module_for(EC_CERT);
        let slot = m.session_slot(a).unwrap_or_default();
        assert_eq!(m.sign_init(a, mech(CKM_ECDSA_SHA256), KEY_HANDLE), Ok(()));
        assert_eq!(m.sign_update(a, b"one"), Ok(()));
        // The first update, up to the point where it hashes outside the lock.
        let (serial, mut hasher) = m.begin_update(a).unwrap_or_else(|e| unreachable!("{e}"));
        hash_part(&mut hasher, b"two");
        // Other sessions still work.
        let b = m.open_session(slot).unwrap_or_default();
        assert_eq!(m.sign_init(b, mech(CKM_ECDSA_SHA256), KEY_HANDLE), Ok(()));
        // The second call ends the operation.
        let second = match call {
            0 => m.sign_update(a, b"x").map(|()| SignOutcome::Length(0)),
            1 => m.sign_final(a, Some(size)),
            _ => m.sign(a, b"x", Some(size)),
        };
        assert_eq!(second, Err(CKR_OPERATION_ACTIVE));
        // A further call, then sign_init: the operation is still open until the first returns.
        assert_eq!(
            m.sign_final(a, Some(size)),
            Err(CKR_OPERATION_NOT_INITIALIZED)
        );
        assert_eq!(m.sign_update(a, b"x"), Err(CKR_OPERATION_NOT_INITIALIZED));
        assert_eq!(
            m.sign_init(a, mech(CKM_ECDSA_SHA256), KEY_HANDLE),
            Err(CKR_OPERATION_ACTIVE)
        );
        // The first call returns: its hasher is dropped and the operation is over.
        m.end_update(a, serial, hasher);
        assert_eq!(
            m.sign_final(a, Some(size)),
            Err(CKR_OPERATION_NOT_INITIALIZED)
        );
        assert_eq!(calls(&m).len(), 0);
        assert_eq!(m.sign_init(a, mech(CKM_ECDSA_SHA256), KEY_HANDLE), Ok(()));
    }
}

#[test]
fn multipart_late_return_never_overwrites_a_newer_operation() {
    let (m, a, size) = module_for(EC_CERT);
    assert_eq!(m.sign_init(a, mech(CKM_ECDSA_SHA256), KEY_HANDLE), Ok(()));
    let (serial, mut hasher) = m.begin_update(a).unwrap_or_else(|e| unreachable!("{e}"));
    hash_part(&mut hasher, b"stale");
    assert_eq!(m.sign_update(a, b"x"), Err(CKR_OPERATION_ACTIVE));
    // The aborting call has marked the session; the first call returns, then a new operation.
    m.end_update(a, serial, hasher);
    assert_eq!(m.sign_init(a, mech(CKM_ECDSA_SHA256), KEY_HANDLE), Ok(()));
    assert_eq!(m.sign_update(a, b"new"), Ok(()));
    // A call that began on the old operation returns late, after the new one started.
    let mut late = DigestHasher::new(crate::composed::Hash::Sha256);
    hash_part(&mut late, b"stale");
    m.end_update(a, serial, late);
    assert_eq!(m.sign_update(a, b"er"), Ok(()));
    assert!(m.sign_final(a, Some(size)).is_ok());
    assert_eq!(calls(&m)[0].2, Sha256::digest(b"newer").to_vec());
}

#[test]
fn multipart_sign_init_while_busy_and_not_aborted() {
    let (m, a, _) = module_for(EC_CERT);
    assert_eq!(m.sign_init(a, mech(CKM_ECDSA_SHA256), KEY_HANDLE), Ok(()));
    let (serial, hasher) = m.begin_update(a).unwrap_or_else(|e| unreachable!("{e}"));
    assert_eq!(
        m.sign_init(a, mech(CKM_ECDSA_SHA256), KEY_HANDLE),
        Err(CKR_OPERATION_ACTIVE)
    );
    m.end_update(a, serial, hasher);
    // Operation kept, with the part's effect.
    assert_eq!(m.sign_update(a, b"x"), Ok(()));
}

#[test]
fn multipart_final_length_and_small_buffer() {
    for (cert, ckm, n) in [
        (RSA_CERT, CKM_SHA256_RSA_PKCS, 256),
        (EC_CERT, CKM_ECDSA_SHA256, 64),
    ] {
        let (m, s, size) = module_for(cert);
        assert_eq!(size, n);
        assert_eq!(m.sign_init(s, mech(ckm), KEY_HANDLE), Ok(()));
        assert_eq!(m.sign_update(s, b"ab"), Ok(()));
        assert_eq!(m.sign_final(s, None), Ok(SignOutcome::Length(n)));
        assert_eq!(m.sign_final(s, Some(n - 1)), Ok(SignOutcome::TooSmall(n)));
        assert_eq!(m.sign_final(s, Some(0)), Ok(SignOutcome::TooSmall(n)));
        assert_eq!(calls(&m).len(), 0);
        // The state survived: an update extends the same message.
        assert_eq!(m.sign_update(s, b"c"), Ok(()));
        assert_eq!(
            m.sign_final(s, Some(n)),
            Ok(SignOutcome::Signature(vec![7; n]))
        );
        assert_eq!(calls(&m).len(), 1);
        assert_eq!(calls(&m)[0].2, single_part_input(cert, ckm, b"abc"));
        assert_eq!(m.sign_final(s, Some(n)), Err(CKR_OPERATION_NOT_INITIALIZED));
        assert_eq!(calls(&m).len(), 1);
    }
    // Without the extra update the retry signs the earlier parts only.
    let (m, s, size) = module_for(EC_CERT);
    assert_eq!(m.sign_init(s, mech(CKM_ECDSA_SHA256), KEY_HANDLE), Ok(()));
    assert_eq!(m.sign_update(s, b"abc"), Ok(()));
    assert_eq!(m.sign_final(s, Some(1)), Ok(SignOutcome::TooSmall(size)));
    assert!(m.sign_final(s, Some(size)).is_ok());
    assert_eq!(calls(&m)[0].2, unhex(ABC_SHA256));
}

#[test]
fn multipart_failure_ends_the_operation() {
    let cases = [
        (Err(BackendError::Denied), CKR_FUNCTION_FAILED),
        (Err(BackendError::Invalid), CKR_DATA_INVALID),
        (Err(BackendError::Unavailable), CKR_DEVICE_ERROR),
        (Ok(vec![0; 10]), CKR_FUNCTION_FAILED),
    ];
    for (result, code) in cases {
        let (m, s, size) = module_for(EC_CERT);
        *m.backend
            .result
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = result;
        assert_eq!(m.sign_init(s, mech(CKM_ECDSA_SHA256), KEY_HANDLE), Ok(()));
        assert_eq!(m.sign_update(s, b"old"), Ok(()));
        assert_eq!(m.sign_final(s, Some(size)), Err(code));
        assert_eq!(m.sign_update(s, b"x"), Err(CKR_OPERATION_NOT_INITIALIZED));
        assert_eq!(
            m.sign_final(s, Some(size)),
            Err(CKR_OPERATION_NOT_INITIALIZED)
        );
        assert_eq!(
            m.sign(s, b"x", Some(size)),
            Err(CKR_OPERATION_NOT_INITIALIZED)
        );
        assert_eq!(calls(&m).len(), 1);
        // A new operation starts from an empty hash.
        *m.backend
            .result
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Ok(vec![7; size]);
        assert_eq!(m.sign_init(s, mech(CKM_ECDSA_SHA256), KEY_HANDLE), Ok(()));
        assert_eq!(m.sign_update(s, b"new"), Ok(()));
        assert!(m.sign_final(s, Some(size)).is_ok());
        assert_eq!(calls(&m)[1].2, Sha256::digest(b"new").to_vec());
    }
}

#[test]
fn multipart_raw_mechanism_ends() {
    let pss = Mechanism::new(CKM_RSA_PKCS_PSS, Some((CKM_SHA256, CKG_MGF1_SHA256, 32)))
        .unwrap_or(Mechanism::RsaPkcs);
    let cases = [
        (RSA_CERT, mech(CKM_RSA_PKCS), CKM_RSA_PKCS),
        (RSA_CERT, pss, CKM_RSA_PKCS_PSS),
        (EC_CERT, mech(CKM_ECDSA), CKM_ECDSA),
    ];
    for (cert, mechanism, _) in cases {
        for how in 0..3 {
            let (m, s, size) = module_for(cert);
            assert_eq!(m.sign_init(s, mechanism, KEY_HANDLE), Ok(()));
            let r = match how {
                0 => m.sign_update(s, b"x").map(|()| SignOutcome::Length(0)),
                1 => m.sign_final(s, None),
                _ => m.sign_final(s, Some(size)),
            };
            assert_eq!(r, Err(CKR_OPERATION_NOT_INITIALIZED));
            assert_eq!(
                m.sign(s, b"x", Some(size)),
                Err(CKR_OPERATION_NOT_INITIALIZED)
            );
            assert_eq!(m.sign_update(s, b"x"), Err(CKR_OPERATION_NOT_INITIALIZED));
            assert_eq!(
                m.sign_final(s, Some(size)),
                Err(CKR_OPERATION_NOT_INITIALIZED)
            );
            assert_eq!(calls(&m).len(), 0);
            // A new single-part signature works.
            assert_eq!(m.sign_init(s, mechanism, KEY_HANDLE), Ok(()));
            assert!(m.sign(s, b"x", Some(size)).is_ok());
            assert_eq!(calls(&m).len(), 1);
        }
    }
}

#[test]
fn multipart_sign_after_update_is_rejected() {
    for query in [false, true] {
        let (m, s, size) = module_for(EC_CERT);
        assert_eq!(m.sign_init(s, mech(CKM_ECDSA_SHA256), KEY_HANDLE), Ok(()));
        assert_eq!(m.sign_update(s, b"x"), Ok(()));
        let capacity = if query { None } else { Some(size) };
        assert_eq!(m.sign(s, b"y", capacity), Err(CKR_OPERATION_ACTIVE));
        assert_eq!(calls(&m).len(), 0);
        assert_eq!(
            m.sign_final(s, Some(size)),
            Err(CKR_OPERATION_NOT_INITIALIZED)
        );
        assert_eq!(m.sign_update(s, b"x"), Err(CKR_OPERATION_NOT_INITIALIZED));
        assert_eq!(
            m.sign(s, b"y", capacity),
            Err(CKR_OPERATION_NOT_INITIALIZED)
        );
        assert_eq!(calls(&m).len(), 0);
    }
}

#[test]
fn multipart_sign_query_before_update() {
    let (m, s, size) = module_for(EC_CERT);
    assert_eq!(m.sign_init(s, mech(CKM_ECDSA_SHA256), KEY_HANDLE), Ok(()));
    assert_eq!(m.sign(s, b"", None), Ok(SignOutcome::Length(size)));
    assert!(multipart(&m, s, size, &[b"a", b"bc"]).is_ok());
    assert_eq!(calls(&m).len(), 1);
    assert_eq!(calls(&m)[0].2, unhex(ABC_SHA256));
}

#[test]
fn multipart_sign_init_while_open() {
    let (m, s, size) = module_for(EC_CERT);
    let init = |m: &Module<Rec>| m.sign_init(s, mech(CKM_ECDSA_SHA256), KEY_HANDLE);
    assert_eq!(init(&m), Ok(()));
    assert_eq!(init(&m), Err(CKR_OPERATION_ACTIVE));
    assert_eq!(m.sign_update(s, b"ab"), Ok(()));
    assert_eq!(init(&m), Err(CKR_OPERATION_ACTIVE));
    assert_eq!(m.sign_update(s, b"c"), Ok(()));
    assert!(m.sign_final(s, Some(size)).is_ok());
    assert_eq!(calls(&m)[0].2, unhex(ABC_SHA256));
}
