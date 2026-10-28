//! Composed mechanisms through `Module`, against a backend that records what the service gets.

use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::thread;
use std::time::Duration;

use cryptoki_sys::{
    CK_MECHANISM_TYPE, CKF_EC_F_P, CKF_EC_NAMEDCURVE, CKF_SIGN, CKM_ECDSA_SHA1, CKM_ECDSA_SHA256,
    CKM_ECDSA_SHA384, CKM_ECDSA_SHA512, CKM_SHA1_RSA_PKCS, CKM_SHA224_RSA_PKCS,
    CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS,
};
use sha2::{Digest, Sha256};

use super::*;

pub(super) const RSA_CERT: &[u8] = include_bytes!("../../../tests/rsa2048-cert.der");

pub(super) const RSA_MECHS: [CK_MECHANISM_TYPE; 3] = [
    CKM_SHA256_RSA_PKCS,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS,
];
pub(super) const EC_MECHS: [CK_MECHANISM_TYPE; 3] =
    [CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512];

pub(super) type Call = (String, SignParams, Vec<u8>);

/// Records `(id, params, data)` of every `sign`, and can run a hook inside the call.
pub(super) struct Rec {
    cert: &'static [u8],
    pub(super) result: Mutex<Result<Vec<u8>, BackendError>>,
    calls: Mutex<Vec<Call>>,
    hook: OnceLock<Box<dyn Fn() + Send + Sync>>,
}

impl Backend for Rec {
    fn list_certificates(&self) -> Result<Vec<(String, Vec<u8>)>, BackendError> {
        Ok(vec![("key".into(), self.cert.to_vec())])
    }

    fn sign(&self, id: &str, params: SignParams, data: &[u8]) -> Result<Vec<u8>, BackendError> {
        if let Some(hook) = self.hook.get() {
            hook();
        }
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((id.into(), params, data.to_vec()));
        self.result
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

pub(super) fn rec_module(
    cert: &'static [u8],
    result: Result<Vec<u8>, BackendError>,
) -> (Arc<Module<Rec>>, CK_SESSION_HANDLE) {
    let m = Arc::new(Module::new(Rec {
        cert,
        result: Mutex::new(result),
        calls: Mutex::new(Vec::new()),
        hook: OnceLock::new(),
    }));
    m.initialize().unwrap_or_default();
    let slots = m.slot_list().unwrap_or_default();
    let session = m.open_session(slots[0]).unwrap_or_default();
    (m, session)
}

pub(super) fn calls(m: &Module<Rec>) -> Vec<Call> {
    m.backend
        .calls
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

fn token(cert: &[u8]) -> Token {
    Token::parse("key", cert).unwrap_or_else(|| unreachable!("fixture parses"))
}

fn sorted(mut v: Vec<CK_MECHANISM_TYPE>) -> Vec<CK_MECHANISM_TYPE> {
    v.sort_unstable();
    v
}

fn expected(raw: &[CK_MECHANISM_TYPE], composed: [CK_MECHANISM_TYPE; 3]) -> Vec<CK_MECHANISM_TYPE> {
    sorted(raw.iter().copied().chain(composed).collect())
}

#[test]
fn mechanism_lists_fit_the_key() {
    assert_eq!(
        sorted(mechanisms(&token(RSA_CERT))),
        expected(&[CKM_RSA_PKCS, CKM_RSA_PKCS_PSS], RSA_MECHS)
    );
    assert_eq!(
        sorted(mechanisms(&token(EC_CERT))),
        expected(&[CKM_ECDSA], EC_MECHS)
    );
}

#[test]
fn mechanism_info_fits_the_key() {
    let rsa = token(RSA_CERT);
    let ec = token(EC_CERT);
    for m in RSA_MECHS {
        assert_eq!(mechanism_info(&rsa, m), Some((2048, CKF_SIGN)));
        assert_eq!(mechanism_info(&ec, m), None);
    }
    for m in EC_MECHS {
        assert_eq!(
            mechanism_info(&ec, m),
            Some((256, CKF_SIGN | CKF_EC_F_P | CKF_EC_NAMEDCURVE))
        );
        assert_eq!(mechanism_info(&rsa, m), None);
    }
    for m in [CKM_SHA224_RSA_PKCS, CKM_SHA1_RSA_PKCS, CKM_ECDSA_SHA1] {
        assert_eq!(mechanism_info(&rsa, m), None);
        assert_eq!(mechanism_info(&ec, m), None);
    }
}

#[test]
fn composed_with_parameter_is_refused() {
    let (m, s) = rec_module(EC_CERT, Ok(vec![0; 64]));
    for ckm in RSA_MECHS.into_iter().chain(EC_MECHS) {
        assert!(Mechanism::new(ckm, None).is_ok());
        assert_eq!(
            Mechanism::new(ckm, Some((CKM_SHA256, CKG_MGF1_SHA256, 32))),
            Err(CKR_MECHANISM_PARAM_INVALID)
        );
    }
    assert_eq!(
        m.sign(s, b"x", Some(64)),
        Err(CKR_OPERATION_NOT_INITIALIZED)
    );
    assert_eq!(calls(&m).len(), 0);
}

#[test]
fn composed_mismatch_is_refused() {
    for (cert, wrong) in [(EC_CERT, RSA_MECHS), (RSA_CERT, EC_MECHS)] {
        let (m, s) = rec_module(cert, Ok(vec![]));
        for ckm in wrong {
            let mechanism = Mechanism::new(ckm, None).unwrap_or(Mechanism::RsaPkcs);
            assert_eq!(
                m.sign_init(s, mechanism, KEY_HANDLE),
                Err(CKR_KEY_TYPE_INCONSISTENT)
            );
        }
        assert_eq!(calls(&m).len(), 0);
    }
}

pub(super) fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_default())
        .collect()
}

#[test]
fn composed_sign_sends_digest_or_digestinfo() {
    // FIPS 180 "abc" digests and the RFC 8017 section 9.2 prefixes, written out.
    let sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let sha384 = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
                  8086072ba1e7cc2358baeca134c825a7";
    let sha512 = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                  2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    let p256 = "3031300d060960864801650304020105000420";
    let p384 = "3041300d060960864801650304020205000430";
    let p512 = "3051300d060960864801650304020305000440";
    let cases = [
        (
            RSA_CERT,
            CKM_SHA256_RSA_PKCS,
            CKM_RSA_PKCS,
            format!("{p256}{sha256}"),
            51,
        ),
        (
            RSA_CERT,
            CKM_SHA384_RSA_PKCS,
            CKM_RSA_PKCS,
            format!("{p384}{sha384}"),
            67,
        ),
        (
            RSA_CERT,
            CKM_SHA512_RSA_PKCS,
            CKM_RSA_PKCS,
            format!("{p512}{sha512}"),
            83,
        ),
        (EC_CERT, CKM_ECDSA_SHA256, CKM_ECDSA, sha256.to_owned(), 32),
        (EC_CERT, CKM_ECDSA_SHA384, CKM_ECDSA, sha384.to_owned(), 48),
        (EC_CERT, CKM_ECDSA_SHA512, CKM_ECDSA, sha512.to_owned(), 64),
    ];
    for (cert, ckm, raw, data, len) in cases {
        let size = token(cert).signature_len();
        let (m, s) = rec_module(cert, Ok(vec![5; size]));
        let mechanism = Mechanism::new(ckm, None).unwrap_or(Mechanism::RsaPkcs);
        assert_eq!(m.sign_init(s, mechanism, KEY_HANDLE), Ok(()));
        assert_eq!(
            m.sign(s, b"abc", Some(size)),
            Ok(SignOutcome::Signature(vec![5; size]))
        );
        let recorded = calls(&m);
        assert_eq!(recorded.len(), 1);
        let (id, params, sent) = &recorded[0];
        assert_eq!(id, "key");
        assert_eq!(
            *params,
            SignParams {
                mechanism: u32::try_from(raw).unwrap_or_default(),
                hash: 0,
                salt_len: 0
            }
        );
        assert_eq!(sent.len(), len);
        assert_eq!(*sent, unhex(&data));
    }
}

#[test]
fn composed_sign_big_message() {
    let size = if cfg!(miri) { 1 << 20 } else { 16 << 20 };
    let message = vec![0_u8; size];
    let (m, s) = rec_module(EC_CERT, Ok(vec![5; 64]));
    let mechanism = Mechanism::new(CKM_ECDSA_SHA256, None).unwrap_or(Mechanism::Ecdsa);
    assert_eq!(m.sign_init(s, mechanism, KEY_HANDLE), Ok(()));
    assert!(m.sign(s, &message, Some(64)).is_ok());
    let recorded = calls(&m);
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].2, Sha256::digest(&message).to_vec());
}

#[test]
fn composed_backend_runs_outside_the_state_lock() {
    let (m, s) = rec_module(EC_CERT, Ok(vec![5; 64]));
    let weak: Weak<Module<Rec>> = Arc::downgrade(&m);
    let (tx, rx) = channel();
    let hook_tx = Mutex::new(tx.clone());
    let hook = move || {
        if let Some(m) = weak.upgrade() {
            let ok = m.slot_list().is_ok() && m.open_session(0).is_ok();
            let _ = hook_tx
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .send(ok);
        }
    };
    assert!(m.backend.hook.set(Box::new(hook)).is_ok());
    let mechanism = Mechanism::new(CKM_ECDSA_SHA256, None).unwrap_or(Mechanism::Ecdsa);
    assert_eq!(m.sign_init(s, mechanism, KEY_HANDLE), Ok(()));
    let worker = m.clone();
    thread::spawn(move || {
        let _ = worker.sign(s, b"abc", Some(64));
        let _ = tx.send(true);
    });
    assert_eq!(rx.recv_timeout(Duration::from_secs(20)), Ok(true));
    assert_eq!(rx.recv_timeout(Duration::from_secs(20)), Ok(true));
}

#[test]
fn composed_length_query_and_small_buffer() {
    for (cert, ckm, n) in [
        (RSA_CERT, CKM_SHA256_RSA_PKCS, 256),
        (EC_CERT, CKM_ECDSA_SHA256, 64),
    ] {
        let (m, s) = rec_module(cert, Ok(vec![5; n]));
        let mechanism = Mechanism::new(ckm, None).unwrap_or(Mechanism::Ecdsa);
        assert_eq!(m.sign_init(s, mechanism, KEY_HANDLE), Ok(()));
        assert_eq!(m.sign(s, b"abc", None), Ok(SignOutcome::Length(n)));
        assert_eq!(m.sign(s, b"abc", Some(n - 1)), Ok(SignOutcome::TooSmall(n)));
        assert_eq!(m.sign(s, b"abc", Some(0)), Ok(SignOutcome::TooSmall(n)));
        assert_eq!(calls(&m).len(), 0);
        assert_eq!(
            m.sign(s, b"abc", Some(n)),
            Ok(SignOutcome::Signature(vec![5; n]))
        );
        assert_eq!(calls(&m).len(), 1);
        assert_eq!(
            m.sign(s, b"abc", Some(n)),
            Err(CKR_OPERATION_NOT_INITIALIZED)
        );
    }
}

#[test]
fn composed_failure_ends_the_operation() {
    let mechanism = Mechanism::new(CKM_ECDSA_SHA384, None).unwrap_or(Mechanism::Ecdsa);
    let cases = [
        (Err(BackendError::Denied), CKR_FUNCTION_FAILED),
        (Err(BackendError::Invalid), CKR_DATA_INVALID),
        (Err(BackendError::Unavailable), CKR_DEVICE_ERROR),
        (Ok(vec![0; 10]), CKR_FUNCTION_FAILED),
    ];
    for (result, rv) in cases {
        let (m, s) = rec_module(EC_CERT, result);
        assert_eq!(m.sign_init(s, mechanism, KEY_HANDLE), Ok(()));
        assert_eq!(m.sign(s, b"abc", Some(64)), Err(rv));
        assert_eq!(
            m.sign(s, b"abc", Some(64)),
            Err(CKR_OPERATION_NOT_INITIALIZED)
        );
        assert_eq!(m.sign_init(s, mechanism, KEY_HANDLE), Ok(()));
    }
}
