use std::sync::atomic::{AtomicUsize, Ordering};

use cryptoki_sys::{
    CK_ULONG, CKG_MGF1_SHA256, CKG_MGF1_SHA384, CKG_MGF1_SHA512, CKM_ECDSA, CKM_RSA_PKCS,
    CKM_RSA_PKCS_PSS, CKM_SHA256, CKM_SHA512, CKR_BUFFER_TOO_SMALL, CKR_DATA_INVALID,
    CKR_FUNCTION_FAILED, CKR_KEY_HANDLE_INVALID, CKR_KEY_TYPE_INCONSISTENT, CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID, CKR_OPERATION_ACTIVE,
};

use super::*;
use crate::backend::{BackendError, SignParams};

mod composed;
mod login;
mod multipart;

const EC_CERT: &[u8] = include_bytes!("../../tests/p256-cert.der");

/// Counts the signatures that reach the service.
struct Fake {
    result: Result<Vec<u8>, BackendError>,
    signed: AtomicUsize,
    listed: AtomicUsize,
}

impl Backend for Fake {
    fn list_certificates(&self) -> Result<Vec<(String, Vec<u8>)>, BackendError> {
        self.listed.fetch_add(1, Ordering::SeqCst);
        Ok(vec![("ec".into(), EC_CERT.to_vec())])
    }

    fn sign(&self, _: &str, _: SignParams, _: &[u8]) -> Result<Vec<u8>, BackendError> {
        self.signed.fetch_add(1, Ordering::SeqCst);
        self.result.clone()
    }
}

fn module(result: Result<Vec<u8>, BackendError>) -> (Module<Fake>, CK_SESSION_HANDLE) {
    let m = Module::new(Fake {
        result,
        signed: AtomicUsize::new(0),
        listed: AtomicUsize::new(0),
    });
    m.initialize().unwrap_or_default();
    let slots = m.slot_list().unwrap_or_default();
    let session = m.open_session(slots[0]).unwrap_or_default();
    (m, session)
}

#[test]
fn nothing_works_before_initialize() {
    let m = Module::new(Fake {
        result: Ok(vec![]),
        signed: AtomicUsize::new(0),
        listed: AtomicUsize::new(0),
    });
    assert_eq!(m.slot_list(), Err(CKR_CRYPTOKI_NOT_INITIALIZED));
    assert_eq!(m.initialize(), Ok(()));
    assert_eq!(m.initialize(), Err(CKR_CRYPTOKI_ALREADY_INITIALIZED));
    assert_eq!(m.finalize(), Ok(()));
    assert_eq!(m.finalize(), Err(CKR_CRYPTOKI_NOT_INITIALIZED));
}

#[test]
fn length_query_and_small_buffer_do_not_reach_the_service() {
    let (m, s) = module(Ok(vec![0; 64]));
    assert_eq!(m.sign_init(s, Mechanism::Ecdsa, KEY_HANDLE), Ok(()));
    assert_eq!(m.sign(s, b"x", None), Ok(SignOutcome::Length(64)));
    assert_eq!(m.sign(s, b"x", Some(63)), Ok(SignOutcome::TooSmall(64)));
    assert_eq!(m.backend.signed.load(Ordering::SeqCst), 0);
    // The operation is still active after both.
    assert_eq!(
        m.sign_init(s, Mechanism::Ecdsa, KEY_HANDLE),
        Err(CKR_OPERATION_ACTIVE)
    );
    assert_eq!(
        m.sign(s, b"x", Some(64)),
        Ok(SignOutcome::Signature(vec![0; 64]))
    );
    assert_eq!(m.backend.signed.load(Ordering::SeqCst), 1);
    let _ = CKR_BUFFER_TOO_SMALL;
}

#[test]
fn every_signature_needs_its_own_init() {
    let (m, s) = module(Ok(vec![0; 64]));
    m.sign_init(s, Mechanism::Ecdsa, KEY_HANDLE)
        .unwrap_or_default();
    assert!(m.sign(s, b"x", Some(64)).is_ok());
    assert_eq!(
        m.sign(s, b"x", Some(64)),
        Err(CKR_OPERATION_NOT_INITIALIZED)
    );
    assert_eq!(m.backend.signed.load(Ordering::SeqCst), 1);
}

#[test]
fn service_failures_map_to_pkcs11_errors_and_end_the_operation() {
    for (error, rv) in [
        (BackendError::Denied, CKR_FUNCTION_FAILED),
        (BackendError::Invalid, CKR_DATA_INVALID),
        (BackendError::Unavailable, CKR_DEVICE_ERROR),
    ] {
        let (m, s) = module(Err(error));
        m.sign_init(s, Mechanism::Ecdsa, KEY_HANDLE)
            .unwrap_or_default();
        assert_eq!(m.sign(s, b"x", Some(64)), Err(rv));
        assert_eq!(
            m.sign(s, b"x", Some(64)),
            Err(CKR_OPERATION_NOT_INITIALIZED)
        );
    }
}

#[test]
fn a_wrong_sized_signature_is_not_passed_on() {
    let (m, s) = module(Ok(vec![0; 10]));
    m.sign_init(s, Mechanism::Ecdsa, KEY_HANDLE)
        .unwrap_or_default();
    assert_eq!(m.sign(s, b"x", Some(64)), Err(CKR_FUNCTION_FAILED));
}

#[test]
fn only_the_private_key_and_a_fitting_mechanism_can_sign() {
    let (m, s) = module(Ok(vec![0; 64]));
    assert_eq!(
        m.sign_init(s, Mechanism::Ecdsa, CERT_HANDLE),
        Err(CKR_KEY_HANDLE_INVALID)
    );
    assert_eq!(
        m.sign_init(s, Mechanism::Ecdsa, 99),
        Err(CKR_KEY_HANDLE_INVALID)
    );
    assert_eq!(
        m.sign_init(s, Mechanism::RsaPkcs, KEY_HANDLE),
        Err(CKR_KEY_TYPE_INCONSISTENT)
    );
    assert_eq!(
        m.sign_init(77, Mechanism::Ecdsa, KEY_HANDLE),
        Err(CKR_SESSION_HANDLE_INVALID)
    );
}

#[test]
fn mechanism_parameters_are_checked() {
    assert_eq!(Mechanism::new(CKM_ECDSA, None), Ok(Mechanism::Ecdsa));
    assert_eq!(
        Mechanism::new(CKM_ECDSA, Some((CKM_SHA256, CKG_MGF1_SHA256, 32))),
        Err(CKR_MECHANISM_PARAM_INVALID)
    );
    assert_eq!(
        Mechanism::new(CKM_RSA_PKCS_PSS, None),
        Err(CKR_MECHANISM_PARAM_INVALID)
    );
    assert_eq!(
        Mechanism::new(CKM_RSA_PKCS_PSS, Some((CKM_SHA256, CKG_MGF1_SHA384, 32))),
        Err(CKR_MECHANISM_PARAM_INVALID)
    );
    assert_eq!(
        Mechanism::new(CKM_RSA_PKCS_PSS, Some((0x220, CKG_MGF1_SHA256, 32))),
        Err(CKR_MECHANISM_PARAM_INVALID)
    );
    assert_eq!(Mechanism::new(0x1234, None), Err(CKR_MECHANISM_INVALID));
    assert!(Mechanism::new(CKM_RSA_PKCS_PSS, Some((CKM_SHA512, CKG_MGF1_SHA512, 64))).is_ok());
}

#[test]
fn search_matches_templates_and_pages() {
    let (m, s) = module(Ok(vec![]));
    let class = |c: CK_ULONG| vec![(cryptoki_sys::CKA_CLASS, c.to_ne_bytes().to_vec())];
    m.find_init(s, &class(cryptoki_sys::CKO_PRIVATE_KEY))
        .unwrap_or_default();
    assert_eq!(m.find_init(s, &[]), Err(CKR_OPERATION_ACTIVE));
    assert_eq!(m.find(s, 5), Ok(vec![KEY_HANDLE]));
    assert_eq!(m.find(s, 5), Ok(vec![]));
    assert_eq!(m.find_final(s), Ok(()));
    assert_eq!(m.find(s, 5), Err(CKR_OPERATION_NOT_INITIALIZED));
    m.find_init(s, &[]).unwrap_or_default();
    assert_eq!(m.find(s, 1), Ok(vec![CERT_HANDLE]));
    assert_eq!(m.find(s, 1), Ok(vec![KEY_HANDLE]));
    m.find_final(s).unwrap_or_default();
    m.find_init(s, &[(cryptoki_sys::CKA_ID, b"other".to_vec())])
        .unwrap_or_default();
    assert_eq!(m.find(s, 5), Ok(vec![]));
}

#[test]
fn sessions_and_slots_are_validated() {
    let (m, s) = module(Ok(vec![]));
    assert_eq!(m.token(5).map(|t| t.id.clone()), Err(CKR_SLOT_ID_INVALID));
    assert_eq!(m.open_session(5), Err(CKR_SLOT_ID_INVALID));
    assert_eq!(m.close_session(s), Ok(()));
    assert_eq!(m.close_session(s), Err(CKR_SESSION_HANDLE_INVALID));
    assert_eq!(m.object(s, KEY_HANDLE), Err(CKR_SESSION_HANDLE_INVALID));
}

#[test]
fn private_values_are_sensitive_not_unknown() {
    assert_eq!(
        Module::<Fake>::missing_attribute(KEY_HANDLE, cryptoki_sys::CKA_VALUE),
        CKR_ATTRIBUTE_SENSITIVE
    );
    assert_eq!(
        Module::<Fake>::missing_attribute(CERT_HANDLE, 0x9999),
        CKR_ATTRIBUTE_TYPE_INVALID
    );
}
