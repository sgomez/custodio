//! `C_SignUpdate` and `C_SignFinal` through the `extern "C"` functions.

use cryptoki_sys::{CKM_ECDSA_SHA256, CKR_OK, CKR_OPERATION_ACTIVE};

use super::*;

/// Starts a composed ECDSA operation on the only token.
///
/// # Safety
/// `session` is a live session.
unsafe fn init(session: CK_SESSION_HANDLE) {
    let mut m = mechanism(CKM_ECDSA_SHA256, ptr::null_mut(), 0);
    // SAFETY: `m` is a live local.
    assert_eq!(unsafe { C_SignInit(session, &raw mut m, 2) }, CKR_OK);
}

#[test]
fn sign_update_and_final_arguments() {
    let s = Session::new();
    let mut byte = 0_u8;
    let mut len: CK_ULONG = 64;
    let mut sig = [0_u8; 64];
    // SAFETY: pointers are to live locals; lengths are the real ones.
    unsafe {
        assert_eq!(
            C_SignUpdate(1, &raw mut byte, 1),
            CKR_CRYPTOKI_NOT_INITIALIZED
        );
        assert_eq!(
            C_SignFinal(1, sig.as_mut_ptr(), &raw mut len),
            CKR_CRYPTOKI_NOT_INITIALIZED
        );
        let session = s.open();
        assert_eq!(
            C_SignUpdate(session + 1, &raw mut byte, 1),
            CKR_SESSION_HANDLE_INVALID
        );
        assert_eq!(
            C_SignFinal(session + 1, sig.as_mut_ptr(), &raw mut len),
            CKR_SESSION_HANDLE_INVALID
        );
        init(session);
        assert_eq!(C_SignUpdate(session, &raw mut byte, 1), CKR_OK);
        // Argument errors leave the operation as it was.
        assert_eq!(C_SignUpdate(session, ptr::null_mut(), 1), CKR_ARGUMENTS_BAD);
        assert_eq!(
            C_SignUpdate(session, &raw mut byte, CK_ULONG::MAX),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(
            C_SignFinal(session, sig.as_mut_ptr(), ptr::null_mut()),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(C_SignUpdate(session, ptr::null_mut(), 0), CKR_OK);
        // Length query, then the signature.
        assert_eq!(C_SignFinal(session, ptr::null_mut(), &raw mut len), CKR_OK);
        assert_eq!(len, 64);
        len = 63;
        assert_eq!(
            C_SignFinal(session, sig.as_mut_ptr(), &raw mut len),
            CKR_BUFFER_TOO_SMALL
        );
        assert_eq!(len, 64);
        assert_eq!(C_SignFinal(session, sig.as_mut_ptr(), &raw mut len), CKR_OK);
        assert_eq!((len, sig), (64, [7; 64]));
        // The operation is over.
        assert_eq!(
            C_SignFinal(session, sig.as_mut_ptr(), &raw mut len),
            CKR_OPERATION_NOT_INITIALIZED
        );
        assert_eq!(
            C_SignUpdate(session, &raw mut byte, 1),
            CKR_OPERATION_NOT_INITIALIZED
        );
    }
}

#[test]
fn sign_update_rules_through_the_c_functions() {
    let s = Session::new();
    let session = s.open();
    let mut byte = 0_u8;
    let mut len: CK_ULONG = 64;
    let mut sig = [0_u8; 64];
    // SAFETY: pointers are to live locals; lengths are the real ones.
    unsafe {
        init(session);
        assert_eq!(C_SignUpdate(session, &raw mut byte, 1), CKR_OK);
        assert_eq!(
            C_Sign(session, &raw mut byte, 1, sig.as_mut_ptr(), &raw mut len),
            CKR_OPERATION_ACTIVE
        );
        assert_eq!(
            C_SignFinal(session, sig.as_mut_ptr(), &raw mut len),
            CKR_OPERATION_NOT_INITIALIZED
        );
        // A raw mechanism is single-part only.
        let mut raw = mechanism(CKM_ECDSA, ptr::null_mut(), 0);
        assert_eq!(C_SignInit(session, &raw mut raw, 2), CKR_OK);
        assert_eq!(
            C_SignUpdate(session, &raw mut byte, 1),
            CKR_OPERATION_NOT_INITIALIZED
        );
        assert_eq!(
            C_SignFinal(session, sig.as_mut_ptr(), &raw mut len),
            CKR_OPERATION_NOT_INITIALIZED
        );
    }
}
