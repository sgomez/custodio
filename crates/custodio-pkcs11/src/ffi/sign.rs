//! `C_SignInit`, `C_Sign`, `C_SignUpdate` and `C_SignFinal`.

use std::ptr;

use cryptoki_sys::{
    CK_BYTE_PTR, CK_MECHANISM, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_RSA_PKCS_PSS_PARAMS, CK_RV,
    CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR, CKM_ECDSA, CKM_RSA_PKCS, CKM_RSA_PKCS_PSS,
    CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID,
};

use super::MODULE;
use super::args::{guard, input, out, to_ulong, to_usize};
use crate::composed::Composed;
use crate::module::{Mechanism, SignOutcome};

pub(super) unsafe extern "C" fn C_SignInit(
    session: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    guard(|| {
        // SAFETY: checked for null; validity is the caller's promise.
        let m: &CK_MECHANISM = unsafe { mechanism.as_ref() }.ok_or(CKR_ARGUMENTS_BAD)?;
        let pss = if m.mechanism == CKM_RSA_PKCS_PSS {
            if m.pParameter.is_null()
                || to_usize(m.ulParameterLen)? != size_of::<CK_RSA_PKCS_PSS_PARAMS>()
                || !m.pParameter.cast::<CK_RSA_PKCS_PSS_PARAMS>().is_aligned()
            {
                return Err(CKR_MECHANISM_PARAM_INVALID);
            }
            // SAFETY: non-null, aligned and exactly the size of the structure.
            let p = unsafe { &*m.pParameter.cast::<CK_RSA_PKCS_PSS_PARAMS>() };
            Some((p.hashAlg, p.mgf, p.sLen))
        } else if m.mechanism == CKM_RSA_PKCS
            || m.mechanism == CKM_ECDSA
            || Composed::from_ckm(m.mechanism).is_some()
        {
            if !m.pParameter.is_null() || m.ulParameterLen != 0 {
                return Err(CKR_MECHANISM_PARAM_INVALID);
            }
            None
        } else {
            return Err(CKR_MECHANISM_INVALID);
        };
        MODULE.sign_init(session, Mechanism::new(m.mechanism, pss)?, key)
    })
}

pub(super) unsafe extern "C" fn C_Sign(
    session: CK_SESSION_HANDLE,
    data: CK_BYTE_PTR,
    data_len: CK_ULONG,
    signature: CK_BYTE_PTR,
    signature_len: CK_ULONG_PTR,
) -> CK_RV {
    guard(|| {
        // SAFETY: checked for null; validity is the caller's promise.
        let signature_len = unsafe { out(signature_len) }?;
        // SAFETY: the caller promises `data_len` readable bytes at `data`.
        let data = unsafe { input(data, data_len) }?;
        let capacity = if signature.is_null() {
            None
        } else {
            Some(to_usize(*signature_len)?)
        };
        match MODULE.sign(session, data, capacity)? {
            SignOutcome::Length(n) => *signature_len = to_ulong(n)?,
            SignOutcome::TooSmall(n) => {
                *signature_len = to_ulong(n)?;
                return Err(CKR_BUFFER_TOO_SMALL);
            }
            SignOutcome::Signature(bytes) => {
                // SAFETY: `sign` only returns a signature when `capacity` (the caller's buffer
                // size at the non-null `signature`) is at least its length.
                unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), signature, bytes.len()) };
                *signature_len = to_ulong(bytes.len())?;
            }
        }
        Ok(())
    })
}

pub(super) unsafe extern "C" fn C_SignUpdate(
    session: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> CK_RV {
    guard(|| {
        // SAFETY: the caller promises `part_len` readable bytes at `part`.
        let part = unsafe { input(part, part_len) }?;
        MODULE.sign_update(session, part)
    })
}

pub(super) unsafe extern "C" fn C_SignFinal(
    session: CK_SESSION_HANDLE,
    signature: CK_BYTE_PTR,
    signature_len: CK_ULONG_PTR,
) -> CK_RV {
    guard(|| {
        // SAFETY: checked for null; validity is the caller's promise.
        let signature_len = unsafe { out(signature_len) }?;
        let capacity = if signature.is_null() {
            None
        } else {
            Some(to_usize(*signature_len)?)
        };
        match MODULE.sign_final(session, capacity)? {
            SignOutcome::Length(n) => *signature_len = to_ulong(n)?,
            SignOutcome::TooSmall(n) => {
                *signature_len = to_ulong(n)?;
                return Err(CKR_BUFFER_TOO_SMALL);
            }
            SignOutcome::Signature(bytes) => {
                // SAFETY: `sign_final` only returns a signature when `capacity` (the caller's
                // buffer size at the non-null `signature`) is at least its length.
                unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), signature, bytes.len()) };
                *signature_len = to_ulong(bytes.len())?;
            }
        }
        Ok(())
    })
}
