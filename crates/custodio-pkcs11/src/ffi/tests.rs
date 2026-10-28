//! The C functions called through the function list with hostile arguments, against a fake
//! service. These run under Miri (`just miri`) and `AddressSanitizer` (`just asan`).
use std::ffi::c_void;
use std::sync::{Mutex, MutexGuard, PoisonError};

use cryptoki_sys::{
    CK_ATTRIBUTE, CKA_CLASS, CKA_LABEL, CKA_VALUE, CKO_CERTIFICATE, CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_OBJECT_HANDLE_INVALID,
    CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID, CKR_SLOT_ID_INVALID,
    CKU_USER,
};

use super::*;

mod composed;
mod login;
mod multipart;

use crate::fake::EC_CERT;

/// The module is a process-wide global: one test at a time, each starting uninitialized.
static SERIAL: Mutex<()> = Mutex::new(());

struct Session {
    _lock: MutexGuard<'static, ()>,
}

impl Session {
    fn new() -> Self {
        let lock = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        // SAFETY: NULL is a valid argument.
        let _ = unsafe { C_Finalize(ptr::null_mut()) };
        Self { _lock: lock }
    }

    /// Initialized module with one open session on the only slot.
    // Taking `&self` proves the serial lock is held.
    #[allow(clippy::unused_self)]
    fn open(&self) -> CK_SESSION_HANDLE {
        // SAFETY: NULL arguments are valid; the out pointers are to live locals.
        unsafe {
            assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
            let mut count: CK_ULONG = 0;
            assert_eq!(C_GetSlotList(1, ptr::null_mut(), &raw mut count), CKR_OK);
            assert_eq!(count, 1);
            let mut slot: CK_SLOT_ID = 99;
            assert_eq!(C_GetSlotList(1, &raw mut slot, &raw mut count), CKR_OK);
            let mut session: CK_SESSION_HANDLE = 0;
            let rv = C_OpenSession(
                slot,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &raw mut session,
            );
            assert_eq!(rv, CKR_OK);
            session
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: NULL is a valid argument.
        let _ = unsafe { C_Finalize(ptr::null_mut()) };
    }
}

fn attr(type_: CK_ULONG, value: *mut c_void, len: CK_ULONG) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_,
        pValue: value,
        ulValueLen: len,
    }
}

#[test]
fn function_list_is_complete_and_null_checked() {
    let _s = Session::new();
    // SAFETY: the out pointer is a live local; NULL is checked.
    unsafe {
        assert_eq!(C_GetFunctionList(ptr::null_mut()), CKR_ARGUMENTS_BAD);
        let mut list: *mut CK_FUNCTION_LIST = ptr::null_mut();
        assert_eq!(C_GetFunctionList(&raw mut list), CKR_OK);
        let list = &*list;
        assert_eq!(
            list.C_Login.map(|f| f(0, CKU_USER, ptr::null_mut(), 0)),
            Some(CKR_CRYPTOKI_NOT_INITIALIZED)
        );
        assert_eq!(
            list.C_Logout.map(|f| f(0)),
            Some(CKR_CRYPTOKI_NOT_INITIALIZED)
        );
        assert_eq!(C_GetInfo(ptr::null_mut()), CKR_ARGUMENTS_BAD);
        let mut info = std::mem::MaybeUninit::<CK_INFO>::zeroed();
        assert_eq!(C_GetInfo(info.as_mut_ptr()), CKR_OK);
    }
}

#[test]
fn initialize_arguments() {
    let s = Session::new();
    let mut args: CK_C_INITIALIZE_ARGS = unsafe { std::mem::zeroed() };
    // SAFETY: pointers are to live locals.
    unsafe {
        args.pReserved = ptr::dangling_mut();
        assert_eq!(C_Initialize((&raw mut args).cast()), CKR_ARGUMENTS_BAD);
        args.pReserved = ptr::null_mut();
        args.flags = CKF_OS_LOCKING_OK;
        assert_eq!(C_Initialize((&raw mut args).cast()), CKR_OK);
        assert_eq!(
            C_Initialize(ptr::null_mut()),
            CKR_CRYPTOKI_ALREADY_INITIALIZED
        );
        assert_eq!(C_Finalize(ptr::dangling_mut()), CKR_ARGUMENTS_BAD);
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_CRYPTOKI_NOT_INITIALIZED);
    }
    drop(s);
}

#[test]
fn calls_before_initialize_fail_cleanly() {
    let _s = Session::new();
    let mut count: CK_ULONG = 0;
    // SAFETY: pointers are to live locals.
    unsafe {
        assert_eq!(
            C_GetSlotList(1, ptr::null_mut(), &raw mut count),
            CKR_CRYPTOKI_NOT_INITIALIZED
        );
        assert_eq!(C_CloseSession(1), CKR_CRYPTOKI_NOT_INITIALIZED);
        assert_eq!(
            C_GetSlotInfo(0, ptr::null_mut()),
            CKR_CRYPTOKI_NOT_INITIALIZED
        );
    }
}

#[test]
fn list_outputs_respect_the_callers_sizes() {
    let s = Session::new();
    let _ = s.open();
    let mut count: CK_ULONG = 0;
    let mut slot: CK_SLOT_ID = 0;
    let mut mechs = [0 as CK_MECHANISM_TYPE; 5];
    // SAFETY: pointers are to live locals; the sizes passed are the real ones.
    unsafe {
        assert_eq!(
            C_GetSlotList(1, ptr::null_mut(), ptr::null_mut()),
            CKR_ARGUMENTS_BAD
        );
        // Room for zero slots: too small, and the count is reported.
        assert_eq!(
            C_GetSlotList(1, &raw mut slot, &raw mut count),
            CKR_BUFFER_TOO_SMALL
        );
        assert_eq!(count, 1);
        assert_eq!(
            C_GetMechanismList(7, mechs.as_mut_ptr(), &raw mut count),
            CKR_SLOT_ID_INVALID
        );
        count = 5;
        assert_eq!(
            C_GetMechanismList(0, mechs.as_mut_ptr(), &raw mut count),
            CKR_OK
        );
        assert_eq!(count, 4);
        assert_eq!(mechs[0], CKM_ECDSA);
        assert_eq!(mechs[4], 0, "nothing written past the count");
        let mut info = std::mem::MaybeUninit::<CK_MECHANISM_INFO>::zeroed();
        assert_eq!(
            C_GetMechanismInfo(0, CKM_RSA_PKCS, info.as_mut_ptr()),
            CKR_MECHANISM_INVALID
        );
        assert_eq!(
            C_GetMechanismInfo(0, CKM_ECDSA, ptr::null_mut()),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(C_GetMechanismInfo(0, CKM_ECDSA, info.as_mut_ptr()), CKR_OK);
        let mut token = std::mem::MaybeUninit::<CK_TOKEN_INFO>::zeroed();
        assert_eq!(C_GetTokenInfo(0, token.as_mut_ptr()), CKR_OK);
        assert_eq!(C_GetTokenInfo(0, ptr::null_mut()), CKR_ARGUMENTS_BAD);
        let mut slot_info = std::mem::MaybeUninit::<CK_SLOT_INFO>::zeroed();
        assert_eq!(C_GetSlotInfo(0, slot_info.as_mut_ptr()), CKR_OK);
    }
}

#[test]
fn sessions_open_flags_and_pointers() {
    let s = Session::new();
    let session = s.open();
    let mut out_session: CK_SESSION_HANDLE = 0;
    // SAFETY: pointers are to live locals.
    unsafe {
        assert_eq!(
            C_OpenSession(0, 0, ptr::null_mut(), None, &raw mut out_session),
            CKR_SESSION_PARALLEL_NOT_SUPPORTED
        );
        assert_eq!(
            C_OpenSession(
                0,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                ptr::null_mut(),
                None,
                &raw mut out_session
            ),
            CKR_TOKEN_WRITE_PROTECTED
        );
        assert_eq!(
            C_OpenSession(
                0,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                ptr::null_mut()
            ),
            CKR_ARGUMENTS_BAD
        );
        let mut info = std::mem::MaybeUninit::<CK_SESSION_INFO>::zeroed();
        assert_eq!(C_GetSessionInfo(session, info.as_mut_ptr()), CKR_OK);
        assert_eq!(
            C_GetSessionInfo(session, ptr::null_mut()),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(C_CloseSession(session), CKR_OK);
        assert_eq!(C_CloseSession(session), CKR_SESSION_HANDLE_INVALID);
        assert_eq!(C_CloseAllSessions(0), CKR_OK);
    }
}

/// Finds the certificate object; returns its handle.
unsafe fn find_certificate(session: CK_SESSION_HANDLE) -> CK_OBJECT_HANDLE {
    let mut class = CKO_CERTIFICATE;
    let mut template = [attr(
        CKA_CLASS,
        (&raw mut class).cast(),
        size_of::<CK_ULONG>() as CK_ULONG,
    )];
    let mut handles = [0 as CK_OBJECT_HANDLE; 4];
    let mut found: CK_ULONG = 0;
    // SAFETY: caller's promise plus live locals.
    unsafe {
        assert_eq!(C_FindObjectsInit(session, template.as_mut_ptr(), 1), CKR_OK);
        assert_eq!(
            C_FindObjects(session, handles.as_mut_ptr(), 4, &raw mut found),
            CKR_OK
        );
        assert_eq!(C_FindObjectsFinal(session), CKR_OK);
    }
    assert_eq!(found, 1);
    handles[0]
}

#[test]
fn search_templates_are_checked() {
    let s = Session::new();
    let session = s.open();
    let mut byte = 0_u8;
    let mut handles = [0 as CK_OBJECT_HANDLE; 2];
    let mut found: CK_ULONG = 5;
    // SAFETY: pointers are to live locals, or deliberately NULL with sizes that promise nothing.
    unsafe {
        assert_eq!(
            C_FindObjectsInit(session, ptr::null_mut(), 1),
            CKR_ARGUMENTS_BAD
        );
        let mut many = [attr(CKA_CLASS, ptr::null_mut(), 0); 65];
        assert_eq!(
            C_FindObjectsInit(session, many.as_mut_ptr(), 65),
            CKR_ARGUMENTS_BAD
        );
        let mut big = [attr(CKA_LABEL, (&raw mut byte).cast(), 1 << 20)];
        assert_eq!(
            C_FindObjectsInit(session, big.as_mut_ptr(), 1),
            CKR_ARGUMENTS_BAD
        );
        let mut null_value = [attr(CKA_LABEL, ptr::null_mut(), 3)];
        assert_eq!(
            C_FindObjectsInit(session, null_value.as_mut_ptr(), 1),
            CKR_ARGUMENTS_BAD
        );
        // An empty template matches everything; a zero-length value needs no pointer.
        let mut empty = [attr(CKA_LABEL, ptr::null_mut(), 0)];
        assert_eq!(C_FindObjectsInit(session, empty.as_mut_ptr(), 1), CKR_OK);
        assert_eq!(
            C_FindObjects(session, ptr::null_mut(), 1, &raw mut found),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(
            C_FindObjects(session, handles.as_mut_ptr(), 2, ptr::null_mut()),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(
            C_FindObjects(session, ptr::null_mut(), 0, &raw mut found),
            CKR_OK
        );
        assert_eq!(
            C_FindObjects(session, handles.as_mut_ptr(), 2, &raw mut found),
            CKR_OK
        );
        assert!(found <= 2);
        assert_eq!(C_FindObjectsFinal(session), CKR_OK);
        assert_eq!(C_FindObjectsFinal(session), CKR_OPERATION_NOT_INITIALIZED);
    }
}

#[test]
fn attribute_reads_never_write_past_the_callers_buffer() {
    let s = Session::new();
    let session = s.open();
    // SAFETY: pointers are to live locals; each buffer is at least as large as it claims.
    unsafe {
        let cert = find_certificate(session);
        // Length query.
        let mut q = [attr(CKA_VALUE, ptr::null_mut(), 0)];
        assert_eq!(
            C_GetAttributeValue(session, cert, q.as_mut_ptr(), 1),
            CKR_OK
        );
        assert_eq!(usize::try_from(q[0].ulValueLen), Ok(EC_CERT.len()));
        // Too small: marked unavailable, nothing written (guard bytes stay).
        let mut buf = vec![0xAA_u8; EC_CERT.len() + 8];
        let mut small = [attr(
            CKA_VALUE,
            buf.as_mut_ptr().cast(),
            (EC_CERT.len() - 1) as CK_ULONG,
        )];
        assert_eq!(
            C_GetAttributeValue(session, cert, small.as_mut_ptr(), 1),
            CKR_BUFFER_TOO_SMALL
        );
        assert_eq!(small[0].ulValueLen, CK_UNAVAILABLE_INFORMATION);
        assert!(buf.iter().all(|b| *b == 0xAA));
        // Exact fit.
        let mut fit = [attr(
            CKA_VALUE,
            buf.as_mut_ptr().cast(),
            EC_CERT.len() as CK_ULONG,
        )];
        assert_eq!(
            C_GetAttributeValue(session, cert, fit.as_mut_ptr(), 1),
            CKR_OK
        );
        assert_eq!(&buf[..EC_CERT.len()], EC_CERT);
        assert!(buf[EC_CERT.len()..].iter().all(|b| *b == 0xAA));
        // Unknown attribute type, next to a good one: the good one is still filled in.
        let mut mixed = [
            attr(0xdead_beef, ptr::null_mut(), 0),
            attr(CKA_VALUE, ptr::null_mut(), 0),
        ];
        assert_eq!(
            C_GetAttributeValue(session, cert, mixed.as_mut_ptr(), 2),
            CKR_ATTRIBUTE_TYPE_INVALID
        );
        assert_eq!(mixed[0].ulValueLen, CK_UNAVAILABLE_INFORMATION);
        assert_eq!(usize::try_from(mixed[1].ulValueLen), Ok(EC_CERT.len()));
        // Bad counts and pointers.
        assert_eq!(
            C_GetAttributeValue(session, cert, ptr::null_mut(), 1),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(
            C_GetAttributeValue(session, cert, ptr::null_mut(), 0),
            CKR_OK
        );
        assert_eq!(
            C_GetAttributeValue(session, cert, q.as_mut_ptr(), 65),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(
            C_GetAttributeValue(session, 77, q.as_mut_ptr(), 1),
            CKR_OBJECT_HANDLE_INVALID
        );
    }
}

fn mechanism(type_: CK_MECHANISM_TYPE, parameter: *mut c_void, len: CK_ULONG) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: type_,
        pParameter: parameter,
        ulParameterLen: len,
    }
}

#[test]
// One straight script of calls; splitting it would hide the order that matters.
#[allow(clippy::too_many_lines)]
fn sign_checks_mechanisms_and_buffers() {
    let s = Session::new();
    let session = s.open();
    let mut byte = 0_u8;
    let data = [1_u8, 2, 3];
    let mut sig = [0xAA_u8; 70];
    let mut sig_len: CK_ULONG = 70;
    // SAFETY: pointers are to live locals; sizes passed are the real ones.
    unsafe {
        assert_eq!(C_SignInit(session, ptr::null_mut(), 2), CKR_ARGUMENTS_BAD);
        let mut m = mechanism(CKM_RSA_PKCS_PSS, ptr::null_mut(), 0);
        assert_eq!(
            C_SignInit(session, &raw mut m, 2),
            CKR_MECHANISM_PARAM_INVALID
        );
        // Right length but misaligned parameter pointer.
        let mut raw = [0_u8; size_of::<CK_RSA_PKCS_PSS_PARAMS>() + 1];
        m = mechanism(
            CKM_RSA_PKCS_PSS,
            raw.as_mut_ptr().add(1).cast(),
            size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
        );
        let rv = C_SignInit(session, &raw mut m, 2);
        assert!(
            rv == CKR_MECHANISM_PARAM_INVALID || rv == CKR_MECHANISM_INVALID,
            "{rv:#x}"
        );
        m = mechanism(CKM_ECDSA, (&raw mut byte).cast(), 1);
        assert_eq!(
            C_SignInit(session, &raw mut m, 2),
            CKR_MECHANISM_PARAM_INVALID
        );
        m = mechanism(0x1234_5678, ptr::null_mut(), 0);
        assert_eq!(C_SignInit(session, &raw mut m, 2), CKR_MECHANISM_INVALID);

        m = mechanism(CKM_ECDSA, ptr::null_mut(), 0);
        assert_eq!(C_SignInit(session, &raw mut m, 2), CKR_OK);
        assert_eq!(
            C_Sign(
                session,
                data.as_ptr().cast_mut(),
                3,
                sig.as_mut_ptr(),
                ptr::null_mut()
            ),
            CKR_ARGUMENTS_BAD
        );
        // Null data with a nonzero length is refused, and the operation survives.
        assert_eq!(
            C_Sign(
                session,
                ptr::null_mut(),
                3,
                sig.as_mut_ptr(),
                &raw mut sig_len
            ),
            CKR_ARGUMENTS_BAD
        );
        sig_len = 0;
        assert_eq!(
            C_Sign(
                session,
                data.as_ptr().cast_mut(),
                3,
                ptr::null_mut(),
                &raw mut sig_len
            ),
            CKR_OK
        );
        assert_eq!(sig_len, 64);
        sig_len = 10;
        assert_eq!(
            C_Sign(
                session,
                data.as_ptr().cast_mut(),
                3,
                sig.as_mut_ptr(),
                &raw mut sig_len
            ),
            CKR_BUFFER_TOO_SMALL
        );
        assert_eq!(sig_len, 64);
        assert!(sig.iter().all(|b| *b == 0xAA));
        sig_len = 64;
        assert_eq!(
            C_Sign(
                session,
                data.as_ptr().cast_mut(),
                3,
                sig.as_mut_ptr(),
                &raw mut sig_len
            ),
            CKR_OK
        );
        assert_eq!(&sig[..64], &[7; 64][..]);
        assert!(sig[64..].iter().all(|b| *b == 0xAA));
        assert_eq!(
            C_Sign(
                session,
                data.as_ptr().cast_mut(),
                3,
                sig.as_mut_ptr(),
                &raw mut sig_len
            ),
            CKR_OPERATION_NOT_INITIALIZED
        );
        // Absurd lengths are refused before any slice is made.
        assert_eq!(C_SignInit(session, &raw mut m, 2), CKR_OK);
        sig_len = 64;
        assert_eq!(
            C_Sign(
                session,
                data.as_ptr().cast_mut(),
                CK_ULONG::MAX,
                sig.as_mut_ptr(),
                &raw mut sig_len
            ),
            CKR_ARGUMENTS_BAD
        );
    }
}

#[test]
fn helpers_handle_edge_cases() {
    // SAFETY: only zero-length or NULL cases, plus live locals.
    unsafe {
        assert_eq!(input(ptr::null(), 0), Ok(&[][..]));
        assert_eq!(input(ptr::null(), 1), Err(CKR_ARGUMENTS_BAD));
        let b = [1_u8, 2];
        assert_eq!(input(b.as_ptr(), CK_ULONG::MAX), Err(CKR_ARGUMENTS_BAD));
        assert_eq!(input(b.as_ptr(), 2), Ok(&b[..]));
        assert!(out::<u8>(ptr::null_mut()).is_err());
        assert_eq!(template(ptr::null_mut(), 0), Ok(Vec::new()));
    }
    assert_eq!(&padded::<4>("ab"), b"ab  ");
    assert_eq!(&padded::<2>("abcd"), b"ab");
}
