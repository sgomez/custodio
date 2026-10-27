//! The C side: raw pointers in, `CK_RV` out. Every function checks its pointers, converts them
//! to safe values and calls [`Module`]; a panic is caught here and becomes `CKR_GENERAL_ERROR`,
//! because unwinding into C is undefined behaviour.
// PKCS#11 names its functions and fields in camel case with underscores.
#![allow(non_snake_case)]

use std::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::Once;

use cryptoki_sys::{
    CK_ATTRIBUTE_PTR, CK_BYTE_PTR, CK_C_INITIALIZE_ARGS, CK_FLAGS, CK_FUNCTION_LIST,
    CK_FUNCTION_LIST_PTR_PTR, CK_INFO, CK_INFO_PTR, CK_MECHANISM, CK_MECHANISM_INFO,
    CK_MECHANISM_INFO_PTR, CK_MECHANISM_PTR, CK_MECHANISM_TYPE, CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE_PTR, CK_RSA_PKCS_PSS_PARAMS, CK_RV, CK_SESSION_HANDLE, CK_SESSION_HANDLE_PTR,
    CK_SESSION_INFO, CK_SESSION_INFO_PTR, CK_SLOT_ID, CK_SLOT_ID_PTR, CK_SLOT_INFO,
    CK_SLOT_INFO_PTR, CK_TOKEN_INFO, CK_TOKEN_INFO_PTR, CK_ULONG, CK_ULONG_PTR,
    CK_UNAVAILABLE_INFORMATION, CK_VERSION, CK_VOID_PTR, CKF_EC_F_P, CKF_EC_NAMEDCURVE,
    CKF_OS_LOCKING_OK, CKF_RW_SESSION, CKF_SERIAL_SESSION, CKF_SIGN, CKF_TOKEN_INITIALIZED,
    CKF_TOKEN_PRESENT, CKF_WRITE_PROTECTED, CKM_ECDSA, CKM_RSA_PKCS, CKM_RSA_PKCS_PSS,
    CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CANT_LOCK, CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_SESSION_PARALLEL_NOT_SUPPORTED,
    CKR_TOKEN_WRITE_PROTECTED, CKS_RO_PUBLIC_SESSION,
};

#[cfg(feature = "fuzzing")]
pub mod fuzzing;

#[cfg(not(any(test, feature = "fuzzing")))]
use crate::backend::DbusBackend;
use crate::module::{ForkGuard, Mechanism, Module, SignOutcome, mechanisms};
use crate::token::Attribute;
use crate::unsupported;

/// The service behind the global module. Tests (and Miri, which cannot talk to a bus) and the fuzz
/// target use a fake.
#[cfg(not(any(test, feature = "fuzzing")))]
type ActiveBackend = DbusBackend;
#[cfg(not(any(test, feature = "fuzzing")))]
const BACKEND: ActiveBackend = DbusBackend;
#[cfg(any(test, feature = "fuzzing"))]
type ActiveBackend = crate::fake::FakeBackend;
#[cfg(any(test, feature = "fuzzing"))]
const BACKEND: ActiveBackend = crate::fake::FakeBackend;

static MODULE: Module<ActiveBackend> = Module::new(BACKEND);

const MANUFACTURER: &str = "Custodio";
const SERIAL_LEN: usize = 16;
/// Search templates and attribute lists above this size are refused rather than allocated.
const MAX_ATTRIBUTES: usize = 64;
/// Largest value of a search template attribute.
const MAX_ATTRIBUTE_LEN: usize = 16 * 1024;

type Rv<T> = Result<T, CK_RV>;

fn guard(f: impl FnOnce() -> Rv<()>) -> CK_RV {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => CKR_OK,
        Ok(Err(rv)) => rv,
        Err(_) => CKR_GENERAL_ERROR,
    }
}

fn to_usize(v: CK_ULONG) -> Rv<usize> {
    usize::try_from(v).map_err(|_| CKR_ARGUMENTS_BAD)
}

fn to_ulong(v: usize) -> Rv<CK_ULONG> {
    CK_ULONG::try_from(v).map_err(|_| CKR_GENERAL_ERROR)
}

fn padded<const N: usize>(text: &str) -> [u8; N] {
    let mut out = [b' '; N];
    for (dst, src) in out.iter_mut().zip(text.bytes()) {
        *dst = src;
    }
    out
}

/// A non-null pointer to write one value through.
unsafe fn out<'a, T>(p: *mut T) -> Rv<&'a mut T> {
    // SAFETY: the caller promises that a non-null `p` is valid for writes of `T`.
    unsafe { p.as_mut() }.ok_or(CKR_ARGUMENTS_BAD)
}

/// `len` bytes at `p`; an empty slice for `len == 0` whatever `p` is.
unsafe fn input<'a>(p: *const u8, len: CK_ULONG) -> Rv<&'a [u8]> {
    let len = to_usize(len)?;
    if len == 0 {
        return Ok(&[]);
    }
    if p.is_null() || isize::try_from(len).is_err() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    // SAFETY: non-null, and the caller promises `len` readable bytes at `p`.
    Ok(unsafe { std::slice::from_raw_parts(p, len) })
}

/// The usual two-call output of a list: `dst` null asks for the count.
unsafe fn write_list<T: Copy>(items: &[T], dst: *mut T, count: CK_ULONG_PTR) -> Rv<()> {
    // SAFETY: `count` is checked for null; validity is the caller's promise.
    let count = unsafe { out(count) }?;
    let needed = to_ulong(items.len())?;
    if dst.is_null() {
        *count = needed;
        return Ok(());
    }
    let room = *count;
    *count = needed;
    if room < needed {
        return Err(CKR_BUFFER_TOO_SMALL);
    }
    // SAFETY: `dst` is non-null and the caller promises room for `room >= needed` items.
    unsafe { ptr::copy_nonoverlapping(items.as_ptr(), dst, items.len()) };
    Ok(())
}

unsafe fn template(attrs: CK_ATTRIBUTE_PTR, count: CK_ULONG) -> Rv<Vec<Attribute>> {
    let count = to_usize(count)?;
    if count == 0 {
        return Ok(Vec::new());
    }
    if attrs.is_null() || count > MAX_ATTRIBUTES {
        return Err(CKR_ARGUMENTS_BAD);
    }
    // SAFETY: non-null, and the caller promises `count` attributes.
    let attrs = unsafe { std::slice::from_raw_parts(attrs, count) };
    attrs
        .iter()
        .map(|a| {
            if to_usize(a.ulValueLen)? > MAX_ATTRIBUTE_LEN {
                return Err(CKR_ARGUMENTS_BAD);
            }
            // SAFETY: the caller promises `ulValueLen` readable bytes at `pValue`.
            let value = unsafe { input(a.pValue.cast::<u8>(), a.ulValueLen) }?;
            Ok((a.type_, value.to_vec()))
        })
        .collect()
}

// Fork safety. The state lock is held by the forking thread from `prepare` until `parent` or
// `child` runs, so the child never inherits it locked by a thread that no longer exists. The
// module keeps no connection or thread between calls, so nothing else needs repair.
thread_local! {
    static FORK_GUARD: RefCell<Option<ForkGuard<'static>>> = const { RefCell::new(None) };
}

extern "C" fn fork_prepare() {
    let guard = MODULE.lock_for_fork();
    let _ = FORK_GUARD.try_with(|slot| *slot.borrow_mut() = Some(guard));
}

extern "C" fn fork_release() {
    let _ = FORK_GUARD.try_with(|slot| slot.borrow_mut().take());
}

fn register_fork_handlers() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: the three handlers are plain `extern "C"` functions that live for the whole
        // process. A failure only means no handlers, which is the state before this call.
        unsafe {
            libc::pthread_atfork(Some(fork_prepare), Some(fork_release), Some(fork_release));
        }
    });
}

unsafe extern "C" fn C_Initialize(args: CK_VOID_PTR) -> CK_RV {
    guard(|| {
        if !args.is_null() {
            // SAFETY: the caller passes a `CK_C_INITIALIZE_ARGS` or NULL.
            let args = unsafe { &*args.cast::<CK_C_INITIALIZE_ARGS>() };
            let callbacks = [
                args.CreateMutex.is_some(),
                args.DestroyMutex.is_some(),
                args.LockMutex.is_some(),
                args.UnlockMutex.is_some(),
            ];
            if !args.pReserved.is_null() {
                return Err(CKR_ARGUMENTS_BAD);
            }
            // Our own locking is always on; custom mutex callbacks are not used, and a caller
            // that insists on them (without allowing OS locking) is told so.
            let all = callbacks.iter().all(|c| *c);
            let none = callbacks.iter().all(|c| !*c);
            if !all && !none {
                return Err(CKR_ARGUMENTS_BAD);
            }
            if all && args.flags & CKF_OS_LOCKING_OK == 0 {
                return Err(CKR_CANT_LOCK);
            }
        }
        register_fork_handlers();
        MODULE.initialize()
    })
}

unsafe extern "C" fn C_Finalize(reserved: CK_VOID_PTR) -> CK_RV {
    guard(|| {
        if !reserved.is_null() {
            return Err(CKR_ARGUMENTS_BAD);
        }
        MODULE.finalize()
    })
}

unsafe extern "C" fn C_GetInfo(info: CK_INFO_PTR) -> CK_RV {
    guard(|| {
        // SAFETY: checked for null; validity is the caller's promise.
        let info = unsafe { out(info) }?;
        *info = CK_INFO {
            cryptokiVersion: CK_VERSION {
                major: 2,
                minor: 40,
            },
            manufacturerID: padded(MANUFACTURER),
            flags: 0,
            libraryDescription: padded("Custodio PKCS#11 module"),
            libraryVersion: CK_VERSION { major: 0, minor: 1 },
        };
        Ok(())
    })
}

/// The only exported symbol: the entry point every PKCS#11 loader looks for.
///
/// # Safety
/// `list` must be NULL or valid for a write of one pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(list: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    guard(|| {
        // SAFETY: checked for null; validity is the caller's promise.
        let list = unsafe { out(list) }?;
        *list = ptr::from_ref(&FUNCTION_LIST).cast_mut();
        Ok(())
    })
}

unsafe extern "C" fn C_GetSlotList(
    _token_present: u8,
    list: CK_SLOT_ID_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    // Every slot holds a token, so `token_present` does not change the answer.
    guard(|| {
        let slots = MODULE.slot_list()?;
        // SAFETY: pointers are checked inside; validity is the caller's promise.
        unsafe { write_list(&slots, list, count) }
    })
}

unsafe extern "C" fn C_GetSlotInfo(slot: CK_SLOT_ID, info: CK_SLOT_INFO_PTR) -> CK_RV {
    guard(|| {
        let token = MODULE.token(slot)?;
        // SAFETY: checked for null; validity is the caller's promise.
        let info = unsafe { out(info) }?;
        *info = CK_SLOT_INFO {
            slotDescription: padded(&format!("Custodio key {}", token.id)),
            manufacturerID: padded(MANUFACTURER),
            flags: CKF_TOKEN_PRESENT,
            hardwareVersion: CK_VERSION { major: 0, minor: 0 },
            firmwareVersion: CK_VERSION { major: 0, minor: 0 },
        };
        Ok(())
    })
}

/// A serial number that tells tokens apart: FNV-1a of the key id, in hex.
fn serial(id: &str) -> [u8; SERIAL_LEN] {
    let hash = id.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    });
    padded(&format!("{hash:016x}"))
}

unsafe extern "C" fn C_GetTokenInfo(slot: CK_SLOT_ID, info: CK_TOKEN_INFO_PTR) -> CK_RV {
    guard(|| {
        let token = MODULE.token(slot)?;
        // SAFETY: checked for null; validity is the caller's promise.
        let info = unsafe { out(info) }?;
        let unavailable = CK_UNAVAILABLE_INFORMATION;
        *info = CK_TOKEN_INFO {
            label: padded(&token.id),
            manufacturerID: padded(MANUFACTURER),
            model: padded("Custodio key"),
            serialNumber: serial(&token.id),
            flags: CKF_TOKEN_INITIALIZED | CKF_WRITE_PROTECTED,
            ulMaxSessionCount: unavailable,
            ulSessionCount: unavailable,
            ulMaxRwSessionCount: 0,
            ulRwSessionCount: 0,
            ulMaxPinLen: 0,
            ulMinPinLen: 0,
            ulTotalPublicMemory: unavailable,
            ulFreePublicMemory: unavailable,
            ulTotalPrivateMemory: unavailable,
            ulFreePrivateMemory: unavailable,
            hardwareVersion: CK_VERSION { major: 0, minor: 0 },
            firmwareVersion: CK_VERSION { major: 0, minor: 0 },
            utcTime: [b' '; 16],
        };
        Ok(())
    })
}

unsafe extern "C" fn C_GetMechanismList(
    slot: CK_SLOT_ID,
    list: *mut CK_MECHANISM_TYPE,
    count: CK_ULONG_PTR,
) -> CK_RV {
    guard(|| {
        let mechs = mechanisms(&*MODULE.token(slot)?);
        // SAFETY: pointers are checked inside; validity is the caller's promise.
        unsafe { write_list(&mechs, list, count) }
    })
}

unsafe extern "C" fn C_GetMechanismInfo(
    slot: CK_SLOT_ID,
    mechanism: CK_MECHANISM_TYPE,
    info: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    guard(|| {
        let token = MODULE.token(slot)?;
        if !mechanisms(&token).contains(&mechanism) {
            return Err(CKR_MECHANISM_INVALID);
        }
        // SAFETY: checked for null; validity is the caller's promise.
        let info = unsafe { out(info) }?;
        let (bits, flags) = match mechanism {
            CKM_ECDSA => (256, CKF_SIGN | CKF_EC_F_P | CKF_EC_NAMEDCURVE),
            _ => (2048, CKF_SIGN),
        };
        *info = CK_MECHANISM_INFO {
            ulMinKeySize: bits,
            ulMaxKeySize: bits,
            flags,
        };
        Ok(())
    })
}

unsafe extern "C" fn C_OpenSession(
    slot: CK_SLOT_ID,
    flags: CK_FLAGS,
    _application: CK_VOID_PTR,
    _notify: cryptoki_sys::CK_NOTIFY,
    session: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    guard(|| {
        if flags & CKF_SERIAL_SESSION == 0 {
            return Err(CKR_SESSION_PARALLEL_NOT_SUPPORTED);
        }
        if flags & CKF_RW_SESSION != 0 {
            return Err(CKR_TOKEN_WRITE_PROTECTED);
        }
        // SAFETY: checked for null; validity is the caller's promise.
        let session = unsafe { out(session) }?;
        *session = MODULE.open_session(slot)?;
        Ok(())
    })
}

unsafe extern "C" fn C_CloseSession(session: CK_SESSION_HANDLE) -> CK_RV {
    guard(|| MODULE.close_session(session))
}

unsafe extern "C" fn C_CloseAllSessions(slot: CK_SLOT_ID) -> CK_RV {
    guard(|| MODULE.close_all_sessions(slot))
}

unsafe extern "C" fn C_GetSessionInfo(
    session: CK_SESSION_HANDLE,
    info: CK_SESSION_INFO_PTR,
) -> CK_RV {
    guard(|| {
        let slot = MODULE.session_slot(session)?;
        // SAFETY: checked for null; validity is the caller's promise.
        let info = unsafe { out(info) }?;
        *info = CK_SESSION_INFO {
            slotID: slot,
            state: CKS_RO_PUBLIC_SESSION,
            flags: CKF_SERIAL_SESSION,
            ulDeviceError: 0,
        };
        Ok(())
    })
}

unsafe extern "C" fn C_GetAttributeValue(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    attrs: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    guard(|| {
        let known = MODULE.object(session, object)?;
        let count = to_usize(count)?;
        if count == 0 {
            return Ok(());
        }
        if attrs.is_null() || count > MAX_ATTRIBUTES {
            return Err(CKR_ARGUMENTS_BAD);
        }
        // SAFETY: non-null, and the caller promises `count` attributes it lets us write.
        let attrs = unsafe { std::slice::from_raw_parts_mut(attrs, count) };
        let mut result = Ok(());
        for attr in attrs {
            let Some((_, value)) = known.iter().find(|(t, _)| *t == attr.type_) else {
                attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                result = result.and(Err(Module::<ActiveBackend>::missing_attribute(
                    object, attr.type_,
                )));
                continue;
            };
            let len = to_ulong(value.len())?;
            if attr.pValue.is_null() {
                attr.ulValueLen = len;
            } else if attr.ulValueLen < len {
                attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                result = result.and(Err(CKR_BUFFER_TOO_SMALL));
            } else {
                // SAFETY: `pValue` has room for `ulValueLen >= len` bytes, by the caller's promise.
                unsafe {
                    ptr::copy_nonoverlapping(value.as_ptr(), attr.pValue.cast::<u8>(), value.len());
                }
                attr.ulValueLen = len;
            }
        }
        result
    })
}

unsafe extern "C" fn C_FindObjectsInit(
    session: CK_SESSION_HANDLE,
    attrs: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    guard(|| {
        // SAFETY: pointers are checked inside; validity is the caller's promise.
        let template = unsafe { template(attrs, count) }?;
        MODULE.find_init(session, &template)
    })
}

unsafe extern "C" fn C_FindObjects(
    session: CK_SESSION_HANDLE,
    objects: CK_OBJECT_HANDLE_PTR,
    max: CK_ULONG,
    found: CK_ULONG_PTR,
) -> CK_RV {
    guard(|| {
        // SAFETY: checked for null; validity is the caller's promise.
        let found = unsafe { out(found) }?;
        let max = to_usize(max)?;
        if objects.is_null() && max > 0 {
            return Err(CKR_ARGUMENTS_BAD);
        }
        let handles = MODULE.find(session, max)?;
        for (i, handle) in handles.iter().enumerate() {
            // SAFETY: at most `max` handles, and the caller promises room for `max`.
            unsafe { objects.add(i).write(*handle) };
        }
        *found = to_ulong(handles.len())?;
        Ok(())
    })
}

unsafe extern "C" fn C_FindObjectsFinal(session: CK_SESSION_HANDLE) -> CK_RV {
    guard(|| MODULE.find_final(session))
}

unsafe extern "C" fn C_SignInit(
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
        } else if m.mechanism == CKM_RSA_PKCS || m.mechanism == CKM_ECDSA {
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

unsafe extern "C" fn C_Sign(
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

/// The function list: the calls above, and `CKR_FUNCTION_NOT_SUPPORTED` for every other entry.
static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION {
        major: 2,
        minor: 40,
    },
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: Some(C_GetMechanismInfo),
    C_InitToken: Some(unsupported::InitToken),
    C_InitPIN: Some(unsupported::InitPIN),
    C_SetPIN: Some(unsupported::SetPIN),
    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_CloseAllSessions: Some(C_CloseAllSessions),
    C_GetSessionInfo: Some(C_GetSessionInfo),
    C_GetOperationState: Some(unsupported::GetOperationState),
    C_SetOperationState: Some(unsupported::SetOperationState),
    C_Login: Some(unsupported::Login),
    C_Logout: Some(unsupported::Logout),
    C_CreateObject: Some(unsupported::CreateObject),
    C_CopyObject: Some(unsupported::CopyObject),
    C_DestroyObject: Some(unsupported::DestroyObject),
    C_GetObjectSize: Some(unsupported::GetObjectSize),
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_SetAttributeValue: Some(unsupported::SetAttributeValue),
    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),
    C_EncryptInit: Some(unsupported::EncryptInit),
    C_Encrypt: Some(unsupported::Encrypt),
    C_EncryptUpdate: Some(unsupported::EncryptUpdate),
    C_EncryptFinal: Some(unsupported::EncryptFinal),
    C_DecryptInit: Some(unsupported::DecryptInit),
    C_Decrypt: Some(unsupported::Decrypt),
    C_DecryptUpdate: Some(unsupported::DecryptUpdate),
    C_DecryptFinal: Some(unsupported::DecryptFinal),
    C_DigestInit: Some(unsupported::DigestInit),
    C_Digest: Some(unsupported::Digest),
    C_DigestUpdate: Some(unsupported::DigestUpdate),
    C_DigestKey: Some(unsupported::DigestKey),
    C_DigestFinal: Some(unsupported::DigestFinal),
    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: Some(unsupported::SignUpdate),
    C_SignFinal: Some(unsupported::SignFinal),
    C_SignRecoverInit: Some(unsupported::SignRecoverInit),
    C_SignRecover: Some(unsupported::SignRecover),
    C_VerifyInit: Some(unsupported::VerifyInit),
    C_Verify: Some(unsupported::Verify),
    C_VerifyUpdate: Some(unsupported::VerifyUpdate),
    C_VerifyFinal: Some(unsupported::VerifyFinal),
    C_VerifyRecoverInit: Some(unsupported::VerifyRecoverInit),
    C_VerifyRecover: Some(unsupported::VerifyRecover),
    C_DigestEncryptUpdate: Some(unsupported::DigestEncryptUpdate),
    C_DecryptDigestUpdate: Some(unsupported::DecryptDigestUpdate),
    C_SignEncryptUpdate: Some(unsupported::SignEncryptUpdate),
    C_DecryptVerifyUpdate: Some(unsupported::DecryptVerifyUpdate),
    C_GenerateKey: Some(unsupported::GenerateKey),
    C_GenerateKeyPair: Some(unsupported::GenerateKeyPair),
    C_WrapKey: Some(unsupported::WrapKey),
    C_UnwrapKey: Some(unsupported::UnwrapKey),
    C_DeriveKey: Some(unsupported::DeriveKey),
    C_SeedRandom: Some(unsupported::SeedRandom),
    C_GenerateRandom: Some(unsupported::GenerateRandom),
    C_GetFunctionStatus: Some(unsupported::GetFunctionStatus),
    C_CancelFunction: Some(unsupported::CancelFunction),
    C_WaitForSlotEvent: Some(unsupported::WaitForSlotEvent),
};

#[cfg(test)]
mod tests {
    //! The C functions called through the function list with hostile arguments, against a fake
    //! service. These run under Miri (`just miri`) and `AddressSanitizer` (`just asan`).
    use std::ffi::c_void;
    use std::sync::{Mutex, MutexGuard, PoisonError};

    use cryptoki_sys::{
        CK_ATTRIBUTE, CKA_CLASS, CKA_LABEL, CKA_VALUE, CKO_CERTIFICATE, CKR_ATTRIBUTE_TYPE_INVALID,
        CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_NOT_SUPPORTED,
        CKR_OBJECT_HANDLE_INVALID, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID,
        CKR_SLOT_ID_INVALID,
    };

    use super::*;

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
                list.C_Login.map(|f| f(0, 0, ptr::null_mut(), 0)),
                Some(CKR_FUNCTION_NOT_SUPPORTED)
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
        let mut mechs = [0 as CK_MECHANISM_TYPE; 4];
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
            count = 4;
            assert_eq!(
                C_GetMechanismList(0, mechs.as_mut_ptr(), &raw mut count),
                CKR_OK
            );
            assert_eq!(count, 1);
            assert_eq!(mechs[0], CKM_ECDSA);
            assert_eq!(mechs[1], 0, "nothing written past the count");
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
}
