//! The C side: raw pointers in, `CK_RV` out. Every function checks its pointers, converts them
//! to safe values and calls [`Module`]; a panic is caught here and becomes `CKR_GENERAL_ERROR`,
//! because unwinding into C is undefined behaviour.
// PKCS#11 names its functions and fields in camel case with underscores.
#![allow(non_snake_case)]

use std::cell::RefCell;
use std::ptr;
use std::sync::Once;

use cryptoki_sys::{
    CK_ATTRIBUTE_PTR, CK_C_INITIALIZE_ARGS, CK_FLAGS, CK_FUNCTION_LIST, CK_FUNCTION_LIST_PTR_PTR,
    CK_INFO, CK_INFO_PTR, CK_MECHANISM_INFO, CK_MECHANISM_INFO_PTR, CK_MECHANISM_TYPE,
    CK_OBJECT_HANDLE, CK_OBJECT_HANDLE_PTR, CK_RV, CK_SESSION_HANDLE, CK_SESSION_HANDLE_PTR,
    CK_SESSION_INFO, CK_SESSION_INFO_PTR, CK_SLOT_ID, CK_SLOT_ID_PTR, CK_SLOT_INFO,
    CK_SLOT_INFO_PTR, CK_TOKEN_INFO, CK_TOKEN_INFO_PTR, CK_ULONG, CK_ULONG_PTR,
    CK_UNAVAILABLE_INFORMATION, CK_VERSION, CK_VOID_PTR, CKF_OS_LOCKING_OK, CKF_RW_SESSION,
    CKF_SERIAL_SESSION, CKF_TOKEN_INITIALIZED, CKF_TOKEN_PRESENT, CKF_WRITE_PROTECTED,
    CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CANT_LOCK, CKR_MECHANISM_INVALID,
    CKR_SESSION_PARALLEL_NOT_SUPPORTED, CKR_TOKEN_WRITE_PROTECTED, CKS_RO_PUBLIC_SESSION,
};

// What the tests reach through `use super::*`.
#[cfg(test)]
use cryptoki_sys::{
    CK_MECHANISM, CK_RSA_PKCS_PSS_PARAMS, CKM_ECDSA, CKM_RSA_PKCS, CKM_RSA_PKCS_PSS,
    CKR_MECHANISM_PARAM_INVALID,
};

mod args;
#[cfg(feature = "fuzzing")]
pub mod fuzzing;
mod login;
mod sign;

#[cfg(not(any(test, feature = "fuzzing")))]
use crate::backend::DbusBackend;
use crate::module::{ForkGuard, Module, mechanism_info, mechanisms};
use crate::unsupported;
#[cfg(test)]
use args::input;
use args::{guard, out, padded, template, to_ulong, to_usize, write_list};
use login::{C_Login, C_Logout};
use sign::{C_Sign, C_SignFinal, C_SignInit, C_SignUpdate};

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
        let (bits, flags) = mechanism_info(&token, mechanism).ok_or(CKR_MECHANISM_INVALID)?;
        // SAFETY: checked for null; validity is the caller's promise.
        let info = unsafe { out(info) }?;
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
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),
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
    C_SignUpdate: Some(C_SignUpdate),
    C_SignFinal: Some(C_SignFinal),
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
mod tests;
