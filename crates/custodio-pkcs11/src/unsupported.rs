//! Entries of the function list that this module does not support.
//!
//! Generated from the `CK_C_*` types of `cryptoki-sys`; each one only returns
//! `CKR_FUNCTION_NOT_SUPPORTED`, so a consumer that does not check for NULL entries still works.

// PKCS#11 function names are camel case.
#![allow(non_snake_case)]

use cryptoki_sys::{
    CK_ATTRIBUTE, CK_BYTE, CK_FLAGS, CK_MECHANISM, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE,
    CK_SLOT_ID, CK_ULONG, CK_USER_TYPE, CK_UTF8CHAR, CKR_FUNCTION_NOT_SUPPORTED,
};

pub unsafe extern "C" fn InitToken(
    _: CK_SLOT_ID,
    _: *mut CK_UTF8CHAR,
    _: CK_ULONG,
    _: *mut CK_UTF8CHAR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn InitPIN(_: CK_SESSION_HANDLE, _: *mut CK_UTF8CHAR, _: CK_ULONG) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn SetPIN(
    _: CK_SESSION_HANDLE,
    _: *mut CK_UTF8CHAR,
    _: CK_ULONG,
    _: *mut CK_UTF8CHAR,
    _: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn GetOperationState(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn SetOperationState(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: CK_OBJECT_HANDLE,
    _: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn Login(
    _: CK_SESSION_HANDLE,
    _: CK_USER_TYPE,
    _: *mut CK_UTF8CHAR,
    _: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn Logout(_: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn CreateObject(
    _: CK_SESSION_HANDLE,
    _: *mut CK_ATTRIBUTE,
    _: CK_ULONG,
    _: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn CopyObject(
    _: CK_SESSION_HANDLE,
    _: CK_OBJECT_HANDLE,
    _: *mut CK_ATTRIBUTE,
    _: CK_ULONG,
    _: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn DestroyObject(_: CK_SESSION_HANDLE, _: CK_OBJECT_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn GetObjectSize(
    _: CK_SESSION_HANDLE,
    _: CK_OBJECT_HANDLE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn SetAttributeValue(
    _: CK_SESSION_HANDLE,
    _: CK_OBJECT_HANDLE,
    _: *mut CK_ATTRIBUTE,
    _: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn EncryptInit(
    _: CK_SESSION_HANDLE,
    _: *mut CK_MECHANISM,
    _: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn Encrypt(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn EncryptUpdate(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn EncryptFinal(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn DecryptInit(
    _: CK_SESSION_HANDLE,
    _: *mut CK_MECHANISM,
    _: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn Decrypt(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn DecryptUpdate(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn DecryptFinal(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn DigestInit(_: CK_SESSION_HANDLE, _: *mut CK_MECHANISM) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn Digest(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn DigestUpdate(_: CK_SESSION_HANDLE, _: *mut CK_BYTE, _: CK_ULONG) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn DigestKey(_: CK_SESSION_HANDLE, _: CK_OBJECT_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn DigestFinal(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn SignRecoverInit(
    _: CK_SESSION_HANDLE,
    _: *mut CK_MECHANISM,
    _: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn SignRecover(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn VerifyInit(
    _: CK_SESSION_HANDLE,
    _: *mut CK_MECHANISM,
    _: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn Verify(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_BYTE,
    _: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn VerifyUpdate(_: CK_SESSION_HANDLE, _: *mut CK_BYTE, _: CK_ULONG) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn VerifyFinal(_: CK_SESSION_HANDLE, _: *mut CK_BYTE, _: CK_ULONG) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn VerifyRecoverInit(
    _: CK_SESSION_HANDLE,
    _: *mut CK_MECHANISM,
    _: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn VerifyRecover(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn DigestEncryptUpdate(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn DecryptDigestUpdate(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn SignEncryptUpdate(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn DecryptVerifyUpdate(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn GenerateKey(
    _: CK_SESSION_HANDLE,
    _: *mut CK_MECHANISM,
    _: *mut CK_ATTRIBUTE,
    _: CK_ULONG,
    _: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn GenerateKeyPair(
    _: CK_SESSION_HANDLE,
    _: *mut CK_MECHANISM,
    _: *mut CK_ATTRIBUTE,
    _: CK_ULONG,
    _: *mut CK_ATTRIBUTE,
    _: CK_ULONG,
    _: *mut CK_OBJECT_HANDLE,
    _: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn WrapKey(
    _: CK_SESSION_HANDLE,
    _: *mut CK_MECHANISM,
    _: CK_OBJECT_HANDLE,
    _: CK_OBJECT_HANDLE,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn UnwrapKey(
    _: CK_SESSION_HANDLE,
    _: *mut CK_MECHANISM,
    _: CK_OBJECT_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_ATTRIBUTE,
    _: CK_ULONG,
    _: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn DeriveKey(
    _: CK_SESSION_HANDLE,
    _: *mut CK_MECHANISM,
    _: CK_OBJECT_HANDLE,
    _: *mut CK_ATTRIBUTE,
    _: CK_ULONG,
    _: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn SeedRandom(_: CK_SESSION_HANDLE, _: *mut CK_BYTE, _: CK_ULONG) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn GenerateRandom(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn GetFunctionStatus(_: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn CancelFunction(_: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn WaitForSlotEvent(
    _: CK_FLAGS,
    _: *mut CK_SLOT_ID,
    _: *mut ::std::os::raw::c_void,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
