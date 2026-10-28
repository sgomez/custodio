//! `C_Login` and `C_Logout`: the token has no secret to check, so a login changes nothing. The
//! credential argument is never read; a signature asks polkit whatever came before it.

use cryptoki_sys::{
    CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_USER_TYPE, CK_UTF8CHAR, CKR_SESSION_READ_ONLY_EXISTS,
    CKR_USER_TYPE_INVALID, CKU_CONTEXT_SPECIFIC, CKU_SO, CKU_USER,
};

use super::MODULE;
use super::args::guard;

pub(super) unsafe extern "C" fn C_Login(
    session: CK_SESSION_HANDLE,
    user: CK_USER_TYPE,
    _pin_ptr: *mut CK_UTF8CHAR,
    _pin_len: CK_ULONG,
) -> CK_RV {
    guard(|| {
        MODULE.check_session(session)?;
        match user {
            CKU_USER | CKU_CONTEXT_SPECIFIC => Ok(()),
            // Every session is read-only, and an SO login needs a read/write one.
            CKU_SO => Err(CKR_SESSION_READ_ONLY_EXISTS),
            _ => Err(CKR_USER_TYPE_INVALID),
        }
    })
}

pub(super) unsafe extern "C" fn C_Logout(session: CK_SESSION_HANDLE) -> CK_RV {
    guard(|| MODULE.check_session(session))
}
