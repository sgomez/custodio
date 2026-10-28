//! `C_Login` and `C_Logout` through the `extern "C"` functions.

use cryptoki_sys::{
    CK_ATTRIBUTE_TYPE, CK_BBOOL, CK_TOKEN_INFO, CK_USER_TYPE, CKA_ALWAYS_AUTHENTICATE,
    CKF_LOGIN_REQUIRED, CKF_PROTECTED_AUTHENTICATION_PATH, CKM_ECDSA_SHA256, CKR_OK,
    CKR_SESSION_READ_ONLY_EXISTS, CKR_USER_TYPE_INVALID, CKU_CONTEXT_SPECIFIC, CKU_SO, CKU_USER,
};

use super::*;

const SENTINEL: &[u8] = b"sentinel-pin-7731";

fn session_info(session: CK_SESSION_HANDLE) -> (CK_RV, [CK_ULONG; 4]) {
    let mut info = CK_SESSION_INFO {
        slotID: 99,
        state: 99,
        flags: 99,
        ulDeviceError: 99,
    };
    // SAFETY: `info` is a live local.
    let rv = unsafe { C_GetSessionInfo(session, &raw mut info) };
    (
        rv,
        [info.slotID, info.state, info.flags, info.ulDeviceError],
    )
}

fn login(session: CK_SESSION_HANDLE, user: CK_USER_TYPE) -> CK_RV {
    // SAFETY: the credential is never read.
    unsafe { C_Login(session, user, ptr::null_mut(), 0) }
}

#[test]
fn login_accepts_any_pin() {
    let s = Session::new();
    let session = s.open();
    let mut pin = *b"1234";
    for user in [CKU_USER, CKU_CONTEXT_SPECIFIC] {
        // SAFETY: `pin` is a live local with the length given.
        unsafe {
            assert_eq!(C_Login(session, user, ptr::null_mut(), 0), CKR_OK);
            assert_eq!(C_Login(session, user, pin.as_mut_ptr(), 0), CKR_OK);
            assert_eq!(C_Login(session, user, pin.as_mut_ptr(), 4), CKR_OK);
            assert_eq!(C_Login(session, user, ptr::null_mut(), 4), CKR_OK);
            assert_eq!(C_Login(session, user, pin.as_mut_ptr(), 1), CKR_OK);
            assert_eq!(
                C_Login(session, user, ptr::null_mut(), CK_ULONG::MAX),
                CKR_OK
            );
            let mut empty = [0_u8; 0];
            assert_eq!(C_Login(session, user, empty.as_mut_ptr(), 0), CKR_OK);
        }
    }
}

#[test]
fn login_never_dereferences_the_pin() {
    let s = Session::new();
    let session = s.open();
    // SAFETY: the credential is never read, so a dangling pointer is fine.
    unsafe {
        assert_eq!(
            C_Login(session, CKU_USER, ptr::dangling_mut(), 1_000_000),
            CKR_OK
        );
        assert_eq!(
            C_Login(
                session,
                CKU_CONTEXT_SPECIFIC,
                ptr::dangling_mut(),
                1_000_000
            ),
            CKR_OK
        );
        assert_eq!(C_Login(session, CKU_USER, ptr::null_mut(), 5), CKR_OK);
    }
}

#[test]
fn login_invalid_session() {
    let s = Session::new();
    // SAFETY: the credential is never read.
    unsafe {
        for user in [CKU_USER, CKU_CONTEXT_SPECIFIC, CKU_SO] {
            assert_eq!(
                C_Login(1, user, ptr::null_mut(), 0),
                CKR_CRYPTOKI_NOT_INITIALIZED
            );
        }
        assert_eq!(C_Logout(1), CKR_CRYPTOKI_NOT_INITIALIZED);
        let open = s.open();
        let never = open + 100;
        assert_eq!(C_CloseSession(open), CKR_OK);
        for handle in [never, open] {
            for user in [CKU_USER, CKU_CONTEXT_SPECIFIC, CKU_SO, 3] {
                assert_eq!(
                    C_Login(handle, user, ptr::null_mut(), 0),
                    CKR_SESSION_HANDLE_INVALID
                );
            }
            assert_eq!(C_Logout(handle), CKR_SESSION_HANDLE_INVALID);
        }
    }
}

#[test]
fn login_security_officer_fails() {
    let s = Session::new();
    let session = s.open();
    let before = session_info(session);
    let mut pin = *b"0000";
    // SAFETY: `pin` is a live local with the length given.
    unsafe {
        assert_eq!(
            C_Login(session, CKU_SO, ptr::null_mut(), 0),
            CKR_SESSION_READ_ONLY_EXISTS
        );
        assert_eq!(
            C_Login(session, CKU_SO, pin.as_mut_ptr(), 4),
            CKR_SESSION_READ_ONLY_EXISTS
        );
        assert_eq!(
            C_Login(session, 3, ptr::null_mut(), 0),
            CKR_USER_TYPE_INVALID
        );
        assert_eq!(
            C_Login(session, CK_ULONG::MAX, pin.as_mut_ptr(), 4),
            CKR_USER_TYPE_INVALID
        );
    }
    assert_eq!(session_info(session), before);
    // The operation state is unchanged: a signature still goes through.
    // SAFETY: pointers are to live locals.
    unsafe {
        let mut m = mechanism(CKM_ECDSA_SHA256, ptr::null_mut(), 0);
        assert_eq!(C_SignInit(session, &raw mut m, 2), CKR_OK);
    }
}

#[test]
fn login_twice_and_after_logout() {
    let s = Session::new();
    let session = s.open();
    let (_, before) = session_info(session);
    assert_eq!(before[1], CKS_RO_PUBLIC_SESSION);
    assert_eq!(before[2], CKF_SERIAL_SESSION);
    let steps: [(&str, CK_USER_TYPE); 7] = [
        ("login", CKU_USER),
        ("login", CKU_USER),
        ("login", CKU_CONTEXT_SPECIFIC),
        ("logout", 0),
        ("login", CKU_USER),
        ("logout", 0),
        ("logout", 0),
    ];
    for (what, user) in steps {
        // SAFETY: the credential is never read.
        let rv = if what == "login" {
            login(session, user)
        } else {
            unsafe { C_Logout(session) }
        };
        assert_eq!(rv, CKR_OK);
        assert_eq!(session_info(session), (CKR_OK, before));
    }
}

#[test]
fn session_state_does_not_change_with_login() {
    let s = Session::new();
    let session = s.open();
    let before = session_info(session);
    let mut pin = SENTINEL.to_vec();
    // SAFETY: `pin` is a live local with the length given.
    unsafe {
        assert_eq!(
            C_Login(
                session,
                CKU_USER,
                pin.as_mut_ptr(),
                to_ulong(pin.len()).unwrap_or(0)
            ),
            CKR_OK
        );
    }
    assert_eq!(session_info(session), before);
    // SAFETY: no arguments to check.
    assert_eq!(unsafe { C_Logout(session) }, CKR_OK);
    assert_eq!(session_info(session), before);
}

#[test]
fn logout_is_ok() {
    let s = Session::new();
    let session = s.open();
    // SAFETY: no arguments to check.
    unsafe {
        assert_eq!(C_Logout(session), CKR_OK);
        assert_eq!(login(session, CKU_USER), CKR_OK);
        assert_eq!(C_Logout(session), CKR_OK);
        assert_eq!(C_Logout(session), CKR_OK);
    }
}

fn flags_and_attribute(session: CK_SESSION_HANDLE) -> (CK_FLAGS, CK_BBOOL, Vec<CK_MECHANISM_TYPE>) {
    // SAFETY: pointers are to live locals; the lengths are the real ones.
    unsafe {
        let mut info = std::mem::MaybeUninit::<CK_TOKEN_INFO>::zeroed();
        assert_eq!(C_GetTokenInfo(0, info.as_mut_ptr()), CKR_OK);
        let flags = info.assume_init().flags;
        let mut value: CK_BBOOL = 99;
        let mut a = attr(
            CK_ATTRIBUTE_TYPE::from(CKA_ALWAYS_AUTHENTICATE),
            (&raw mut value).cast(),
            1,
        );
        assert_eq!(C_GetAttributeValue(session, 2, &raw mut a, 1), CKR_OK);
        let mut count: CK_ULONG = 0;
        assert_eq!(
            C_GetMechanismList(0, ptr::null_mut(), &raw mut count),
            CKR_OK
        );
        let mut list = vec![0; to_usize(count).unwrap_or(0)];
        assert_eq!(
            C_GetMechanismList(0, list.as_mut_ptr(), &raw mut count),
            CKR_OK
        );
        (flags, value, list)
    }
}

#[test]
fn token_flags_ignore_login() {
    let s = Session::new();
    let session = s.open();
    let before = flags_and_attribute(session);
    assert_eq!(login(session, CKU_USER), CKR_OK);
    assert_eq!(login(session, CKU_CONTEXT_SPECIFIC), CKR_OK);
    // SAFETY: no arguments to check.
    assert_eq!(unsafe { C_Logout(session) }, CKR_OK);
    let after = flags_and_attribute(session);
    assert_eq!(before, after);
    assert_eq!(
        after.0 & (CKF_LOGIN_REQUIRED | CKF_PROTECTED_AUTHENTICATION_PATH),
        0
    );
    assert_eq!(after.1, 0);
}

#[test]
fn login_keeps_the_open_operation() {
    let s = Session::new();
    let session = s.open();
    let run = |with_login: bool| {
        let mut m = mechanism(CKM_ECDSA_SHA256, ptr::null_mut(), 0);
        let (mut part, mut sig, mut len) = (*b"ab", [0_u8; 64], 64 as CK_ULONG);
        // SAFETY: pointers are to live locals; lengths are the real ones.
        unsafe {
            assert_eq!(C_SignInit(session, &raw mut m, 2), CKR_OK);
            assert_eq!(C_SignUpdate(session, part.as_mut_ptr(), 2), CKR_OK);
            if with_login {
                assert_eq!(login(session, CKU_USER), CKR_OK);
                assert_eq!(C_Logout(session), CKR_OK);
            }
            assert_eq!(C_SignUpdate(session, part.as_mut_ptr(), 2), CKR_OK);
            assert_eq!(C_SignFinal(session, sig.as_mut_ptr(), &raw mut len), CKR_OK);
        }
        crate::fake::LAST_INPUT.lock().map(|g| g.clone()).ok()
    };
    let without = run(false);
    assert!(without.is_some());
    assert_eq!(run(true), without);
}
