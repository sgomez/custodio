//! The new and changed entry points under hostile buffers, for Miri (`just miri`) and
//! `AddressSanitizer` (`just asan`). Output buffers are heap `Vec<u8>` of exactly the length
//! passed, so a write one byte past `*len` is an out-of-bounds write for both tools.

use std::sync::atomic::Ordering;

use cryptoki_sys::{
    CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512, CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS, CKR_KEY_TYPE_INCONSISTENT, CKR_OK, CKR_OPERATION_ACTIVE,
};

use super::*;
use crate::fake::SIGN_CALLS;

const ECDSA: [CK_ULONG; 3] = [CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512];
const RSA: [CK_ULONG; 3] = [
    CKM_SHA256_RSA_PKCS,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS,
];
const SENTINEL: u8 = 0xA5;

fn calls() -> usize {
    SIGN_CALLS.load(Ordering::SeqCst)
}

/// A buffer of `len` sentinel bytes handed to the module, in a heap allocation of exactly `len`
/// bytes (`new`, so a sanitizer sees a write past it) or of one more, whose last byte is a canary
/// that must stay intact (`guarded`).
struct Out(Vec<u8>, usize);

impl Out {
    fn new(len: usize) -> Self {
        Self(vec![SENTINEL; len], len)
    }

    fn guarded(len: usize) -> Self {
        Self(vec![SENTINEL; len + 1], len)
    }

    fn ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }

    fn data(&self) -> &[u8] {
        self.0.get(..self.1).unwrap_or_default()
    }

    fn untouched(&self) -> bool {
        self.0.iter().all(|b| *b == SENTINEL)
    }

    fn canary_intact(&self) -> bool {
        self.0
            .get(self.1..)
            .is_some_and(|c| c.iter().all(|b| *b == SENTINEL))
    }
}

type Make = fn(usize) -> Out;

/// Every ECDSA composed type with both kinds of buffer.
fn cases() -> Vec<(CK_ULONG, Make)> {
    ECDSA
        .into_iter()
        .flat_map(|ckm| [(ckm, Out::new as Make), (ckm, Out::guarded as Make)])
        .collect()
}

/// `C_SignInit` with a composed mechanism on the only token.
///
/// # Safety
/// `session` is a live session.
unsafe fn init(session: CK_SESSION_HANDLE, ckm: CK_ULONG) -> CK_RV {
    let mut m = mechanism(ckm, ptr::null_mut(), 0);
    // SAFETY: `m` is a live local.
    unsafe { C_SignInit(session, &raw mut m, 2) }
}

#[test]
fn mechanism_list_sizes_with_composed() {
    let s = Session::new();
    s.open();
    let mut count: CK_ULONG = 0;
    // SAFETY: the buffers are heap allocations of at least the length passed.
    unsafe {
        assert_eq!(
            C_GetMechanismList(0, ptr::null_mut(), &raw mut count),
            CKR_OK
        );
        assert_eq!(count, 4);
        // A larger buffer: exactly 4 entries written, the rest intact.
        let mut list = vec![CK_ULONG::MAX; 5 + 1];
        count = 5;
        assert_eq!(
            C_GetMechanismList(0, list.as_mut_ptr(), &raw mut count),
            CKR_OK
        );
        assert_eq!(count, 4);
        let (written, rest) = list.split_at(4);
        assert_eq!(rest, [CK_ULONG::MAX; 2]);
        for m in ECDSA {
            assert!(written.contains(&m), "{m:#x}");
        }
        for m in RSA {
            assert!(!written.contains(&m), "{m:#x}");
        }
        // One short: nothing written.
        let mut exact = vec![CK_ULONG::MAX; 3];
        count = 3;
        assert_eq!(
            C_GetMechanismList(0, exact.as_mut_ptr(), &raw mut count),
            CKR_BUFFER_TOO_SMALL
        );
        assert_eq!(count, 4);
        assert_eq!(exact, [CK_ULONG::MAX; 3]);
        // Exactly 4 entries of room.
        let mut full = vec![CK_ULONG::MAX; 4];
        count = 4;
        assert_eq!(
            C_GetMechanismList(0, full.as_mut_ptr(), &raw mut count),
            CKR_OK
        );
        assert!(full.iter().all(|m| *m != CK_ULONG::MAX));
    }
}

#[test]
fn composed_sign_init_null_mechanism() {
    let s = Session::new();
    let session = s.open();
    // SAFETY: a NULL mechanism is the case under test; the rest are live locals.
    unsafe {
        for ckm in ECDSA {
            assert_eq!(C_SignInit(session, ptr::null_mut(), 2), CKR_ARGUMENTS_BAD);
            // Nothing is active: a valid init works.
            assert_eq!(init(session, ckm), CKR_OK);
            let mut len: CK_ULONG = 0;
            let mut byte = 0_u8;
            assert_eq!(
                C_Sign(session, &raw mut byte, 0, ptr::null_mut(), &raw mut len),
                CKR_OK
            );
            let mut sig = Out::new(64);
            len = 64;
            assert_eq!(
                C_Sign(session, &raw mut byte, 0, sig.ptr(), &raw mut len),
                CKR_OK
            );
        }
    }
}

#[test]
fn composed_rsa_types_refused_by_sign_init() {
    let s = Session::new();
    let session = s.open();
    // SAFETY: pointers are to live locals.
    unsafe {
        let before = calls();
        for ckm in RSA {
            // The key is EC, so the module answers with a key-type mismatch, as for the plain RSA types.
            assert_eq!(init(session, ckm), CKR_KEY_TYPE_INCONSISTENT);
            // No operation is active: a following update has nothing to continue.
            let mut byte = 0_u8;
            assert_eq!(
                C_SignUpdate(session, &raw mut byte, 1),
                CKR_OPERATION_NOT_INITIALIZED
            );
        }
        assert_eq!(init(session, CKM_ECDSA_SHA256), CKR_OK);
        assert_eq!(calls(), before);
    }
}

#[test]
fn composed_sign_length_query_and_small_buffer() {
    let s = Session::new();
    let session = s.open();
    let mut message = *b"abc";
    // SAFETY: the buffers are heap allocations of at least the length passed.
    unsafe {
        for (ckm, make) in cases() {
            assert_eq!(init(session, ckm), CKR_OK);
            let before = calls();
            let mut len: CK_ULONG = 0;
            assert_eq!(
                C_Sign(
                    session,
                    message.as_mut_ptr(),
                    3,
                    ptr::null_mut(),
                    &raw mut len
                ),
                CKR_OK
            );
            assert_eq!(len, 64);
            assert_eq!(calls(), before);
            let mut small = make(63);
            len = 63;
            assert_eq!(
                C_Sign(session, message.as_mut_ptr(), 3, small.ptr(), &raw mut len),
                CKR_BUFFER_TOO_SMALL
            );
            assert_eq!(len, 64);
            assert!(small.untouched());
            assert_eq!(calls(), before);
            let mut exact = make(64);
            len = 64;
            assert_eq!(
                C_Sign(session, message.as_mut_ptr(), 3, exact.ptr(), &raw mut len),
                CKR_OK
            );
            assert_eq!(len, 64);
            assert_eq!(exact.data(), [7; 64]);
            assert!(exact.canary_intact());
            assert_eq!(calls(), before + 1);
        }
    }
}

#[test]
fn composed_sign_after_update_is_rejected() {
    let s = Session::new();
    let session = s.open();
    let mut byte = 1_u8;
    // SAFETY: the buffers are heap allocations of at least the length passed.
    unsafe {
        for (ckm, make) in cases() {
            for query in [false, true] {
                assert_eq!(init(session, ckm), CKR_OK);
                assert_eq!(C_SignUpdate(session, &raw mut byte, 1), CKR_OK);
                let before = calls();
                let mut sig = make(64);
                let mut len: CK_ULONG = 64;
                let target = if query { ptr::null_mut() } else { sig.ptr() };
                assert_eq!(
                    C_Sign(session, &raw mut byte, 1, target, &raw mut len),
                    CKR_OPERATION_ACTIVE
                );
                assert!(sig.untouched());
                assert_eq!(calls(), before);
                assert_eq!(
                    C_SignFinal(session, sig.ptr(), &raw mut len),
                    CKR_OPERATION_NOT_INITIALIZED
                );
                assert!(sig.untouched());
                assert_eq!(calls(), before);
            }
        }
    }
}

#[test]
fn multipart_final_small_buffer_keeps_operation() {
    let s = Session::new();
    let session = s.open();
    let mut part_a = *b"first ";
    let mut part_b = *b"second";
    // SAFETY: the buffers are heap allocations of at least the length passed.
    unsafe {
        for (ckm, make) in cases() {
            assert_eq!(init(session, ckm), CKR_OK);
            assert_eq!(C_SignUpdate(session, part_a.as_mut_ptr(), 6), CKR_OK);
            assert_eq!(C_SignUpdate(session, part_b.as_mut_ptr(), 6), CKR_OK);
            let before = calls();
            let mut len: CK_ULONG = 0;
            assert_eq!(C_SignFinal(session, ptr::null_mut(), &raw mut len), CKR_OK);
            assert_eq!(len, 64);
            assert_eq!(calls(), before);
            let mut small = make(63);
            len = 63;
            assert_eq!(
                C_SignFinal(session, small.ptr(), &raw mut len),
                CKR_BUFFER_TOO_SMALL
            );
            assert_eq!(len, 64);
            assert!(small.untouched());
            assert_eq!(calls(), before);
            let mut exact = make(64);
            len = 64;
            assert_eq!(C_SignFinal(session, exact.ptr(), &raw mut len), CKR_OK);
            assert_eq!(len, 64);
            assert_eq!(exact.data(), [7; 64]);
            assert!(exact.canary_intact());
            assert_eq!(calls(), before + 1);
            let streamed = crate::fake::LAST_INPUT.lock().map(|g| g.clone()).ok();
            // The same bytes through one-shot `C_Sign` of the concatenation: same signature,
            // and the service gets the same digest.
            let mut whole = *b"first second";
            assert_eq!(init(session, ckm), CKR_OK);
            let mut one_shot = make(64);
            len = 64;
            assert_eq!(
                C_Sign(
                    session,
                    whole.as_mut_ptr(),
                    12,
                    one_shot.ptr(),
                    &raw mut len
                ),
                CKR_OK
            );
            assert_eq!(one_shot.data(), exact.data());
            let digest = crate::fake::LAST_INPUT.lock().map(|g| g.clone()).ok();
            assert_eq!(streamed, digest);
            assert_eq!(calls(), before + 2);
        }
    }
}
