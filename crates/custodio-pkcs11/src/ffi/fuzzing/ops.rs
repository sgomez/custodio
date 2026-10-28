//! The multi-part signing and login operations of the fuzz script, and the mechanism table.
//!
//! Output buffers are heap `Vec`s of exactly the length passed, so `AddressSanitizer` sees a write
//! one byte past `*len`. Nothing is remembered between calls: every operation is chosen from the
//! script bytes, so any order and any sizes occur.

use std::ptr;

use cryptoki_sys::{
    CK_FUNCTION_LIST, CK_ULONG, CKM_ECDSA, CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512,
    CKM_RSA_PKCS, CKM_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS,
};

use super::{Input, MAX_BUFFER};

/// The mechanism types the module knows or must refuse: the raw ones, the three composed ECDSA
/// ones the fake supports and the three composed RSA ones it refuses.
const MECHANISMS: [CK_ULONG; 9] = [
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_PSS,
    CKM_ECDSA,
    CKM_ECDSA_SHA256,
    CKM_ECDSA_SHA384,
    CKM_ECDSA_SHA512,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS,
];

/// One of [`MECHANISMS`].
pub(super) fn known_mechanism(input: &mut Input<'_>) -> CK_ULONG {
    let i = usize::from(input.byte()) % MECHANISMS.len();
    MECHANISMS.get(i).copied().unwrap_or(CKM_ECDSA)
}

/// The length of a part: the interesting sizes, or anything up to `MAX_BUFFER`.
fn part_size(input: &mut Input<'_>) -> usize {
    match input.byte() % 8 {
        0 => 0,
        1 => 1,
        2 => 129,
        3 => MAX_BUFFER,
        4 => usize::from(input.byte()),
        5 => usize::from(input.byte()) * 16,
        6 => 2,
        _ => 3,
    }
}

/// `C_SignUpdate` with a part of `part_size` bytes, `fill`, `fill + 1`, and so on. A NULL
/// pointer is passed with the real length (or, now and then, any length).
///
/// # Safety
/// `f` must be the module's function list.
pub(super) unsafe fn sign_update(
    f: &CK_FUNCTION_LIST,
    input: &mut Input<'_>,
    a: CK_ULONG,
    b: CK_ULONG,
    null: bool,
) {
    let size = part_size(input);
    let fill = input.byte();
    let mut part: Vec<u8> = (0..size)
        .map(|i| fill.wrapping_add(i.to_le_bytes()[0]))
        .collect();
    let len = if null && b % 4 == 3 {
        b
    } else {
        part.len() as CK_ULONG
    };
    let p = if null {
        ptr::null_mut()
    } else {
        part.as_mut_ptr()
    };
    if let Some(call) = f.C_SignUpdate {
        // SAFETY: `p` is NULL or points to `part`, which is as long as `len`.
        unsafe { call(a, p, len) };
    }
}

/// `C_SignFinal` with a buffer of exactly the length passed, or NULL; the length pointer is
/// sometimes NULL.
///
/// # Safety
/// `f` must be the module's function list.
pub(super) unsafe fn sign_final(
    f: &CK_FUNCTION_LIST,
    input: &mut Input<'_>,
    a: CK_ULONG,
    null: bool,
) {
    let size = match input.byte() % 6 {
        0 | 1 => 64,
        2 => 63,
        3 => 0,
        4 => 65,
        _ => usize::from(input.byte()),
    };
    let mut sig = vec![0_u8; size];
    let mut len = size as CK_ULONG;
    let len_ptr = if input.byte().is_multiple_of(16) {
        ptr::null_mut()
    } else {
        &raw mut len
    };
    let p = if null {
        ptr::null_mut()
    } else {
        sig.as_mut_ptr()
    };
    if let Some(call) = f.C_SignFinal {
        // SAFETY: `p` is NULL or points to `sig`, which is as long as `len`.
        unsafe { call(a, p, len_ptr) };
    }
}

/// `C_Login` with any session, user type and PIN length. The module never reads the PIN, so up
/// to `MAX_BUFFER` bytes it gets NULL or a buffer of exactly that length, and beyond it NULL or a
/// dangling non-NULL pointer: no allocation follows the fuzz bytes, and a read of the pointer is
/// an error for Miri.
///
/// # Safety
/// `f` must be the module's function list.
pub(super) unsafe fn login(
    f: &CK_FUNCTION_LIST,
    input: &mut Input<'_>,
    a: CK_ULONG,
    b: CK_ULONG,
    null: bool,
) {
    let pin_len = input.ulong();
    let mut pin = Vec::new();
    let p = match usize::try_from(pin_len) {
        _ if null => ptr::null_mut(),
        Ok(n) if n <= MAX_BUFFER => {
            pin = vec![b'1'; n];
            pin.as_mut_ptr()
        }
        _ => ptr::NonNull::<u8>::dangling().as_ptr(),
    };
    if let Some(call) = f.C_Login {
        // SAFETY: `p` is NULL, a buffer as long as `pin_len` or (above `MAX_BUFFER`) dangling.
        unsafe { call(a, b, p, pin_len) };
    }
    drop(pin);
}
