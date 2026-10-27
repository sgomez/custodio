//! Pointer and argument checks shared by the C functions: every raw pointer becomes a safe value or
//! a `CK_RV` here.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

use cryptoki_sys::{
    CK_ATTRIBUTE_PTR, CK_RV, CK_ULONG, CK_ULONG_PTR, CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL,
    CKR_GENERAL_ERROR, CKR_OK,
};

use super::{MAX_ATTRIBUTE_LEN, MAX_ATTRIBUTES};
use crate::token::Attribute;

pub(super) type Rv<T> = Result<T, CK_RV>;

pub(super) fn guard(f: impl FnOnce() -> Rv<()>) -> CK_RV {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => CKR_OK,
        Ok(Err(rv)) => rv,
        Err(_) => CKR_GENERAL_ERROR,
    }
}

pub(super) fn to_usize(v: CK_ULONG) -> Rv<usize> {
    usize::try_from(v).map_err(|_| CKR_ARGUMENTS_BAD)
}

pub(super) fn to_ulong(v: usize) -> Rv<CK_ULONG> {
    CK_ULONG::try_from(v).map_err(|_| CKR_GENERAL_ERROR)
}

pub(super) fn padded<const N: usize>(text: &str) -> [u8; N] {
    let mut out = [b' '; N];
    for (dst, src) in out.iter_mut().zip(text.bytes()) {
        *dst = src;
    }
    out
}

/// A non-null pointer to write one value through.
pub(super) unsafe fn out<'a, T>(p: *mut T) -> Rv<&'a mut T> {
    // SAFETY: the caller promises that a non-null `p` is valid for writes of `T`.
    unsafe { p.as_mut() }.ok_or(CKR_ARGUMENTS_BAD)
}

/// `len` bytes at `p`; an empty slice for `len == 0` whatever `p` is.
pub(super) unsafe fn input<'a>(p: *const u8, len: CK_ULONG) -> Rv<&'a [u8]> {
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
pub(super) unsafe fn write_list<T: Copy>(items: &[T], dst: *mut T, count: CK_ULONG_PTR) -> Rv<()> {
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

pub(super) unsafe fn template(attrs: CK_ATTRIBUTE_PTR, count: CK_ULONG) -> Rv<Vec<Attribute>> {
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
