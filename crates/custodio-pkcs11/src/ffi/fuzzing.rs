//! Entry point for the fuzz target (feature `fuzzing`, never built into the shipped module).
//!
//! The input is a script of PKCS#11 calls made through the function list, as a consumer would,
//! against a fake service. Values are arbitrary (handles, slot ids, flags, mechanism types and
//! parameters, attribute types and values, lengths, NULL or not); the buffers behind pointers are
//! always at least as large as the sizes passed with them, because a caller that lies about those
//! is undefined behaviour by the PKCS#11 contract, not something the module can detect.
//!
//! Session handles only grow while the process lives, so `run` first learns the handle the next
//! session will get (`first_session`) and the ops that take a session pass `base + (value % 4)`:
//! the sessions the script opens are handles 1 to 3 of every run, and 0 is never valid.

use std::ffi::c_void;
use std::ptr;

use cryptoki_sys::{CK_ATTRIBUTE, CK_C_INITIALIZE_ARGS, CK_FUNCTION_LIST, CK_MECHANISM, CK_ULONG};

use super::C_GetFunctionList;

mod ops;
#[cfg(test)]
mod tests;

/// Largest buffer the script allocates for one argument.
const MAX_BUFFER: usize = 4096;

struct Input<'a>(&'a [u8]);

impl Input<'_> {
    fn byte(&mut self) -> u8 {
        let (first, rest) = self.0.split_first().map_or((0, self.0), |(b, r)| (*b, r));
        self.0 = rest;
        first
    }

    fn ulong(&mut self) -> CK_ULONG {
        // Mostly small values (valid handles and slots), sometimes anything.
        match self.byte() % 4 {
            0 => CK_ULONG::from(self.byte() % 4),
            1 => CK_ULONG::from(self.byte()),
            2 => CK_ULONG::from_le_bytes([self.byte(); size_of::<CK_ULONG>()]),
            _ => {
                let mut bytes = [0; size_of::<CK_ULONG>()];
                for b in &mut bytes {
                    *b = self.byte();
                }
                CK_ULONG::from_le_bytes(bytes)
            }
        }
    }

    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let len = usize::from(self.byte()) * 16 % (max + 1);
        let len = len.min(self.0.len());
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        head.to_vec()
    }
}

/// Eight-byte aligned zeroed storage of at least `len` bytes, so structures can live in it.
fn storage(len: usize) -> Vec<u64> {
    vec![0; len.div_ceil(8).max(1)]
}

/// Runs one script. Never panics for any input; the module must not either.
pub fn run(data: &[u8]) {
    let mut input = Input(data);
    let mut list: *mut CK_FUNCTION_LIST = ptr::null_mut();
    // SAFETY: `list` is a live local.
    if unsafe { C_GetFunctionList(&raw mut list) } != 0 {
        return;
    }
    // SAFETY: on success the module stored a pointer to its static function list.
    let f = unsafe { &*list };
    // Leave the module as found, whatever the script did.
    // SAFETY: NULL is a valid argument.
    unsafe { f.C_Finalize.map(|finalize| finalize(ptr::null_mut())) };
    // SAFETY: `f` is the module's function list.
    let base = unsafe { first_session(f) };
    for _ in 0..64 {
        if input.0.is_empty() {
            break;
        }
        // SAFETY: every pointer passed below is NULL or points to a buffer at least as large as
        // the size passed with it (see the module documentation).
        unsafe { step(f, &mut input, base) };
    }
    // SAFETY: NULL is a valid argument.
    unsafe { f.C_Finalize.map(|finalize| finalize(ptr::null_mut())) };
}

/// Handle of the session the script's `a`-th `C_OpenSession` creates (`a` from 1 to 3; 0 and
/// anything above 3 miss or reach later ones).
fn session(base: CK_ULONG, value: CK_ULONG) -> CK_ULONG {
    base.wrapping_add(value % 4)
}

/// The handle the last session of a probe run got: the script's first session is the next one.
/// 0 if the module does not answer.
///
/// # Safety
/// `f` must be the module's function list.
unsafe fn first_session(f: &CK_FUNCTION_LIST) -> CK_ULONG {
    let (mut slot, mut count, mut handle): (CK_ULONG, CK_ULONG, CK_ULONG) = (0, 1, 0);
    // SAFETY: every pointer is to a live local, NULL where the function allows it.
    unsafe {
        if let (Some(init), Some(list), Some(open), Some(finalize)) = (
            f.C_Initialize,
            f.C_GetSlotList,
            f.C_OpenSession,
            f.C_Finalize,
        ) {
            init(ptr::null_mut());
            list(1, &raw mut slot, &raw mut count);
            open(
                slot,
                cryptoki_sys::CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &raw mut handle,
            );
            finalize(ptr::null_mut());
        }
    }
    handle
}

/// A pointer to `buf`, or NULL.
fn maybe(buf: &mut [u8], null: bool) -> *mut u8 {
    if null {
        ptr::null_mut()
    } else {
        buf.as_mut_ptr()
    }
}

/// # Safety
/// `f` must be the module's function list.
#[allow(clippy::too_many_lines)] // one arm per PKCS#11 function; splitting would hide the table
unsafe fn step(f: &CK_FUNCTION_LIST, input: &mut Input<'_>, base: CK_ULONG) {
    let op = input.byte() % 21;
    let a = input.ulong();
    let b = input.ulong();
    let null = input.byte().is_multiple_of(5);
    // SAFETY (whole body): see the function's and `run`'s safety comments; out pointers are
    // to live locals or buffers sized as claimed.
    unsafe {
        match op {
            0 => {
                let mut args: CK_C_INITIALIZE_ARGS = std::mem::zeroed();
                args.flags = a;
                if input.byte().is_multiple_of(2) {
                    args.pReserved = ptr::dangling_mut();
                }
                let p = if null {
                    ptr::null_mut()
                } else {
                    (&raw mut args).cast()
                };
                if let Some(call) = f.C_Initialize {
                    call(p);
                }
            }
            1 => {
                if let Some(call) = f.C_Finalize {
                    call(ptr::null_mut());
                }
            }
            2 => {
                let room = usize::from(input.byte() % 4);
                let mut slots = vec![0 as CK_ULONG; room];
                let mut count = room as CK_ULONG;
                let list = if null || room == 0 {
                    ptr::null_mut()
                } else {
                    slots.as_mut_ptr()
                };
                if let Some(call) = f.C_GetSlotList {
                    call(u8::from(b.is_multiple_of(2)), list, &raw mut count);
                }
            }
            3 => {
                let mut info = std::mem::MaybeUninit::<cryptoki_sys::CK_SLOT_INFO>::zeroed();
                let p = if null {
                    ptr::null_mut()
                } else {
                    info.as_mut_ptr()
                };
                if let Some(call) = f.C_GetSlotInfo {
                    call(a, p);
                }
            }
            4 => {
                let mut info = std::mem::MaybeUninit::<cryptoki_sys::CK_TOKEN_INFO>::zeroed();
                let p = if null {
                    ptr::null_mut()
                } else {
                    info.as_mut_ptr()
                };
                if let Some(call) = f.C_GetTokenInfo {
                    call(a, p);
                }
            }
            5 => {
                let room = usize::from(input.byte() % 4);
                let mut mechs = vec![0 as CK_ULONG; room];
                let mut count = room as CK_ULONG;
                let list = if null || room == 0 {
                    ptr::null_mut()
                } else {
                    mechs.as_mut_ptr()
                };
                if let Some(call) = f.C_GetMechanismList {
                    call(a, list, &raw mut count);
                }
            }
            6 => {
                let mut info = std::mem::MaybeUninit::<cryptoki_sys::CK_MECHANISM_INFO>::zeroed();
                let p = if null {
                    ptr::null_mut()
                } else {
                    info.as_mut_ptr()
                };
                // Sometimes a mechanism the module knows, the composed ones among them.
                let ckm = if input.byte().is_multiple_of(2) {
                    ops::known_mechanism(input)
                } else {
                    b
                };
                if let Some(call) = f.C_GetMechanismInfo {
                    call(a, ckm, p);
                }
            }
            7 => {
                let mut session: CK_ULONG = 0;
                let p = if null {
                    ptr::null_mut()
                } else {
                    &raw mut session
                };
                if let Some(call) = f.C_OpenSession {
                    call(a, b, ptr::null_mut(), None, p);
                }
            }
            8 => {
                if let Some(call) = f.C_CloseSession {
                    call(a);
                }
            }
            9 => {
                if let Some(call) = f.C_CloseAllSessions {
                    call(a);
                }
            }
            10 => {
                let mut info = std::mem::MaybeUninit::<cryptoki_sys::CK_SESSION_INFO>::zeroed();
                let p = if null {
                    ptr::null_mut()
                } else {
                    info.as_mut_ptr()
                };
                if let Some(call) = f.C_GetSessionInfo {
                    call(a, p);
                }
            }
            11 | 13 => {
                // A template (op 11) or a list to fill in (op 13, `C_GetAttributeValue`).
                let count = usize::from(input.byte() % 70);
                let mut values: Vec<Vec<u8>> = Vec::new();
                let mut attrs: Vec<CK_ATTRIBUTE> = Vec::new();
                for _ in 0..count {
                    let type_ = input.ulong();
                    let mut value = input.bytes(64);
                    if op == 13 {
                        value.resize(usize::from(input.byte()) * 4, 0);
                    }
                    let no_value = input.byte().is_multiple_of(4);
                    let len = if op == 13 && no_value {
                        0
                    } else {
                        value.len() as CK_ULONG
                    };
                    let p = if no_value && op == 13 {
                        ptr::null_mut()
                    } else {
                        value.as_mut_ptr()
                    };
                    attrs.push(CK_ATTRIBUTE {
                        type_,
                        pValue: p.cast::<c_void>(),
                        ulValueLen: len,
                    });
                    // Moving the Vec keeps its heap buffer in place.
                    values.push(value);
                }
                let p = if null || attrs.is_empty() {
                    ptr::null_mut()
                } else {
                    attrs.as_mut_ptr()
                };
                // The count never exceeds the number of attributes allocated.
                let claimed = if p.is_null() {
                    b % 3
                } else {
                    attrs.len() as CK_ULONG
                };
                if op == 11 {
                    if let Some(call) = f.C_FindObjectsInit {
                        call(a, p, claimed);
                    }
                } else if let Some(call) = f.C_GetAttributeValue {
                    call(a, b % 4, p, claimed);
                }
                drop(values);
            }
            12 => {
                let room = usize::from(input.byte() % 4);
                let mut objects = vec![0 as CK_ULONG; room];
                let mut found: CK_ULONG = 0;
                let p = if null || room == 0 {
                    ptr::null_mut()
                } else {
                    objects.as_mut_ptr()
                };
                let max = if p.is_null() { 0 } else { room as CK_ULONG };
                if let Some(call) = f.C_FindObjects {
                    call(a, p, max, &raw mut found);
                }
            }
            14 => {
                if let Some(call) = f.C_FindObjectsFinal {
                    call(a);
                }
            }
            15 => {
                // Mechanism parameter: sometimes exactly the size of the PSS structure.
                let want = if input.byte().is_multiple_of(2) {
                    size_of::<cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS>()
                } else {
                    usize::from(input.byte() % 64)
                };
                let mut param = storage(want);
                let bytes = std::slice::from_raw_parts_mut(param.as_mut_ptr().cast::<u8>(), want);
                for x in bytes.iter_mut() {
                    *x = input.byte();
                }
                let mut m = CK_MECHANISM {
                    mechanism: if input.byte().is_multiple_of(2) {
                        a % 2 + 0x1
                    } else {
                        a
                    },
                    pParameter: if null {
                        ptr::null_mut()
                    } else {
                        param.as_mut_ptr().cast()
                    },
                    ulParameterLen: if null { b % 2 } else { want as CK_ULONG },
                };
                if input.byte().is_multiple_of(2) {
                    m.mechanism = ops::known_mechanism(input);
                }
                let mp = if input.byte().is_multiple_of(16) {
                    ptr::null_mut()
                } else {
                    &raw mut m
                };
                if let Some(call) = f.C_SignInit {
                    call(session(base, b), mp, input.ulong() % 4);
                }
            }
            17 => ops::sign_update(f, input, session(base, a), b, null),
            18 => ops::sign_final(f, input, session(base, a), null),
            19 => ops::login(f, input, session(base, a), b, null),
            20 => {
                if let Some(call) = f.C_Logout {
                    call(session(base, a));
                }
            }
            _ => {
                let mut data = input.bytes(MAX_BUFFER);
                let mut sig = vec![0_u8; usize::from(input.byte()) % 130];
                let mut sig_len = sig.len() as CK_ULONG;
                let sp = maybe(&mut sig, null);
                let data_len = data.len() as CK_ULONG;
                let dp = if data.is_empty() {
                    ptr::null_mut()
                } else {
                    data.as_mut_ptr()
                };
                if let Some(call) = f.C_Sign {
                    call(session(base, a), dp, data_len, sp, &raw mut sig_len);
                }
            }
        }
    }
}
