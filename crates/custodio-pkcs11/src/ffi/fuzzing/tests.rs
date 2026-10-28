//! Hand-built scripts for the fuzz harness: they show that each op reaches its PKCS#11 function,
//! and that any order of the multi-part calls ends as a reference model of F21 says. Run with
//! `--features fuzzing` (`just test`), also under Miri and `AddressSanitizer`.

use std::ptr;
use std::sync::atomic::Ordering;
use std::sync::{MutexGuard, PoisonError};

use cryptoki_sys::{CK_ULONG, CKR_OK};
use sha2::{Digest, Sha256};

use super::run;
use crate::fake::{LAST_INPUT, SIGN_CALLS};
use crate::ffi::tests::SERIAL;
use crate::ffi::{C_Finalize, C_Initialize};

/// Index of `CKM_ECDSA_SHA256` and `CKM_SHA256_RSA_PKCS` in the harness's mechanism table.
const ECDSA_SHA256: u8 = 3;
const SHA256_RSA: u8 = 6;
/// The script opens two sessions, which the ops reach as 1 and 2 (see `session` in the harness);
/// the sign init op needs an even number (`b % 2` is the length of its NULL parameter).
const SESSION: CK_ULONG = 2;

// Part sizes, as the size selector byte of the update op encodes them.
const SIZES: [(u8, usize); 4] = [(0, 0), (1, 1), (2, 129), (3, 4096)];

fn lock() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

fn calls() -> usize {
    SIGN_CALLS.load(Ordering::SeqCst)
}

fn last_input() -> Vec<u8> {
    LAST_INPUT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// A script, built the way the harness reads it.
#[derive(Default, Clone)]
struct Script(Vec<u8>);

impl Script {
    fn byte(&mut self, x: u8) -> &mut Self {
        self.0.push(x);
        self
    }

    fn ulong(&mut self, v: CK_ULONG) -> &mut Self {
        if v < 4 {
            self.0.extend([0, u8::try_from(v).unwrap_or(0)]);
        } else {
            self.0.push(3);
            self.0.extend(v.to_le_bytes());
        }
        self
    }

    /// An op with its two numbers; `null` is the NULL-pointer flag every op reads.
    fn op(&mut self, op: u8, a: CK_ULONG, b: CK_ULONG, null: bool) -> &mut Self {
        self.byte(op).ulong(a).ulong(b).byte(u8::from(!null))
    }

    fn setup(&mut self) -> &mut Self {
        // C_Initialize(NULL), a slot list query (it loads the token), then two sessions on slot 0.
        self.op(0, 0, 0, true).byte(1);
        self.op(2, 0, 0, true).byte(0);
        self.op(7, 0, 4, false).op(7, 0, 4, false)
    }

    fn get_mechanism_info(&mut self, mechanism: u8) -> &mut Self {
        self.op(6, 0, 0, false).byte(0).byte(mechanism)
    }

    fn init(&mut self, mechanism: u8) -> &mut Self {
        // Odd byte: parameter size 0; even: a mechanism from the table; non-NULL mechanism
        // pointer; key handle 2.
        self.op(15, 0, SESSION, true)
            .byte(1)
            .byte(0)
            .byte(1)
            .byte(0)
            .byte(mechanism)
            .byte(1)
            .ulong(2)
    }

    /// `size` selects the size byte (`SIZES`); `null` passes a NULL part with that length.
    fn update(&mut self, size: u8, fill: u8, null: bool) -> &mut Self {
        self.op(17, SESSION, 0, null).byte(size).byte(fill)
    }

    fn finish(&mut self) -> &mut Self {
        // 64-byte buffer, non-NULL length pointer.
        self.op(18, SESSION, 0, false).byte(0).byte(1)
    }

    fn sign(&mut self, query: bool) -> &mut Self {
        // Empty message, 64-byte buffer (or NULL for a length query).
        self.op(16, SESSION, 0, query).byte(0).byte(64)
    }

    fn login(&mut self, session: CK_ULONG, user: CK_ULONG, null: bool, len: CK_ULONG) -> &mut Self {
        self.op(19, session, user, null).ulong(len)
    }

    fn logout(&mut self, session: CK_ULONG) -> &mut Self {
        self.op(20, session, 0, false)
    }
}

/// The bytes of the part the update op builds: `fill`, `fill + 1`, ...
fn part(len: usize, fill: u8) -> Vec<u8> {
    (0..len)
        .map(|i| fill.wrapping_add(i.to_le_bytes()[0]))
        .collect()
}

/// Runs the script with the module finalized before and after.
fn play(script: &Script) {
    run(&script.0);
    // SAFETY: NULL is a valid argument. The harness finalized the module.
    unsafe {
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    }
}

#[test]
fn script_reaches_composed_mechanisms() {
    let _lock = lock();
    // Two parts "a" and "bc", whose concatenation is "abc": one more is selected by size 1.
    let mut script = Script::default();
    script
        .setup()
        .get_mechanism_info(ECDSA_SHA256)
        .init(ECDSA_SHA256)
        .update(1, b'a', false)
        .update(6, b'b', false)
        .finish();
    let before = calls();
    play(&script);
    assert_eq!(calls() - before, 1);
    assert_eq!(
        last_input(),
        Sha256::digest(b"abc").to_vec(),
        "the digest of the concatenated parts"
    );
    // A composed RSA type is refused by the fake's EC key: nothing is signed.
    let mut script = Script::default();
    script
        .setup()
        .init(SHA256_RSA)
        .update(1, b'a', false)
        .finish();
    let before = calls();
    play(&script);
    assert_eq!(calls(), before);
}

#[test]
fn login_logout_ops_are_wired() {
    let _lock = lock();
    let mut script = Script::default();
    script
        .setup()
        .init(ECDSA_SHA256)
        .login(SESSION, 1, true, 0)
        .logout(SESSION)
        .finish();
    let before = calls();
    play(&script);
    assert_eq!(calls() - before, 1, "login and logout leave the operation");
}

#[test]
fn login_arguments() {
    let _lock = lock();
    let lengths: [CK_ULONG; 8] = [
        0,
        1,
        4,
        4096,
        4097,
        CK_ULONG::try_from(isize::MAX).unwrap_or(CK_ULONG::MAX),
        CK_ULONG::MAX,
        7,
    ];
    let before = calls();
    for session in [0, 1, SESSION, 99, CK_ULONG::MAX] {
        for user in [0, 1, 2, 3, CK_ULONG::MAX] {
            // 4 setup steps and 32 calls: within the 64 steps of one run.
            let mut script = Script::default();
            script.setup();
            for null in [true, false] {
                for len in lengths {
                    script.login(session, user, null, len).logout(session);
                }
            }
            play(&script);
        }
    }
    assert_eq!(calls(), before, "nothing here signs");
}

/// One call of a multi-part sequence.
#[derive(Clone, Copy, Debug)]
enum Step {
    Init,
    Update(Update),
    Final,
    Sign { query: bool },
}

#[derive(Clone, Copy, Debug)]
enum Update {
    /// A part of this size selector (`SIZES`).
    Part(u8),
    /// A NULL part with length 0 (the size selector 0).
    Null0,
    /// A NULL part with a non-zero length: refused by `ffi.rs`.
    NullN,
}

const FILL: u8 = 0x41;

fn size_of_selector(selector: u8) -> usize {
    SIZES
        .iter()
        .find(|(s, _)| *s == selector)
        .map_or(0, |(_, n)| *n)
}

fn build(steps: &[Step]) -> Script {
    let mut script = Script::default();
    script.setup();
    for step in steps {
        match *step {
            Step::Init => script.init(ECDSA_SHA256),
            Step::Update(Update::Part(s)) => script.update(s, FILL, false),
            Step::Update(Update::Null0) => script.update(0, FILL, true),
            Step::Update(Update::NullN) => script.update(1, FILL, true),
            Step::Final => script.finish(),
            Step::Sign { query } => script.sign(query),
        };
    }
    script
}

/// The reference model of F21: the number of service calls and the last digest signed.
fn model(steps: &[Step]) -> (usize, Option<Vec<u8>>) {
    // `Some((updated, data))` while an operation is active.
    let mut active: Option<(bool, Vec<u8>)> = None;
    let mut calls = 0;
    let mut last = None;
    for step in steps {
        match (*step, active.take()) {
            (Step::Init, None) => active = Some((false, Vec::new())),
            (Step::Update(u), Some((updated, mut data))) => {
                let updated = match u {
                    Update::Part(s) => {
                        data.extend(part(size_of_selector(s), FILL));
                        true
                    }
                    Update::Null0 => true,
                    Update::NullN => updated,
                };
                active = Some((updated, data));
            }
            (Step::Final, Some((_, data))) => {
                calls += 1;
                last = Some(Sha256::digest(&data).to_vec());
            }
            (Step::Sign { query }, Some((updated, data))) => {
                if !updated && !query {
                    calls += 1;
                    last = Some(Sha256::digest(b"").to_vec());
                } else if !updated {
                    active = Some((updated, data));
                }
            }
            // Init while active keeps the operation; the rest has no operation to act on.
            (Step::Init, kept) => active = kept,
            _ => {}
        }
    }
    (calls, last)
}

fn check(steps: &[Step]) {
    let before = calls();
    play(&build(steps));
    let (expected, digest) = model(steps);
    assert_eq!(calls() - before, expected, "{steps:?}");
    if expected > 0 {
        assert_eq!(Some(last_input()), digest, "{steps:?}");
    }
}

fn permutations(items: &mut Vec<Step>, k: usize, out: &mut Vec<Vec<Step>>) {
    if k == items.len() {
        out.push(items.clone());
        return;
    }
    for i in k..items.len() {
        items.swap(k, i);
        permutations(items, k + 1, out);
        items.swap(k, i);
    }
}

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn sequences_in_any_order() {
    let _lock = lock();
    let selectors: &[u8] = if cfg!(miri) { &[0, 2] } else { &[0, 1, 2, 3] };
    let mut updates: Vec<Update> = selectors.iter().map(|s| Update::Part(*s)).collect();
    updates.extend([Update::Null0, Update::NullN]);
    for update in updates {
        let mut orders = Vec::new();
        let mut base = vec![
            Step::Init,
            Step::Update(update),
            Step::Final,
            Step::Sign { query: false },
        ];
        permutations(&mut base, 0, &mut orders);
        assert_eq!(orders.len(), 24);
        for steps in &orders {
            check(steps);
        }
    }
    // The worked examples of the contract.
    let part1 = Step::Update(Update::Part(1));
    let sign = Step::Sign { query: false };
    let query = Step::Sign { query: true };
    let cases: [(&[Step], usize); 12] = [
        (&[Step::Init, part1, Step::Final], 1),
        (&[Step::Init, part1, sign], 0),
        (&[Step::Init, sign, part1, Step::Final], 1),
        (&[Step::Init, Step::Final, part1, sign], 1),
        (&[part1, Step::Final, Step::Init, sign], 1),
        (&[Step::Final, sign, part1, Step::Init], 0),
        (&[Step::Init, part1, sign, Step::Final], 0),
        (&[Step::Init, part1, sign, Step::Init, Step::Final], 1),
        (&[Step::Init, Step::Update(Update::Part(0)), sign], 0),
        (&[Step::Init, Step::Update(Update::Null0), sign], 0),
        (&[Step::Init, Step::Update(Update::NullN), sign], 1),
        (&[Step::Init, part1, query, Step::Final], 0),
    ];
    for (steps, expected) in cases {
        assert_eq!(model(steps).0, expected, "model: {steps:?}");
        check(steps);
    }
    let more: [(&[Step], usize); 2] = [
        (
            &[Step::Init, Step::Update(Update::NullN), part1, Step::Final],
            1,
        ),
        (&[Step::Init, query, part1, Step::Final], 1),
    ];
    for (steps, expected) in more {
        assert_eq!(model(steps).0, expected, "model: {steps:?}");
        check(steps);
    }
    // Arbitrary scripts: no panic, no abort.
    let (scripts, max) = if cfg!(miri) { (20, 96) } else { (2000, 512) };
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    for _ in 0..scripts {
        let len = usize::try_from(xorshift(&mut state) % max).unwrap_or(0);
        let bytes: Vec<u8> = (0..len)
            .map(|_| xorshift(&mut state).to_le_bytes()[0])
            .collect();
        run(&bytes);
    }
}
