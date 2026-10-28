//! Child scenarios for `C_SignUpdate` and `C_SignFinal`.

use std::sync::Barrier;

use cryptoki_sys::{
    CK_MECHANISM_TYPE, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_ULONG, CKM_ECDSA,
    CKM_ECDSA_SHA256, CKM_SHA256_RSA_PKCS, CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED, CKR_OK, CKR_OPERATION_ACTIVE, CKR_OPERATION_NOT_INITIALIZED,
};

use super::composed_child::{Raw, composed_for, each_token};
use super::*;

/// Part sizes of the equivalence scenario; the last part is the rest.
const PARTS: [usize; 4] = [1, 0, 4095, 4096];
const EQUIVALENCE_LEN: usize = 100_000;

/// The raw calls on a bare session handle, so a thread can use a session it does not own.
impl Raw {
    fn init_handle(
        &self,
        session: CK_SESSION_HANDLE,
        key: CK_OBJECT_HANDLE,
        mechanism: CK_MECHANISM_TYPE,
    ) -> CK_RV {
        let mut m = cryptoki_sys::CK_MECHANISM {
            mechanism,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let f = self.list.C_SignInit.expect("C_SignInit");
        // SAFETY: `m` is a live local.
        unsafe { f(session, &raw mut m, key) }
    }

    fn update(&self, session: CK_SESSION_HANDLE, part: &[u8]) -> CK_RV {
        let f = self.list.C_SignUpdate.expect("C_SignUpdate");
        // SAFETY: `part` is live for the length given.
        unsafe { f(session, part.as_ptr().cast_mut(), part.len() as CK_ULONG) }
    }

    fn finish(
        &self,
        session: CK_SESSION_HANDLE,
        out: Option<&mut [u8]>,
        len: &mut CK_ULONG,
    ) -> CK_RV {
        let f = self.list.C_SignFinal.expect("C_SignFinal");
        let buffer = out.map_or(std::ptr::null_mut(), <[u8]>::as_mut_ptr);
        // SAFETY: `buffer` is live for `*len` bytes when non-null; `len` is a live local.
        unsafe { f(session, buffer, len) }
    }

    fn sign_handle(&self, session: CK_SESSION_HANDLE, data: &[u8], out: &mut [u8]) -> CK_RV {
        let f = self.list.C_Sign.expect("C_Sign");
        let mut len = out.len() as CK_ULONG;
        // SAFETY: `data` and `out` are live for the sizes given.
        unsafe {
            f(
                session,
                data.as_ptr().cast_mut(),
                data.len() as CK_ULONG,
                out.as_mut_ptr(),
                &raw mut len,
            )
        }
    }
}

/// Signs `msg` in `parts` through the `cryptoki` crate.
fn sign_parts(
    session: &Session,
    mechanism: &Mechanism,
    key: ObjectHandle,
    parts: &[&[u8]],
) -> Result<Vec<u8>, Box<dyn Error>> {
    session.sign_init(mechanism, key)?;
    for part in parts {
        session.sign_update(part)?;
    }
    Ok(session.sign_final()?)
}

/// Splits `msg` at the uneven sizes, the rest in the last part.
fn uneven(msg: &[u8]) -> Vec<&[u8]> {
    let mut parts = Vec::new();
    let mut rest = msg;
    for n in PARTS {
        let (head, tail) = rest.split_at(n);
        parts.push(head);
        rest = tail;
    }
    parts.push(rest);
    parts
}

/// Every composed mechanism twice, single-part and multi-part, over one message.
pub(super) fn multipart_equivalence(pkcs11: &Pkcs11) -> TestResult {
    let msg = message(EQUIVALENCE_LEN);
    each_token(pkcs11, |label, session, key, _| {
        for (mechanism, name) in composed_for(label) {
            let single = session.sign(&mechanism, key, &msg)?;
            println!("SIG {label} {name} {}", hex(&single));
            let multi = sign_parts(session, &mechanism, key, &uneven(&msg))?;
            println!("SIG {label} {name} {}", hex(&multi));
        }
        Ok(())
    })
}

/// 64 MiB in 1 MiB parts.
pub(super) fn multipart_large(pkcs11: &Pkcs11) -> TestResult {
    let msg = message(LARGE_LEN);
    each_token(pkcs11, |label, session, key, _| {
        let (mechanism, name) = if label == "ec" {
            (Mechanism::EcdsaSha384, "ecdsa-sha384")
        } else {
            (Mechanism::Sha256RsaPkcs, "rsa-sha256")
        };
        let parts: Vec<&[u8]> = msg.chunks(1 << 20).collect();
        let sig = sign_parts(session, &mechanism, key, &parts)?;
        println!("SIG {label} {name} {}", hex(&sig));
        Ok(())
    })
}

/// Length query, short buffer and exact buffer on `C_SignFinal`, with one `C_SignInit`.
pub(super) fn multipart_retry(pkcs11: &Pkcs11) -> TestResult {
    let raw = Raw::load()?;
    let msg = message(COMPOSED_LEN);
    each_token(pkcs11, |label, session, key, _| {
        let (mechanism, name, n) = if label == "ec" {
            (CKM_ECDSA_SHA256, "ecdsa-sha256", 64)
        } else {
            (CKM_SHA256_RSA_PKCS, "rsa-sha256", 256)
        };
        let handle = session.handle();
        assert_eq!(raw.init_handle(handle, key.handle(), mechanism), CKR_OK);
        let (first, second) = msg.split_at(COMPOSED_LEN / 2);
        assert_eq!(raw.update(handle, first), CKR_OK);
        assert_eq!(raw.update(handle, second), CKR_OK);
        let mut len: CK_ULONG = 0;
        assert_eq!(raw.finish(handle, None, &mut len), CKR_OK);
        assert_eq!(len, n);
        let mut short = [0xAA_u8; 1];
        len = 1;
        assert_eq!(
            raw.finish(handle, Some(&mut short), &mut len),
            CKR_BUFFER_TOO_SMALL
        );
        assert_eq!(len, n);
        assert_eq!(short, [0xAA]);
        let mut sig = vec![0_u8; usize::try_from(n)?];
        assert_eq!(raw.finish(handle, Some(&mut sig), &mut len), CKR_OK);
        assert_eq!(len, n);
        println!("SIG {label} {name} {}", hex(&sig));
        Ok(())
    })
}

/// Raw mechanisms are single-part only: the refusal ends the operation, and no polkit.
pub(super) fn multipart_raw(pkcs11: &Pkcs11) -> TestResult {
    let raw = Raw::load()?;
    let (session, key) = first_key(pkcs11)?;
    let (handle, key) = (session.handle(), key.handle());
    let mut out = [0_u8; 64];
    let mut len: CK_ULONG = 64;
    // Update first.
    assert_eq!(raw.init_handle(handle, key, CKM_ECDSA), CKR_OK);
    assert_eq!(raw.update(handle, b"x"), CKR_FUNCTION_NOT_SUPPORTED);
    assert_eq!(
        raw.finish(handle, Some(&mut out), &mut len),
        CKR_OPERATION_NOT_INITIALIZED
    );
    // Final first, as a length query and with a full buffer.
    assert_eq!(raw.init_handle(handle, key, CKM_ECDSA), CKR_OK);
    assert_eq!(
        raw.finish(handle, None, &mut len),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(raw.update(handle, b"x"), CKR_OPERATION_NOT_INITIALIZED);
    assert_eq!(raw.init_handle(handle, key, CKM_ECDSA), CKR_OK);
    assert_eq!(
        raw.finish(handle, Some(&mut out), &mut len),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    // A raw single-part signature still works.
    assert_eq!(raw.init_handle(handle, key, CKM_ECDSA), CKR_OK);
    assert_eq!(raw.sign_handle(handle, &[7; 32], &mut out), CKR_OK);
    Ok(())
}

/// `C_Sign` after `C_SignUpdate` is refused and ends the operation.
pub(super) fn multipart_sign_after_update(pkcs11: &Pkcs11) -> TestResult {
    let raw = Raw::load()?;
    let (session, key) = first_key(pkcs11)?;
    let (handle, key) = (session.handle(), key.handle());
    let mut out = [0_u8; 64];
    let mut len: CK_ULONG = 64;
    assert_eq!(raw.init_handle(handle, key, CKM_ECDSA_SHA256), CKR_OK);
    assert_eq!(raw.update(handle, b"x"), CKR_OK);
    assert_eq!(
        raw.sign_handle(handle, DATA, &mut out),
        CKR_OPERATION_ACTIVE
    );
    assert_eq!(
        raw.finish(handle, Some(&mut out), &mut len),
        CKR_OPERATION_NOT_INITIALIZED
    );
    Ok(())
}

/// One full attempt: init, two updates, final into a buffer. Returns the code of the final.
fn attempt(raw: &Raw, handle: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE, out: &mut [u8]) -> CK_RV {
    assert_eq!(raw.init_handle(handle, key, CKM_ECDSA_SHA256), CKR_OK);
    assert_eq!(raw.update(handle, b"first "), CKR_OK);
    assert_eq!(raw.update(handle, b"second"), CKR_OK);
    let mut len = out.len() as CK_ULONG;
    let rv = raw.finish(handle, Some(out), &mut len);
    if rv != CKR_OK {
        println!(
            "\nUNTOUCHED {}",
            out.iter().all(|b| *b == 0xAA) && len == 64
        );
    }
    rv
}

/// Polkit refuses: no bytes come back, every attempt asks again, the operation is over.
pub(super) fn multipart_denied(pkcs11: &Pkcs11) -> TestResult {
    let raw = Raw::load()?;
    let (session, key) = first_key(pkcs11)?;
    let (handle, key) = (session.handle(), key.handle());
    let mut out = [0xAA_u8; 64];
    for _ in 0..2 {
        assert_eq!(attempt(&raw, handle, key, &mut out), CKR_FUNCTION_FAILED);
        let mut len: CK_ULONG = 64;
        assert_eq!(
            raw.finish(handle, Some(&mut out), &mut len),
            CKR_OPERATION_NOT_INITIALIZED
        );
    }
    Ok(())
}

/// The same attempt once polkit allows it; prints the signature and the certificate.
pub(super) fn multipart_allowed(pkcs11: &Pkcs11) -> TestResult {
    let raw = Raw::load()?;
    each_token(pkcs11, |label, session, key, _| {
        if label == "ec" {
            let mut out = [0xAA_u8; 64];
            assert_eq!(
                attempt(&raw, session.handle(), key.handle(), &mut out),
                CKR_OK
            );
            println!("SIG ec ecdsa-sha256 {}", hex(&out));
        }
        Ok(())
    })
}

/// `(threads, descriptors)` of this process.
fn census() -> (Vec<String>, usize) {
    let fds = std::fs::read_dir("/proc/self/fd").map_or(0, Iterator::count);
    (task_names(), fds)
}

/// Threads and descriptors before, right after and two seconds after `C_SignUpdate` and after
/// `C_SignFinal` (the call that uses the bus): the module keeps nothing past a call.
pub(super) fn multipart_tasks(pkcs11: &Pkcs11) -> TestResult {
    let (session, key) = first_key(pkcs11)?;
    session.sign_init(&Mechanism::EcdsaSha256, key)?;
    // The listing's own descriptor is in every count alike.
    let _ = census();
    for step in ["update", "final"] {
        let before = census();
        if step == "update" {
            session.sign_update(&message(COMPOSED_LEN))?;
        } else {
            session.sign_final()?;
        }
        let after = census();
        std::thread::sleep(std::time::Duration::from_secs(2));
        let later = census();
        println!(
            "\nTASKS {step} {} {} {}",
            before.0.len(),
            after.0.len(),
            later.0.len()
        );
        println!("FDS {step} {} {} {}", before.1, after.1, later.1);
        println!(
            "NAMES before={:?} after={:?} later={:?}",
            before.0, after.0, later.0
        );
        if before.0.len() != after.0.len() || before.0.len() != later.0.len() {
            return Err(format!("thread count changed around C_Sign{step}").into());
        }
        if before.1 != after.1 || before.1 != later.1 {
            return Err(format!("descriptor count changed around C_Sign{step}").into());
        }
    }
    Ok(())
}

/// Fork with an open multi-part operation, while another thread uses the module.
pub(super) fn multipart_forks(pkcs11: &Pkcs11) -> TestResult {
    let raw = Raw::load()?;
    let msg = message(400);
    let (part1, part2) = msg.split_at(160);
    let pkcs11 = Arc::new(Pkcs11::clone(pkcs11));
    each_token(&pkcs11, |label, session, key, _| {
        if label != "ec" {
            return Ok(());
        }
        let handle = session.handle();
        assert_eq!(
            raw.init_handle(handle, key.handle(), CKM_ECDSA_SHA256),
            CKR_OK
        );
        assert_eq!(raw.update(handle, part1), CKR_OK);
        let stop = Arc::new(AtomicBool::new(false));
        let busy = {
            let (pkcs11, stop) = (pkcs11.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let _ = pkcs11.get_slots_with_token();
                }
            })
        };
        for _ in 0..5 {
            // SAFETY: the child only uses the module (fork-safe by design) and leaves with
            // `_exit`; `alarm` turns a deadlock in the child into a failure instead of a hang.
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                unsafe { libc::alarm(60) };
                let ok = fork_child(&raw, &pkcs11, handle);
                unsafe { libc::_exit(i32::from(!ok)) };
            }
            assert!(pid > 0, "fork failed");
            let mut status = 0;
            // SAFETY: `pid` is our child.
            unsafe { libc::waitpid(pid, &raw mut status, 0) };
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "child status {status}"
            );
        }
        stop.store(true, Ordering::SeqCst);
        busy.join().map_err(|_| "busy thread panicked")?;
        assert_eq!(raw.update(handle, part2), CKR_OK);
        let mut sig = [0_u8; 64];
        let mut len: CK_ULONG = 64;
        assert_eq!(raw.finish(handle, Some(&mut sig), &mut len), CKR_OK);
        println!("SIG ec ecdsa-sha256 {}", hex(&sig));
        Ok(())
    })
}

/// What a forked child does with the inherited multi-part operation; true if all as expected.
fn fork_child(raw: &Raw, pkcs11: &Pkcs11, handle: CK_SESSION_HANDLE) -> bool {
    let mut len: CK_ULONG = 0;
    let inherited = raw.update(handle, b"garbage of the child") == CKR_OK
        && raw.finish(handle, None, &mut len) == CKR_OK
        && len == 64;
    let own = || -> Result<(), Box<dyn Error>> {
        let (session, key) = first_key(pkcs11)?;
        session.sign(&Mechanism::EcdsaSha256, key, b"child single message")?;
        sign_parts(
            &session,
            &Mechanism::EcdsaSha256,
            key,
            &[b"child multi", b" message"],
        )?;
        Ok(())
    };
    inherited && own().is_ok()
}

/// Message of a worker's `round`.
pub(super) fn worker_message(worker: usize, round: usize) -> Vec<u8> {
    message(500 + worker * 8 + round)
}

const A_LEN: usize = 300;
const RACE_LEN: usize = 77;
const ROUNDS: usize = 50;

/// Other threads cannot corrupt or finish a multi-part operation; two threads racing on
/// `C_SignFinal` sign once.
pub(super) fn multipart_threads(pkcs11: &Pkcs11) -> TestResult {
    let raw = Arc::new(Raw::load()?);
    let arc = Arc::new(Pkcs11::clone(pkcs11));
    each_token(pkcs11, |label, session, key, _| {
        if label != "ec" {
            return Ok(());
        }
        let (handle, key_handle) = (session.handle(), key.handle());
        let msg = message(A_LEN);
        let (first, second) = msg.split_at(100);
        session.sign_init(&Mechanism::EcdsaSha256, key)?;
        session.sign_update(first)?;

        let stop = Arc::new(AtomicBool::new(false));
        let intruder = {
            let (raw, stop) = (raw.clone(), stop.clone());
            std::thread::spawn(move || {
                let mut codes = Vec::new();
                loop {
                    codes.push(raw.init_handle(handle, key_handle, CKM_ECDSA_SHA256));
                    if stop.load(Ordering::SeqCst) {
                        break codes;
                    }
                }
            })
        };
        let workers: Vec<_> = (0..8)
            .map(|w| {
                let pkcs11 = arc.clone();
                std::thread::spawn(move || -> Result<Vec<String>, String> {
                    let mut lines = Vec::new();
                    for r in 0..3 {
                        let (session, key) = first_key(&pkcs11).map_err(|e| e.to_string())?;
                        let text = worker_message(w, r);
                        let (head, tail) = text.split_at(text.len() / 3);
                        let sig = sign_parts(&session, &Mechanism::EcdsaSha256, key, &[head, tail])
                            .map_err(|e| e.to_string())?;
                        lines.push(format!("WSIG {w} {r} {}", hex(&sig)));
                    }
                    Ok(lines)
                })
            })
            .collect();
        let mut lines = Vec::new();
        for w in workers {
            lines.extend(w.join().map_err(|_| "worker panicked")??);
        }
        stop.store(true, Ordering::SeqCst);
        let codes = intruder.join().map_err(|_| "intruder panicked")?;
        assert_ne!(codes.first(), None, "the intruder never ran");
        assert!(
            codes.iter().all(|c| *c == CKR_OPERATION_ACTIVE),
            "{codes:?}"
        );
        session.sign_update(second)?;
        let sig = session.sign_final()?;
        println!("ASIG {}", hex(&sig));
        for line in lines {
            println!("{line}");
        }

        // Two threads race on the final of one session.
        let race = message(RACE_LEN);
        for _ in 0..ROUNDS {
            assert_eq!(
                raw.init_handle(handle, key_handle, CKM_ECDSA_SHA256),
                CKR_OK
            );
            assert_eq!(raw.update(handle, &race), CKR_OK);
            let barrier = Barrier::new(2);
            let mut codes: Vec<CK_RV> = std::thread::scope(|scope| {
                let racers: Vec<_> = (0..2)
                    .map(|_| {
                        scope.spawn(|| {
                            let mut out = [0_u8; 64];
                            let mut len: CK_ULONG = 64;
                            barrier.wait();
                            raw.finish(handle, Some(&mut out), &mut len)
                        })
                    })
                    .collect();
                racers.into_iter().map(|r| r.join().unwrap_or(0)).collect()
            });
            codes.sort_unstable();
            assert_eq!(codes, [CKR_OK, CKR_OPERATION_NOT_INITIALIZED]);
        }
        Ok(())
    })
}
