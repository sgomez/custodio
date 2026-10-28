//! The child: a PKCS#11 consumer of the built module.

use super::*;

pub(super) fn module() -> Result<Pkcs11, Box<dyn Error>> {
    let pkcs11 = Pkcs11::new(std::env::var(MODULE_VAR)?)?;
    pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    Ok(pkcs11)
}

pub(super) fn find(session: &Session, class: ObjectClass) -> Result<ObjectHandle, Box<dyn Error>> {
    let found = session.find_objects(&[Attribute::Class(class)])?;
    assert_eq!(found.len(), 1, "one {class:?} per token");
    Ok(found[0])
}

/// Lists, finds and signs on every token; prints what the parent checks.
pub(super) fn basic(pkcs11: &Pkcs11) -> TestResult {
    let slots = pkcs11.get_slots_with_token()?;
    assert_eq!(slots.len(), 2, "one token per key");
    for slot in slots {
        let label = pkcs11.get_token_info(slot)?.label().to_owned();
        let session = pkcs11.open_ro_session(slot)?;
        let cert = find(&session, ObjectClass::CERTIFICATE)?;
        let key = find(&session, ObjectClass::PRIVATE_KEY)?;
        let Some(Attribute::Value(der)) = session
            .get_attributes(cert, &[AttributeType::Value])?
            .into_iter()
            .next()
        else {
            return Err("no certificate value".into());
        };
        println!("CERT {label} {}", hex(&der));
        // The key is found by the certificate's id, as NSS does.
        let ids = session.get_attributes(cert, &[AttributeType::Id])?;
        let by_id =
            session.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY), ids[0].clone()])?;
        assert_eq!(by_id, vec![key]);
        // The private key value is never given out.
        let value = session.get_attributes(key, &[AttributeType::Value]);
        assert!(
            !matches!(value.as_deref(), Ok([Attribute::Value(_)])),
            "{value:?}"
        );
        let mechs = pkcs11.get_mechanism_list(slot)?;
        if label == "ec" {
            assert!(mechs.contains(&MechanismType::ECDSA));
            let sig = session.sign(&Mechanism::Ecdsa, key, &[7; 32])?;
            println!("SIG ec ecdsa {}", hex(&sig));
        } else {
            assert!(mechs.contains(&MechanismType::RSA_PKCS));
            let sig = session.sign(&Mechanism::RsaPkcs, key, DATA)?;
            println!("SIG rsa pkcs {}", hex(&sig));
            let pss = PkcsPssParams {
                hash_alg: MechanismType::SHA256,
                mgf: PkcsMgfType::MGF1_SHA256,
                s_len: Ulong::from(32),
            };
            let sig = session.sign(&Mechanism::RsaPkcsPss(pss), key, &[9; 32])?;
            println!("SIG rsa pss {}", sig.len());
            // An ECDSA mechanism on an RSA key, and a bad mgf, are refused before the service.
            assert!(session.sign(&Mechanism::Ecdsa, key, DATA).is_err());
            let bad = PkcsPssParams {
                mgf: PkcsMgfType::MGF1_SHA384,
                ..pss
            };
            assert!(
                session
                    .sign(&Mechanism::RsaPkcsPss(bad), key, &[9; 32])
                    .is_err()
            );
        }
    }
    Ok(())
}

pub(super) fn first_key(pkcs11: &Pkcs11) -> Result<(Session, ObjectHandle), Box<dyn Error>> {
    let slot = *pkcs11.get_slots_with_token()?.first().ok_or("no token")?;
    let session = pkcs11.open_ro_session(slot)?;
    let key = find(&session, ObjectClass::PRIVATE_KEY)?;
    Ok((session, key))
}

pub(super) fn is_rv(e: &P11Error, rv: RvError) -> bool {
    matches!(e, P11Error::Pkcs11(got, _) if *got == rv)
}

pub(super) fn denied(pkcs11: &Pkcs11) -> TestResult {
    let (session, key) = first_key(pkcs11)?;
    let err = session
        .sign(&Mechanism::Ecdsa, key, &[1; 32])
        .expect_err("signature must be refused");
    assert!(is_rv(&err, RvError::FunctionFailed), "{err:?}");
    // A refusal ends the operation; the next signature starts from scratch and asks again.
    let err = session
        .sign(&Mechanism::Ecdsa, key, &[1; 32])
        .expect_err("still refused");
    assert!(is_rv(&err, RvError::FunctionFailed), "{err:?}");
    Ok(())
}

pub(super) fn unsupported(pkcs11: &Pkcs11) -> TestResult {
    let (session, key) = first_key(pkcs11)?;
    for err in [
        session.generate_random_vec(8).expect_err("random"),
        session.destroy_object(key).expect_err("destroy"),
    ] {
        assert!(is_rv(&err, RvError::FunctionNotSupported), "{err:?}");
    }
    assert!(
        pkcs11
            .open_rw_session(pkcs11.get_slots_with_token()?[0])
            .is_err(),
        "read-write sessions are refused"
    );
    Ok(())
}

pub(super) fn no_service(pkcs11: &Pkcs11) -> TestResult {
    assert_eq!(pkcs11.get_slots_with_token()?, vec![]);
    Ok(())
}

/// Many threads, each with its own session, sign at once.
pub(super) fn threads(pkcs11: &Pkcs11) -> TestResult {
    let pkcs11 = Arc::new(Pkcs11::clone(pkcs11));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let pkcs11 = pkcs11.clone();
            std::thread::spawn(move || -> Result<(), String> {
                for _ in 0..3 {
                    let (session, key) = first_key(&pkcs11).map_err(|e| e.to_string())?;
                    let sig = session
                        .sign(&Mechanism::Ecdsa, key, &[3; 32])
                        .map_err(|e| e.to_string())?;
                    if sig.len() != 64 {
                        return Err("bad length".into());
                    }
                }
                Ok(())
            })
        })
        .collect();
    for w in workers {
        w.join().map_err(|_| "worker panicked")??;
    }
    Ok(())
}

pub(super) fn task_names() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir("/proc/self/task")
        .into_iter()
        .flatten()
        .flatten()
        .map(|t| {
            std::fs::read_to_string(t.path().join("comm"))
                .unwrap_or_default()
                .trim()
                .to_owned()
        })
        .collect();
    names.sort();
    names
}

/// OS threads of this process before `C_Sign`, right after it returns and two seconds later: the
/// module must not leave helper threads behind. A thread started and joined inside the call is
/// not seen (NSS initializes the module with `CKF_LIBRARY_CANT_CREATE_OS_THREADS`).
pub(super) fn tasks(pkcs11: &Pkcs11) -> TestResult {
    let before = task_names();
    let (session, key) = first_key(pkcs11)?;
    session.sign(&Mechanism::Ecdsa, key, &[3; 32])?;
    let after = task_names();
    std::thread::sleep(std::time::Duration::from_secs(2));
    let later = task_names();
    println!("\nTASKS {} {} {}", before.len(), after.len(), later.len());
    println!("NAMES before={before:?} after={after:?} later={later:?}");
    if before.len() != after.len() || before.len() != later.len() {
        return Err("thread count changed around C_Sign".into());
    }
    Ok(())
}

/// `fork` while other threads use the module: the children must not deadlock and can sign.
pub(super) fn forks(pkcs11: &Pkcs11) -> TestResult {
    let pkcs11 = Arc::new(Pkcs11::clone(pkcs11));
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
        // SAFETY: the child only uses the module (which is fork-safe by design) and leaves with
        // `_exit`; `alarm` turns a deadlock in the child into a failure instead of a hang.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe { libc::alarm(60) };
            let ok = first_key(&pkcs11)
                .and_then(|(s, k)| Ok(s.sign(&Mechanism::Ecdsa, k, &[5; 32])?))
                .is_ok();
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
    Ok(())
}
