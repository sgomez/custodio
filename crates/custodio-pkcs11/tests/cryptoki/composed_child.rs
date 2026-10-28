//! Child scenarios for the composed mechanisms.

use cryptoki_sys::{
    CK_FUNCTION_LIST, CK_FUNCTION_LIST_PTR, CK_MECHANISM, CK_MECHANISM_TYPE, CK_RV, CK_ULONG,
    CKM_ECDSA, CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512, CKM_RSA_PKCS,
    CKM_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS,
    CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED, CKR_OK, CKR_OPERATION_NOT_INITIALIZED,
};

use super::*;

/// The composed mechanisms of each token, by token label.
pub(super) fn composed_for(label: &str) -> [(Mechanism<'static>, &'static str); 3] {
    if label == "ec" {
        [
            (Mechanism::EcdsaSha256, "ecdsa-sha256"),
            (Mechanism::EcdsaSha384, "ecdsa-sha384"),
            (Mechanism::EcdsaSha512, "ecdsa-sha512"),
        ]
    } else {
        [
            (Mechanism::Sha256RsaPkcs, "rsa-sha256"),
            (Mechanism::Sha384RsaPkcs, "rsa-sha384"),
            (Mechanism::Sha512RsaPkcs, "rsa-sha512"),
        ]
    }
}

/// Opens a session on every token and hands the label, session and key to `each`.
fn each_token(
    pkcs11: &Pkcs11,
    mut each: impl FnMut(&str, &Session, ObjectHandle, &[u8]) -> TestResult,
) -> TestResult {
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
        println!("\nCERT {label} {}", hex(&der));
        each(&label, &session, key, &der)?;
    }
    Ok(())
}

fn types(list: &[MechanismType]) -> Vec<CK_MECHANISM_TYPE> {
    let mut v: Vec<CK_MECHANISM_TYPE> = list.iter().map(|m| (*m).into()).collect();
    v.sort_unstable();
    v
}

fn sorted(mut v: Vec<CK_MECHANISM_TYPE>) -> Vec<CK_MECHANISM_TYPE> {
    v.sort_unstable();
    v
}

/// Exact mechanism lists and `C_GetMechanismInfo` of both tokens.
pub(super) fn mechanisms(pkcs11: &Pkcs11) -> TestResult {
    let rsa = [
        CKM_RSA_PKCS,
        CKM_RSA_PKCS_PSS,
        CKM_SHA256_RSA_PKCS,
        CKM_SHA384_RSA_PKCS,
        CKM_SHA512_RSA_PKCS,
    ];
    let ec = [
        CKM_ECDSA,
        CKM_ECDSA_SHA256,
        CKM_ECDSA_SHA384,
        CKM_ECDSA_SHA512,
    ];
    let slots = pkcs11.get_slots_with_token()?;
    assert_eq!(slots.len(), 2);
    for slot in slots {
        let label = pkcs11.get_token_info(slot)?.label().to_owned();
        let (own, other) = if label == "ec" {
            (&ec[..], &rsa[..])
        } else {
            (&rsa[..], &ec[..])
        };
        let listed = pkcs11.get_mechanism_list(slot)?;
        assert_eq!(types(&listed), sorted(own.to_vec()), "{label}");
        let as_set: std::collections::HashSet<_> = types(&listed).into_iter().collect();
        assert_eq!(as_set, own.iter().copied().collect(), "{label}");
        for m in own {
            let info = pkcs11.get_mechanism_info(slot, MechanismType::try_from(*m)?)?;
            assert!(info.sign() && !info.verify(), "{label} {m:#x}");
        }
        for m in other {
            assert!(
                pkcs11
                    .get_mechanism_info(slot, MechanismType::try_from(*m)?)
                    .is_err(),
                "{label} {m:#x} must not be described"
            );
        }
    }
    Ok(())
}

/// Every composed mechanism on its own token, over a message of known content.
pub(super) fn composed_sign(pkcs11: &Pkcs11) -> TestResult {
    let msg = message(COMPOSED_LEN);
    each_token(pkcs11, |label, session, key, _| {
        for (mechanism, name) in composed_for(label) {
            let sig = session.sign(&mechanism, key, &msg)?;
            println!("SIG {label} {name} {}", hex(&sig));
        }
        Ok(())
    })
}

/// A 64 MiB message, far over the service's input limit.
pub(super) fn composed_large(pkcs11: &Pkcs11) -> TestResult {
    let msg = message(LARGE_LEN);
    each_token(pkcs11, |label, session, key, _| {
        let (mechanism, name) = if label == "ec" {
            (Mechanism::EcdsaSha384, "ecdsa-sha384")
        } else {
            (Mechanism::Sha256RsaPkcs, "rsa-sha256")
        };
        let sig = session.sign(&mechanism, key, &msg)?;
        println!("SIG {label} {name} {}", hex(&sig));
        Ok(())
    })
}

/// Each composed mechanism on the other kind of token: refused before the service.
pub(super) fn composed_refusals(pkcs11: &Pkcs11) -> TestResult {
    each_token(pkcs11, |label, session, key, _| {
        let other = composed_for(if label == "ec" { "rsa" } else { "ec" });
        for (mechanism, name) in other {
            let err = session
                .sign(&mechanism, key, DATA)
                .expect_err("a mismatched mechanism must be refused");
            assert!(
                is_rv(&err, RvError::KeyTypeInconsistent),
                "{label} {name}: {err:?}"
            );
        }
        Ok(())
    })
}

/// The module's own function list, to call `C_Sign` with a NULL or short buffer.
struct Raw {
    list: CK_FUNCTION_LIST,
    _library: libloading::Library,
}

impl Raw {
    fn load() -> Result<Self, Box<dyn Error>> {
        // SAFETY: loads the module the scenario already loaded; `C_GetFunctionList` has this type.
        unsafe {
            let library = libloading::Library::new(std::env::var(MODULE_VAR)?)?;
            let get: libloading::Symbol<unsafe extern "C" fn(*mut CK_FUNCTION_LIST_PTR) -> CK_RV> =
                library.get(b"C_GetFunctionList")?;
            let mut list: CK_FUNCTION_LIST_PTR = std::ptr::null_mut();
            assert_eq!(get(&raw mut list), CKR_OK);
            Ok(Self {
                list: *list.as_ref().ok_or("no function list")?,
                _library: library,
            })
        }
    }

    fn init(&self, session: &Session, key: ObjectHandle, mechanism: CK_MECHANISM_TYPE) -> CK_RV {
        let mut m = CK_MECHANISM {
            mechanism,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let f = self.list.C_SignInit.expect("C_SignInit");
        // SAFETY: `m` is a live local; the handles come from the loaded module.
        unsafe { f(session.handle(), &raw mut m, key.handle()) }
    }

    fn sign(
        &self,
        session: &Session,
        data: &[u8],
        out: Option<&mut [u8]>,
        len: &mut CK_ULONG,
    ) -> CK_RV {
        let f = self.list.C_Sign.expect("C_Sign");
        let buffer = out.map_or(std::ptr::null_mut(), <[u8]>::as_mut_ptr);
        // SAFETY: `data` and `buffer` are live for the sizes given; `len` is a live local.
        unsafe {
            f(
                session.handle(),
                data.as_ptr().cast_mut(),
                data.len() as CK_ULONG,
                buffer,
                len,
            )
        }
    }
}

/// Length query, short buffer, then the real call, with one `C_SignInit`.
pub(super) fn composed_retry(pkcs11: &Pkcs11) -> TestResult {
    let raw = Raw::load()?;
    let msg = message(COMPOSED_LEN);
    each_token(pkcs11, |label, session, key, _| {
        let (mechanism, name, n) = if label == "ec" {
            (CKM_ECDSA_SHA256, "ecdsa-sha256", 64)
        } else {
            (CKM_SHA256_RSA_PKCS, "rsa-sha256", 256)
        };
        assert_eq!(raw.init(session, key, mechanism), CKR_OK);
        let mut len: CK_ULONG = 0;
        assert_eq!(raw.sign(session, &msg, None, &mut len), CKR_OK);
        assert_eq!(len, n);
        let mut short = [0xAA_u8; 1];
        len = 1;
        assert_eq!(
            raw.sign(session, &msg, Some(&mut short), &mut len),
            CKR_BUFFER_TOO_SMALL
        );
        assert_eq!(len, n);
        assert_eq!(short, [0xAA]);
        let mut sig = vec![0_u8; usize::try_from(n)?];
        assert_eq!(raw.sign(session, &msg, Some(&mut sig), &mut len), CKR_OK);
        assert_eq!(len, n);
        println!("SIG {label} {name} {}", hex(&sig));
        Ok(())
    })
}

/// Polkit refuses: no bytes come back, every attempt asks again, the operation is over.
pub(super) fn composed_denied(pkcs11: &Pkcs11) -> TestResult {
    let raw = Raw::load()?;
    let (session, key) = first_key(pkcs11)?;
    let mut out = [0xAA_u8; 64];
    for _ in 0..2 {
        assert_eq!(raw.init(&session, key, CKM_ECDSA_SHA256), CKR_OK);
        let mut len: CK_ULONG = 64;
        assert_eq!(
            raw.sign(&session, DATA, Some(&mut out), &mut len),
            CKR_FUNCTION_FAILED
        );
        println!(
            "\nUNTOUCHED {}",
            out.iter().all(|b| *b == 0xAA) && len == 64
        );
    }
    let mut len: CK_ULONG = 64;
    assert_eq!(
        raw.sign(&session, DATA, Some(&mut out), &mut len),
        CKR_OPERATION_NOT_INITIALIZED
    );
    Ok(())
}
