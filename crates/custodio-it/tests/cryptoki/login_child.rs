//! Child scenarios for `C_Login` and `C_Logout`.

use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use cryptoki_sys::{CK_ULONG, CKM_ECDSA, CKM_RSA_PKCS, CKR_FUNCTION_FAILED, CKR_OK};

use super::composed::expected_input;
use super::composed_child::{Raw, composed_for, each_token};
use super::*;

/// The setup both login scenarios share: list the slots, open a session, list the objects.
fn setup(pkcs11: &Pkcs11) -> Result<Session, Box<dyn Error>> {
    let (session, _) = first_key(pkcs11)?;
    assert_eq!(session.find_objects(&[])?.len(), 2);
    Ok(session)
}

/// The setup and nothing else.
pub(super) fn login_baseline(pkcs11: &Pkcs11) -> TestResult {
    drop(setup(pkcs11)?);
    Ok(())
}

/// Every login variant and a logout, through the `cryptoki` crate.
pub(super) fn login_variants(pkcs11: &Pkcs11) -> TestResult {
    let session = setup(pkcs11)?;
    let empty = AuthPin::from(String::new());
    let arbitrary = AuthPin::from("arbitrary pin 12345".to_owned());
    for user in [UserType::User, UserType::ContextSpecific] {
        session.login(user, None)?;
        session.login(user, Some(&empty))?;
        session.login(user, Some(&arbitrary))?;
    }
    session.logout()?;
    session.login(UserType::User, None)?;
    session.logout()?;
    session.logout()?;
    for pin in [None, Some(&arbitrary)] {
        let err = session
            .login(UserType::So, pin)
            .expect_err("the security officer cannot log in");
        assert!(is_rv(&err, RvError::SessionReadOnlyExists), "{err:?}");
    }
    drop(session);
    Ok(())
}

/// Token flags, `CKA_ALWAYS_AUTHENTICATE` and the mechanism list, before and after a login.
pub(super) fn login_flags(pkcs11: &Pkcs11) -> TestResult {
    let arbitrary = AuthPin::from("arbitrary pin 12345".to_owned());
    each_token(pkcs11, |label, session, key, _| {
        let slot = session.get_session_info()?.slot_id();
        let look = || -> Result<_, Box<dyn Error>> {
            let info = pkcs11.get_token_info(slot)?;
            assert!(!info.login_required(), "{label}");
            assert!(!info.protected_authentication_path(), "{label}");
            let always = session.get_attributes(key, &[AttributeType::AlwaysAuthenticate])?;
            assert_eq!(
                always,
                vec![Attribute::AlwaysAuthenticate(false)],
                "{label}"
            );
            let mut mechs: Vec<u64> = pkcs11
                .get_mechanism_list(slot)?
                .into_iter()
                .map(Into::into)
                .collect();
            mechs.sort_unstable();
            Ok((format!("{info:?}"), always, mechs))
        };
        let before = look()?;
        session.login(UserType::User, Some(&arbitrary))?;
        session.login(UserType::ContextSpecific, None)?;
        assert_eq!(look()?, before, "{label}: after login");
        session.logout()?;
        assert_eq!(look()?, before, "{label}: after logout");
        Ok(())
    })
}

/// The message `login_sign` signs with a raw mechanism: the service must be sent exactly what the
/// composed mechanism would send.
fn raw_input(label: &str, msg: &[u8]) -> Vec<u8> {
    expected_input(
        if label == "ec" {
            "ecdsa-sha256"
        } else {
            "rsa-sha256"
        },
        msg,
    )
}

/// Per token three signatures after logins: a raw one after `CKU_USER`, a raw one with a
/// `CKU_CONTEXT_SPECIFIC` login between `C_SignInit` and `C_Sign`, and a composed one.
pub(super) fn login_sign(pkcs11: &Pkcs11) -> TestResult {
    let raw = Raw::load()?;
    let msg = message(COMPOSED_LEN);
    each_token(pkcs11, |label, session, key, _| {
        let (ckm, name) = if label == "ec" {
            (CKM_ECDSA, "ecdsa-sha256")
        } else {
            (CKM_RSA_PKCS, "rsa-sha256")
        };
        let input = raw_input(label, &msg);
        let mut sig = vec![0_u8; if label == "ec" { 64 } else { 256 }];
        let mut len = sig.len() as CK_ULONG;
        session.login(UserType::User, None)?;
        assert_eq!(raw.init(session, key, ckm), CKR_OK);
        assert_eq!(raw.sign(session, &input, Some(&mut sig), &mut len), CKR_OK);
        println!("SIG {label} {name} {}", hex(&sig));

        assert_eq!(raw.init(session, key, ckm), CKR_OK);
        session.login(UserType::ContextSpecific, None)?;
        len = sig.len() as CK_ULONG;
        assert_eq!(raw.sign(session, &input, Some(&mut sig), &mut len), CKR_OK);
        println!("SIG {label} {name} {}", hex(&sig));

        session.logout()?;
        session.login(UserType::User, None)?;
        let [(mechanism, composed), ..] = composed_for(label);
        let sig = session.sign(&mechanism, key, &msg)?;
        println!("SIG {label} {composed} {}", hex(&sig));
        Ok(())
    })
}

/// A multi-part operation survives a login and a logout; on an RSA key the result is the
/// signature of the same operation without them. Prints both.
pub(super) fn login_open_operation(pkcs11: &Pkcs11) -> TestResult {
    let msg = message(COMPOSED_LEN);
    each_token(pkcs11, |label, session, key, _| {
        if label != "rsa" {
            return Ok(());
        }
        for with_login in [false, true] {
            session.sign_init(&Mechanism::Sha256RsaPkcs, key)?;
            session.sign_update(&msg[..100])?;
            if with_login {
                session.login(UserType::User, None)?;
                session.logout()?;
            }
            session.sign_update(&msg[100..])?;
            let sig = session.sign_final()?;
            println!("SIG {label} rsa-sha256 {}", hex(&sig));
        }
        Ok(())
    })
}

/// Polkit refuses: a login changes nothing, and every attempt asks again.
pub(super) fn login_denied(pkcs11: &Pkcs11) -> TestResult {
    let raw = Raw::load()?;
    let (session, key) = first_key(pkcs11)?;
    for _ in 0..2 {
        session.login(UserType::User, None)?;
        assert_eq!(raw.init(&session, key, CKM_ECDSA), CKR_OK);
        let mut out = [0xAA_u8; 64];
        let mut len: CK_ULONG = 64;
        assert_eq!(
            raw.sign(&session, &[1; 32], Some(&mut out), &mut len),
            CKR_FUNCTION_FAILED
        );
        println!(
            "\nUNTOUCHED {}",
            out.iter().all(|b| *b == 0xAA) && len == 64
        );
        session.logout()?;
    }
    Ok(())
}
