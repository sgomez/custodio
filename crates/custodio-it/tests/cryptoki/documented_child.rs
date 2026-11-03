//! The child half of the documented-API scenarios: what the module shows for the uid the service
//! was told is calling.

use super::*;

/// Prints `TOKEN <label> <certificate hex>` for every token, then `TOKENS <count>`.
fn print_tokens(pkcs11: &Pkcs11) -> TestResult {
    let slots = pkcs11.get_slots_with_token()?;
    for slot in &slots {
        let label = pkcs11.get_token_info(*slot)?.label().to_owned();
        let session = pkcs11.open_ro_session(*slot)?;
        let cert = find(&session, ObjectClass::CERTIFICATE)?;
        let Some(Attribute::Value(der)) = session
            .get_attributes(cert, &[AttributeType::Value])?
            .into_iter()
            .next()
        else {
            return Err("no certificate value".into());
        };
        // A token holds a certificate and its key, nothing else.
        assert_eq!(session.find_objects(&[])?.len(), 2, "objects of {label}");
        println!("\nTOKEN {label} {}", hex(&der));
    }
    println!("TOKENS {}", slots.len());
    Ok(())
}

/// Every token and its certificate.
pub(super) fn tokens(pkcs11: &Pkcs11) -> TestResult {
    print_tokens(pkcs11)
}

/// Signs with the key of the token labelled `label`; `NOTOKEN` if there is none.
pub(super) fn sign_with(pkcs11: &Pkcs11, label: &str) -> TestResult {
    for slot in pkcs11.get_slots_with_token()? {
        if pkcs11.get_token_info(slot)?.label() != label {
            continue;
        }
        let session = pkcs11.open_ro_session(slot)?;
        let key = find(&session, ObjectClass::PRIVATE_KEY)?;
        let sig = if pkcs11
            .get_mechanism_list(slot)?
            .contains(&MechanismType::RSA_PKCS)
        {
            session.sign(&Mechanism::RsaPkcs, key, DATA)
        } else {
            session.sign(&Mechanism::Ecdsa, key, &[7; 32])
        };
        match sig {
            Ok(sig) => println!("\nSIG {label} {}", hex(&sig)),
            Err(e) => println!("\nSIGERR {label} {e:?}"),
        }
        return Ok(());
    }
    println!("\nNOTOKEN {label}");
    Ok(())
}

/// Waits for the parent to say go.
fn wait_for_parent() -> TestResult {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(())
}

/// The same loaded module before and after the parent changed something at the service: no
/// restart, no new `C_Initialize`.
pub(super) fn held_tokens(pkcs11: &Pkcs11) -> TestResult {
    print_tokens(pkcs11)?;
    println!("READY");
    wait_for_parent()?;
    print_tokens(pkcs11)?;
    println!("DONE");
    Ok(())
}

/// A key handle taken before the parent deletes the key is used after it.
pub(super) fn held_key(pkcs11: &Pkcs11) -> TestResult {
    let slots = pkcs11.get_slots_with_token()?;
    let mut held = None;
    for slot in slots {
        if pkcs11.get_token_info(slot)?.label() == "ec" {
            let session = pkcs11.open_ro_session(slot)?;
            let key = find(&session, ObjectClass::PRIVATE_KEY)?;
            held = Some((session, key));
        }
    }
    let (session, key) = held.ok_or("no ec token")?;
    session.sign(&Mechanism::Ecdsa, key, &[7; 32])?;
    println!("\nREADY");
    wait_for_parent()?;
    match session.sign(&Mechanism::Ecdsa, key, &[7; 32]) {
        Ok(_) => println!("OLDSIGN ok"),
        Err(e) => println!("OLDSIGN err {e:?}"),
    }
    print_tokens(pkcs11)?;
    println!("DONE");
    Ok(())
}
