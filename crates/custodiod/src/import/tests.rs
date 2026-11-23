use super::*;
use crate::creds::seal;
use crate::store::Protected;

#[test]
fn rollback_import_removes_the_record_and_nothing_else() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    let creds = crate::creds::memory::MemoryCreds::host();
    let key = SecretSlice::from(vec![1_u8]);
    for id in ["a", "b"] {
        let sealed = seal(&creds, &credential_name(7, id), &key)?;
        let protected = Protected::from_sealed(&sealed);
        let kind = protected.natural_kind();
        store.put(&Record::new(7, id, kind, b"cert", protected)?)?;
    }
    rollback_import(&store, 7, "a")?;
    assert_eq!(store.list(7)?, ["b"]);
    // Rolling back what is not there is not an error.
    rollback_import(&store, 7, "a")?;
    assert_eq!(store.list(7)?, ["b"]);
    Ok(())
}

#[test]
fn the_credential_name_binds_owner_and_id() {
    assert_eq!(credential_name(1000, "my-key"), "custodio-1000-my-key");
    assert_ne!(credential_name(1, "a"), credential_name(2, "a"));
    assert_ne!(credential_name(1, "a"), credential_name(1, "b"));
}

#[test]
fn every_import_error_has_its_own_message() {
    let cases = [
        (ImportError::TooLarge, "larger than"),
        (ImportError::WrongPassword, "does not match the MAC"),
        (ImportError::WrongPasswordOrBad, "wrong password or corrupt"),
        (
            ImportError::Unreadable("bad der".into()),
            "read the .p12 file: bad der",
        ),
        (ImportError::NoPrivateKey, "no private key"),
        (ImportError::MultipleKeys, "more than one private key"),
        (ImportError::NoCertificate, "has no certificate"),
        (ImportError::CertificateMismatch, "matches the private key"),
        (
            ImportError::UnsupportedKey("RSA 4096".into()),
            "unsupported key: RSA 4096;",
        ),
        (
            ImportError::Store(StoreError::AlreadyExists),
            "cannot store the key: ",
        ),
    ];
    for (error, expected) in cases {
        let message = error.to_string();
        assert!(message.contains(expected), "{message:?} lacks {expected:?}");
    }
}

#[test]
fn a_p256_curve_under_another_algorithm_is_not_an_ecdsa_key()
-> Result<(), Box<dyn std::error::Error>> {
    let cert = include_bytes!("../../tests/fixtures/cert-p256-other.der");
    assert!(cert_public_key(KeyKind::EcdsaP256, cert).is_some());
    // id-ecPublicKey (1.2.840.10045.2.1) to 1.2.840.10045.2.2, the P-256 parameter kept.
    let ec_public_key = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    let at = cert
        .windows(ec_public_key.len())
        .position(|w| w == ec_public_key)
        .ok_or("no id-ecPublicKey")?;
    let mut other = cert.to_vec();
    *other.get_mut(at + 8).ok_or("short")? = 0x02;
    assert_eq!(cert_public_key(KeyKind::EcdsaP256, &other), None);
    Ok(())
}

#[test]
fn an_rsa_key_under_another_algorithm_is_not_an_rsa2048_key()
-> Result<(), Box<dyn std::error::Error>> {
    let cert = include_bytes!("../../tests/fixtures/cert-rsa2048-other.der");
    assert!(cert_public_key(KeyKind::Rsa2048, cert).is_some());
    // rsaEncryption (1.2.840.113549.1.1.1) to id-RSASSA-PSS (1.2.840.113549.1.1.10): the same SEQUENCE(n, e).
    let rsa_encryption = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ];
    let at = cert
        .windows(rsa_encryption.len())
        .position(|w| w == rsa_encryption)
        .ok_or("no rsaEncryption")?;
    let mut other = cert.to_vec();
    *other.get_mut(at + 10).ok_or("short")? = 0x0a;
    assert_eq!(cert_public_key(KeyKind::Rsa2048, &other), None);
    Ok(())
}

/// The three failures of docs/findings/F195.md, by the file and the password.
#[test]
fn a_failed_parse_is_told_by_the_librarys_result() -> Result<(), Box<dyn std::error::Error>> {
    // (file, with the right password, with a wrong one): a = MAC does not verify, b = unreadable, c = cannot tell.
    let table = [
        ("nokey.p12", 'b', 'a'),
        ("nokey-nomac.p12", 'b', 'b'),
        ("nocert.p12", 'b', 'a'),
        ("nocert-nomac.p12", 'b', 'c'),
        ("twokeys.p12", 'b', 'a'),
        ("twokeys-nomac.p12", 'b', 'c'),
        ("notp12.bin", 'b', 'b'),
        ("good-nomac.p12", 'o', 'c'),
        ("p256.p12", 'o', 'a'),
        ("rsa2048-nss.p12", 'o', 'a'),
    ];
    let letter = |r: Result<ParsedP12, ImportError>| match r {
        Ok(_) => 'o',
        Err(ImportError::WrongPassword) => 'a',
        Err(ImportError::WrongPasswordOrBad) => 'c',
        Err(_) => 'b',
    };
    for (name, right, wrong) in table {
        let data = std::fs::read(format!(
            "{}/tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))?;
        let got = |pw: &str| letter(parse_p12(&data, &SecretString::from(pw.to_owned())));
        assert_eq!(got("test-password"), right, "{name} right password");
        assert_eq!(got("wrong"), wrong, "{name} wrong password");
    }
    Ok(())
}

/// A failed decryption after a verified MAC is a corrupt file, not a wrong password (docs/findings/F195.md).
#[test]
fn a_decryption_failure_is_the_combined_error_only_without_a_mac() {
    let e = P12Error::Pkcs5Error("bad padding".into());
    assert!(matches!(
        classify_p12_error(&e, false),
        ImportError::WrongPasswordOrBad
    ));
    assert!(matches!(
        classify_p12_error(&e, true),
        ImportError::Unreadable(_)
    ));
}

#[test]
fn a_mac_is_seen_in_the_outer_structure_of_der_and_ber_files() -> Result<(), std::io::Error> {
    for (name, mac) in [
        ("p256.p12", true),
        ("rsa2048-nss.p12", true),
        ("good-nomac.p12", false),
        ("twokeys-nomac.p12", false),
        ("notp12.bin", false),
    ] {
        let data = std::fs::read(format!(
            "{}/tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))?;
        assert_eq!(ber::has_mac(&data), mac, "{name}");
    }
    Ok(())
}
