//! Signing tests: known answers (RSA from OpenSSL, ECDSA from RFC 6979 A.2.5) and verify
//! round trips with an independent public-key operation.

use std::error::Error;

use custodiod::import::parse_p12;
use custodiod::sign::{Mechanism, PssHash, SignError, sign};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::{Pkcs1v15Sign, Pss, RsaPrivateKey};
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use sha2::{Digest, Sha256, Sha384, Sha512};

type TestResult = Result<(), Box<dyn Error>>;

fn fixture_key(name: &str) -> Result<SecretSlice<u8>, Box<dyn Error>> {
    let data = std::fs::read(format!(
        "{}/tests/fixtures/{name}.p12",
        env!("CARGO_MANIFEST_DIR")
    ))?;
    Ok(parse_p12(&data, &SecretString::from("test-password".to_owned()))?.key)
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| s.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
        .collect()
}

/// `openssl pkeyutl -sign -pkeyopt rsa_padding_mode:pkcs1` over `KAT_DATA` with the key in
/// `rsa2048.p12`.
const RSA_KAT_SIG: &str = "5870734fceb049110d43fd1e7dc017f008dd7655e5c12cda7a1b109586aead7757e12bafbe549a819674975ddba25acefb48c1a591b5f5784667db3f8726ee14ac5e0ae7e21448d6292dc08b3f0b6fdeafa142c5735406ca5dbbd47d6384367483d82ed715edd86dc1f44e7c291841e95e5dde8b1ee7fad08ee357fe99093982b4d9be8fa5136bdf71489231b5e061ceb512b4dcc0941e444e568bfb9a235143714f048a670919c37117a6a0fb1f8245878514b5d792439d16bb6d1e8be495bae9b61ac4466e11a0cad37581274fac7aca397f6136a1251a28835620b2f8b8fbe88968a287a495c028738d5b8471eb226ef8bc7141c587196f9cda5f1ab65b31";
const KAT_DATA: &[u8] = b"custodio known-answer test 0001!";

#[test]
fn rsa_pkcs_known_answer() -> TestResult {
    let sig = sign(&fixture_key("rsa2048")?, Mechanism::RsaPkcs, KAT_DATA)?;
    assert_eq!(sig, unhex(RSA_KAT_SIG));
    Ok(())
}

/// DER prefix of `DigestInfo` for SHA-256 (RFC 8017 section 9.2).
const SHA256_DIGEST_INFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

#[test]
fn rsa_pkcs_with_digest_info_verifies_as_sha256() -> TestResult {
    let key = fixture_key("rsa2048")?;
    let digest = Sha256::digest(b"hello");
    let mut info = SHA256_DIGEST_INFO.to_vec();
    info.extend_from_slice(&digest);
    let sig = sign(&key, Mechanism::RsaPkcs, &info)?;
    let public = RsaPrivateKey::from_pkcs8_der(key.expose_secret())?.to_public_key();
    public.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &sig)?;
    assert_eq!(sig.len(), 256);
    Ok(())
}

#[test]
fn rsa_pkcs_rejects_oversized_data() -> TestResult {
    let key = fixture_key("rsa2048")?;
    assert_eq!(
        sign(&key, Mechanism::RsaPkcs, &[0xAA; 246]),
        Err(SignError::BadData)
    );
    assert!(sign(&key, Mechanism::RsaPkcs, &[0xAA; 245]).is_ok());
    Ok(())
}

#[test]
fn rsa_pss_round_trips_for_each_hash() -> TestResult {
    let key = fixture_key("rsa2048")?;
    let public = RsaPrivateKey::from_pkcs8_der(key.expose_secret())?.to_public_key();
    let msg = b"message to sign";

    let d = Sha256::digest(msg);
    let mech = Mechanism::RsaPkcsPss {
        hash: PssHash::Sha256,
        salt_len: 32,
    };
    let sig = sign(&key, mech, &d)?;
    public.verify(Pss::<Sha256>::new_with_salt(32), &d, &sig)?;

    let d = Sha384::digest(msg);
    let mech = Mechanism::RsaPkcsPss {
        hash: PssHash::Sha384,
        salt_len: 48,
    };
    let sig = sign(&key, mech, &d)?;
    public.verify(Pss::<Sha384>::new_with_salt(48), &d, &sig)?;

    let d = Sha512::digest(msg);
    let mech = Mechanism::RsaPkcsPss {
        hash: PssHash::Sha512,
        salt_len: 20,
    };
    let sig = sign(&key, mech, &d)?;
    public.verify(Pss::<Sha512>::new_with_salt(20), &d, &sig)?;
    Ok(())
}

#[test]
fn rsa_pss_is_randomized_and_zero_salt_is_deterministic() -> TestResult {
    let key = fixture_key("rsa2048")?;
    let d = Sha256::digest(b"x");
    let salted = Mechanism::RsaPkcsPss {
        hash: PssHash::Sha256,
        salt_len: 32,
    };
    assert_ne!(sign(&key, salted, &d)?, sign(&key, salted, &d)?);
    let unsalted = Mechanism::RsaPkcsPss {
        hash: PssHash::Sha256,
        salt_len: 0,
    };
    assert_eq!(sign(&key, unsalted, &d)?, sign(&key, unsalted, &d)?);
    Ok(())
}

#[test]
fn rsa_pss_signature_does_not_verify_for_other_digest() -> TestResult {
    let key = fixture_key("rsa2048")?;
    let public = RsaPrivateKey::from_pkcs8_der(key.expose_secret())?.to_public_key();
    let mech = Mechanism::RsaPkcsPss {
        hash: PssHash::Sha256,
        salt_len: 32,
    };
    let sig = sign(&key, mech, &Sha256::digest(b"a"))?;
    assert!(
        public
            .verify(
                Pss::<Sha256>::new_with_salt(32),
                &Sha256::digest(b"b"),
                &sig
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn rsa_pss_rejects_wrong_digest_length_and_huge_salt() -> TestResult {
    let key = fixture_key("rsa2048")?;
    let mech = Mechanism::RsaPkcsPss {
        hash: PssHash::Sha256,
        salt_len: 32,
    };
    assert_eq!(sign(&key, mech, &[0; 31]), Err(SignError::BadData));
    assert_eq!(sign(&key, mech, &[0; 48]), Err(SignError::BadData));
    let huge = Mechanism::RsaPkcsPss {
        hash: PssHash::Sha256,
        salt_len: 300,
    };
    assert_eq!(sign(&key, huge, &[0; 32]), Err(SignError::BadData));
    Ok(())
}

/// RFC 6979 A.2.5: P-256 private key.
const RFC6979_X: &str = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";

fn rfc6979_key() -> Result<SecretSlice<u8>, Box<dyn Error>> {
    let sk = SigningKey::from_slice(&unhex(RFC6979_X))?;
    let der = sk.to_pkcs8_der()?;
    Ok(SecretSlice::from(der.as_bytes().to_vec()))
}

#[test]
fn ecdsa_p256_rfc6979_known_answer() -> TestResult {
    // SHA-256("sample"), deterministic nonce, RFC 6979 A.2.5.
    let sig = sign(
        &rfc6979_key()?,
        Mechanism::Ecdsa,
        &Sha256::digest(b"sample"),
    )?;
    let want = unhex(
        "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716\
         F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
    );
    assert_eq!(sig, want);
    let sig = sign(&rfc6979_key()?, Mechanism::Ecdsa, &Sha256::digest(b"test"))?;
    let want = unhex(
        "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367\
         019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",
    );
    assert_eq!(sig, want);
    Ok(())
}

#[test]
fn ecdsa_round_trips_with_fixture_key() -> TestResult {
    let key = fixture_key("p256")?;
    let digest = Sha256::digest(b"hello");
    let sig = sign(&key, Mechanism::Ecdsa, &digest)?;
    assert_eq!(sig.len(), 64);
    let public = VerifyingKey::from(SigningKey::from_pkcs8_der(key.expose_secret())?);
    public.verify_prehash(&digest, &Signature::from_slice(&sig)?)?;
    assert!(
        public
            .verify_prehash(&Sha256::digest(b"other"), &Signature::from_slice(&sig)?)
            .is_err()
    );
    Ok(())
}

#[test]
fn ecdsa_accepts_longer_digests() -> TestResult {
    let key = fixture_key("p256")?;
    let digest = Sha384::digest(b"hello");
    let sig = sign(&key, Mechanism::Ecdsa, &digest)?;
    let public = VerifyingKey::from(SigningKey::from_pkcs8_der(key.expose_secret())?);
    public.verify_prehash(&digest, &Signature::from_slice(&sig)?)?;
    Ok(())
}

#[test]
fn ecdsa_long_digest_standard_result() -> TestResult {
    let key = fixture_key("p256")?;
    let public = VerifyingKey::from(SigningKey::from_pkcs8_der(key.expose_secret())?);
    let digests = [
        Sha384::digest(b"hello").to_vec(),
        Sha512::digest(b"hello").to_vec(),
    ];
    for digest in digests {
        let sig = Signature::from_slice(&sign(&key, Mechanism::Ecdsa, &digest)?)?;
        // FIPS 186 / SEC 1: the leftmost 32 bytes; the rightmost ones must not verify.
        public.verify_prehash(digest.get(..32).unwrap_or_default(), &sig)?;
        let right = digest.get(digest.len() - 32..).unwrap_or_default();
        assert!(public.verify_prehash(right, &sig).is_err());
        if let Some(ok) = openssl_verify(&public, &digest, &sig)? {
            assert!(ok, "openssl rejects the signature");
        }
    }
    Ok(())
}

/// `openssl pkeyutl -verify` over the digest; `None` if the binary is missing.
fn openssl_verify(
    public: &VerifyingKey,
    digest: &[u8],
    sig: &Signature,
) -> Result<Option<bool>, Box<dyn Error>> {
    use p256::pkcs8::EncodePublicKey;
    let dir = tempfile::tempdir()?;
    let (pem, dgst, sigf) = (
        dir.path().join("pub.pem"),
        dir.path().join("digest"),
        dir.path().join("sig"),
    );
    std::fs::write(
        &pem,
        public.to_public_key_pem(pkcs8::spki::der::pem::LineEnding::LF)?,
    )?;
    std::fs::write(&dgst, digest)?;
    std::fs::write(&sigf, sig.to_der().as_bytes())?;
    let status = std::process::Command::new("openssl")
        .args(["pkeyutl", "-verify", "-pubin", "-inkey"])
        .arg(&pem)
        .arg("-in")
        .arg(&dgst)
        .arg("-sigfile")
        .arg(&sigf)
        .output();
    Ok(match status {
        Ok(out) => Some(out.status.success()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    })
}

#[test]
fn ecdsa_rejects_empty_data() -> TestResult {
    assert_eq!(
        sign(&fixture_key("p256")?, Mechanism::Ecdsa, &[]),
        Err(SignError::BadData)
    );
    Ok(())
}

#[test]
fn mechanism_must_match_key_type() -> TestResult {
    let rsa = fixture_key("rsa2048")?;
    let ec = fixture_key("p256")?;
    let pss = Mechanism::RsaPkcsPss {
        hash: PssHash::Sha256,
        salt_len: 32,
    };
    assert_eq!(
        sign(&rsa, Mechanism::Ecdsa, &[0; 32]),
        Err(SignError::MechanismMismatch)
    );
    assert_eq!(
        sign(&ec, Mechanism::RsaPkcs, &[0; 32]),
        Err(SignError::MechanismMismatch)
    );
    assert_eq!(sign(&ec, pss, &[0; 32]), Err(SignError::MechanismMismatch));
    Ok(())
}

#[test]
fn garbage_key_is_rejected_without_leaking_it() {
    let key = SecretSlice::from(vec![1_u8, 2, 3]);
    let err = sign(&key, Mechanism::Ecdsa, &[0; 32]);
    assert_eq!(err, Err(SignError::BadKey));
    assert!(!format!("{err:?}{}", SignError::BadKey).contains("[1, 2, 3]"));
}

#[test]
fn ecdsa_never_panics_on_any_short_or_long_length() -> TestResult {
    let key = fixture_key("p256")?;
    for len in 0..=100 {
        let _ = sign(&key, Mechanism::Ecdsa, &vec![0x5A; len]);
    }
    Ok(())
}
