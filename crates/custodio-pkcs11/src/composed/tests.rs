use std::error::Error;

use const_oid::db::rfc5912::{ID_SHA_256, ID_SHA_384, ID_SHA_512};
use cryptoki_sys::{
    CKM_ECDSA, CKM_ECDSA_SHA1, CKM_ECDSA_SHA224, CKM_RSA_PKCS, CKM_RSA_PKCS_PSS, CKM_SHA1_RSA_PKCS,
    CKM_SHA224_RSA_PKCS, CKM_SHA256,
};
use custodiod::sign::{Mechanism, sign};
use der::Encode;
use der::asn1::{Null, OctetString};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::{Digest, Sha256, Sha384, Sha512};
use rsa::signature::Verifier as _;
use rsa::{RsaPrivateKey, RsaPublicKey};
use secrecy::SecretSlice;
use spki::AlgorithmIdentifierOwned;

use super::*;

type TestResult = Result<(), Box<dyn Error>>;

const ALL: [Composed; 6] = [
    Composed::Sha256RsaPkcs,
    Composed::Sha384RsaPkcs,
    Composed::Sha512RsaPkcs,
    Composed::EcdsaSha256,
    Composed::EcdsaSha384,
    Composed::EcdsaSha512,
];

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| s.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
        .collect()
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn hashed(hash: Hash, chunks: &[&[u8]]) -> Vec<u8> {
    let mut h = DigestHasher::new(hash);
    for c in chunks {
        h.update(c);
    }
    h.finalize()
}

#[test]
fn mapping_table() {
    // (CKM value from PKCS#11 v2.40 / SPEC.md section 1, hash, key type, raw mechanism)
    let rows = [
        (0x40, Hash::Sha256, KeyType::Rsa, 0x1),
        (0x41, Hash::Sha384, KeyType::Rsa, 0x1),
        (0x42, Hash::Sha512, KeyType::Rsa, 0x1),
        (0x1044, Hash::Sha256, KeyType::EcP256, 0x1041),
        (0x1045, Hash::Sha384, KeyType::EcP256, 0x1041),
        (0x1046, Hash::Sha512, KeyType::EcP256, 0x1041),
    ];
    for (composed, (ckm, hash, key_type, raw)) in ALL.into_iter().zip(rows) {
        assert_eq!(composed.ckm(), ckm);
        assert_eq!(Composed::from_ckm(ckm), Some(composed));
        assert_eq!(composed.hash(), hash);
        assert_eq!(composed.key_type(), key_type);
        assert_eq!(composed.raw(), raw);
    }
}

#[test]
fn rejects_non_composed() {
    for ckm in [
        CKM_RSA_PKCS,
        CKM_ECDSA,
        CKM_RSA_PKCS_PSS,
        CKM_SHA256,
        CKM_SHA1_RSA_PKCS,
        CKM_ECDSA_SHA1,
        CKM_SHA224_RSA_PKCS,
        CKM_ECDSA_SHA224,
        0,
    ] {
        assert_eq!(Composed::from_ckm(ckm), None, "{ckm:#x}");
    }
}

const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const SHA384_ABC: &str = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7";
const SHA512_ABC: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

#[test]
fn hash_known_answers() {
    let long = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let long2 = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    let cases: [(Hash, &[u8], &str); 9] = [
        (
            Hash::Sha256,
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (Hash::Sha256, b"abc", SHA256_ABC),
        (
            Hash::Sha256,
            long,
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        (
            Hash::Sha384,
            b"",
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        ),
        (Hash::Sha384, b"abc", SHA384_ABC),
        (
            Hash::Sha384,
            long2,
            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
        ),
        (
            Hash::Sha512,
            b"",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ),
        (Hash::Sha512, b"abc", SHA512_ABC),
        (
            Hash::Sha512,
            long2,
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        ),
    ];
    for (hash, data, expected) in cases {
        assert_eq!(hex(&hashed(hash, &[data])), expected, "{hash:?}");
    }
}

#[test]
fn incremental_equals_one_shot() {
    let message: Vec<u8> = (0..1000u32)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect();
    for hash in [Hash::Sha256, Hash::Sha384, Hash::Sha512] {
        let whole = hashed(hash, &[&message]);
        for size in [1, 7, message.len()] {
            let chunks: Vec<&[u8]> = message.chunks(size).collect();
            assert_eq!(hashed(hash, &chunks), whole, "{hash:?} {size}");
        }
    }
}

#[test]
fn clone_keeps_state() {
    for hash in [Hash::Sha256, Hash::Sha384, Hash::Sha512] {
        let mut h = DigestHasher::new(hash);
        h.update(b"ab");
        let clone = h.clone();
        let from_clone = clone.finalize();
        h.update(b"c");
        assert_eq!(from_clone, hashed(hash, &[b"ab"]));
        assert_eq!(h.finalize(), hashed(hash, &[b"abc"]));
    }
}

#[test]
fn digest_info_prefix_rfc8017() -> TestResult {
    let rows = [
        (
            Hash::Sha256,
            "3031300d060960864801650304020105000420",
            ID_SHA_256,
        ),
        (
            Hash::Sha384,
            "3041300d060960864801650304020205000430",
            ID_SHA_384,
        ),
        (
            Hash::Sha512,
            "3051300d060960864801650304020305000440",
            ID_SHA_512,
        ),
    ];
    for (hash, prefix, oid) in rows {
        let digest: Vec<u8> = (0..hash.len())
            .map(|i| u8::try_from(i).unwrap_or(0))
            .collect();
        let got = digest_info(hash, &digest)?;
        let mut literal = unhex(prefix);
        literal.extend_from_slice(&digest);
        assert_eq!(got, literal, "{hash:?}");

        let alg = AlgorithmIdentifierOwned {
            oid,
            parameters: Some(der::Any::encode_from(&Null)?),
        };
        let mut body = alg.to_der()?;
        body.extend(OctetString::new(digest)?.to_der()?);
        let mut der_bytes = vec![0x30, u8::try_from(body.len())?];
        der_bytes.extend(body);
        assert_eq!(got, der_bytes, "{hash:?}");
    }
    Ok(())
}

#[test]
fn digest_info_rejects_bad_length() {
    for len in [0, 31, 33] {
        assert_eq!(
            digest_info(Hash::Sha256, &vec![0; len]),
            Err(BadDigestLength)
        );
    }
    assert_eq!(digest_info(Hash::Sha384, &[0; 32]), Err(BadDigestLength));
}

#[test]
fn hash_len_is_never_empty() {
    for hash in [Hash::Sha256, Hash::Sha384, Hash::Sha512] {
        assert!(!hash.is_empty(), "{hash:?}");
    }
}

#[test]
fn bad_digest_length_displays_its_reason() {
    assert_eq!(
        BadDigestLength.to_string(),
        "digest length does not match the hash"
    );
}

#[test]
fn sign_input_shape() {
    let expected = [
        ("3031300d060960864801650304020105000420", SHA256_ABC),
        ("3041300d060960864801650304020205000430", SHA384_ABC),
        ("3051300d060960864801650304020305000440", SHA512_ABC),
    ];
    for (i, composed) in ALL.into_iter().enumerate() {
        let (prefix, digest) = expected[i % 3];
        let mut h = DigestHasher::new(composed.hash());
        h.update(b"abc");
        let want = if composed.key_type() == KeyType::Rsa {
            format!("{prefix}{digest}")
        } else {
            digest.to_owned()
        };
        let first = sign_input(composed, &h);
        assert_eq!(hex(&first), want, "{composed:?}");
        assert_eq!(sign_input(composed, &h), first);
        h.update(b"d");
        assert_eq!(
            sign_input(composed, &h),
            sign_input(composed, &{
                let mut fresh = DigestHasher::new(composed.hash());
                fresh.update(b"abcd");
                fresh
            })
        );
        assert_ne!(sign_input(composed, &h), first);
    }
}

#[test]
fn debug_does_not_leak() {
    let mut h = DigestHasher::new(Hash::Sha256);
    h.update(b"secret-data");
    assert_eq!(format!("{h:?}"), "DigestHasher { hash: Sha256, .. }");
}

// --- cross-verification -------------------------------------------------------------------

fn fixture_key(name: &str) -> Result<SecretSlice<u8>, Box<dyn Error>> {
    // The PKCS#8 key of the `custodiod` fixture of that name, embedded, not read at run time and
    // not unwrapped from the `.p12` (its key derivation takes minutes under Miri).
    let data: &[u8] = match name {
        "p256" => include_bytes!("../../tests/p256-key.pk8.der"),
        "rsa2048" => include_bytes!("../../tests/rsa2048-key.pk8.der"),
        other => return Err(format!("unknown fixture {other}").into()),
    };
    Ok(SecretSlice::from(data.to_vec()))
}

fn service_sign(
    composed: Composed,
    key: &SecretSlice<u8>,
    message: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut h = DigestHasher::new(composed.hash());
    h.update(message);
    let mechanism = match composed.raw() {
        CKM_RSA_PKCS => Mechanism::RsaPkcs,
        _ => Mechanism::Ecdsa,
    };
    Ok(sign(key, mechanism, &sign_input(composed, &h))?)
}

fn rsa_public(key: &SecretSlice<u8>) -> Result<RsaPublicKey, Box<dyn Error>> {
    use secrecy::ExposeSecret;
    Ok(RsaPrivateKey::from_pkcs8_der(key.expose_secret())?.to_public_key())
}

fn p256_public(key: &SecretSlice<u8>) -> Result<p256::ecdsa::VerifyingKey, Box<dyn Error>> {
    use p256::pkcs8::DecodePrivateKey as _;
    use secrecy::ExposeSecret;
    Ok(*p256::ecdsa::SigningKey::from_pkcs8_der(key.expose_secret())?.verifying_key())
}

fn rsa_verify(composed: Composed, public: &RsaPublicKey, msg: &[u8], sig: &[u8]) -> bool {
    let Ok(sig) = RsaSignature::try_from(sig) else {
        return false;
    };
    let public = public.clone();
    match composed.hash() {
        Hash::Sha256 => RsaVerifyingKey::<Sha256>::new(public)
            .verify(msg, &sig)
            .is_ok(),
        Hash::Sha384 => RsaVerifyingKey::<Sha384>::new(public)
            .verify(msg, &sig)
            .is_ok(),
        Hash::Sha512 => RsaVerifyingKey::<Sha512>::new(public)
            .verify(msg, &sig)
            .is_ok(),
    }
}

fn own_digest(hash: Hash, msg: &[u8]) -> Vec<u8> {
    match hash {
        Hash::Sha256 => Sha256::digest(msg).to_vec(),
        Hash::Sha384 => Sha384::digest(msg).to_vec(),
        Hash::Sha512 => Sha512::digest(msg).to_vec(),
    }
}

const MESSAGE: &[u8] = b"the message that is signed through the composed mechanisms";

#[test]
fn cross_verify_rsa() -> TestResult {
    let key = fixture_key("rsa2048")?;
    let public = rsa_public(&key)?;
    for composed in &ALL[..3] {
        let sig = service_sign(*composed, &key, MESSAGE)?;
        assert!(
            rsa_verify(*composed, &public, MESSAGE, &sig),
            "{composed:?}"
        );
        assert!(!rsa_verify(*composed, &public, b"another message", &sig));
        // A DigestInfo of another hash must not verify.
        let other = match composed.hash() {
            Hash::Sha256 => Composed::Sha384RsaPkcs,
            _ => Composed::Sha256RsaPkcs,
        };
        let mut h = DigestHasher::new(other.hash());
        h.update(MESSAGE);
        let wrong = sign(&key, Mechanism::RsaPkcs, &sign_input(other, &h))?;
        assert!(!rsa_verify(*composed, &public, MESSAGE, &wrong));
    }
    Ok(())
}

#[test]
fn cross_verify_ecdsa() -> TestResult {
    let key = fixture_key("p256")?;
    let public = p256_public(&key)?;
    for composed in &ALL[3..] {
        let sig = p256::ecdsa::Signature::from_slice(&service_sign(*composed, &key, MESSAGE)?)?;
        let digest = own_digest(composed.hash(), MESSAGE);
        public.verify_prehash(&digest, &sig)?;
        public.verify_prehash(digest.get(..32).unwrap_or_default(), &sig)?;
        assert!(
            public
                .verify_prehash(&own_digest(composed.hash(), b"another message"), &sig)
                .is_err()
        );
    }
    Ok(())
}
