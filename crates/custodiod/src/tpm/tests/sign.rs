//! Unit tests of the TPM signature front end: bounds, blocks, the check of the result and the errors (F114).
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::ecdsa::{Signature, SigningKey};
use pkcs8::EncodePrivateKey;
use rsa::traits::{PublicKeyParts, SignatureScheme};
use rsa::{BoxedUint, Pkcs1v15Sign, Pss, RsaPrivateKey};
use secrecy::SecretSlice;
use sha2::{Digest, Sha256, Sha384, Sha512};
use tss_esapi::structures::Public;

use crate::sign::{Mechanism, PssHash, SignError, sign as software_sign};
use crate::tpm::blob::{Blob, Imported};
use crate::tpm::classify::{ResponseCode, TpmError};
use crate::tpm::key::{ImportKey, Material};
use crate::tpm::list::Item;
use crate::tpm::sign::block::{self, K, Kind, prepare, prepare_with};
use crate::tpm::sign::check::{left_pad, rsa_result};
use crate::tpm::sign::{Prepared, SignRequest, TpmSignError, sign};
use crate::tpm::{OpenError, Session, TpmAccess, wrap};

const HASHES: [PssHash; 3] = [PssHash::Sha256, PssHash::Sha384, PssHash::Sha512];

fn rsa_software() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| RsaPrivateKey::new(&mut rand::rng(), 2048).unwrap())
}

fn p256_software() -> SigningKey {
    SigningKey::from_slice(&[0x5a; 32]).unwrap()
}

fn pkcs8_of(der: &[u8]) -> SecretSlice<u8> {
    SecretSlice::from(der.to_vec())
}

fn rsa_pkcs8() -> SecretSlice<u8> {
    pkcs8_of(rsa_software().to_pkcs8_der().unwrap().as_bytes())
}

fn p256_pkcs8() -> SecretSlice<u8> {
    pkcs8_of(p256_software().to_pkcs8_der().unwrap().as_bytes())
}

fn modulus() -> Vec<u8> {
    rsa_software().n().as_ref().to_be_bytes().to_vec()
}

fn public_of(key: &ImportKey) -> Public {
    wrap::template(key).unwrap()
}

fn rsa_public() -> Public {
    public_of(&ImportKey {
        material: Material::Rsa {
            modulus: modulus(),
            prime: SecretSlice::from(vec![0x5a; 128]),
        },
    })
}

fn private_area() -> Vec<u8> {
    let mut v = vec![0, 32];
    v.extend([9u8; 32]);
    v.extend([7u8; 40]);
    v
}

fn blob_of(public: &Public) -> Blob {
    use tss_esapi::traits::Marshall;
    Blob::from_parts(&public.marshall().unwrap(), &private_area()).unwrap()
}

fn rsa_blob() -> Blob {
    blob_of(&rsa_public())
}

fn p256_blob() -> Blob {
    blob_of(&public_of(&ImportKey {
        material: Material::P256 {
            scalar: SecretSlice::from(vec![0x5a; 32]),
            x: [1; 32],
            y: [2; 32],
        },
    }))
}

/// The raw private operation the TPM would do.
fn raw_private(block: &[u8]) -> Vec<u8> {
    let c = BoxedUint::from_be_slice(block, 2048).unwrap();
    let m =
        rsa::hazmat::rsa_decrypt(None::<&mut rand::rngs::ThreadRng>, rsa_software(), &c).unwrap();
    left_pad(&m.to_be_bytes(), K).unwrap()
}

fn class(result: &Result<Prepared, TpmSignError>) -> Result<(), SignError> {
    match result {
        Ok(_) => Ok(()),
        Err(TpmSignError::Refused(e)) => Err(*e),
        Err(other) => panic!("not a refusal: {other:?}"),
    }
}

fn prepared(kind: Kind, mechanism: Mechanism, data: &[u8]) -> Result<(), SignError> {
    class(&prepare_with(kind, mechanism, data, &mut |s| s.fill(0x33)))
}

fn software(key: &SecretSlice<u8>, mechanism: Mechanism, data: &[u8]) -> Result<(), SignError> {
    software_sign(key, mechanism, data).map(|_| ())
}

#[test]
fn bounds_parity() {
    let (rsa, ec) = (rsa_pkcs8(), p256_pkcs8());
    let mut cases: Vec<(Kind, Mechanism, usize)> = Vec::new();
    // CKM_RSA_PKCS around k - 11.
    for len in [0, 1, K - 12, K - 11, K - 10, K, 1000] {
        cases.push((Kind::Rsa2048, Mechanism::RsaPkcs, len));
    }
    // CKM_RSA_PKCS_PSS: digest length against the hash, and the salt around its bound.
    for hash in HASHES {
        let h = hash.len();
        for len in [0, h - 1, h, h + 1] {
            for salt_len in [0, h, K - h - 2, K - h - 1, 300, 10_000] {
                let mechanism = Mechanism::RsaPkcsPss { hash, salt_len };
                cases.push((Kind::Rsa2048, mechanism, len));
            }
        }
    }
    // CKM_ECDSA digests.
    for len in [0, 1, 15, 16, 17, 31, 32, 33, 48, 64, 65] {
        cases.push((Kind::P256, Mechanism::Ecdsa, len));
    }
    // A mechanism that does not fit the key type.
    let mismatched = [
        (Kind::Rsa2048, Mechanism::Ecdsa, 32),
        (Kind::P256, Mechanism::RsaPkcs, 32),
        (
            Kind::P256,
            Mechanism::RsaPkcsPss {
                hash: PssHash::Sha256,
                salt_len: 32,
            },
            32,
        ),
    ];
    cases.extend(mismatched);
    for (kind, mechanism, len) in cases {
        let data = vec![0x42u8; len];
        let key = if kind == Kind::Rsa2048 { &rsa } else { &ec };
        assert_eq!(
            prepared(kind, mechanism, &data),
            software(key, mechanism, &data),
            "{kind:?} {mechanism:?} {len}"
        );
    }
    // The classes are what the table above exercised.
    let mut seen = Vec::new();
    for (kind, mechanism, len) in [
        (Kind::Rsa2048, Mechanism::RsaPkcs, K - 11),
        (Kind::Rsa2048, Mechanism::RsaPkcs, K - 10),
        (Kind::P256, Mechanism::Ecdsa, 0),
        (Kind::P256, Mechanism::RsaPkcs, 1),
    ] {
        seen.push(prepared(kind, mechanism, &vec![1; len]));
    }
    assert_eq!(
        seen,
        [
            Ok(()),
            Err(SignError::BadData),
            Err(SignError::BadData),
            Err(SignError::MechanismMismatch)
        ]
    );
}

#[test]
fn huge_salt_is_refused_before_it_is_allocated() {
    let mechanism = Mechanism::RsaPkcsPss {
        hash: PssHash::Sha256,
        salt_len: usize::MAX,
    };
    let mut asked = false;
    let got = prepare_with(Kind::Rsa2048, mechanism, &[0; 32], &mut |_| asked = true);
    assert_eq!(got.unwrap_err(), TpmSignError::Refused(SignError::BadData));
    assert!(!asked, "the salt source was not asked");
}

#[test]
fn pkcs1_blocks_verify_with_the_public_key() {
    let public = rsa_software().to_public_key();
    let digest_info: Vec<u8> = [
        &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ][..],
        &Sha256::digest(b"m")[..],
    ]
    .concat();
    for payload in [vec![], vec![7u8], digest_info, vec![0xee; K - 11]] {
        let block = block::pkcs1_block(&payload).unwrap();
        assert_eq!(block.len(), K);
        let signature = raw_private(&block);
        Pkcs1v15Sign::new_unprefixed()
            .verify(&public, &payload, &signature)
            .unwrap();
        // Another payload does not verify under the same signature.
        let mut other = payload.clone();
        other.push(0);
        assert!(
            Pkcs1v15Sign::new_unprefixed()
                .verify(&public, &other, &signature)
                .is_err()
        );
    }
    assert!(block::pkcs1_block(&vec![0; K - 10]).is_none());
}

#[test]
fn pss_blocks_verify_with_the_public_key() {
    let public = rsa_software().to_public_key();
    for hash in HASHES {
        let h = hash.len();
        for salt_len in [0, 1, h, K - h - 2] {
            let digest = vec![0x61u8; h];
            let salt: Vec<u8> = (0..salt_len)
                .map(|i| u8::try_from(i % 251).unwrap())
                .collect();
            let block = block::pss_block(hash, &digest, &salt);
            assert_eq!(block.len(), K);
            assert_eq!(block[0] & 0x80, 0, "the top bit is clear");
            assert_eq!(block[K - 1], 0xbc);
            let signature = raw_private(&block);
            let ok = match hash {
                PssHash::Sha256 => {
                    Pss::<Sha256>::new_with_salt(salt_len).verify(&public, &digest, &signature)
                }
                PssHash::Sha384 => {
                    Pss::<Sha384>::new_with_salt(salt_len).verify(&public, &digest, &signature)
                }
                PssHash::Sha512 => {
                    Pss::<Sha512>::new_with_salt(salt_len).verify(&public, &digest, &signature)
                }
            };
            ok.unwrap_or_else(|e| panic!("{hash:?} salt {salt_len}: {e}"));
            // The salt length is part of what verifies.
            if salt_len > 0 {
                let wrong = match hash {
                    PssHash::Sha256 => Pss::<Sha256>::new_with_salt(salt_len - 1)
                        .verify(&public, &digest, &signature),
                    PssHash::Sha384 => Pss::<Sha384>::new_with_salt(salt_len - 1)
                        .verify(&public, &digest, &signature),
                    PssHash::Sha512 => Pss::<Sha512>::new_with_salt(salt_len - 1)
                        .verify(&public, &digest, &signature),
                };
                assert!(wrong.is_err());
            }
        }
    }
}

#[test]
fn pss_uses_a_fresh_salt() {
    let mechanism = Mechanism::RsaPkcsPss {
        hash: PssHash::Sha256,
        salt_len: 32,
    };
    let (a, b) = (
        prepare(&rsa_blob(), mechanism, &[1; 32]).unwrap(),
        prepare(&rsa_blob(), mechanism, &[1; 32]).unwrap(),
    );
    assert_ne!(a, b);
}

#[test]
fn ecdsa_digests_follow_the_software_signer() {
    let key = p256_software();
    let verifying = *key.verifying_key();
    for len in [1, 2, 15, 16, 17, 20, 31, 32, 33, 48, 64, 65, 100] {
        let data: Vec<u8> = (0..len)
            .map(|i| u8::try_from(i * 7 % 256).unwrap())
            .collect();
        let digest = block::ecdsa_digest(&data).unwrap();
        assert_eq!(digest.len(), 32, "{len}");
        if len >= 32 {
            assert_eq!(digest, data[..32], "leftmost bytes for {len}");
        } else {
            let (zeros, rest) = digest.split_at(32 - len);
            assert!(zeros.iter().all(|b| *b == 0), "zeros on the left for {len}");
            assert_eq!(rest, data, "{len}");
        }
        // A signature over the 32 bytes verifies as a prehash of the caller's digest, and the software signer's
        // signature of the caller's digest verifies over the 32 bytes.
        let signature: Signature = key.sign_prehash(&digest).unwrap();
        verifying.verify_prehash(&data, &signature).unwrap();
        let direct: Signature = key.sign_prehash(&data).unwrap();
        verifying.verify_prehash(&digest, &direct).unwrap();
    }
    assert!(block::ecdsa_digest(&[]).is_none());
}

#[test]
fn payload_is_opaque() {
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    payloads.push(
        (0..200u16)
            .map(|i| u8::try_from(i * 31 % 256).unwrap())
            .collect(),
    );
    // A DigestInfo with trailing bytes, a truncated one, one whose length field claims more than the input.
    let good: Vec<u8> = [
        &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ][..],
        &[0x11; 32][..],
    ]
    .concat();
    let mut trailing = good.clone();
    trailing.extend([0xde, 0xad]);
    payloads.push(trailing);
    payloads.push(good[..good.len() - 5].to_vec());
    let mut claims_more = good.clone();
    claims_more[1] = 0x82;
    claims_more[18] = 0xff;
    payloads.push(claims_more);
    payloads.push(vec![0x30; 3]);
    payloads.push(vec![0x00; 40]);
    payloads.push(vec![0xff; K - 11]);
    for payload in payloads {
        let Prepared::Rsa(block) = prepare(&rsa_blob(), Mechanism::RsaPkcs, &payload).unwrap()
        else {
            panic!("not an RSA block");
        };
        assert_eq!(block.len(), K);
        // 00 01 FF.. 00 payload, the payload byte for byte.
        assert_eq!(block[..2], [0, 1]);
        let separator = block[2..].iter().position(|b| *b != 0xff).unwrap() + 2;
        assert_eq!(block[separator], 0);
        assert!(separator >= 10, "at least 8 bytes of padding");
        assert_eq!(block[separator + 1..], payload[..]);
    }
}

#[test]
fn no_secret_in_the_api() {
    let imported = Imported {
        blob: p256_blob(),
        parent_name: vec![0, 0x0b],
    };
    let request = SignRequest {
        imported: &imported,
        mechanism: Mechanism::Ecdsa,
        data: &[1; 32],
    };
    // Exactly these fields: a new one (a key, a password) makes this pattern not compile.
    let SignRequest {
        imported: _,
        mechanism: _,
        data: _,
    } = request;
    let shown = format!("{request:?}{:?}", Prepared::Rsa(vec![0xab; 256]));
    assert!(
        !shown.contains("171") && !shown.contains("ab, ab"),
        "{shown}"
    );
}

mod later;
