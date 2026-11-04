//! Every mechanism, both key types, verified by `openssl` with the certificate; and many signatures in a row.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use custodiod::sign::{Mechanism, PssHash, sign as software_sign};
use custodiod::tpm::open::TestTcti;
use secrecy::SecretSlice;

use super::oracle::{
    HASHES, Subject, digest_info_prefix, digest_of, ecdsa_der, flip, hash_name, mechanisms_pss,
    pss_opts, recovered, strs, verifies,
};
use super::support::{Kind, Rig, TestResult};

const PKCS1: [&str; 2] = ["-pkeyopt", "rsa_padding_mode:pkcs1"];

type Ctx<'a> = (&'a Rig, &'a TestTcti);

fn digest_info_payloads(ctx: Ctx, rsa: &Subject, other: &Subject) -> TestResult {
    let (rig, access) = ctx;
    // CKM_RSA_PKCS with a DigestInfo per hash: openssl checks the structure and the digest.
    for hash in HASHES {
        let digest = digest_of(hash, b"a message");
        let payload = [digest_info_prefix(hash), digest.clone()].concat();
        let signature = rsa.sign(access, Mechanism::RsaPkcs, &payload)?;
        assert_eq!(signature.len(), 256);
        let name = hash_name(hash);
        let opts = [PKCS1[0], PKCS1[1], "-pkeyopt", &format!("digest:{name}")];
        assert!(
            verifies(rig, &rsa.cert, &digest, &signature, &opts)?,
            "{name}"
        );
        // Controls: a flipped bit, another digest, another hash, another certificate.
        assert!(!verifies(
            rig,
            &rsa.cert,
            &digest,
            &flip(&signature),
            &opts
        )?);
        let wrong = digest_of(hash, b"another message");
        assert!(!verifies(rig, &rsa.cert, &wrong, &signature, &opts)?);
        let other_hash = if hash == PssHash::Sha256 {
            "sha384"
        } else {
            "sha256"
        };
        let opts_other = [
            PKCS1[0],
            PKCS1[1],
            "-pkeyopt",
            &format!("digest:{other_hash}"),
        ];
        assert!(!verifies(rig, &rsa.cert, &digest, &signature, &opts_other)?);
        assert!(!verifies(rig, &other.cert, &digest, &signature, &opts)?);
    }

    Ok(())
}

fn opaque_payloads(ctx: Ctx, rsa: &Subject, other: &Subject) -> TestResult {
    let (rig, access) = ctx;
    // CKM_RSA_PKCS with payloads that are not a DigestInfo: the payload is recovered byte for byte.
    let long = vec![0xa5u8; 245];
    for payload in [&b"not a digest info"[..], &[0u8], &long] {
        let signature = rsa.sign(access, Mechanism::RsaPkcs, payload)?;
        assert_eq!(
            recovered(rig, &rsa.cert, &signature)?.as_deref(),
            Some(payload),
            "payload of {}",
            payload.len()
        );
        // Controls: a flipped bit and another certificate do not recover the payload.
        assert_ne!(
            recovered(rig, &rsa.cert, &flip(&signature))?.as_deref(),
            Some(payload)
        );
        assert_ne!(
            recovered(rig, &other.cert, &signature)?.as_deref(),
            Some(payload)
        );
        if payload.len() <= 64 {
            assert!(verifies(rig, &rsa.cert, payload, &signature, &PKCS1)?);
        }
    }

    Ok(())
}

fn pss_salts(ctx: Ctx, rsa: &Subject, other: &Subject) -> TestResult {
    let (rig, access) = ctx;
    // CKM_RSA_PKCS_PSS per hash with salt 0, hLen and the largest salt.
    for hash in HASHES {
        let h = hash.len();
        let digest = digest_of(hash, b"to be signed");
        for salt_len in [0, h, 256 - h - 2] {
            let signature = rsa.sign(access, mechanisms_pss(hash, salt_len), &digest)?;
            assert_eq!(signature.len(), 256);
            let right = pss_opts(hash, salt_len);
            let ctx = format!("{hash:?} salt {salt_len}");
            assert!(
                verifies(rig, &rsa.cert, &digest, &signature, &strs(&right))?,
                "{ctx}"
            );
            // Controls: flipped bit, other certificate, other salt length, other hash.
            assert!(!verifies(
                rig,
                &rsa.cert,
                &digest,
                &flip(&signature),
                &strs(&right)
            )?);
            assert!(!verifies(
                rig,
                &other.cert,
                &digest,
                &signature,
                &strs(&right)
            )?);
            let wrong_salt = pss_opts(hash, if salt_len == 0 { 1 } else { salt_len - 1 });
            assert!(
                !verifies(rig, &rsa.cert, &digest, &signature, &strs(&wrong_salt))?,
                "{ctx}"
            );
            let other_hash = if hash == PssHash::Sha256 {
                PssHash::Sha384
            } else {
                PssHash::Sha256
            };
            let wrong_hash = pss_opts(other_hash, salt_len);
            assert!(
                !verifies(rig, &rsa.cert, &digest, &signature, &strs(&wrong_hash))?,
                "{ctx}"
            );
        }
    }

    Ok(())
}

fn ecdsa_digests(ctx: Ctx, ec: &Subject, ec_other: &Subject) -> TestResult {
    let (rig, access) = ctx;
    // CKM_ECDSA with 1-, 16-, 32-, 48- and 64-byte digests; the shortest accepted length is 1.
    for len in [1usize, 16, 32, 48, 64] {
        let digest: Vec<u8> = (0..len)
            .map(|i| u8::try_from(i * 13 % 251 + 1).unwrap())
            .collect();
        let signature = ec.sign(access, Mechanism::Ecdsa, &digest)?;
        assert_eq!(signature.len(), 64);
        let der = ecdsa_der(&signature);
        assert!(verifies(rig, &ec.cert, &digest, &der, &[])?, "{len}");
        if len > 32 {
            // The signature is over the leftmost 32 bytes, taken as a prehash.
            assert!(
                verifies(rig, &ec.cert, &digest[..32], &der, &[])?,
                "{len}: leftmost 32"
            );
        }
        // Controls: flipped bit, another certificate, another digest.
        assert!(!verifies(
            rig,
            &ec.cert,
            &digest,
            &ecdsa_der(&flip(&signature)),
            &[]
        )?);
        assert!(!verifies(rig, &ec_other.cert, &digest, &der, &[])?);
        let mut changed = digest.clone();
        changed[0] ^= 1;
        assert!(!verifies(rig, &ec.cert, &changed, &der, &[])?, "{len}");
    }
    Ok(())
}

#[test]
fn every_mechanism_verifies_with_the_certificate() -> TestResult {
    let rig = Rig::new()?;
    let access = TestTcti::new(&rig.tcti());
    let rsa = Subject::new(&rig, &access, Kind::Rsa)?;
    let other = Subject::new(&rig, &access, Kind::Rsa)?;
    let ec = Subject::new(&rig, &access, Kind::P256)?;
    let ec_other = Subject::new(&rig, &access, Kind::P256)?;
    digest_info_payloads((&rig, &access), &rsa, &other)?;
    opaque_payloads((&rig, &access), &rsa, &other)?;
    pss_salts((&rig, &access), &rsa, &other)?;
    ecdsa_digests((&rig, &access), &ec, &ec_other)?;
    rig.assert_nothing_loaded("after the mechanisms")?;
    Ok(())
}

#[test]
fn ecdsa_truncation_matches_the_software_signer() -> TestResult {
    let rig = Rig::new()?;
    let access = TestTcti::new(&rig.tcti());
    let ec = Subject::new(&rig, &access, Kind::P256)?;
    let software = SecretSlice::from(ec.key.pkcs8.clone());
    for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 48, 63, 64, 65, 100] {
        let digest = vec![0x5cu8; len];
        let tpm = ec.sign(&access, Mechanism::Ecdsa, &digest);
        let soft = software_sign(&software, Mechanism::Ecdsa, &digest);
        assert_eq!(tpm.is_ok(), soft.is_ok(), "{len}");
        if let (Ok(tpm), Ok(soft)) = (&tpm, &soft) {
            // The software signer is deterministic and so are both: they are different nonces, but the same size and
            // both verify.
            assert_eq!(tpm.len(), soft.len());
            // openssl takes at most 64 bytes of prehash; the signature is over the leftmost 32 of a longer digest.
            let shown = &digest[..len.min(32)];
            assert!(
                verifies(&rig, &ec.cert, shown, &ecdsa_der(tpm), &[])?,
                "{len}"
            );
        }
    }
    Ok(())
}

/// The number of transient objects the TPM holds at once.
fn transient_slots(rig: &Rig) -> usize {
    let text = rig.getcap("properties-fixed").unwrap();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if line.trim() == "TPM2_PT_HR_TRANSIENT_MIN:" {
            let raw = lines
                .next()
                .unwrap()
                .trim()
                .strip_prefix("raw:")
                .unwrap()
                .trim();
            return usize::from_str_radix(raw.trim_start_matches("0x"), 16).unwrap();
        }
    }
    panic!("no TPM2_PT_HR_TRANSIENT_MIN in {text}");
}

#[test]
fn many_signatures_in_a_row() -> TestResult {
    let rig = Rig::new()?;
    let access = TestTcti::new(&rig.tcti());
    let slots = transient_slots(&rig);
    assert!((1..30).contains(&slots), "slots: {slots}");
    for kind in [Kind::Rsa, Kind::P256] {
        let subject = Subject::new(&rig, &access, kind)?;
        for i in 0..30usize {
            let digest = digest_of(HASHES[i % 3], format!("message {i}").as_bytes());
            match kind {
                Kind::Rsa if i % 2 == 0 => {
                    let hash = HASHES[i % 3];
                    let payload = [digest_info_prefix(hash), digest.clone()].concat();
                    let signature = subject.sign(&access, Mechanism::RsaPkcs, &payload)?;
                    let name = hash_name(hash);
                    let opts = [PKCS1[0], PKCS1[1], "-pkeyopt", &format!("digest:{name}")];
                    assert!(
                        verifies(&rig, &subject.cert, &digest, &signature, &opts)?,
                        "{i}"
                    );
                }
                Kind::Rsa => {
                    let hash = HASHES[i % 3];
                    let signature = subject.sign(&access, mechanisms_pss(hash, 20), &digest)?;
                    let opts = pss_opts(hash, 20);
                    assert!(
                        verifies(&rig, &subject.cert, &digest, &signature, &strs(&opts))?,
                        "{i}"
                    );
                }
                Kind::P256 => {
                    let signature = subject.sign(&access, Mechanism::Ecdsa, &digest)?;
                    assert!(
                        verifies(&rig, &subject.cert, &digest, &ecdsa_der(&signature), &[])?,
                        "{i}"
                    );
                }
            }
        }
        assert_eq!(
            rig.handles("handles-transient")?,
            Vec::<String>::new(),
            "{kind:?}"
        );
    }
    rig.assert_nothing_loaded("after many signatures")?;
    Ok(())
}
