//! Unit tests of the import: the pieces that need no TPM (F113).
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use secrecy::SecretSlice;
use tss_esapi::traits::Marshall;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::tpm::TpmError;
use crate::tpm::blob::{Blob, BlobError, Imported, MAX_PRIVATE, MAX_PUBLIC, same_name};
use crate::tpm::import::ImportError;
use crate::tpm::key::{ImportKey, KeyRefusal, Material};
use crate::tpm::wrap;

fn p256_key() -> ImportKey {
    ImportKey {
        material: Material::P256 {
            scalar: SecretSlice::from(vec![0x5a; 32]),
            x: [1; 32],
            y: [2; 32],
        },
    }
}

fn rsa_key() -> ImportKey {
    ImportKey {
        material: Material::Rsa {
            modulus: vec![0xc3; 256],
            prime: SecretSlice::from(vec![0x5a; 128]),
        },
    }
}

fn public_area(key: &ImportKey) -> Vec<u8> {
    wrap::template(key).unwrap().marshall().unwrap()
}

fn private_area() -> Vec<u8> {
    let mut v = vec![0, 32];
    v.extend([9u8; 32]);
    v.extend([7u8; 40]);
    v
}

fn blob() -> Blob {
    Blob::from_parts(&public_area(&p256_key()), &private_area()).unwrap()
}

#[test]
fn result_fields() {
    // Exactly the blob and the parent name: a new field makes this pattern not compile.
    let Imported { blob, parent_name } = Imported {
        blob: blob(),
        parent_name: vec![0, 0x0b],
    };
    assert_eq!(parent_name, vec![0, 0x0b]);
    // The blob is the two structures and nothing else.
    assert_eq!(
        blob.to_bytes().len(),
        blob.public_bytes().len() + blob.private_bytes().len()
    );
}

fn zeroing<T: ZeroizeOnDrop>(_: &T) {}

fn zeroing_type<T: ZeroizeOnDrop>() {}

#[test]
fn key_path_types() {
    zeroing(&p256_key());
    zeroing(&rsa_key());
    zeroing(&SecretSlice::from(vec![1u8]));
    zeroing(&Zeroizing::new(vec![1u8]));
    zeroing(&p256::SecretKey::from_slice(&[1; 32]).unwrap());
    // Every intermediate of the wrap is returned in a zeroing type.
    zeroing(&wrap::kdfa(&[1; 32], "STORAGE", &[], &[], 128).unwrap());
    zeroing(&wrap::kdfe(&[1; 32], "DUPLICATE", &[], &[], 256));
    zeroing(&wrap::sensitive(&p256_key()).unwrap());
    zeroing(&<aes::Aes128 as aes::cipher::KeyInit>::new(&[1; 16].into()));
    // `Hmac` in hmac 0.13 has no `ZeroizeOnDrop`; its keyed state is two of these cores, which wipe on drop.
    zeroing_type::<<sha2::Sha256 as sha2::digest::block_api::CoreProxy>::Core>();
    zeroing(&sha2::Sha256::default());
    zeroing(&Zeroizing::new(p256::AffinePoint::GENERATOR));
    zeroing(&Zeroizing::new(p256::ProjectivePoint::GENERATOR));
    let mut z = Zeroizing::new(vec![3u8; 4]);
    z.zeroize();
    assert!(z.is_empty());
}

#[test]
fn refusal_before_any_tpm_call() {
    for junk in [&[][..], &[0x30, 0x00], b"not a key"] {
        assert_eq!(
            ImportKey::from_pkcs8(junk).unwrap_err(),
            KeyRefusal::Unsupported
        );
    }
}

#[test]
fn debug_and_display_hold_no_key_bytes() {
    for key in [p256_key(), rsa_key()] {
        let shown = format!("{key:?}");
        assert!(shown.starts_with("ImportKey("), "{shown}");
        assert!(
            !shown.contains("5a") && !shown.contains("90") && !shown.contains("c3"),
            "{shown}"
        );
        // Other encodings of the secret: upper-case hex, the raw bytes as text, decimal.
        for form in ["5A", "ZZ", "90", "C3", "\u{c3}", "[90", "0x5a"] {
            assert!(!shown.contains(form), "{form} in {shown}");
        }
    }
    let imported = Imported {
        blob: blob(),
        parent_name: vec![0xab; 34],
    };
    let shown = format!("{imported:?} {:?}", imported.blob);
    assert!(!shown.contains("ab") && !shown.contains("171"), "{shown}");
    for error in [
        ImportError::Refused(KeyRefusal::Unsupported),
        ImportError::Refused(KeyRefusal::RsaExponent),
        ImportError::Refused(KeyRefusal::Malformed),
        ImportError::NoTpm,
        ImportError::Tpm(TpmError::Transport),
        ImportError::ParentMismatch,
        ImportError::Internal,
    ] {
        let text = format!("{error} {error:?}");
        assert!(!text.is_empty() && !text.contains("0x5a"), "{text}");
    }
    for error in [
        BlobError::Truncated,
        BlobError::Oversized,
        BlobError::Trailing,
        BlobError::Inconsistent,
    ] {
        assert!(error.to_string().len() > 10);
    }
    assert_eq!(
        ImportError::Tpm(TpmError::OwnerAuthSet).to_string(),
        "TPM error: owner hierarchy has an authorization value"
    );
    assert_eq!(
        ImportError::ParentMismatch.to_string(),
        "the key was wrapped to another TPM parent"
    );
}

#[test]
fn name_comparison() {
    let name: Vec<u8> = std::iter::once(0)
        .chain(std::iter::once(0x0b))
        .chain(1..=32)
        .collect();
    assert!(same_name(&name, &name));
    assert!(same_name(&[], &[]));
    assert!(!same_name(&name, &name[..33]), "shorter");
    assert!(!same_name(&name[..33], &name), "shorter recorded");
    let mut longer = name.clone();
    longer.push(0);
    assert!(!same_name(&name, &longer), "longer");
    for i in [0, 1, 17, 33] {
        let mut other = name.clone();
        other[i] ^= 1;
        assert!(!same_name(&name, &other), "byte {i}");
    }
}

#[test]
fn blob_parsing_bounds() {
    let good = blob();
    let stored = good.to_bytes();
    assert_eq!(Blob::parse(&stored).unwrap(), good, "round trip");
    // Truncated at every length.
    for n in 0..stored.len() {
        let e = Blob::parse(&stored[..n]).unwrap_err();
        assert!(
            matches!(e, BlobError::Truncated | BlobError::Inconsistent),
            "{n}: {e:?}"
        );
    }
    // Trailing bytes.
    let mut trailing = stored.clone();
    trailing.push(0);
    assert_eq!(Blob::parse(&trailing), Err(BlobError::Trailing));
    // A size field larger than the input, and larger than the limit: no allocation beyond the input.
    let mut big = stored.clone();
    big[..2].copy_from_slice(&u16::MAX.to_be_bytes());
    assert_eq!(Blob::parse(&big), Err(BlobError::Oversized));
    let mut over_limit = stored.clone();
    over_limit[..2].copy_from_slice(&u16::try_from(MAX_PUBLIC + 1).unwrap().to_be_bytes());
    assert_eq!(Blob::parse(&over_limit), Err(BlobError::Oversized));
    let mut past_end = stored.clone();
    let n = u16::try_from(stored.len()).unwrap();
    past_end[..2].copy_from_slice(&n.to_be_bytes());
    assert_eq!(Blob::parse(&past_end), Err(BlobError::Truncated));
    // The private size field.
    let at = good.public_bytes().len();
    let mut private_big = stored.clone();
    private_big[at..at + 2].copy_from_slice(&u16::try_from(MAX_PRIVATE + 1).unwrap().to_be_bytes());
    assert_eq!(Blob::parse(&private_big), Err(BlobError::Oversized));
    // Sizes that disagree with the content: a public area one byte short or long, an integrity length that is not 32.
    let public = public_area(&p256_key());
    assert_eq!(
        Blob::from_parts(&public[..public.len() - 1], &private_area()),
        Err(BlobError::Inconsistent)
    );
    let mut long = public.clone();
    long.push(0);
    assert_eq!(
        Blob::from_parts(&long, &private_area()),
        Err(BlobError::Inconsistent)
    );
    let mut bad_integrity = private_area();
    bad_integrity[1] = 31;
    assert_eq!(
        Blob::from_parts(&public, &bad_integrity),
        Err(BlobError::Inconsistent)
    );
    assert_eq!(
        Blob::from_parts(&public, &private_area()[..34]),
        Err(BlobError::Inconsistent)
    );
    assert_eq!(Blob::from_parts(&public, &[0]), Err(BlobError::Truncated));
    assert_eq!(Blob::from_parts(&public, &[]), Err(BlobError::Truncated));
    assert_eq!(
        Blob::from_parts(&public, &vec![0; MAX_PRIVATE + 1]),
        Err(BlobError::Oversized)
    );
    assert_eq!(
        Blob::from_parts(&vec![0; MAX_PUBLIC + 1], &private_area()),
        Err(BlobError::Oversized)
    );
    // Limits themselves are accepted by the size check (the content check then decides).
    assert!(
        Blob::from_parts(&public, &{
            let mut p = private_area();
            p.resize(MAX_PRIVATE, 1);
            p
        })
        .is_ok()
    );
}

#[test]
fn the_rsa_public_area_parses_too() {
    let public = public_area(&rsa_key());
    // type, name algorithm, attributes, empty policy (2+2+4+2), RSA parameters (10), modulus (2+256).
    assert_eq!(public.len(), 278);
}

#[test]
fn aes_cfb_with_a_zero_iv() {
    // AES-128 with the zero key: E(0, 0) and E(0, E(0, 0)) are the well-known pair, so zeros encrypt to them.
    let mut data = [0u8; 40];
    wrap::cfb_encrypt(&[0; 16], &mut data).unwrap();
    let first = hex("66e94bd4ef8a2c3b884cfa59ca342b2e");
    let second = hex("f795bd4a52e29ed713d313fa20e98dbc");
    assert_eq!(&data[..16], &first[..]);
    assert_eq!(&data[16..32], &second[..]);
    // A partial last block uses the leading bytes of the next keystream block and nothing else changes.
    let mut short = [0u8; 20];
    wrap::cfb_encrypt(&[0; 16], &mut short).unwrap();
    assert_eq!(&short[..], &data[..20]);
    // Decrypting is the same feedback of the ciphertext: encrypting data = ciphertext xor keystream.
    let mut plain = [0xffu8; 16];
    wrap::cfb_encrypt(&[0; 16], &mut plain).unwrap();
    assert_eq!(plain[0], 0xff ^ 0x66);
    assert!(wrap::cfb_encrypt(&[0; 15], &mut plain).is_err());
    let mut empty: [u8; 0] = [];
    wrap::cfb_encrypt(&[0; 16], &mut empty).unwrap();
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn kdfs_follow_the_construction() {
    // KDFa: counter, label with its terminator, contexts, bit count, HMAC-SHA-256 under the key; first 128 bits.
    use hmac::{Hmac, Mac};
    use sha2::Digest;
    let mut mac = <Hmac<sha2::Sha256> as hmac::KeyInit>::new_from_slice(b"key").unwrap();
    mac.update(&1u32.to_be_bytes());
    mac.update(b"STORAGE\0");
    mac.update(b"uv");
    mac.update(&128u32.to_be_bytes());
    let expected = mac.finalize().into_bytes();
    let got = wrap::kdfa(b"key", "STORAGE", b"u", b"v", 128).unwrap();
    assert_eq!(&got[..], &expected[..16]);
    // 512 bits are two blocks with counters 1 and 2.
    let long = wrap::kdfa(b"key", "X", &[], &[], 512).unwrap();
    assert_eq!(long.len(), 64);
    assert_ne!(long[..32], long[32..]);
    // KDFe: SHA-256 over counter, Z, label with terminator, the two party values.
    let mut h = sha2::Sha256::new();
    h.update(1u32.to_be_bytes());
    h.update(b"zz");
    h.update(b"DUPLICATE\0");
    h.update(b"ab");
    assert_eq!(
        &wrap::kdfe(b"zz", "DUPLICATE", b"a", b"b", 256)[..],
        &h.finalize()[..]
    );
    assert_eq!(wrap::kdfe(b"zz", "L", &[], &[], 128).len(), 16);
    assert_eq!(wrap::kdfe(b"zz", "L", &[], &[], 264).len(), 33);
}

#[test]
fn the_public_area_follows_the_decisions() {
    let rsa = public_area(&rsa_key());
    let ecc = public_area(&p256_key());
    assert_eq!(&rsa[..2], &[0, 1], "RSA");
    assert_eq!(&ecc[..2], &[0, 0x23], "ECC");
    assert_eq!(&rsa[2..4], &[0, 0x0b], "SHA-256 name");
    // sign (0x40000) | decrypt (0x20000) | userWithAuth (0x40) | adminWithPolicy (0x80)
    assert_eq!(&rsa[4..8], &0x0006_00c0u32.to_be_bytes());
    assert_eq!(&ecc[4..8], &0x0004_00c0u32.to_be_bytes());
    assert_eq!(&rsa[8..10], &[0, 0], "empty authPolicy");
    assert_eq!(&ecc[8..10], &[0, 0], "empty authPolicy");
    assert_eq!(wrap::name_of(&ecc).len(), 34);
    assert_eq!(&wrap::name_of(&ecc)[..2], &[0, 0x0b]);
}

#[test]
fn limits_and_messages() {
    let public = public_area(&p256_key());
    // Exactly at the limit is a content problem, not an oversized field.
    let at_limit = vec![0u8; MAX_PUBLIC];
    assert_eq!(
        Blob::from_parts(&at_limit, &private_area()),
        Err(BlobError::Inconsistent)
    );
    let mut stored = u16::try_from(MAX_PUBLIC).unwrap().to_be_bytes().to_vec();
    stored.extend_from_slice(&at_limit);
    stored.extend_from_slice(&[0, 0]);
    assert_eq!(Blob::parse(&stored), Err(BlobError::Inconsistent));
    // The smallest private area: integrity digest and one byte.
    let mut smallest = vec![0, 32];
    smallest.extend([1u8; 33]);
    assert!(Blob::from_parts(&public, &smallest).is_ok());
    assert_eq!(
        format!("{:?}", blob()),
        format!(
            "Blob({} + {} bytes)",
            blob().public_bytes().len(),
            blob().private_bytes().len()
        )
    );
    let imported = Imported {
        blob: blob(),
        parent_name: vec![0; 34],
    };
    assert!(format!("{imported:?}").ends_with("parent name 34 bytes)"));
    assert!(format!("{imported:?}").starts_with("Imported(Blob("));
    assert_eq!(
        KeyRefusal::RsaExponent.to_string(),
        "RSA public exponent is not 65537"
    );
    assert_eq!(KeyRefusal::Malformed.to_string(), "key is malformed");
    assert!(
        KeyRefusal::Unsupported
            .to_string()
            .contains("only RSA 2048 and P-256")
    );
    assert_eq!(wrap::kdfa(b"k", "L", &[], &[], 256).unwrap().len(), 32);
    assert_eq!(wrap::kdfe(b"z", "L", &[], &[], 256).len(), 32);
    assert_eq!(wrap::kdfe(b"z", "L", &[], &[], 8).len(), 1);
}
