//! Unit tests of the TPM signature front end, second half: messages, the result check and the access point (F114).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use super::*;

#[test]
fn error_messages() {
    let all = [
        TpmSignError::Refused(SignError::BadData),
        TpmSignError::Refused(SignError::MechanismMismatch),
        TpmSignError::NoTpm,
        TpmSignError::Tpm(TpmError::Transport),
        TpmSignError::Tpm(TpmError::Response(ResponseCode(0x101))),
        TpmSignError::Lacks(Item::CmdSign),
        TpmSignError::Lacks(Item::CmdRsaDecrypt),
        TpmSignError::ParentMismatch,
        TpmSignError::LoadFailed(ResponseCode(0x1df)),
        TpmSignError::BadResult,
        TpmSignError::Internal,
    ];
    let mut texts = std::collections::HashSet::new();
    let mut debugs = std::collections::HashSet::new();
    for e in all {
        assert!(texts.insert(e.to_string()), "{e:?}");
        assert!(debugs.insert(format!("{e:?}")), "{e:?}");
    }
    assert_eq!(
        TpmSignError::Lacks(Item::CmdSign).to_string(),
        "TPM lacks: command Sign"
    );
    assert_eq!(
        TpmSignError::LoadFailed(ResponseCode(0x1df)).to_string(),
        "the TPM refused to load the key (response code 0x000001DF)"
    );
    assert_eq!(
        TpmSignError::ParentMismatch.to_string(),
        "the key was wrapped to another TPM parent"
    );
    assert_eq!(TpmSignError::NoTpm.to_string(), "no TPM");
    assert_eq!(
        TpmSignError::Refused(SignError::BadData).to_string(),
        "request refused: data length is not valid for the mechanism"
    );
    assert_eq!(
        TpmSignError::Tpm(TpmError::Transport).to_string(),
        "TPM error: TPM connection failed"
    );
    assert_eq!(
        TpmSignError::BadResult.to_string(),
        "the TPM returned a result that is not a valid signature"
    );
    assert_eq!(
        TpmSignError::Internal.to_string(),
        "internal error preparing the TPM signature"
    );
}

#[test]
fn rsa_result_is_checked_with_the_public_key() {
    let public = rsa_public();
    let block = block::pkcs1_block(&[3; 40]).unwrap();
    let good = raw_private(&block);
    assert_eq!(rsa_result(&public, &block, &good).unwrap(), good);
    // One flipped bit anywhere in the answer.
    for at in [0usize, 100, K - 1] {
        let mut bad = good.clone();
        bad[at] ^= 1;
        assert_eq!(
            rsa_result(&public, &block, &bad).unwrap_err(),
            TpmSignError::BadResult,
            "{at}"
        );
    }
    // The signature of another block.
    let other = raw_private(&block::pkcs1_block(&[4; 40]).unwrap());
    assert_eq!(
        rsa_result(&public, &block, &other).unwrap_err(),
        TpmSignError::BadResult
    );
    // Leading zeros of the answer do not matter; the number does.
    let mut padded = good.clone();
    padded.insert(0, 0);
    assert_eq!(rsa_result(&public, &block, &padded).unwrap(), good);
    // The same number plus the modulus gives the same block under the public key and is not the signature.
    let n = BoxedUint::from_be_slice(&modulus(), 4096).unwrap();
    let s = BoxedUint::from_be_slice(&good, 4096).unwrap();
    let sum = s.wrapping_add(&n).to_be_bytes();
    assert_eq!(
        rsa_result(&public, &block, &sum).unwrap_err(),
        TpmSignError::BadResult
    );
    // Not an RSA public area.
    let ec = public_of(&ImportKey {
        material: Material::P256 {
            scalar: SecretSlice::from(vec![0x5a; 32]),
            x: [1; 32],
            y: [2; 32],
        },
    });
    assert_eq!(
        rsa_result(&ec, &block, &good).unwrap_err(),
        TpmSignError::Internal
    );
}

#[test]
fn left_padding() {
    assert_eq!(left_pad(&[1, 2], 4).unwrap(), [0, 0, 1, 2]);
    assert_eq!(left_pad(&[1, 2], 2).unwrap(), [1, 2]);
    assert_eq!(left_pad(&[0, 0, 1, 2], 2).unwrap(), [1, 2]);
    assert_eq!(left_pad(&[], 2).unwrap(), [0, 0]);
    assert_eq!(
        left_pad(&[1, 1, 2], 2).unwrap_err(),
        TpmSignError::BadResult
    );
}

#[test]
fn the_key_type_is_read_from_the_blob() {
    assert_eq!(block::kind_of(&rsa_blob()).unwrap(), Kind::Rsa2048);
    assert_eq!(block::kind_of(&p256_blob()).unwrap(), Kind::P256);
    // A request whose mechanism does not fit the blob is refused with the class of the software signer.
    assert_eq!(
        prepare(&p256_blob(), Mechanism::RsaPkcs, &[0; 8]).unwrap_err(),
        TpmSignError::Refused(SignError::MechanismMismatch)
    );
    assert_eq!(
        prepare(&rsa_blob(), Mechanism::Ecdsa, &[0; 32]).unwrap_err(),
        TpmSignError::Refused(SignError::MechanismMismatch)
    );
}

/// An access point that counts the times it is opened.
struct Counting(AtomicUsize);

impl TpmAccess for Counting {
    fn open(&self) -> Result<Box<dyn Session>, OpenError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(OpenError::NoDevice)
    }
}

#[test]
fn no_tpm_call_before_validation() {
    let imported = Imported {
        blob: rsa_blob(),
        parent_name: vec![0, 0x0b],
    };
    let access = Counting(AtomicUsize::new(0));
    let ask = |mechanism, data: &[u8]| {
        sign(
            &access,
            &SignRequest {
                imported: &imported,
                mechanism,
                data,
            },
        )
        .unwrap_err()
    };
    assert_eq!(
        ask(Mechanism::RsaPkcs, &[0; K - 10]),
        TpmSignError::Refused(SignError::BadData)
    );
    assert_eq!(
        ask(Mechanism::Ecdsa, &[0; 32]),
        TpmSignError::Refused(SignError::MechanismMismatch)
    );
    assert_eq!(access.0.load(Ordering::SeqCst), 0, "the TPM was not opened");
    assert_eq!(ask(Mechanism::RsaPkcs, &[0; K - 11]), TpmSignError::NoTpm);
    assert_eq!(access.0.load(Ordering::SeqCst), 1);
}

#[test]
fn prepared_debug_shows_lengths_only() {
    assert_eq!(
        format!("{:?}", Prepared::Rsa(vec![0xab; 256])),
        "Prepared::Rsa(256 bytes)"
    );
    assert_eq!(
        format!("{:?}", Prepared::Ecdsa(vec![1; 32])),
        "Prepared::Ecdsa(32 bytes)"
    );
}

#[test]
fn other_key_sizes_and_curves_are_not_served() {
    use tss_esapi::attributes::ObjectAttributesBuilder;
    use tss_esapi::interface_types::algorithm::HashingAlgorithm;
    use tss_esapi::interface_types::ecc::EccCurve;
    use tss_esapi::interface_types::key_bits::RsaKeyBits;
    use tss_esapi::structures::{
        Digest as TpmDigest, EccPoint, EccScheme, HashScheme, PublicBuilder,
        PublicEccParametersBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaExponent,
        RsaScheme,
    };
    let attributes = || {
        ObjectAttributesBuilder::new()
            .with_sign_encrypt(true)
            .with_user_with_auth(true)
            .build()
            .unwrap()
    };
    let rsa3072 = PublicBuilder::new()
        .with_public_algorithm(tss_esapi::interface_types::algorithm::PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes())
        .with_auth_policy(TpmDigest::default())
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new()
                .with_scheme(RsaScheme::Null)
                .with_key_bits(RsaKeyBits::Rsa3072)
                .with_exponent(RsaExponent::default())
                .with_is_signing_key(true)
                .build()
                .unwrap(),
        )
        .with_rsa_unique_identifier(PublicKeyRsa::try_from(vec![0xc3; 384]).unwrap())
        .build()
        .unwrap();
    let p384 = PublicBuilder::new()
        .with_public_algorithm(tss_esapi::interface_types::algorithm::PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes())
        .with_auth_policy(TpmDigest::default())
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_unrestricted_signing_key(
                EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
                EccCurve::NistP384,
            )
            .build()
            .unwrap(),
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .unwrap();
    assert_eq!(
        block::kind_of(&blob_of(&rsa3072)),
        Err(TpmSignError::Internal)
    );
    assert_eq!(block::kind_of(&blob_of(&p384)), Err(TpmSignError::Internal));
}
