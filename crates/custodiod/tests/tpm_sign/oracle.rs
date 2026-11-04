//! `openssl` as the independent verifier, and the subjects it verifies: a key the test generated, its self-signed
//! certificate, and the blob the service imported.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use custodiod::sign::{Mechanism, PssHash};
use custodiod::tpm::TpmAccess;
use custodiod::tpm::blob::Imported;
use custodiod::tpm::import::import_pkcs8;
use custodiod::tpm::sign::{SignRequest, TpmSignError, sign};
use sha2::{Digest, Sha256, Sha384, Sha512};

use super::support::{Kind, Res, Rig, TestKey};

/// A key of the test, its certificate file and the stored form of the key in the TPM.
pub struct Subject {
    pub kind: Kind,
    pub key: TestKey,
    pub cert: String,
    pub imported: Imported,
}

static COUNTER: AtomicUsize = AtomicUsize::new(0);

impl Subject {
    pub fn new(rig: &Rig, access: &dyn TpmAccess, kind: Kind) -> Res<Self> {
        let key = TestKey::new(kind);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let pem = rig.write(&format!("key{n}.pem"), &key.pem)?;
        let cert = rig.path(&format!("cert{n}.pem"));
        let out = Command::new("openssl")
            .args(["req", "-new", "-x509", "-key", &pem, "-days", "2"])
            .args(["-subj", &format!("/CN=subject{n}"), "-out", &cert])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        assert!(out.success(), "openssl req");
        let imported = import_pkcs8(access, &key.pkcs8)?;
        Ok(Self {
            kind,
            key,
            cert,
            imported,
        })
    }

    /// Signs through the TPM.
    pub fn sign(
        &self,
        access: &dyn TpmAccess,
        mechanism: Mechanism,
        data: &[u8],
    ) -> Result<Vec<u8>, TpmSignError> {
        sign(
            access,
            &SignRequest {
                imported: &self.imported,
                mechanism,
                data,
            },
        )
    }
}

/// Whether `openssl pkeyutl -verify` accepts `signature` over `input` with the certificate and these options.
pub fn verifies(rig: &Rig, cert: &str, input: &[u8], signature: &[u8], opts: &[&str]) -> Res<bool> {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let input = rig.write(&format!("in{n}"), input)?;
    let sigfile = rig.write(&format!("sig{n}"), signature)?;
    let out = Command::new("openssl")
        .args(["pkeyutl", "-verify", "-certin", "-inkey", cert])
        .args(["-in", &input, "-sigfile", &sigfile])
        .args(opts)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    Ok(out.success())
}

/// What `openssl pkeyutl -verifyrecover` recovers from a PKCS#1 v1.5 signature with the certificate: the payload, byte for
/// byte, or `None` when the padding is wrong.
pub fn recovered(rig: &Rig, cert: &str, signature: &[u8]) -> Res<Option<Vec<u8>>> {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let sigfile = rig.write(&format!("rec{n}"), signature)?;
    let out = Command::new("openssl")
        .args(["pkeyutl", "-verifyrecover", "-certin", "-inkey", cert])
        .args(["-in", &sigfile, "-pkeyopt", "rsa_padding_mode:pkcs1"])
        .stderr(Stdio::null())
        .output()?;
    Ok(out.status.success().then_some(out.stdout))
}

/// `r || s` (64 bytes) as the DER `ECDSA-Sig-Value`.
pub fn ecdsa_der(raw: &[u8]) -> Vec<u8> {
    assert_eq!(raw.len(), 64);
    let integer = |bytes: &[u8]| {
        let start = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        let mut v = bytes[start..].to_vec();
        if v[0] & 0x80 != 0 {
            v.insert(0, 0);
        }
        let mut out = vec![0x02, u8::try_from(v.len()).unwrap()];
        out.extend(v);
        out
    };
    let body = [integer(&raw[..32]), integer(&raw[32..])].concat();
    let mut out = vec![0x30, u8::try_from(body.len()).unwrap()];
    out.extend(body);
    out
}

pub const HASHES: [PssHash; 3] = [PssHash::Sha256, PssHash::Sha384, PssHash::Sha512];

pub const fn hash_name(hash: PssHash) -> &'static str {
    match hash {
        PssHash::Sha256 => "sha256",
        PssHash::Sha384 => "sha384",
        PssHash::Sha512 => "sha512",
    }
}

pub fn digest_of(hash: PssHash, message: &[u8]) -> Vec<u8> {
    match hash {
        PssHash::Sha256 => Sha256::digest(message).to_vec(),
        PssHash::Sha384 => Sha384::digest(message).to_vec(),
        PssHash::Sha512 => Sha512::digest(message).to_vec(),
    }
}

/// The DER prefix of a `DigestInfo` for the hash.
pub fn digest_info_prefix(hash: PssHash) -> Vec<u8> {
    let hex = match hash {
        PssHash::Sha256 => "3031300d060960864801650304020105000420",
        PssHash::Sha384 => "3041300d060960864801650304020205000430",
        PssHash::Sha512 => "3051300d060960864801650304020305000440",
    };
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// The `openssl` options that verify a PSS signature of this hash and salt length.
pub fn pss_opts(hash: PssHash, salt_len: usize) -> Vec<String> {
    let name = hash_name(hash);
    vec![
        "-pkeyopt".into(),
        "rsa_padding_mode:pss".into(),
        "-pkeyopt".into(),
        format!("digest:{name}"),
        "-pkeyopt".into(),
        format!("rsa_mgf1_md:{name}"),
        "-pkeyopt".into(),
        format!("rsa_pss_saltlen:{salt_len}"),
    ]
}

pub fn strs(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

/// A copy of the signature with one bit flipped.
pub fn flip(signature: &[u8]) -> Vec<u8> {
    let mut bad = signature.to_vec();
    let at = bad.len() / 2;
    bad[at] ^= 1;
    bad
}

pub fn mechanisms_pss(hash: PssHash, salt_len: usize) -> Mechanism {
    Mechanism::RsaPkcsPss { hash, salt_len }
}
