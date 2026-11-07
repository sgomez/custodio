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

/// The PSS salt lengths of the table for a hash: none, the length of the hash and the largest one a 2048-bit key takes.
pub fn salt_lengths(hash: PssHash) -> [usize; 3] {
    [0, hash.len(), 256 - hash.len() - 2]
}

/// The payloads of `CKM_RSA_PKCS` that are not a `DigestInfo`: text, one zero byte and the longest one a 2048-bit key
/// takes (245 bytes).
pub fn opaque_inputs() -> Vec<Vec<u8>> {
    vec![b"not a digest info".to_vec(), vec![0], vec![0xa5; 245]]
}

/// The digest lengths of `CKM_ECDSA` in the table; the shortest the service accepts is 1.
pub const ECDSA_LENGTHS: [usize; 5] = [1, 16, 32, 48, 64];

/// The digest of the table for a length.
pub fn ecdsa_digest(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i * 13 % 251 + 1).unwrap())
        .collect()
}

/// What `openssl` is asked to do with a signature of a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    /// `pkeyutl -verify` with PKCS#1 v1.5 and this hash, over the digest.
    DigestInfo(PssHash),
    /// `pkeyutl -verifyrecover`: the payload comes back byte for byte.
    Opaque,
    /// `pkeyutl -verify` with PSS, this hash and salt length, over the digest.
    Pss(PssHash, usize),
    /// `pkeyutl -verify` of the DER form of the signature over the digest.
    Ecdsa,
}

/// One line of the table: a mechanism, the bytes handed to `Sign`, and how an independent verifier checks the result.
#[derive(Debug, Clone)]
pub struct Row {
    pub label: String,
    pub mechanism: Mechanism,
    /// What `Sign` is given.
    pub data: Vec<u8>,
    /// What `openssl` is given as the signed input (the digest, or for the opaque rows the payload).
    pub input: Vec<u8>,
    pub check: Check,
}

impl Row {
    /// Whether the verifier accepts `signature` with the certificate file `cert`.
    pub fn accepts(&self, rig: &Rig, cert: &str, signature: &[u8]) -> Res<bool> {
        match self.check {
            Check::DigestInfo(hash) => {
                let opts = [
                    "-pkeyopt",
                    "rsa_padding_mode:pkcs1",
                    "-pkeyopt",
                    &format!("digest:{}", hash_name(hash)),
                ];
                verifies(rig, cert, &self.input, signature, &opts)
            }
            Check::Opaque => {
                Ok(recovered(rig, cert, signature)?.as_deref() == Some(&self.data[..]))
            }
            Check::Pss(hash, salt) => {
                let opts = pss_opts(hash, salt);
                verifies(rig, cert, &self.input, signature, &strs(&opts))
            }
            Check::Ecdsa => {
                if signature.len() != 64 {
                    return Ok(false);
                }
                verifies(rig, cert, &self.input, &ecdsa_der(signature), &[])
            }
        }
    }
}

/// Every mechanism of an RSA-2048 key.
pub fn rsa_rows() -> Vec<Row> {
    let mut rows = Vec::new();
    for hash in HASHES {
        let digest = digest_of(hash, b"a message");
        rows.push(Row {
            label: format!("pkcs {hash:?} digest info"),
            mechanism: Mechanism::RsaPkcs,
            data: [digest_info_prefix(hash), digest.clone()].concat(),
            input: digest,
            check: Check::DigestInfo(hash),
        });
    }
    for payload in opaque_inputs() {
        rows.push(Row {
            label: format!("pkcs opaque {}", payload.len()),
            mechanism: Mechanism::RsaPkcs,
            input: payload.clone(),
            data: payload,
            check: Check::Opaque,
        });
    }
    for hash in HASHES {
        let digest = digest_of(hash, b"to be signed");
        for salt in salt_lengths(hash) {
            rows.push(Row {
                label: format!("pss {hash:?} salt {salt}"),
                mechanism: mechanisms_pss(hash, salt),
                data: digest.clone(),
                input: digest.clone(),
                check: Check::Pss(hash, salt),
            });
        }
    }
    rows
}

/// Every mechanism of a P-256 key.
pub fn p256_rows() -> Vec<Row> {
    ECDSA_LENGTHS
        .iter()
        .map(|&len| {
            let digest = ecdsa_digest(len);
            Row {
                label: format!("ecdsa {len}"),
                mechanism: Mechanism::Ecdsa,
                data: digest.clone(),
                input: digest,
                check: Check::Ecdsa,
            }
        })
        .collect()
}
