//! `tpm-probe mechanisms` (F107): every mechanism the service offers, run on the TPM both ways.
//!
//! Way (a): `TPM2_Sign` only. The probe parses a `DigestInfo` for `CKM_RSA_PKCS`, serves `CKM_RSA_PKCS_PSS` only when the
//! requested salt length is the one the TPM produces, and calls anything else `lacks`.
//! Way (b): the padding is built here and the TPM does the raw RSA private operation (`TPM2_RSA_Decrypt`, null scheme,
//! key with the `decrypt` attribute). RSA only: `CKM_ECDSA` has no raw private operation to replace.
//!
//! Every signature is checked by the `openssl` command line (an external verifier; the padding code of this file is never
//! run backwards). Only transient keys are created and each is flushed; no `EvictControl`, no auth value, no clear.

use std::process::Command;

use sha2::{Digest as _, Sha256, Sha384, Sha512};
use tss_esapi::Context;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::CapabilityType;
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::reserved_handles::Hierarchy;
use tss_esapi::structures::{
    CapabilityData, Digest, EccPoint, EccScheme, HashScheme, Public, PublicBuilder,
    PublicEccParametersBuilder, PublicKeyRsa, PublicParameters, PublicRsaParametersBuilder,
    RsaDecryptionScheme, RsaExponent, RsaScheme, Signature, SignatureScheme,
    SymmetricDefinitionObject,
};

use super::{Fail, connect, srk_template};

const RSA_BYTES: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    const fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }
    const fn openssl(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }
    const fn len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
    const fn tpm(self) -> HashingAlgorithm {
        match self {
            Self::Sha1 => HashingAlgorithm::Sha1,
            Self::Sha256 => HashingAlgorithm::Sha256,
            Self::Sha384 => HashingAlgorithm::Sha384,
            Self::Sha512 => HashingAlgorithm::Sha512,
        }
    }
    /// The DER prefix of a `DigestInfo` for this hash (RFC 8017, section 9.2, note 1).
    const fn prefix(self) -> &'static [u8] {
        match self {
            Self::Sha1 => &[
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
                0x14,
            ],
            Self::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            Self::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            Self::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }
    /// A digest of `message`. SHA-1 is not computed (no SHA-1 crate): the first 20 bytes of SHA-256 stand in, which is
    /// enough because neither the TPM nor the verifier recomputes the digest.
    fn digest(self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => Sha256::digest(message)[..20].to_vec(),
            Self::Sha256 => Sha256::digest(message).to_vec(),
            Self::Sha384 => Sha384::digest(message).to_vec(),
            Self::Sha512 => Sha512::digest(message).to_vec(),
        }
    }
}

const ALL: [Hash; 4] = [Hash::Sha1, Hash::Sha256, Hash::Sha384, Hash::Sha512];
const PSS: [Hash; 3] = [Hash::Sha256, Hash::Sha384, Hash::Sha512];

/// The `DigestInfo` the service would parse: a known prefix followed by a digest of the right length.
fn parse_digest_info(payload: &[u8]) -> Option<(Hash, &[u8])> {
    ALL.into_iter().find_map(|h| {
        let rest = payload.strip_prefix(h.prefix())?;
        (rest.len() == h.len()).then_some((h, rest))
    })
}

fn digest_info(h: Hash, message: &[u8]) -> Vec<u8> {
    let mut v = h.prefix().to_vec();
    v.extend(h.digest(message));
    v
}

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![u8::try_from(n).unwrap_or(0)]
    } else if n < 0x100 {
        vec![0x81, u8::try_from(n).unwrap_or(0)]
    } else {
        vec![
            0x82,
            u8::try_from(n >> 8).unwrap_or(0),
            u8::try_from(n & 0xff).unwrap_or(0),
        ]
    }
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend(der_len(body.len()));
    v.extend(body);
    v
}

/// DER INTEGER from big-endian unsigned bytes.
fn der_uint(bytes: &[u8]) -> Vec<u8> {
    let start = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    let mut body = Vec::new();
    if bytes[start] & 0x80 != 0 {
        body.push(0);
    }
    body.extend(&bytes[start..]);
    tlv(0x02, &body)
}

fn spki_rsa(n: &[u8], e: u32) -> Vec<u8> {
    let key = tlv(0x30, &[der_uint(n), der_uint(&e.to_be_bytes())].concat());
    let alg = tlv(
        0x30,
        &[
            tlv(
                0x06,
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
            ),
            vec![0x05, 0x00],
        ]
        .concat(),
    );
    tlv(
        0x30,
        &[alg, tlv(0x03, &[&[0u8][..], &key].concat())].concat(),
    )
}

fn spki_p256(x: &[u8], y: &[u8]) -> Vec<u8> {
    let alg = tlv(
        0x30,
        &[
            tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
            tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
        ]
        .concat(),
    );
    let mut point = vec![0u8, 4];
    point.extend(pad32(x));
    point.extend(pad32(y));
    tlv(0x30, &[alg, tlv(0x03, &point)].concat())
}

fn pad32(v: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32usize.saturating_sub(v.len())];
    out.extend(v);
    out
}

/// The independent verifier: the `openssl` command line, on files in a private temporary directory.
struct Verifier {
    dir: tempfile::TempDir,
}

impl Verifier {
    fn new(public_der: &[u8]) -> Result<Self, Fail> {
        let dir = tempfile::tempdir()?;
        std::fs::write(dir.path().join("pub.der"), public_der)?;
        Ok(Self { dir })
    }
    fn run(&self, data: &[u8], sig: &[u8], opts: &[String]) -> Result<bool, Fail> {
        let p = |n: &str| -> std::path::PathBuf { self.dir.path().join(n) };
        std::fs::write(p("data"), data)?;
        std::fs::write(p("sig"), sig)?;
        let mut cmd = Command::new("openssl");
        cmd.args(["pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey"])
            .arg(p("pub.der"))
            .arg("-in")
            .arg(p("data"))
            .arg("-sigfile")
            .arg(p("sig"));
        for o in opts {
            cmd.args(["-pkeyopt", o]);
        }
        let out = cmd
            .output()
            .map_err(|e| format!("cannot run openssl (package openssl): {e}"))?;
        Ok(out.status.success())
    }
    /// `CKM_RSA_PKCS`: the signature opens to exactly `payload` under block type 1 padding. `verifyrecover` because
    /// `pkeyutl -verify` refuses an input longer than 64 bytes ("looks too long to be a hash"), a SHA-512 `DigestInfo` is 83.
    fn pkcs1(&self, payload: &[u8], sig: &[u8]) -> Result<bool, Fail> {
        std::fs::write(self.dir.path().join("sig"), sig)?;
        let out = Command::new("openssl")
            .args([
                "pkeyutl",
                "-verifyrecover",
                "-pubin",
                "-keyform",
                "DER",
                "-inkey",
            ])
            .arg(self.dir.path().join("pub.der"))
            .arg("-in")
            .arg(self.dir.path().join("sig"))
            .args(["-pkeyopt", "rsa_padding_mode:pkcs1"])
            .output()
            .map_err(|e| format!("cannot run openssl (package openssl): {e}"))?;
        Ok(out.status.success() && out.stdout == payload)
    }
    fn pss(&self, h: Hash, digest: &[u8], sig: &[u8], salt: usize) -> Result<bool, Fail> {
        self.run(
            digest,
            sig,
            &[
                "rsa_padding_mode:pss".into(),
                format!("digest:{}", h.openssl()),
                format!("rsa_mgf1_md:{}", h.openssl()),
                format!("rsa_pss_saltlen:{salt}"),
            ],
        )
    }
    fn ecdsa(&self, digest: &[u8], der_sig: &[u8]) -> Result<bool, Fail> {
        self.run(digest, der_sig, &[])
    }
    /// Smallest salt length 0..=max under which the PSS signature verifies.
    fn find_salt(&self, h: Hash, digest: &[u8], sig: &[u8]) -> Result<Option<usize>, Fail> {
        for salt in 0..=(RSA_BYTES - h.len() - 2) {
            if self.pss(h, digest, sig, salt)? {
                return Ok(Some(salt));
            }
        }
        Ok(None)
    }
}

#[derive(Clone, Copy)]
enum Kind {
    RsaSign,
    RsaSignDecrypt,
    EccSign,
}

struct Key {
    handle: KeyHandle,
    public_der: Vec<u8>,
    attributes: String,
}

fn template(kind: Kind) -> Result<Public, Fail> {
    let (sign, decrypt) = match kind {
        Kind::RsaSign | Kind::EccSign => (true, false),
        Kind::RsaSignDecrypt => (true, true),
    };
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(sign)
        .with_decrypt(decrypt)
        .build()?;
    let builder = PublicBuilder::new()
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes);
    Ok(match kind {
        Kind::EccSign => builder
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_ecc_parameters(
                // The wrapper refuses a signing key with the null scheme, which the TPM accepts; the usage flags are
                // left out of the builder (the object attributes carry `sign`), the scheme stays null.
                PublicEccParametersBuilder::new_unrestricted_signing_key(
                    EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
                    EccCurve::NistP256,
                )
                .with_ecc_scheme(EccScheme::Null)
                .with_is_signing_key(false)
                .build()?,
            )
            .with_ecc_unique_identifier(EccPoint::default())
            .build()?,
        _ => builder
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_rsa_parameters(
                PublicRsaParametersBuilder::new()
                    .with_scheme(RsaScheme::Null)
                    .with_key_bits(RsaKeyBits::Rsa2048)
                    .with_exponent(RsaExponent::default())
                    .with_is_signing_key(sign)
                    .with_is_decryption_key(decrypt)
                    .build()?,
            )
            .with_rsa_unique_identifier(PublicKeyRsa::default())
            .build()?,
    })
}

fn describe(public: &Public) -> String {
    let a = public.object_attributes();
    format!(
        "fixedtpm={} fixedparent={} sensitivedataorigin={} restricted={} sign={} decrypt={}",
        a.fixed_tpm(),
        a.fixed_parent(),
        a.sensitive_data_origin(),
        a.restricted(),
        a.sign_encrypt(),
        a.decrypt()
    )
}

fn spki_of(public: &Public) -> Result<Vec<u8>, Fail> {
    Ok(match public {
        Public::Rsa { unique, .. } => spki_rsa(unique.as_bytes(), 65537),
        Public::Ecc { unique, .. } => spki_p256(unique.x().as_bytes(), unique.y().as_bytes()),
        _ => return Err("unexpected key type".into()),
    })
}

fn make_key(ctx: &mut Context, kind: Kind) -> Result<Key, Fail> {
    let result = ctx.execute_with_nullauth_session(|c| {
        c.create_primary(Hierarchy::Owner, template(kind)?, None, None, None, None)
            .map_err(Fail::from)
    })?;
    Ok(Key {
        handle: result.key_handle,
        public_der: spki_of(&result.out_public)?,
        attributes: describe(&result.out_public),
    })
}

/// The TPM's answer to a failed call: `Code: 0x…, Message: …`.
fn rc(e: tss_esapi::Error) -> String {
    e.to_string().replace("TSS Layer: TPM, ", "")
}

fn tpm_sign(
    ctx: &mut Context,
    key: &Key,
    digest: &[u8],
    scheme: SignatureScheme,
) -> Result<Signature, tss_esapi::Error> {
    let d = Digest::try_from(digest.to_vec())?;
    ctx.execute_with_nullauth_session(|c| c.sign(key.handle, d, scheme, None))
}

fn rsa_sig(s: &Signature) -> Option<Vec<u8>> {
    match s {
        Signature::RsaSsa(r) | Signature::RsaPss(r) => Some(r.signature().as_bytes().to_vec()),
        _ => None,
    }
}

fn line(way: &str, mechanism: &str, fields: &[(&str, String)]) {
    let rest: Vec<String> = fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
    println!("case: way={way} mechanism={mechanism} {}", rest.join(" "));
}

fn yn(b: bool) -> String {
    if b { "yes" } else { "no" }.into()
}

/// Probe state: the problems that make the exit status 1.
struct Run {
    bad: Vec<String>,
}

impl Run {
    fn expect(&mut self, ok: bool, what: &str) {
        if !ok {
            self.bad.push(what.to_owned());
        }
    }
}

/// Way (a), RSA: `CKM_RSA_PKCS` payloads and `CKM_RSA_PKCS_PSS`.
fn way_a_rsa(ctx: &mut Context, key: &Key, v: &Verifier, run: &mut Run) -> Result<(), Fail> {
    let message = b"custodio F107 message";
    // CKM_RSA_PKCS with a DigestInfo per hash.
    for h in ALL {
        let payload = digest_info(h, message);
        let (hash, digest) = parse_digest_info(&payload).ok_or("own DigestInfo does not parse")?;
        let scheme = SignatureScheme::RsaSsa {
            scheme: HashScheme::new(hash.tpm()),
        };
        match tpm_sign(ctx, key, digest, scheme) {
            Ok(sig) => {
                let bytes = rsa_sig(&sig).ok_or("not an RSA signature")?;
                let ok = v.pkcs1(&payload, &bytes)?;
                run.expect(
                    ok,
                    "a served CKM_RSA_PKCS DigestInfo signature does not verify",
                );
                line(
                    "a",
                    "CKM_RSA_PKCS",
                    &[
                        ("payload", format!("DigestInfo/{}", h.name())),
                        ("outcome", "served".into()),
                        ("rc", "-".into()),
                        ("verified", yn(ok)),
                    ],
                );
            }
            Err(e) => line(
                "a",
                "CKM_RSA_PKCS",
                &[
                    ("payload", format!("DigestInfo/{}", h.name())),
                    ("outcome", "lacks".into()),
                    ("rc", rc(e)),
                    ("verified", "n/a".into()),
                ],
            ),
        }
    }
    // Payloads that are not a parseable DigestInfo.
    let md5sha1 = [
        Sha256::digest(b"m").to_vec(),
        Sha256::digest(b"s")[..4].to_vec(),
    ]
    .concat();
    let mut unknown_oid = digest_info(Hash::Sha256, message);
    unknown_oid[14] = 0x63; // 2.16.840.1.101.3.4.2.99: a hash OID no table knows
    for (label, payload) in [
        ("36-byte MD5+SHA-1 (TLS 1.0/1.1)", md5sha1),
        ("DigestInfo with an unknown hash OID", unknown_oid),
    ] {
        let parsed = parse_digest_info(&payload).is_some();
        // What the TPM itself says when the payload is handed over as a digest (the only call that could carry it).
        let attempt = match tpm_sign(
            ctx,
            key,
            &payload,
            SignatureScheme::RsaSsa {
                scheme: HashScheme::new(HashingAlgorithm::Sha256),
            },
        ) {
            Ok(_) => "served".to_owned(),
            Err(e) => rc(e),
        };
        run.expect(!parsed, "a non-DigestInfo payload parsed");
        line(
            "a",
            "CKM_RSA_PKCS",
            &[
                ("payload", format!("{label:?}")),
                ("outcome", "lacks".into()),
                ("rc", "service parser: not a known DigestInfo".into()),
                ("tpm_if_passed_as_digest", attempt),
                ("verified", "n/a".into()),
            ],
        );
    }
    way_a_pss(ctx, key, v, run)
}

/// Way (a), `CKM_RSA_PKCS_PSS`.
fn way_a_pss(ctx: &mut Context, key: &Key, v: &Verifier, run: &mut Run) -> Result<(), Fail> {
    let message = b"custodio F107 message";
    // CKM_RSA_PKCS_PSS: the TPM's own salt first, then every requested length against it.
    for h in PSS {
        let digest = h.digest(message);
        let scheme = SignatureScheme::RsaPss {
            scheme: HashScheme::new(h.tpm()),
        };
        let sig = rsa_sig(&tpm_sign(ctx, key, &digest, scheme).map_err(rc)?).ok_or("not RSA")?;
        let found = v.find_salt(h, &digest, &sig)?;
        run.expect(
            found.is_some(),
            "a TPM PSS signature verifies under no salt length",
        );
        let found_n = found.unwrap_or(usize::MAX);
        let largest = RSA_BYTES - h.len() - 2;
        let wrong = v.pss(h, &digest, &sig, found_n.wrapping_add(1))?;
        run.expect(!wrong, "negative control: a wrong salt length verified");
        println!(
            "salt_found: hash={} tpm_salt={} hash_len={} equals_hash_len={} largest_possible={largest} wrong_salt_verifies={}",
            h.name(),
            found_n,
            h.len(),
            yn(found_n == h.len()),
            yn(wrong)
        );
        let mut requests = vec![h.len(), largest, 0, 20];
        requests.dedup();
        for req in requests {
            let ok = v.pss(h, &digest, &sig, req)?;
            line(
                "a",
                "CKM_RSA_PKCS_PSS",
                &[
                    ("hash", h.name().into()),
                    ("salt_requested", req.to_string()),
                    ("outcome", if ok { "served" } else { "lacks" }.into()),
                    (
                        "rc",
                        if ok {
                            "-".into()
                        } else {
                            format!("policy: TPM salt is {found_n}, not {req}")
                        },
                    ),
                    ("salt_found", found_n.to_string()),
                    ("verified", if ok { "yes".into() } else { "n/a".to_owned() }),
                ],
            );
        }
    }
    Ok(())
}

fn ecdsa_der(sig: &Signature) -> Result<Vec<u8>, Fail> {
    match sig {
        Signature::EcDsa(e) => Ok(tlv(
            0x30,
            &[
                der_uint(e.signature_r().as_bytes()),
                der_uint(e.signature_s().as_bytes()),
            ]
            .concat(),
        )),
        _ => Err("not an ECDSA signature".into()),
    }
}

/// Way (a), `CKM_ECDSA` on P-256: the service's truncated digest, and the full digest, per hash.
fn way_a_ecdsa(ctx: &mut Context, key: &Key, v: &Verifier, run: &mut Run) -> Result<(), Fail> {
    for h in [Hash::Sha256, Hash::Sha384, Hash::Sha512] {
        let digest = h.digest(b"custodio F107 ecdsa");
        let truncated = digest[..digest.len().min(32)].to_vec();
        // Hand-over 1: the service's leftmost 32 bytes, scheme hash SHA-256 (the TPM needs SHA-256 only).
        // Hand-over 2: the full digest with the matching scheme hash (the TPM needs that hash).
        for (how, data, scheme_hash) in [
            ("truncated32+SHA-256", &truncated, Hash::Sha256),
            ("full+own-hash", &digest, h),
        ] {
            let scheme = SignatureScheme::EcDsa {
                scheme: HashScheme::new(scheme_hash.tpm()),
            };
            match tpm_sign(ctx, key, data, scheme) {
                Ok(sig) => {
                    let der = ecdsa_der(&sig)?;
                    let on_truncated = v.ecdsa(&truncated, &der)?;
                    let on_full = v.ecdsa(&digest, &der)?;
                    // Negative control: the rightmost 32 bytes are a different value and must not verify.
                    let on_rightmost =
                        v.ecdsa(&digest[digest.len() - 32..], &der)? && digest.len() > 32;
                    run.expect(
                        !on_rightmost,
                        "negative control: the rightmost 32 bytes verified",
                    );
                    run.expect(
                        on_truncated,
                        "a served ECDSA signature does not verify over the leftmost 32 bytes",
                    );
                    line(
                        "a",
                        "CKM_ECDSA",
                        &[
                            ("curve", "P-256".into()),
                            ("digest", h.name().into()),
                            ("handover", (*how).into()),
                            ("outcome", "served".into()),
                            ("rc", "-".into()),
                            ("verified_over_leftmost_32", yn(on_truncated)),
                            ("verified_over_full_digest", yn(on_full)),
                            ("verified_over_rightmost_32", yn(on_rightmost)),
                        ],
                    );
                }
                Err(e) => line(
                    "a",
                    "CKM_ECDSA",
                    &[
                        ("curve", "P-256".into()),
                        ("digest", h.name().into()),
                        ("handover", (*how).into()),
                        ("outcome", "lacks".into()),
                        ("rc", rc(e)),
                        ("verified_over_leftmost_32", "n/a".into()),
                    ],
                ),
            }
        }
    }
    Ok(())
}

// ---- way (b): padding in the probe, raw RSA private operation in the TPM ----

fn mgf1(h: Hash, seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut counter = 0u32;
    while out.len() < len {
        let mut input = seed.to_vec();
        input.extend(counter.to_be_bytes());
        out.extend(h.digest(&input));
        counter += 1;
    }
    out.truncate(len);
    out
}

/// EMSA-PSS-ENCODE (RFC 8017, 9.1.1) for a 2048-bit modulus (emBits = 2047).
fn pss_encode(h: Hash, digest: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut m = vec![0u8; 8];
    m.extend(digest);
    m.extend(salt);
    let hash = h.digest(&m);
    let mut db = vec![0u8; RSA_BYTES - salt.len() - h.len() - 2];
    db.push(1);
    db.extend(salt);
    let mask = mgf1(h, &hash, db.len());
    for (b, m) in db.iter_mut().zip(mask) {
        *b ^= m;
    }
    db[0] &= 0x7f;
    db.extend(hash);
    db.push(0xbc);
    db
}

fn pkcs1_pad(payload: &[u8]) -> Vec<u8> {
    let mut em = vec![0u8, 1];
    em.extend(vec![0xff; RSA_BYTES - 3 - payload.len()]);
    em.push(0);
    em.extend(payload);
    em
}

fn raw_private(ctx: &mut Context, key: &Key, em: &[u8]) -> Result<Vec<u8>, tss_esapi::Error> {
    let cipher = PublicKeyRsa::try_from(em.to_vec())?;
    let out = ctx.execute_with_nullauth_session(|c| {
        c.rsa_decrypt(key.handle, cipher, RsaDecryptionScheme::Null, None)
    })?;
    let mut bytes = out.as_bytes().to_vec();
    // The TPM strips leading zero bytes of the result; restore the modulus length.
    while bytes.len() < RSA_BYTES {
        bytes.insert(0, 0);
    }
    Ok(bytes)
}

fn way_b_rsa(
    ctx: &mut Context,
    key: &Key,
    a_key: &Key,
    v: &Verifier,
    run: &mut Run,
) -> Result<(), Fail> {
    let message = b"custodio F107 message";
    let md5sha1 = [
        Sha256::digest(b"m").to_vec(),
        Sha256::digest(b"s")[..4].to_vec(),
    ]
    .concat();
    let mut unknown_oid = digest_info(Hash::Sha256, message);
    unknown_oid[14] = 0x63;
    let mut payloads: Vec<(String, Vec<u8>)> = ALL
        .iter()
        .map(|h| (format!("DigestInfo/{}", h.name()), digest_info(*h, message)))
        .collect();
    payloads.push(("\"36-byte MD5+SHA-1 (TLS 1.0/1.1)\"".into(), md5sha1));
    payloads.push((
        "\"DigestInfo with an unknown hash OID\"".into(),
        unknown_oid,
    ));
    for (label, payload) in payloads {
        match raw_private(ctx, key, &pkcs1_pad(&payload)) {
            Ok(sig) => {
                let ok = v.pkcs1(&payload, &sig)?;
                run.expect(ok, "a served (b) CKM_RSA_PKCS signature does not verify");
                // Same key, way (a), for the bytes: PKCS#1 v1.5 is deterministic.
                let same = parse_digest_info(&payload).and_then(|(h, d)| {
                    let scheme = SignatureScheme::RsaSsa {
                        scheme: HashScheme::new(h.tpm()),
                    };
                    tpm_sign(ctx, key, d, scheme).ok().and_then(|s| rsa_sig(&s))
                });
                let equal = same.map_or("n/a (way a lacks)".to_owned(), |s| yn(s == sig));
                line(
                    "b",
                    "CKM_RSA_PKCS",
                    &[
                        ("payload", label),
                        ("outcome", "served".into()),
                        ("rc", "-".into()),
                        ("verified", yn(ok)),
                        ("bytes_equal_way_a_same_key", equal),
                    ],
                );
            }
            Err(e) => line(
                "b",
                "CKM_RSA_PKCS",
                &[
                    ("payload", label),
                    ("outcome", "lacks".into()),
                    ("rc", rc(e)),
                    ("verified", "n/a".into()),
                ],
            ),
        }
    }
    way_b_pss(ctx, key, v, run)?;
    way_b_controls(ctx, a_key, run);
    Ok(())
}

fn way_b_pss(ctx: &mut Context, key: &Key, v: &Verifier, run: &mut Run) -> Result<(), Fail> {
    let message = b"custodio F107 message";
    for h in PSS {
        let digest = h.digest(message);
        let largest = RSA_BYTES - h.len() - 2;
        let mut requests = vec![h.len(), largest, 0, 20];
        requests.dedup();
        for req in requests {
            let mut salt = Vec::new();
            while salt.len() < req {
                // TPM2_GetRandom returns at most one digest of the largest hash (64 bytes) per call.
                salt.extend(ctx.get_random(req - salt.len())?.as_bytes());
            }
            match raw_private(ctx, key, &pss_encode(h, &digest, &salt)) {
                Ok(sig) => {
                    let found = v.find_salt(h, &digest, &sig)?;
                    let ok = found == Some(req);
                    run.expect(
                        ok,
                        "a served (b) PSS signature does not verify at the requested salt length",
                    );
                    line(
                        "b",
                        "CKM_RSA_PKCS_PSS",
                        &[
                            ("hash", h.name().into()),
                            ("salt_requested", req.to_string()),
                            ("outcome", "served".into()),
                            ("rc", "-".into()),
                            ("salt_found", found.map_or("none".into(), |f| f.to_string())),
                            ("verified", yn(ok)),
                        ],
                    );
                }
                Err(e) => line(
                    "b",
                    "CKM_RSA_PKCS_PSS",
                    &[
                        ("hash", h.name().into()),
                        ("salt_requested", req.to_string()),
                        ("outcome", "lacks".into()),
                        ("rc", rc(e)),
                        ("verified", "n/a".into()),
                    ],
                ),
            }
        }
    }
    Ok(())
}

/// A key without the decrypt attribute cannot do the raw operation: the control showing why (b) needs the attribute.
fn way_b_controls(ctx: &mut Context, a_key: &Key, run: &mut Run) {
    let message = b"custodio F107 message";
    let refusal = match raw_private(ctx, a_key, &pkcs1_pad(&digest_info(Hash::Sha256, message))) {
        Ok(_) => "served (unexpected)".to_owned(),
        Err(e) => rc(e),
    };
    run.expect(
        refusal != "served (unexpected)",
        "a sign-only key did the raw private operation",
    );
    println!("control: way=b key_without_decrypt rsa_decrypt={refusal}");
    for h in [Hash::Sha256, Hash::Sha384, Hash::Sha512] {
        println!(
            "case: way=b mechanism=CKM_ECDSA curve=P-256 digest={} outcome=n/a rc=RSA only: ECDSA has no raw private operation the TPM offers in place of TPM2_Sign",
            h.name()
        );
    }
}

// ---- capabilities ----

fn algorithm_ids(ctx: &mut Context) -> Result<Vec<u16>, Fail> {
    let (data, _) = ctx.get_capability(CapabilityType::Algorithms, 0, 80)?;
    match data {
        CapabilityData::Algorithms(list) => Ok(list
            .iter()
            .map(|p| u16::from(p.algorithm_identifier()))
            .collect()),
        other => Err(format!("unexpected capability data {other:?}").into()),
    }
}

fn curve_ids(ctx: &mut Context) -> Result<Vec<u16>, Fail> {
    let (data, _) = ctx.get_capability(CapabilityType::EccCurves, 0, 32)?;
    match data {
        CapabilityData::EccCurves(list) => Ok(list.iter().map(|c| u16::from(*c)).collect()),
        other => Err(format!("unexpected capability data {other:?}").into()),
    }
}

fn test_parms(ctx: &mut Context, p: PublicParameters) -> String {
    match ctx.test_parms(p) {
        Ok(()) => "supported".into(),
        Err(e) => format!("lacks {}", rc(e)),
    }
}

fn capabilities(ctx: &mut Context) -> Result<(), Fail> {
    let algs = algorithm_ids(ctx)?;
    let names: [(&str, u16); 11] = [
        ("RSA", 0x01),
        ("SHA-1", 0x04),
        ("SHA-256", 0x0b),
        ("SHA-384", 0x0c),
        ("SHA-512", 0x0d),
        ("RSASSA", 0x14),
        ("RSAES", 0x15),
        ("RSAPSS", 0x16),
        ("ECDSA", 0x18),
        ("ECC", 0x23),
        ("MGF1", 0x07),
    ];
    for (name, id) in names {
        println!(
            "capability: call=GetCapability(ALGS) item=algorithm {name} (0x{id:04x}) {}",
            if algs.contains(&id) {
                "present"
            } else {
                "absent"
            }
        );
    }
    let curves = curve_ids(ctx)?;
    println!(
        "capability: call=GetCapability(ECC_CURVES) item=curve NIST P-256 (0x0003) {}",
        if curves.contains(&3) {
            "present"
        } else {
            "absent"
        }
    );
    for h in ALL {
        let rsa = |scheme| {
            PublicRsaParametersBuilder::new()
                .with_scheme(scheme)
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_exponent(RsaExponent::default())
                .build()
                .map(PublicParameters::Rsa)
        };
        let ssa = test_parms(ctx, rsa(RsaScheme::RsaSsa(HashScheme::new(h.tpm())))?);
        println!(
            "capability: call=TestParms key=rsa2048 scheme=RSASSA hash={} {ssa}",
            h.name()
        );
        if h != Hash::Sha1 {
            let pss = test_parms(ctx, rsa(RsaScheme::RsaPss(HashScheme::new(h.tpm())))?);
            println!(
                "capability: call=TestParms key=rsa2048 scheme=RSAPSS hash={} {pss}",
                h.name()
            );
        }
        let ecc = PublicEccParametersBuilder::new_unrestricted_signing_key(
            EccScheme::EcDsa(HashScheme::new(h.tpm())),
            EccCurve::NistP256,
        )
        .build()
        .map(PublicParameters::Ecc)?;
        let r = test_parms(ctx, ecc);
        println!(
            "capability: call=TestParms key=ecc_p256 scheme=ECDSA hash={} {r}",
            h.name()
        );
    }
    let null_rsa = PublicRsaParametersBuilder::new()
        .with_scheme(RsaScheme::Null)
        .with_key_bits(RsaKeyBits::Rsa2048)
        .with_exponent(RsaExponent::default())
        .build()?;
    let r = test_parms(ctx, PublicParameters::Rsa(null_rsa));
    println!(
        "capability: call=TestParms key=rsa2048 scheme=NULL (for way b, with the decrypt attribute) {r}"
    );
    Ok(())
}

// ---- the decrypt attribute ----

/// A blob created under the SRK-template primary, loaded by a second connection: what another holder of the TPM can do.
fn decrypt_experiment(conf: &tss_esapi::tcti_ldr::TctiNameConf) -> Result<(), Fail> {
    let mut ctx =
        Context::new(conf.clone()).map_err(|e| format!("cannot connect to the TPM: {e}"))?;
    let parent = |c: &mut Context| -> Result<KeyHandle, Fail> {
        let tpl = srk_template(false)?;
        Ok(c.execute_with_nullauth_session(|c| {
            c.create_primary(Hierarchy::Owner, tpl, None, None, None, None)
        })?
        .key_handle)
    };
    let p = parent(&mut ctx)?;
    let mut blobs = Vec::new();
    for (label, kind) in [
        ("sign-only", Kind::RsaSign),
        ("sign|decrypt", Kind::RsaSignDecrypt),
    ] {
        let public = template(kind)?;
        let created =
            ctx.execute_with_nullauth_session(|c| c.create(p, public, None, None, None, None))?;
        println!(
            "decrypt_key: {label} attributes: {}",
            describe(&created.out_public)
        );
        blobs.push((label, spki_of(&created.out_public)?, created));
    }
    ctx.flush_context(p.into())?;
    drop(ctx);
    // Another caller: a new connection, a new parent handle, the blobs only.
    let mut other =
        Context::new(conf.clone()).map_err(|e| format!("cannot connect to the TPM: {e}"))?;
    let p2 = parent(&mut other)?;
    for (label, spki, created) in blobs {
        let h = other.execute_with_nullauth_session(|c| {
            c.load(p2, created.out_private.clone(), created.out_public.clone())
        })?;
        let key = Key {
            handle: h,
            public_der: spki.clone(),
            attributes: String::new(),
        };
        // A ciphertext someone encrypted to the public key (an S/MIME message, a recorded TLS RSA key exchange).
        let dir = tempfile::tempdir()?;
        std::fs::write(dir.path().join("pub.der"), &spki)?;
        std::fs::write(dir.path().join("plain"), b"secret message")?;
        let enc = Command::new("openssl")
            .args(["pkeyutl", "-encrypt", "-pubin", "-keyform", "DER", "-inkey"])
            .arg(dir.path().join("pub.der"))
            .arg("-in")
            .arg(dir.path().join("plain"))
            .args(["-pkeyopt", "rsa_padding_mode:pkcs1"])
            .output()?;
        let cipher = PublicKeyRsa::try_from(enc.stdout)?;
        let res = other.execute_with_nullauth_session(|c| {
            c.rsa_decrypt(h, cipher, RsaDecryptionScheme::RsaEs, None)
        });
        let outcome = match res {
            Ok(m) => format!(
                "plaintext recovered: {:?}",
                String::from_utf8_lossy(m.as_bytes())
            ),
            Err(e) => format!("refused {}", rc(e)),
        };
        println!(
            "decrypt_other_caller: key={label} rsa_decrypt(RSAES, chosen ciphertext) {outcome}"
        );
        // The same caller asks for a signature over a digest of its choice.
        let sig = tpm_sign(
            &mut other,
            &key,
            &Sha256::digest(b"chosen"),
            SignatureScheme::RsaSsa {
                scheme: HashScheme::new(HashingAlgorithm::Sha256),
            },
        );
        println!(
            "decrypt_other_caller: key={label} sign(RSASSA, SHA-256, chosen digest) {}",
            if sig.is_ok() {
                "served".to_owned()
            } else {
                "refused".to_owned()
            }
        );
        // Moving the key out: TPM2_Duplicate to no new parent. The key is fixedTPM|fixedParent with an empty authPolicy.
        let dup = other.execute_with_nullauth_session(|c| {
            c.duplicate(
                h.into(),
                tss_esapi::handles::ObjectHandle::None,
                None,
                SymmetricDefinitionObject::Null,
            )
        });
        println!(
            "decrypt_other_caller: key={label} duplicate(no new parent) {}",
            dup.map_or_else(rc, |_| "served (unexpected)".into())
        );
        other.flush_context(h.into())?;
    }
    other.flush_context(p2.into())?;
    Ok(())
}

pub fn run(tcti: Option<&str>) -> Result<bool, Fail> {
    let conf = connect(tcti)?;
    let mut ctx =
        Context::new(conf.clone()).map_err(|e| format!("cannot connect to the TPM: {e}"))?;
    let mut run = Run { bad: Vec::new() };
    super::print_header(&mut ctx)?;
    println!(
        "verifier: {}",
        String::from_utf8_lossy(&Command::new("openssl").arg("version").output()?.stdout).trim()
    );
    println!(
        "table_rule_a: CKM_RSA_PKCS_PSS is served under (a) only when salt_requested equals the salt the TPM produces; any other length is lacks by that policy, not a TPM error"
    );

    let rsa_a = make_key(&mut ctx, Kind::RsaSign)?;
    let rsa_b = make_key(&mut ctx, Kind::RsaSignDecrypt)?;
    let ecc = make_key(&mut ctx, Kind::EccSign)?;
    println!("key: rsa2048 sign-only {}", rsa_a.attributes);
    println!("key: rsa2048 sign|decrypt {}", rsa_b.attributes);
    println!("key: ecc_p256 sign-only {}", ecc.attributes);
    let va = Verifier::new(&rsa_a.public_der)?;
    let vb = Verifier::new(&rsa_b.public_der)?;
    let ve = Verifier::new(&ecc.public_der)?;

    // The verifier must reject: a wrong payload under the right signature (negative control for CKM_RSA_PKCS).
    let digest = Hash::Sha256.digest(b"x");
    let payload = digest_info(Hash::Sha256, b"x");
    let sig = rsa_sig(
        &tpm_sign(
            &mut ctx,
            &rsa_a,
            &digest,
            SignatureScheme::RsaSsa {
                scheme: HashScheme::new(HashingAlgorithm::Sha256),
            },
        )
        .map_err(rc)?,
    )
    .ok_or("not RSA")?;
    let good = va.pkcs1(&payload, &sig)?;
    let bad = va.pkcs1(&digest_info(Hash::Sha256, b"y"), &sig)?;
    run.expect(
        good && !bad,
        "verifier control: right payload must verify and a wrong payload must not",
    );
    println!(
        "control: verifier right_payload={} wrong_payload={}",
        yn(good),
        yn(bad)
    );

    way_a_rsa(&mut ctx, &rsa_a, &va, &mut run)?;
    way_a_ecdsa(&mut ctx, &ecc, &ve, &mut run)?;
    way_b_rsa(&mut ctx, &rsa_b, &rsa_a, &vb, &mut run)?;
    capabilities(&mut ctx)?;
    for k in [&rsa_a, &rsa_b, &ecc] {
        ctx.flush_context(k.handle.into())?;
    }
    drop(ctx);
    decrypt_experiment(&conf)?;
    if run.bad.is_empty() {
        println!("result: every case ran; every served signature verified");
        Ok(true)
    } else {
        for b in &run.bad {
            eprintln!("tpm-probe: FAILED: {b}");
        }
        Ok(false)
    }
}
