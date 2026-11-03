//! Shared pieces of `tpm-probe mechanisms`: hashes, DER, the external verifier, keys and output helpers.

use std::process::Command;

use sha2::{Digest as _, Sha256, Sha384, Sha512};
use tss_esapi::Context;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::reserved_handles::Hierarchy;
use tss_esapi::structures::{
    Digest, EccPoint, EccScheme, HashScheme, Public, PublicBuilder, PublicEccParametersBuilder,
    PublicKeyRsa, PublicRsaParametersBuilder, RsaExponent, RsaScheme, Signature, SignatureScheme,
};

use super::super::Fail;

pub(crate) const RSA_BYTES: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }
    pub(crate) const fn openssl(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }
    pub(crate) const fn len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
    pub(crate) const fn tpm(self) -> HashingAlgorithm {
        match self {
            Self::Sha1 => HashingAlgorithm::Sha1,
            Self::Sha256 => HashingAlgorithm::Sha256,
            Self::Sha384 => HashingAlgorithm::Sha384,
            Self::Sha512 => HashingAlgorithm::Sha512,
        }
    }
    /// The DER prefix of a `DigestInfo` for this hash (RFC 8017, section 9.2, note 1).
    pub(crate) const fn prefix(self) -> &'static [u8] {
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
    pub(crate) fn digest(self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => Sha256::digest(message)[..20].to_vec(),
            Self::Sha256 => Sha256::digest(message).to_vec(),
            Self::Sha384 => Sha384::digest(message).to_vec(),
            Self::Sha512 => Sha512::digest(message).to_vec(),
        }
    }
}

pub(crate) const ALL: [Hash; 4] = [Hash::Sha1, Hash::Sha256, Hash::Sha384, Hash::Sha512];
pub(crate) const PSS: [Hash; 3] = [Hash::Sha256, Hash::Sha384, Hash::Sha512];

/// The `DigestInfo` the service would parse: a known prefix followed by a digest of the right length.
pub(crate) fn parse_digest_info(payload: &[u8]) -> Option<(Hash, &[u8])> {
    ALL.into_iter().find_map(|h| {
        let rest = payload.strip_prefix(h.prefix())?;
        (rest.len() == h.len()).then_some((h, rest))
    })
}

pub(crate) fn digest_info(h: Hash, message: &[u8]) -> Vec<u8> {
    let mut v = h.prefix().to_vec();
    v.extend(h.digest(message));
    v
}

pub(crate) fn der_len(n: usize) -> Vec<u8> {
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

pub(crate) fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend(der_len(body.len()));
    v.extend(body);
    v
}

/// DER INTEGER from big-endian unsigned bytes.
pub(crate) fn der_uint(bytes: &[u8]) -> Vec<u8> {
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

pub(crate) fn spki_rsa(n: &[u8], e: u32) -> Vec<u8> {
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

pub(crate) fn spki_p256(x: &[u8], y: &[u8]) -> Vec<u8> {
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

pub(crate) fn pad32(v: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32usize.saturating_sub(v.len())];
    out.extend(v);
    out
}

/// The independent verifier: the `openssl` command line, on files in a private temporary directory.
pub(crate) struct Verifier {
    pub(crate) dir: tempfile::TempDir,
}

impl Verifier {
    pub(crate) fn new(public_der: &[u8]) -> Result<Self, Fail> {
        let dir = tempfile::tempdir()?;
        std::fs::write(dir.path().join("pub.der"), public_der)?;
        Ok(Self { dir })
    }
    pub(crate) fn run(&self, data: &[u8], sig: &[u8], opts: &[String]) -> Result<bool, Fail> {
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
    pub(crate) fn pkcs1(&self, payload: &[u8], sig: &[u8]) -> Result<bool, Fail> {
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
    pub(crate) fn pss(
        &self,
        h: Hash,
        digest: &[u8],
        sig: &[u8],
        salt: usize,
    ) -> Result<bool, Fail> {
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
    pub(crate) fn ecdsa(&self, digest: &[u8], der_sig: &[u8]) -> Result<bool, Fail> {
        self.run(digest, der_sig, &[])
    }
    /// Smallest salt length 0..=max under which the PSS signature verifies.
    pub(crate) fn find_salt(
        &self,
        h: Hash,
        digest: &[u8],
        sig: &[u8],
    ) -> Result<Option<usize>, Fail> {
        for salt in 0..=(RSA_BYTES - h.len() - 2) {
            if self.pss(h, digest, sig, salt)? {
                return Ok(Some(salt));
            }
        }
        Ok(None)
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Kind {
    RsaSign,
    RsaSignDecrypt,
    EccSign,
}

pub(crate) struct Key {
    pub(crate) handle: KeyHandle,
    pub(crate) public_der: Vec<u8>,
    pub(crate) attributes: String,
}

pub(crate) fn template(kind: Kind) -> Result<Public, Fail> {
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

pub(crate) fn describe(public: &Public) -> String {
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

pub(crate) fn spki_of(public: &Public) -> Result<Vec<u8>, Fail> {
    Ok(match public {
        Public::Rsa { unique, .. } => spki_rsa(unique.as_bytes(), 65537),
        Public::Ecc { unique, .. } => spki_p256(unique.x().as_bytes(), unique.y().as_bytes()),
        _ => return Err("unexpected key type".into()),
    })
}

pub(crate) fn make_key(ctx: &mut Context, kind: Kind) -> Result<Key, Fail> {
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
pub(crate) fn rc(e: tss_esapi::Error) -> String {
    e.to_string().replace("TSS Layer: TPM, ", "")
}

pub(crate) fn tpm_sign(
    ctx: &mut Context,
    key: &Key,
    digest: &[u8],
    scheme: SignatureScheme,
) -> Result<Signature, tss_esapi::Error> {
    let d = Digest::try_from(digest.to_vec())?;
    ctx.execute_with_nullauth_session(|c| c.sign(key.handle, d, scheme, None))
}

pub(crate) fn rsa_sig(s: &Signature) -> Option<Vec<u8>> {
    match s {
        Signature::RsaSsa(r) | Signature::RsaPss(r) => Some(r.signature().as_bytes().to_vec()),
        _ => None,
    }
}

pub(crate) fn line(way: &str, mechanism: &str, fields: &[(&str, String)]) {
    let rest: Vec<String> = fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
    println!("case: way={way} mechanism={mechanism} {}", rest.join(" "));
}

pub(crate) fn yn(b: bool) -> String {
    if b { "yes" } else { "no" }.into()
}

/// Probe state: the problems that make the exit status 1.
pub(crate) struct Run {
    pub(crate) bad: Vec<String>,
}

impl Run {
    pub(crate) fn expect(&mut self, ok: bool, what: &str) {
        if !ok {
            self.bad.push(what.to_owned());
        }
    }
}
