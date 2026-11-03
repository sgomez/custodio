//! Way (b) of `tpm-probe mechanisms`: padding built here, raw RSA private operation in the TPM.

use sha2::{Digest as _, Sha256};
use tss_esapi::Context;
use tss_esapi::structures::{HashScheme, PublicKeyRsa, RsaDecryptionScheme, SignatureScheme};

use super::super::Fail;
use super::support::{
    ALL, Hash, Key, PSS, RSA_BYTES, Run, Verifier, digest_info, line, parse_digest_info, rc,
    rsa_sig, tpm_sign, yn,
};

// ---- way (b): padding in the probe, raw RSA private operation in the TPM ----

pub(crate) fn mgf1(h: Hash, seed: &[u8], len: usize) -> Vec<u8> {
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
pub(crate) fn pss_encode(h: Hash, digest: &[u8], salt: &[u8]) -> Vec<u8> {
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

pub(crate) fn pkcs1_pad(payload: &[u8]) -> Vec<u8> {
    let mut em = vec![0u8, 1];
    em.extend(vec![0xff; RSA_BYTES - 3 - payload.len()]);
    em.push(0);
    em.extend(payload);
    em
}

pub(crate) fn raw_private(
    ctx: &mut Context,
    key: &Key,
    em: &[u8],
) -> Result<Vec<u8>, tss_esapi::Error> {
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

pub(crate) fn way_b_rsa(
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
    payloads.push((
        "\"36-byte MD5+SHA-1 stand-in (TLS 1.0/1.1)\"".into(),
        md5sha1,
    ));
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

pub(crate) fn way_b_pss(
    ctx: &mut Context,
    key: &Key,
    v: &Verifier,
    run: &mut Run,
) -> Result<(), Fail> {
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

/// The TPM refused the `sign|decrypt` template: every (b) case is `lacks` with that code.
pub(crate) fn way_b_refused(code: &str) {
    let mut payloads: Vec<String> = ALL
        .iter()
        .map(|h| format!("DigestInfo/{}", h.name()))
        .collect();
    payloads.push("\"36-byte MD5+SHA-1 stand-in (TLS 1.0/1.1)\"".into());
    payloads.push("\"DigestInfo with an unknown hash OID\"".into());
    for label in payloads {
        line(
            "b",
            "CKM_RSA_PKCS",
            &[
                ("payload", label),
                ("outcome", "lacks".into()),
                ("rc", code.to_owned()),
                ("verified", "n/a".into()),
            ],
        );
    }
    for h in PSS {
        let largest = RSA_BYTES - h.len() - 2;
        let mut requests = vec![h.len(), largest, 0, 20];
        requests.dedup();
        for req in requests {
            line(
                "b",
                "CKM_RSA_PKCS_PSS",
                &[
                    ("hash", h.name().into()),
                    ("salt_requested", req.to_string()),
                    ("outcome", "lacks".into()),
                    ("rc", code.to_owned()),
                    ("verified", "n/a".into()),
                ],
            );
        }
    }
}

/// A key without the decrypt attribute cannot do the raw operation: the control showing why (b) needs the attribute.
pub(crate) fn way_b_controls(ctx: &mut Context, a_key: &Key, run: &mut Run) {
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
