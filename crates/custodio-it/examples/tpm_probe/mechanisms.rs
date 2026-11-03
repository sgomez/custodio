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

use sha2::{Digest as _, Sha256};
use tss_esapi::Context;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{HashScheme, Signature, SignatureScheme};

use super::{Fail, connect};
mod caps;
mod support;
mod wayb;

use caps::{capabilities, decrypt_experiment};
use support::{
    ALL, Hash, Key, Kind, PSS, RSA_BYTES, Run, Verifier, der_uint, digest_info, line, make_key,
    parse_digest_info, rc, rsa_sig, tlv, tpm_sign, yn,
};
use wayb::{way_b_controls, way_b_refused, way_b_rsa};

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
        ("36-byte MD5+SHA-1 stand-in (TLS 1.0/1.1)", md5sha1),
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
        let signed = match tpm_sign(ctx, key, &digest, scheme) {
            Ok(s) => s,
            Err(e) => {
                // A TPM that lacks PSS or this hash is a result, not a failure of the probe.
                let code = rc(e);
                let largest = RSA_BYTES - h.len() - 2;
                let mut requests = vec![h.len(), largest, 0, 20];
                requests.dedup();
                for req in requests {
                    line(
                        "a",
                        "CKM_RSA_PKCS_PSS",
                        &[
                            ("hash", h.name().into()),
                            ("salt_requested", req.to_string()),
                            ("outcome", "lacks".into()),
                            ("rc", code.clone()),
                            ("salt_found", "n/a".into()),
                            ("verified", "n/a".into()),
                        ],
                    );
                }
                continue;
            }
        };
        let sig = rsa_sig(&signed).ok_or("not RSA")?;
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
    let rsa_b = make_key(&mut ctx, Kind::RsaSignDecrypt);
    let ecc = make_key(&mut ctx, Kind::EccSign)?;
    println!("key: rsa2048 sign-only {}", rsa_a.attributes);
    match &rsa_b {
        Ok(k) => println!("key: rsa2048 sign|decrypt {}", k.attributes),
        Err(e) => println!("key: rsa2048 sign|decrypt refused {e}"),
    }
    println!("key: ecc_p256 sign-only {}", ecc.attributes);
    let va = Verifier::new(&rsa_a.public_der)?;
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
    match &rsa_b {
        Ok(k) => {
            let vb = Verifier::new(&k.public_der)?;
            way_b_rsa(&mut ctx, k, &rsa_a, &vb, &mut run)?;
        }
        Err(e) => {
            way_b_refused(&e.to_string());
            way_b_controls(&mut ctx, &rsa_a, &mut run);
        }
    }
    capabilities(&mut ctx)?;
    for k in [Some(&rsa_a), rsa_b.as_ref().ok(), Some(&ecc)]
        .into_iter()
        .flatten()
    {
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
