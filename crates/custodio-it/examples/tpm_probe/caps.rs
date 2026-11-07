//! Capability queries and the `decrypt` experiments of `tpm-probe mechanisms`.

use std::process::Command;

use sha2::{Digest as _, Sha256};
use tss_esapi::Context;
use tss_esapi::constants::CapabilityType;
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::reserved_handles::Hierarchy;
use tss_esapi::structures::{
    CapabilityData, EccScheme, HashScheme, PublicEccParametersBuilder, PublicKeyRsa,
    PublicParameters, PublicRsaParametersBuilder, RsaDecryptionScheme, RsaExponent, RsaScheme,
    SignatureScheme, SymmetricDefinitionObject,
};

use super::super::{Fail, srk_template};
use super::support::{ALL, Hash, Key, Kind, describe, rc, spki_of, template, tpm_sign};

// ---- capabilities ----

pub(crate) fn algorithm_ids(ctx: &mut Context) -> Result<Vec<u16>, Fail> {
    let (data, _) = ctx.get_capability(CapabilityType::Algorithms, 0, 80)?;
    match data {
        CapabilityData::Algorithms(list) => Ok(list
            .iter()
            .map(|p| u16::from(p.algorithm_identifier()))
            .collect()),
        other => Err(format!("unexpected capability data {other:?}").into()),
    }
}

pub(crate) fn curve_ids(ctx: &mut Context) -> Result<Vec<u16>, Fail> {
    let (data, _) = ctx.get_capability(CapabilityType::EccCurves, 0, 32)?;
    match data {
        CapabilityData::EccCurves(list) => Ok(list.iter().map(|c| u16::from(*c)).collect()),
        other => Err(format!("unexpected capability data {other:?}").into()),
    }
}

pub(crate) fn test_parms(ctx: &mut Context, p: PublicParameters) -> String {
    match ctx.test_parms(p) {
        Ok(()) => "supported".into(),
        Err(e) => format!("lacks {}", rc(e)),
    }
}

pub(crate) fn capabilities(ctx: &mut Context) -> Result<(), Fail> {
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
        if h == Hash::Sha1 {
            continue; // SHA-1 is not in the ECC list: P-256 uses SHA-256, SHA-384, SHA-512 only
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

/// A ciphertext someone encrypted to the public key (an S/MIME message, a recorded TLS RSA key exchange).
pub(crate) fn encrypt_to(spki: &[u8]) -> Result<PublicKeyRsa, Fail> {
    let dir = tempfile::tempdir()?;
    std::fs::write(dir.path().join("pub.der"), spki)?;
    std::fs::write(dir.path().join("plain"), b"secret message")?;
    let enc = Command::new("openssl")
        .args(["pkeyutl", "-encrypt", "-pubin", "-keyform", "DER", "-inkey"])
        .arg(dir.path().join("pub.der"))
        .arg("-in")
        .arg(dir.path().join("plain"))
        .args(["-pkeyopt", "rsa_padding_mode:pkcs1"])
        .output()?;
    Ok(PublicKeyRsa::try_from(enc.stdout)?)
}

/// A blob created under the SRK-template primary, loaded by a second connection: what another holder of the TPM can do.
pub(crate) fn decrypt_experiment(conf: &tss_esapi::tcti_ldr::TctiNameConf) -> Result<(), Fail> {
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
        let created = match ctx
            .execute_with_nullauth_session(|c| c.create(p, public, None, None, None, None))
        {
            Ok(c) => c,
            Err(e) => {
                println!("decrypt_key: {label} refused {}", rc(e));
                continue;
            }
        };
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
        let cipher = encrypt_to(&spki)?;
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
