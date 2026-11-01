//! Mismatch, signature after replacement, two uids and store failures.

use super::*;

#[test]
fn replace_mismatch_changes_nothing() -> TestResult {
    block_on(async {
        let r = Rig::start(Answer::Yes, 1000, 1001).await?;
        r.import(r.a(), "ec", EC_P12, Answer::Yes).await?;
        r.import(r.a(), "rsa", RSA_P12, Answer::Yes).await?;
        let before = snapshot(&r.area(1000))?;
        let listed = list(r.a()).await?;
        let cases: [(&str, &[&[u8]]); 2] = [
            ("ec", &[P256_OTHER, RSA_OTHER, RSA_RECERT, P384, ED25519]),
            ("rsa", &[RSA_OTHER, P256_OTHER, P256_RECERT, P384, ED25519]),
        ];
        for (id, certs) in cases {
            for cert in certs {
                r.forget_asks();
                let got = replace(r.a(), id, cert).await;
                assert_eq!(got, Err(ERROR_CERTIFICATE_MISMATCH.to_owned()), "{id}");
                assert_eq!(r.f.asked().len(), 1);
                assert_eq!(snapshot(&r.area(1000))?, before);
                assert_eq!(list(r.a()).await?, listed);
            }
        }
        // The message is the fixed one.
        let e = call(r.a(), "ReplaceCertificate", &("ec", P256_OTHER.to_vec()))
            .await
            .err()
            .ok_or("no error")?;
        assert!(
            e.to_string().contains("certificate does not match the key"),
            "{e}"
        );
        Ok(())
    })
}

fn rsa_public_of(cert: &[u8]) -> Result<rsa::RsaPublicKey, Box<dyn std::error::Error>> {
    use rsa::pkcs8::DecodePublicKey;
    use x509_cert::der::{Decode, Encode};
    let cert = x509_cert::Certificate::from_der(cert)?;
    let spki = cert.tbs_certificate().subject_public_key_info().to_der()?;
    Ok(rsa::RsaPublicKey::from_public_key_der(&spki)?)
}

fn ec_public_of(cert: &[u8]) -> Result<p256::ecdsa::VerifyingKey, Box<dyn std::error::Error>> {
    use p256::pkcs8::DecodePublicKey;
    use x509_cert::der::{Decode, Encode};
    let cert = x509_cert::Certificate::from_der(cert)?;
    let spki = cert.tbs_certificate().subject_public_key_info().to_der()?;
    Ok(p256::ecdsa::VerifyingKey::from_public_key_der(&spki)?)
}

/// The new certificate is for the same key, so the old one would verify the signature too; what is
/// shown is that the old certificate is gone from `ListKeys` and the signature verifies with the key
/// taken from the DER that `ListKeys` returns now.
#[test]
fn sign_after_replace_verifies_with_the_new_certificate() -> TestResult {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    block_on(async {
        let r = Rig::start(Answer::Yes, 1000, 1001).await?;
        r.import(r.a(), "rsa", RSA_P12, Answer::Yes).await?;
        r.import(r.a(), "ec", EC_P12, Answer::Yes).await?;
        let (old_rsa, old_ec) = (
            certificate_of(r.a(), "rsa").await?,
            certificate_of(r.a(), "ec").await?,
        );
        replace(r.a(), "rsa", RSA_RECERT).await?;
        replace(r.a(), "ec", P256_RECERT).await?;
        let (new_rsa, new_ec) = (
            certificate_of(r.a(), "rsa").await?,
            certificate_of(r.a(), "ec").await?,
        );
        assert_eq!((&new_rsa[..], &new_ec[..]), (RSA_RECERT, P256_RECERT));
        assert_ne!(new_rsa, old_rsa);
        assert_ne!(new_ec, old_ec);
        let sig = sign(r.a(), "rsa", CKM_RSA_PKCS, &digest_info()).await?;
        rsa_public_of(&new_rsa)?.verify(
            rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
            &digest(),
            &sig,
        )?;
        let sig = sign(r.a(), "ec", CKM_ECDSA, &digest()).await?;
        ec_public_of(&new_ec)?
            .verify_prehash(&digest(), &p256::ecdsa::Signature::from_slice(&sig)?)?;
        Ok(())
    })
}

#[test]
fn replace_leaves_other_uids_alone() -> TestResult {
    block_on(async {
        for (ua, ub) in UID_PAIRS {
            let r = Rig::start(Answer::Yes, ua, ub).await?;
            r.import(r.a(), "my-key", EC_P12, Answer::Yes).await?;
            r.import(&r.b, "my-key", OTHER_EC_P12, Answer::Yes).await?;
            let (old_a, old_b) = (
                certificate_of(r.a(), "my-key").await?,
                certificate_of(&r.b, "my-key").await?,
            );
            let before_a = snapshot(&r.area(ua))?;
            // b has another key under the same id: its own matching certificate is refused.
            assert_eq!(
                replace(&r.b, "my-key", P256_RECERT).await,
                Err(ERROR_CERTIFICATE_MISMATCH.to_owned()),
                "{ua} {ub}"
            );
            assert_eq!(
                replace(&r.b, "my-key", &old_a).await,
                Err(ERROR_CERTIFICATE_MISMATCH.to_owned())
            );
            assert_eq!(
                replace(r.a(), "my-key", &old_b).await,
                Err(ERROR_CERTIFICATE_MISMATCH.to_owned())
            );
            // b's own key accepts its own certificate again, and a's files do not change.
            replace(&r.b, "my-key", &old_b).await?;
            replace(r.a(), "my-key", P256_RECERT).await?;
            assert_eq!(certificate_of(&r.b, "my-key").await?, old_b);
            assert_eq!(certificate_of(r.a(), "my-key").await?, P256_RECERT);
            assert_ne!(snapshot(&r.area(ua))?, before_a);
            assert_eq!(std::fs::read(r.area(ub).join("my-key-cert"))?, old_b);
            assert_eq!(sign_err(&r.b, "my-key").await, "ok");
        }
        Ok(())
    })
}

#[test]
fn replace_store_failures() -> TestResult {
    block_on(async {
        let r = Rig::start(Answer::Yes, common::uid(), common::uid() + 1).await?;
        let area = r.area(common::uid());
        if !is_root() {
            r.import(r.a(), "k", EC_P12, Answer::Yes).await?;
            let before = snapshot(&area)?;
            // The area becomes read-only while polkit answers, after the lookup found the key.
            let a = area.clone();
            r.f.on_request(move || {
                let _ = std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o500));
            });
            assert_eq!(
                replace(r.a(), "k", P256_RECERT).await,
                Err(ERROR_INTERNAL.to_owned())
            );
            // The lookup did succeed: polkit was asked once.
            assert_eq!(r.f.asked().len(), 1);
            *r.f.hook.lock().unwrap_or_else(PoisonError::into_inner) = None;
            std::fs::set_permissions(&area, std::fs::Permissions::from_mode(0o700))?;
            assert_eq!(snapshot(&area)?, before);
            assert_eq!(sign_err(r.a(), "k").await, "ok");
            std::fs::remove_file(area.join("k"))?;
            std::fs::remove_file(area.join("k-cert"))?;
        }
        // The certificate entry is a directory, or a symlink to a file elsewhere.
        for kind in ["directory", "symlink"] {
            let id = format!("m-{kind}");
            r.import(r.a(), &id, EC_P12, Answer::Yes).await?;
            let cert = area.join(format!("{id}-cert"));
            let outside = r.f.store_dir().join("outside");
            std::fs::write(&outside, b"outside")?;
            std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600))?;
            std::fs::remove_file(&cert)?;
            if kind == "directory" {
                std::fs::create_dir(&cert)?;
            } else {
                std::os::unix::fs::symlink(&outside, &cert)?;
            }
            r.forget_asks();
            assert_eq!(
                replace(r.a(), &id, P256_RECERT).await,
                Err(ERROR_INTERNAL.to_owned())
            );
            assert_eq!(r.f.asked().len(), 1, "{kind}");
            assert_eq!(std::fs::read(&outside)?, b"outside");
            assert_eq!(
                std::fs::symlink_metadata(&cert)?.is_dir(),
                kind == "directory"
            );
            assert_eq!(
                std::fs::symlink_metadata(&cert)?.is_symlink(),
                kind == "symlink"
            );
            assert!(!names(&area)?.iter().any(|n| n.starts_with(".tmp")));
            assert_eq!(sign_err(r.a(), &id).await, "ok");
        }
        Ok(())
    })
}
