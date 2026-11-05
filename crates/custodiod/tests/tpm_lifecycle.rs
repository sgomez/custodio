//! Keys and the TPM over time (F129): PCR extensions, a restart of `swtpm` and of the service, and a cleared TPM. The
//! real service on a private bus with fake polkit, a real `swtpm`, the real `systemd-creds` bound to it for the
//! `encrypted-tpm` keys, and the in-memory journal.
//!
//! One service imports four keys: kind `tpm` (RSA 2048 and P-256) and kind `encrypted-tpm` (the same two key types).
//! Every `#[test]` builds its own store of four and runs its part of the story; each one that clears the TPM signs with
//! every key first, so a `KeyLost` cannot come from an import that was already broken.
//!
//! The single-failure rows (a cleared TPM, a changed host key, a damaged blob) are `sign_kinds` and `kind_audit`;
//! duplication is `tpm_duplicate`; the one polkit request per signature is proven by the sign features and is counted
//! here only after the restart, where an authorization carried over would show.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

// The shared helpers are used in full by other tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/bus.rs"]
mod bus;
// The shared helpers are used in full by other tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/common.rs"]
mod common;
// Shared with `creds`: this target does not use every helper of it.
#[allow(dead_code)]
#[path = "creds/env.rs"]
mod env;
// Shared with `sign_kinds`: this target does not use every helper of it.
#[allow(dead_code, unused_imports)]
#[path = "sign_kinds/kit.rs"]
mod kit;
// Shared with `tpm_sign`: this target does not use every helper of it.
#[allow(dead_code)]
#[path = "tpm_sign/oracle.rs"]
mod oracle;
// Shared with `storage_choice`: this target does not use every helper of it.
#[allow(dead_code)]
#[path = "storage_choice/rig.rs"]
mod rig;
#[path = "tpm_lifecycle/world.rs"]
mod world;
// Shared with `tpm_import`: this target does not use every helper of it.
#[allow(dead_code, unused_imports)]
#[path = "tpm_import/support.rs"]
mod support;

use custodiod::audit::{Outcome, SignCause};
use custodiod::creds::Credentials;
use custodiod::creds::memory::MemoryCreds;
use custodiod::store::Kind;
use custodiod::tpm::open::TestTcti;
use secrecy::SecretSlice;
use zbus::block_on;

use bus::Answer;
use common::{SENTINEL_PASSWORD, uid};
use kit::{ERR_KEY_LOST, ERR_NO_KEY, Family};
use rig::{Counting, Res, SpyCreds, Svc, TestResult, pkcs8_of};
use world::{
    KEYS, Listed, PCRS, World, credentials_of, documented_message, extend_all,
    is_real_tpm_credential, world,
};

#[test]
fn imports_four_keys() -> TestResult {
    block_on(async {
        let w = world().await?;
        let listed = w.list().await?;
        let mut want: Vec<_> = KEYS
            .iter()
            .map(|k| {
                (
                    k.id.to_owned(),
                    k.subject.reply.to_owned(),
                    k.kind.wire().to_owned(),
                )
            })
            .collect();
        want.sort();
        let got: Vec<_> = listed
            .iter()
            .map(|l| (l.0.clone(), l.1.clone(), l.2.clone()))
            .collect();
        assert_eq!(got, want);
        let kinds = |k: Kind| listed.iter().filter(|l| l.2 == k.wire()).count();
        assert_eq!((kinds(Kind::Tpm), kinds(Kind::EncryptedTpm)), (2, 2));
        assert_eq!(w.snapshot().len(), 4);
        for key in KEYS {
            assert_eq!(w.svc.kind_of(key.id), Some(key.kind));
            let credential = credentials_of(&w, key);
            match key.kind {
                Kind::EncryptedTpm => {
                    assert!(is_real_tpm_credential(&credential.unwrap()), "{}", key.id);
                }
                _ => assert!(credential.is_none(), "{}", key.id),
            }
        }
        // The real tool ran for exactly the two encrypted keys, naming an empty PCR list.
        assert_eq!(
            w.daemon.calls_log().matches("ARG --tpm2-pcrs=\n").count(),
            2
        );
        // Control: the credential of the in-memory double is not accepted as a real one.
        let fake = MemoryCreds::tpm()
            .encrypt("k", &SecretSlice::new(Box::from(&b"secret"[..])))
            .unwrap();
        assert!(!is_real_tpm_credential(&fake));
        assert!(!is_real_tpm_credential(b"short"));
        w.assert_all_sign("baseline").await
    })
}

#[test]
fn signs_after_pcr_extension() -> TestResult {
    block_on(async {
        let w = world().await?;
        w.assert_all_sign("baseline").await?;
        // Negative control: a credential bound to PCR 7 decrypts now and not after the extension.
        let bound = w.pcr7_credential();
        assert_eq!(w.decrypts(&bound).as_deref(), Some(&b"lifecycle"[..]));
        let before = w.pcrs();
        extend_all(&w.rig);
        let after = w.pcrs();
        for p in PCRS {
            assert_ne!(before[&p], after[&p], "PCR {p}");
        }
        assert!(
            w.decrypts(&bound).is_none(),
            "a PCR 7 credential must break"
        );
        w.assert_all_sign("after the extension").await
    })
}

#[test]
fn signs_after_restarts() -> TestResult {
    block_on(async {
        let mut w = world().await?;
        w.assert_all_sign("baseline").await?;
        let listed = w.list().await?;
        let files = w.snapshot();
        let bound = w.pcr7_credential();
        let before = w.pcrs();
        extend_all(&w.rig);
        let extended = w.pcrs();
        assert!(w.decrypts(&bound).is_none());
        let owner = w.svc.name_owner().await?;
        // The TPM restarts while the old service is still up and then the service: the order of the acceptance test.
        w.rig.tpm.restart()?;
        let reset = w.pcrs();
        for p in PCRS {
            assert_eq!(reset[&p], before[&p], "PCR {p} is back to its start value");
            assert_ne!(reset[&p], extended[&p], "PCR {p}");
        }
        assert_eq!(w.decrypts(&bound).as_deref(), Some(&b"lifecycle"[..]));
        w.svc.restart_service().await?;
        let new_owner = w.svc.name_owner().await?;
        assert_ne!(new_owner, owner, "a new service owns the name");
        assert_eq!(w.list().await?, listed);
        assert_eq!(w.snapshot(), files);
        let asked = w.svc.requests.lock().unwrap().len();
        let signed = w.svc.sink.entries().len();
        w.assert_all_sign("after the restarts").await?;
        let signatures: usize = KEYS.iter().map(|k| Family::of(k.subject).len()).sum();
        // Nothing is carried over from the old service: polkit is asked once for each signature.
        assert_eq!(w.svc.requests.lock().unwrap().len() - asked, signatures);
        let entries = w.svc.sink.entries();
        assert_eq!(entries.len() - signed, signatures);
        assert!(
            entries[signed..]
                .iter()
                .all(|e| e.outcome() == Outcome::Signed)
        );
        // Negative control: a service on an empty store lists nothing and cannot sign.
        let empty = Svc::start(
            Counting::new(TestTcti::new(&w.rig.tcti())),
            SpyCreds::new(MemoryCreds::host()),
            Answer::Yes,
        )
        .await?;
        let (name, _) = empty
            .call_error(
                "Sign",
                &("tpm-rsa", 1u32, 0u32, 0u32, common::digest_info()),
            )
            .await
            .unwrap_err();
        assert_eq!(name, ERR_NO_KEY);
        Ok(())
    })
}

/// Signs with every key after the TPM was cleared: each fails `KeyLost` with the documented message and one entry.
async fn assert_all_lost(w: &World, context: &str) -> TestResult {
    let message = documented_message(ERR_KEY_LOST);
    assert_eq!(message, "the stored key can no longer be used");
    for key in KEYS {
        let family = Family::of(key.subject)[0];
        let before = w.svc.sink.entries().len();
        let (name, text) = w.sign_raw(key, family).await.unwrap_err();
        assert_eq!(
            (name.as_str(), text.as_str()),
            (ERR_KEY_LOST, message.as_str()),
            "{context}: {}",
            key.id
        );
        let entries = w.svc.sink.entries();
        assert_eq!(entries.len(), before + 1, "{context}: {}", key.id);
        let e = entries.last().unwrap();
        assert_eq!(e.outcome(), Outcome::SigningFailed);
        assert_eq!(e.cause(), Some(SignCause::KeyLost));
        assert_eq!(e.storage_kind(), Some(key.kind));
        assert_eq!(e.key_id().as_str(), key.id);
        let field = |n: &str| {
            e.fields()
                .into_iter()
                .find(|(f, _)| *f == n)
                .map(|(_, v)| v)
        };
        assert_eq!(field("CUSTODIO_UID"), Some(uid().to_string()));
        assert_eq!(field("CUSTODIO_CAUSE").as_deref(), Some("key_lost"));
        let shown = format!("{:?}{:?}", e.fields(), e.message());
        assert!(!shown.contains(SENTINEL_PASSWORD), "{}", key.id);
        let pkcs8 = pkcs8_of(key.subject);
        assert!(
            !support::contains(shown.as_bytes(), &pkcs8[..32]),
            "{}",
            key.id
        );
    }
    Ok(())
}

/// The story up to the clear: the four keys signed before it (no `key_lost` entry among them), then the TPM is cleared.
async fn cleared() -> Res<World> {
    let w = world().await?;
    w.assert_all_sign("baseline").await?;
    assert!(
        w.svc
            .sink
            .entries()
            .iter()
            .all(|e| e.outcome() == Outcome::Signed && e.cause().is_none())
    );
    w.rig.tpm.clear()?;
    Ok(w)
}

#[test]
fn cleared_tpm_sign_fails_documented() -> TestResult {
    block_on(async {
        let w = cleared().await?;
        assert_all_lost(&w, "after the clear").await
    })
}

#[test]
fn cleared_keys_stay_listed() -> TestResult {
    block_on(async {
        let mut w = world().await?;
        w.assert_all_sign("baseline").await?;
        let listed = w.list().await?;
        let files = w.snapshot();
        w.rig.tpm.clear()?;
        assert_all_lost(&w, "after the clear").await?;
        assert_eq!(w.list().await?, listed);
        // The same files under the same names with the same bytes: nothing re-stored, nothing turned into another kind.
        assert_eq!(w.snapshot(), files);
        for key in KEYS {
            assert_eq!(w.svc.kind_of(key.id), Some(key.kind));
        }
        w.svc.restart_service().await?;
        assert_eq!(w.list().await?, listed);
        assert_eq!(w.snapshot(), files);
        assert_all_lost(&w, "after the restart").await
    })
}

#[test]
fn cleared_keys_can_be_deleted() -> TestResult {
    block_on(async {
        let w = cleared().await?;
        assert_all_lost(&w, "before the delete").await?;
        for key in KEYS {
            w.svc.call_method("DeleteKey", &(key.id,)).await?;
        }
        assert_eq!(w.list().await?, Listed::new());
        assert!(w.snapshot().is_empty());
        let deleted: Vec<String> = w
            .svc
            .entries()
            .iter()
            .filter(|e| e.outcome_name() == "deleted")
            .map(|e| e.key_id().as_str().to_owned())
            .collect();
        let mut want: Vec<_> = KEYS.iter().map(|k| k.id.to_owned()).collect();
        want.sort();
        let mut got = deleted;
        got.sort();
        assert_eq!(got, want);
        // The earlier failures came from the stored keys: an id that is gone is another error.
        for key in KEYS {
            let (name, _) = w
                .sign_raw(key, Family::of(key.subject)[0])
                .await
                .unwrap_err();
            assert_eq!(name, ERR_NO_KEY, "{}", key.id);
        }
        Ok(())
    })
}
