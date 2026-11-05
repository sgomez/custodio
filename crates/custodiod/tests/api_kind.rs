//! The storage kind in the API (F119): `ImportP12` returns it next to the key type and `ListKeys` returns it for every
//! key, on the private bus with fake polkit, a software TPM and credential doubles. The replies are read from the raw
//! D-Bus message (signature and value), and compared with the record in the store files.

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
// The rig is shared with `storage_choice`, which uses other parts of it than this target does.
#[allow(dead_code)]
#[path = "storage_choice/rig.rs"]
mod rig;
// Shared with `tpm_import`: this target does not use every helper of it.
#[allow(dead_code)]
#[path = "tpm_import/support.rs"]
mod support;

use custodio_client::{KNOWN_KINDS, Kind as ClientKind};
use custodiod::creds::CredsError;
use custodiod::creds::memory::MemoryCreds;
use custodiod::import::import_p12;
use custodiod::store::Kind;
use custodiod::tpm::open::{NoTpm, TestTcti};
use secrecy::SecretString;
use zbus::block_on;

use crate::common::{SENTINEL_PASSWORD, uid};
use crate::rig::{KindSvc, SUBJECTS, Subject, TestResult, lacks_import};

const KINDS: [Kind; 3] = [Kind::Tpm, Kind::EncryptedTpm, Kind::EncryptedHost];

type Listed = Vec<(String, String, String, Vec<u8>)>;

/// The reply of `ListKeys` as the raw message gives it: signature and rows.
async fn list(svc: &rig::Svc) -> Result<(String, Listed), String> {
    let reply = svc.call_method("ListKeys", &()).await?;
    let body = reply.body();
    let signature = body.signature().to_string();
    let rows = body.deserialize::<Listed>().map_err(|e| e.to_string())?;
    Ok((signature, rows))
}

#[test]
fn import_returns_kind() -> TestResult {
    for kind in KINDS {
        for subject in SUBJECTS {
            block_on(async {
                let k = KindSvc::start(kind).await?;
                let who = format!("{} {}", kind.wire(), subject.reply);
                let reply = k
                    .svc
                    .call_method("ImportP12", &("k", subject.p12.to_vec(), SENTINEL_PASSWORD))
                    .await?;
                let body = reply.body();
                // Nothing but the key type and the kind.
                assert_eq!(body.signature().to_string(), "(ss)", "{who}");
                let (key_type, wire) = body.deserialize::<(String, String)>()?;
                assert_eq!(key_type, subject.reply, "{who}");
                assert_eq!(wire, kind.wire(), "{who}");
                // The reply is the stored record's kind, and a kind the client knows.
                let stored = k.svc.store.get(uid(), "k")?;
                assert_eq!(wire, stored.kind().wire(), "{who}: the stored record");
                assert!(KNOWN_KINDS.contains(&wire.as_str()), "{who}");
                assert!(ClientKind::from_wire(&wire).is_known(), "{who}");
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
        }
    }
    Ok(())
}

/// A service whose store holds one key of each kind for the caller (created in an order that is not the order of the
/// ids, the first one of a kind that differs from the others) and one key of another owner. The keys are put in
/// through the library with the doubles of their kind, the service only lists them.
struct Listing {
    k: KindSvc,
    /// `(id, subject, kind)` in the order of creation.
    keys: Vec<(&'static str, Subject, Kind)>,
}

impl Listing {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let k = KindSvc::start(Kind::EncryptedHost).await?;
        let password = SecretString::from(SENTINEL_PASSWORD.to_owned());
        let keys = vec![
            ("zz-host", SUBJECTS[1], Kind::EncryptedHost),
            ("aa-tpm", SUBJECTS[1], Kind::Tpm),
            ("mm-enc", SUBJECTS[0], Kind::EncryptedTpm),
        ];
        let (filter, _) = k.rig.filter(lacks_import())?;
        for (id, subject, kind) in &keys {
            let put = |owner: u32, id: &str| match kind {
                Kind::Tpm => import_p12(
                    &k.svc.store,
                    &MemoryCreds::host(),
                    &TestTcti::new(&k.rig.tcti()),
                    owner,
                    id,
                    subject.p12,
                    &password,
                ),
                Kind::EncryptedTpm => import_p12(
                    &k.svc.store,
                    &MemoryCreds::tpm(),
                    &TestTcti::new(&filter.tcti()),
                    owner,
                    id,
                    subject.p12,
                    &password,
                ),
                Kind::EncryptedHost => import_p12(
                    &k.svc.store,
                    &MemoryCreds::host(),
                    &NoTpm,
                    owner,
                    id,
                    subject.p12,
                    &password,
                ),
            };
            put(uid(), id)?;
            assert_eq!(k.svc.store.get(uid(), id)?.kind(), *kind, "{id}");
        }
        // Another owner's key, of a kind the caller has too, must not show.
        import_p12(
            &k.svc.store,
            &MemoryCreds::host(),
            &NoTpm,
            uid() + 1,
            "theirs",
            SUBJECTS[0].p12,
            &password,
        )?;
        Ok(Self { k, keys })
    }

    /// What the listing must show: each id with its key type, the kind and the certificate of its own record.
    fn expected(&self) -> Result<Listed, Box<dyn std::error::Error>> {
        let mut rows = Vec::new();
        for (id, subject, kind) in &self.keys {
            let record = self.k.svc.store.get(uid(), id)?;
            assert_eq!(record.kind(), *kind, "{id}");
            rows.push((
                (*id).to_owned(),
                subject.reply.to_owned(),
                record.kind().wire().to_owned(),
                record.certificate().to_vec(),
            ));
        }
        rows.sort();
        Ok(rows)
    }
}

#[test]
fn list_returns_kind() -> TestResult {
    block_on(async {
        let l = Listing::new().await?;
        let (signature, mut rows) = list(&l.k.svc).await?;
        assert_eq!(signature, "a(sssay)");
        rows.sort();
        let want = l.expected()?;
        assert_eq!(rows.len(), 3);
        // The three kinds are all there, each on its own id: a constant kind or the first key's kind fails.
        let kinds: Vec<&str> = rows.iter().map(|r| r.2.as_str()).collect();
        assert_eq!(kinds, ["tpm", "encrypted-tpm", "encrypted-host"]);
        assert_eq!(rows, want);
        // Listing asked neither the TPM nor the credential service.
        assert_eq!(l.k.svc.tpm.opens(), 0);
        assert_eq!(l.k.svc.creds.decrypts(), 0);
        assert_eq!(l.k.svc.creds.encrypts(), 0);
        Ok(())
    })
}

#[test]
fn list_after_loss() -> TestResult {
    block_on(async {
        let l = Listing::new().await?;
        let (_, mut before) = list(&l.k.svc).await?;
        before.sort();
        // The TPM is cleared (the TPM key and the TPM-bound credential are lost) and no credential decrypts.
        l.k.rig.tpm.clear()?;
        l.k.svc
            .creds
            .fail_decrypt_with(Some(CredsError::CannotDecrypt));
        let (_, mut after) = list(&l.k.svc).await?;
        after.sort();
        assert_eq!(after, before);
        assert_eq!(after, l.expected()?);
        assert_eq!(l.k.svc.tpm.opens(), 0);
        assert_eq!(l.k.svc.creds.decrypts(), 0);
        Ok(())
    })
}
