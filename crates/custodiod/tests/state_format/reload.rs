//! A store opened again over the same state directory (what the service does at an upgrade, F141): every kind, every owner, every certificate.

use super::*;
use custodio_it::swtpm::Swtpm;
use custodiod::tpm::import::import_pkcs8;
use custodiod::tpm::open::TestTcti;
use secrecy::ExposeSecret;

const ALICE: u32 = 1000;
const BOB: u32 = 1001;

fn tpm_record(owner: u32, id: &str, certificate: &[u8]) -> Record {
    let tpm = Swtpm::start().expect("swtpm starts");
    let access = TestTcti::new(&tpm.tcti());
    let imported = import_pkcs8(&access, fixture().key.expose_secret()).expect("imported");
    let protected = Protected::from_imported(&imported).expect("a parent name");
    Record::new(owner, id, Kind::Tpm, certificate, protected).expect("a record")
}

/// Alice holds one key of each kind, bob holds a key under the id alice's `host` has, with another certificate, and one of his own.
fn records() -> Vec<Record> {
    vec![
        tpm_record(ALICE, "tpm", b"cert-alice-tpm"),
        encrypted(ALICE, "etpm", Kind::EncryptedTpm, b"cert-alice-etpm"),
        encrypted(ALICE, "host", Kind::EncryptedHost, b"cert-alice-host"),
        encrypted(BOB, "host", Kind::EncryptedHost, b"cert-bob-host"),
        encrypted(BOB, "bobonly", Kind::EncryptedTpm, b"cert-bob-only"),
    ]
}

/// What a listing of the store shows: owner, id, kind, certificate, in order.
fn shown(store: &KeyStore, owners: &[u32]) -> Vec<(u32, String, Kind, Vec<u8>)> {
    let mut out = Vec::new();
    for &owner in owners {
        let mut ids = store.list(owner).expect("a list");
        ids.sort();
        for id in ids {
            let r = store.get(owner, &id).expect("a record");
            out.push((
                r.owner(),
                r.id().to_owned(),
                r.kind(),
                r.certificate().to_vec(),
            ));
        }
    }
    out
}

#[test]
fn kinds_owners_and_certificates_survive_a_reopen() -> TestResult {
    let (_tmp, store) = fresh();
    let all = records();
    for r in &all {
        store.put(r)?;
    }
    let before = shown(&store, &[ALICE, BOB]);
    // Control: the listing tells the records apart (five rows, three kinds, the shared id twice with two certificates).
    assert_eq!(before.len(), 5);
    assert_eq!(before.iter().filter(|r| r.1 == "host").count(), 2);
    for kind in [Kind::Tpm, Kind::EncryptedTpm, Kind::EncryptedHost] {
        assert!(before.iter().any(|r| r.2 == kind), "{kind:?}");
    }
    let dir = store.dir().to_path_buf();
    drop(store);
    let again = KeyStore::open(&dir)?;
    assert_eq!(shown(&again, &[ALICE, BOB]), before);
    for r in &all {
        assert_eq!(
            &again.get(r.owner(), r.id())?,
            r,
            "{} of {}",
            r.id(),
            r.owner()
        );
    }
    // Nobody sees the other owner's keys: bob's `bobonly` is not in alice's area.
    assert!(!again.contains(ALICE, "bobonly")?);
    assert_eq!(again.get(ALICE, "host")?.certificate(), b"cert-alice-host");
    assert_eq!(again.get(BOB, "host")?.certificate(), b"cert-bob-host");
    // Control: the comparison would see a changed kind or certificate.
    let mut changed = before.clone();
    changed[0].2 = Kind::EncryptedHost;
    assert_ne!(changed, shown(&again, &[ALICE, BOB]));
    again.replace_certificate(BOB, "host", b"cert-bob-replaced")?;
    assert_ne!(shown(&again, &[ALICE, BOB]), before);
    Ok(())
}
