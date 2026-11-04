//! The kind, the record round trip and what `put` refuses.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use super::*;
use crate::creds::header::{Binding, HeaderError};
use crate::import::parse_p12;
use crate::tpm::blob::{Blob, Imported};
use crate::tpm::key::ImportKey;
use crate::tpm::wrap;
use secrecy::{ExposeSecret, SecretString};
use tss_esapi::traits::Marshall;

pub(super) const P12: &[u8] = include_bytes!("../../../tests/fixtures/p256.p12");

/// The parent name of the test blobs: a SHA-256 name (algorithm id and digest).
pub(super) fn parent_name() -> Vec<u8> {
    let mut name = vec![0, 0x0b];
    name.extend([0x42; 32]);
    name
}

/// The key and certificate of the P-256 fixture.
pub(super) fn fixture() -> crate::import::ParsedP12 {
    parse_p12(P12, &SecretString::from("test-password".to_owned())).expect("the fixture parses")
}

/// A well-formed blob of the fixture's public key; the private area is a stand-in (integrity digest
/// and data), which is all the framing looks at.
pub(super) fn tpm_blob() -> Blob {
    let key = ImportKey::from_pkcs8(fixture().key.expose_secret()).expect("an importable key");
    let public = wrap::template(&key)
        .expect("a template")
        .marshall()
        .expect("marshalled");
    let mut private = vec![0, 32];
    private.extend([9_u8; 32]);
    private.extend([7_u8; 40]);
    Blob::from_parts(&public, &private).expect("a well-formed blob")
}

pub(super) fn tpm_protected() -> Protected {
    let imported = Imported {
        blob: tpm_blob(),
        parent_name: parent_name(),
    };
    Protected::from_imported(&imported).expect("a parent name within bounds")
}

pub(super) fn sealed_with(creds: &MemoryCreds) -> Protected {
    let plain = secrecy::SecretSlice::from(b"KEY-PLAINTEXT-MARKER".to_vec());
    let sealed = crate::creds::seal(creds, "test", &plain).expect("sealed");
    Protected::from_sealed(&sealed)
}

/// One valid record of each kind, with the file name each is stored under.
pub(super) fn one_of_each() -> Vec<Record> {
    let cert = fixture().certificate;
    [
        (Kind::Tpm, tpm_protected()),
        (Kind::EncryptedTpm, sealed_with(&MemoryCreds::tpm())),
        (Kind::EncryptedHost, sealed_with(&MemoryCreds::host())),
    ]
    .into_iter()
    .map(|(kind, protected)| Record::new(OWNER, kind.wire(), kind, &cert, protected).unwrap())
    .collect()
}

#[test]
fn kind_wire_strings_are_pinned() {
    // Chosen once, only added to: these literals are the contract with F119 and F120.
    assert_eq!(Kind::Tpm.wire(), "tpm");
    assert_eq!(Kind::EncryptedTpm.wire(), "encrypted-tpm");
    assert_eq!(Kind::EncryptedHost.wire(), "encrypted-host");
    let all = [Kind::Tpm, Kind::EncryptedTpm, Kind::EncryptedHost];
    for kind in all {
        assert_eq!(Kind::from_wire(kind.wire()), Some(kind));
        assert_eq!(Kind::from_tag(kind.tag()), Some(kind));
    }
    for unknown in [
        "",
        "TPM",
        "encrypted",
        "encrypted-",
        "tpm ",
        "host",
        "encrypted-tpm\n",
    ] {
        assert_eq!(Kind::from_wire(unknown), None, "{unknown:?}");
    }
    // The tags are their own thing, never reused or equal.
    assert_eq!(all.map(Kind::tag), [1, 2, 3]);
    for tag in [0, 4, 255] {
        assert_eq!(Kind::from_tag(tag), None);
    }
}

#[test]
fn record_round_trip() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    for record in one_of_each() {
        store.put(&record)?;
        let got = store.get(OWNER, record.id())?;
        // All five fields, after a trip through the file.
        assert_eq!(got.owner(), OWNER);
        assert_eq!(got.id(), record.id());
        assert_eq!(got.kind(), record.kind());
        assert_eq!(got.certificate(), record.certificate());
        assert_eq!(got.protected(), record.protected());
        assert_eq!(got, record);
        // The file is exactly the encoding, and the kind follows the protected key.
        assert_eq!(fs::read(area(&store).join(record.id()))?, record.encode()?);
        assert_eq!(got.protected().natural_kind(), got.kind());
    }
    // A TPM record keeps the name of its parent next to the blob.
    let tpm = store.get(OWNER, "tpm")?;
    let (blob, name) = tpm.protected().blob().ok_or("a blob")?;
    assert_eq!(name, parent_name());
    assert_eq!(blob, &tpm_blob());
    assert!(tpm.protected().credential().is_none());
    let host = store.get(OWNER, "encrypted-host")?;
    assert!(host.protected().blob().is_none());
    assert!(host.protected().credential().is_some());
    Ok(())
}

/// What is left in the store after a refused `put`: nothing under the id and no temporary file.
fn nothing_written(store: &KeyStore) -> io::Result<bool> {
    let mut names = Vec::new();
    for entry in fs::read_dir(store.dir())? {
        let path = entry?.path();
        if path.is_dir() {
            for inner in fs::read_dir(&path)? {
                names.push(inner?.file_name());
            }
        }
    }
    Ok(names.is_empty())
}

#[test]
fn put_refuses_plaintext_as_credential() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    let pkcs8 = fixture().key.expose_secret().to_vec();
    let random: Vec<u8> = (0..300_u16)
        .map(|i| i.wrapping_mul(37).to_le_bytes()[0] | 1)
        .collect();
    for plaintext in [pkcs8, random, vec![0x30; 10], Vec::new()] {
        for (kind, binding) in [
            (Kind::EncryptedTpm, Binding::Tpm),
            (Kind::EncryptedHost, Binding::Host),
            (Kind::EncryptedTpm, Binding::Host),
            (Kind::EncryptedHost, Binding::Tpm),
        ] {
            let dressed = Protected::credential_unchecked(plaintext.clone(), binding);
            let record = Record::new_unchecked(OWNER, "k", kind, b"cert", dressed);
            let got = store.put(&record);
            assert!(
                matches!(
                    got,
                    Err(StoreError::Record(
                        RecordError::Credential(_) | RecordError::KindMismatch
                    ))
                ),
                "{kind:?} {binding:?} {} bytes: {got:?}",
                plaintext.len()
            );
            assert!(nothing_written(&store)?, "{kind:?} {binding:?}");
        }
    }
    // A checked constructor refuses it too.
    let dressed =
        Protected::credential_unchecked(fixture().key.expose_secret().to_vec(), Binding::Host);
    assert!(Record::new(OWNER, "k", Kind::EncryptedHost, b"cert", dressed).is_err());
    Ok(())
}

#[test]
fn put_refuses_plaintext_as_blob() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    let pkcs8 = fixture().key.expose_secret().to_vec();
    // A `Blob` is only built by parsing the two TPM structures, so plaintext cannot become one...
    assert!(Blob::parse(&pkcs8).is_err());
    assert!(Blob::from_parts(&pkcs8, &pkcs8).is_err());
    assert!(Blob::from_parts(&[], &[]).is_err());
    // ... and a record file that says TPM but holds the plaintext key is not a record.
    let valid = Record::new(OWNER, "k", Kind::Tpm, b"cert", tpm_protected())?.encode()?;
    // magic, version, tag, owner, id (1 + 1), certificate (4 + 4): the protected length comes next.
    let mut payload = u16::try_from(parent_name().len())?.to_be_bytes().to_vec();
    payload.extend(parent_name());
    payload.extend(&pkcs8);
    let mut forged = valid[..24].to_vec();
    forged.extend(u32::try_from(payload.len())?.to_be_bytes());
    forged.extend(payload);
    assert!(matches!(Record::decode(&forged), Err(RecordError::Blob(_))));
    assert!(nothing_written(&store)?);
    Ok(())
}

#[test]
fn kind_binding_mismatch() -> TestResult {
    let host = sealed_with(&MemoryCreds::host());
    let tpm = sealed_with(&MemoryCreds::tpm());
    let blob = tpm_protected();
    let new =
        |kind, protected: &Protected| Record::new(OWNER, "k", kind, b"cert", protected.clone());
    // A host header under a TPM-bound kind, a TPM header under host-bound, a blob or a credential
    // under the wrong family.
    assert_eq!(
        new(Kind::EncryptedTpm, &host).unwrap_err(),
        RecordError::KindMismatch
    );
    assert_eq!(
        new(Kind::EncryptedHost, &tpm).unwrap_err(),
        RecordError::KindMismatch
    );
    assert_eq!(
        new(Kind::Tpm, &host).unwrap_err(),
        RecordError::KindMismatch
    );
    assert_eq!(new(Kind::Tpm, &tpm).unwrap_err(), RecordError::KindMismatch);
    assert_eq!(
        new(Kind::EncryptedHost, &blob).unwrap_err(),
        RecordError::KindMismatch
    );
    assert_eq!(
        new(Kind::EncryptedTpm, &blob).unwrap_err(),
        RecordError::KindMismatch
    );
    assert!(new(Kind::EncryptedHost, &host).is_ok());
    assert!(new(Kind::EncryptedTpm, &tpm).is_ok());
    assert!(new(Kind::Tpm, &blob).is_ok());
    // The null-key header and a PCR-bound header are refused whatever the kind.
    let mut null = vec![0_u8; 64];
    null[..16].copy_from_slice(&crate::creds::header::NULL_ID);
    let mut pcr = vec![0x11_u8; 64];
    pcr[48..56].fill(0);
    pcr[48] = 7;
    for (bytes, binding, want) in [
        (null, Binding::Host, HeaderError::NullKey),
        (pcr, Binding::Tpm, HeaderError::PcrBound(7)),
    ] {
        for kind in [Kind::EncryptedTpm, Kind::EncryptedHost] {
            let dressed = Protected::credential_unchecked(bytes.clone(), binding);
            assert_eq!(
                new(kind, &dressed).unwrap_err(),
                RecordError::Credential(want)
            );
        }
    }
    // On disk: the kind tag changed from host to TPM-bound makes the record unreadable.
    let mut bytes = new(Kind::EncryptedHost, &host)?.encode()?;
    bytes[9] = Kind::EncryptedTpm.tag();
    assert_eq!(
        Record::decode(&bytes).unwrap_err(),
        RecordError::KindMismatch
    );
    bytes[9] = Kind::Tpm.tag();
    assert!(Record::decode(&bytes).is_err());
    Ok(())
}
