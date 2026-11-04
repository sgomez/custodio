//! The framing readers on a real blob from `swtpm`, and the bounds.

use super::*;
use custodio_it::swtpm::Swtpm;
use custodiod::store::{Field, RecordError};
use custodiod::tpm::blob::Blob;
use custodiod::tpm::import::import_pkcs8;
use custodiod::tpm::open::TestTcti;
use secrecy::ExposeSecret;

const ID: &str = "k";
const CERT: &[u8] = b"certificate-bytes";

fn real_record() -> Record {
    let tpm = Swtpm::start().expect("swtpm starts");
    let access = TestTcti::new(&tpm.tcti());
    let imported = import_pkcs8(&access, fixture().key.expose_secret()).expect("imported");
    let protected = Protected::from_imported(&imported).expect("a parent name");
    Record::new(OWNER, ID, Kind::Tpm, CERT, protected).expect("a record")
}

/// Where the fields start in the record: magic 8, version, tag, owner 4, id length, id.
const CERT_LEN_AT: usize = 8 + 1 + 1 + 4 + 1 + ID.len();
const PROTECTED_LEN_AT: usize = CERT_LEN_AT + 4 + CERT.len();
const NAME_LEN_AT: usize = PROTECTED_LEN_AT + 4;

fn with(bytes: &[u8], at: usize, field: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    v[at..at + field.len()].copy_from_slice(field);
    v
}

#[test]
fn framing_readers() -> TestResult {
    let record = real_record();
    let good = record.encode()?;
    assert_eq!(Record::decode(&good)?, record);
    let (blob, name) = record.protected().blob().expect("a TPM key");
    let stored = blob.to_bytes();
    assert_eq!(Blob::parse(&stored)?, *blob);
    assert_ne!(name, Vec::<u8>::new());

    // Every one-byte truncation of both.
    for len in 0..good.len() {
        assert!(Record::decode(&good[..len]).is_err(), "record cut at {len}");
    }
    for len in 0..stored.len() {
        assert!(Blob::parse(&stored[..len]).is_err(), "blob cut at {len}");
    }
    // Trailing bytes.
    let mut long = good.clone();
    long.push(0);
    assert_eq!(Record::decode(&long), Err(RecordError::Trailing));
    let mut long = stored.clone();
    long.push(0);
    assert!(Blob::parse(&long).is_err());

    // Every size field raised past its bound.
    let max = u32::MAX.to_be_bytes();
    assert_eq!(
        Record::decode(&with(&good, CERT_LEN_AT, &max)),
        Err(RecordError::Oversized(Field::Certificate))
    );
    assert_eq!(
        Record::decode(&with(&good, PROTECTED_LEN_AT, &max)),
        Err(RecordError::Oversized(Field::Protected))
    );
    assert_eq!(
        Record::decode(&with(&good, NAME_LEN_AT, &u16::MAX.to_be_bytes())),
        Err(RecordError::Oversized(Field::ParentName))
    );
    let public_len = usize::from(u16::from_be_bytes([stored[0], stored[1]]));
    for at in [0, 2 + public_len] {
        assert!(
            Blob::parse(&with(&stored, at, &u16::MAX.to_be_bytes())).is_err(),
            "blob size at {at}"
        );
    }
    // Any single bit of a size field turned on is a typed error or a different, still well-formed, record.
    for at in [CERT_LEN_AT, PROTECTED_LEN_AT, NAME_LEN_AT] {
        for bit in 0..8 {
            let mut v = good.clone();
            v[at] ^= 1 << bit;
            let _ = Record::decode(&v);
        }
    }
    Ok(())
}

#[test]
fn bounds_are_checked_before_allocation() {
    // A length field of `u32::MAX` on a short input: a typed error. The reader only hands out
    // slices of its input, so a field can never ask for more than the input holds.
    let (_tmp, store) = fresh();
    store.put(&host(ID, CERT)).unwrap();
    let good = std::fs::read(area(&store, OWNER).join(ID)).unwrap();
    let max = u32::MAX.to_be_bytes();
    for at in [CERT_LEN_AT, PROTECTED_LEN_AT] {
        let short = &with(&good, at, &max)[..at + 8];
        assert!(
            matches!(Record::decode(short), Err(RecordError::Oversized(_))),
            "{at}"
        );
    }
}
