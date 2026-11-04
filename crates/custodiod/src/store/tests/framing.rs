//! The readers: every malformed record is refused with a typed error, whatever the cut or the field.
// A test fails by panicking: unwrap and indexing on data the test itself built are the intended failure mode.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::records::{one_of_each, parent_name, sealed_with, tpm_blob, tpm_protected};
use super::*;
use crate::creds::header::{Binding, HeaderError};
use crate::tpm::blob::{BlobError, Imported};

/// Offsets in the encoding of a record whose id is `k` (1 byte) and certificate `cert` (4 bytes).
const VERSION_AT: usize = 8;
const TAG_AT: usize = 9;
const ID_LEN_AT: usize = 14;
const CERT_LEN_AT: usize = 16;
const PROTECTED_LEN_AT: usize = 24;

fn encoded(protected: Protected, kind: Kind) -> Vec<u8> {
    Record::new(OWNER, "k", kind, b"cert", protected)
        .unwrap()
        .encode()
        .unwrap()
}

fn host() -> Vec<u8> {
    let record = one_of_each().pop().unwrap();
    encoded(record.protected().clone(), Kind::EncryptedHost)
}

fn tpm() -> Vec<u8> {
    encoded(tpm_protected(), Kind::Tpm)
}

fn with_u32(mut bytes: Vec<u8>, at: usize, value: u32) -> Vec<u8> {
    bytes[at..at + 4].copy_from_slice(&value.to_be_bytes());
    bytes
}

#[test]
fn record_valid_ones_decode() {
    for bytes in [host(), tpm()] {
        assert!(Record::decode(&bytes).is_ok());
    }
}

#[test]
fn record_truncated_at_every_length_is_refused() {
    for bytes in [host(), tpm()] {
        assert_eq!(Record::decode(&[]), Err(RecordError::BadMagic));
        for n in 0..bytes.len() {
            let got = Record::decode(&bytes[..n]);
            assert!(got.is_err(), "{n} of {}", bytes.len());
            // Cut inside the magic it is a bad magic; after it, something is missing.
            if n < 8 {
                assert_eq!(got, Err(RecordError::BadMagic), "{n}");
            }
        }
    }
}

#[test]
fn record_header_fields_are_checked() {
    let good = host();
    let mut bad_magic = good.clone();
    bad_magic[0] ^= 1;
    assert_eq!(Record::decode(&bad_magic), Err(RecordError::BadMagic));
    // A file of the earlier format starts with a DER sequence, never with the magic.
    assert_eq!(
        Record::decode(&[0x30, 0x81, 0x87, 2, 1, 0, 3, 3, 3]),
        Err(RecordError::BadMagic)
    );
    for version in [0_u8, 2, 255] {
        let mut v = good.clone();
        v[VERSION_AT] = version;
        assert_eq!(
            Record::decode(&v),
            Err(RecordError::UnknownVersion(version))
        );
    }
    for tag in [0_u8, 4, 255] {
        let mut v = good.clone();
        v[TAG_AT] = tag;
        assert_eq!(Record::decode(&v), Err(RecordError::UnknownKind(tag)));
    }
}

#[test]
fn record_id_is_checked() {
    let good = host();
    let mut long = good.clone();
    long[ID_LEN_AT] = 65;
    assert_eq!(
        Record::decode(&long),
        Err(RecordError::Oversized(Field::Id))
    );
    let mut empty = good.clone();
    empty[ID_LEN_AT] = 0;
    assert!(Record::decode(&empty).is_err());
    for bad in [b'/', b' ', b'.', 0xff] {
        let mut v = good.clone();
        v[ID_LEN_AT + 1] = bad;
        assert_eq!(Record::decode(&v), Err(RecordError::BadId), "{bad}");
    }
}

#[test]
fn record_lengths_are_bounded_and_consistent() {
    for good in [host(), tpm()] {
        // Over the bound, on a short input: `Oversized`, not `Truncated`, so nothing of that size is taken.
        for over in [
            record::MAX_CERTIFICATE + 1,
            usize::try_from(u32::MAX).unwrap(),
        ] {
            let v = with_u32(good.clone(), CERT_LEN_AT, u32::try_from(over).unwrap());
            assert_eq!(
                Record::decode(&v),
                Err(RecordError::Oversized(Field::Certificate))
            );
        }
        let v = with_u32(good.clone(), PROTECTED_LEN_AT, u32::MAX);
        assert_eq!(
            Record::decode(&v),
            Err(RecordError::Oversized(Field::Protected))
        );
        // Within the bound but longer than the input.
        let v = with_u32(good.clone(), CERT_LEN_AT, 5000);
        assert_eq!(Record::decode(&v), Err(RecordError::Truncated));
        let v = with_u32(good.clone(), PROTECTED_LEN_AT, 10_000);
        assert_eq!(Record::decode(&v), Err(RecordError::Truncated));
        // A shorter certificate length leaves bytes that do not fit the rest.
        let v = with_u32(good.clone(), CERT_LEN_AT, 3);
        assert!(Record::decode(&v).is_err());
        // The exact bounds are accepted by the length check (the content then decides).
        let v = with_u32(
            good.clone(),
            CERT_LEN_AT,
            u32::try_from(record::MAX_CERTIFICATE).unwrap(),
        );
        assert_eq!(Record::decode(&v), Err(RecordError::Truncated));
    }
    // A file larger than any record is refused at once.
    let mut huge = host();
    huge.resize(MAX_RECORD + 1, 0);
    assert_eq!(
        Record::decode(&huge),
        Err(RecordError::Oversized(Field::Record))
    );
}

#[test]
fn record_trailing_bytes_are_refused() {
    for mut bytes in [host(), tpm()] {
        bytes.push(0);
        assert_eq!(Record::decode(&bytes), Err(RecordError::Trailing));
    }
}

#[test]
fn bounds_are_checked_before_allocation() {
    // Every length field at `u32::MAX` on a few bytes of input: a typed error. The reader only hands
    // out slices of its input, so a field can never ask for more than the input holds.
    let mut head = record::MAGIC.to_vec();
    head.extend([1, Kind::EncryptedHost.tag(), 0, 0, 0, 7, 1, b'k']);
    for tail in [vec![0xff; 4], [vec![0, 0, 0, 0], vec![0xff; 4]].concat()] {
        let mut v = head.clone();
        v.extend(tail);
        assert!(
            matches!(Record::decode(&v), Err(RecordError::Oversized(_))),
            "{v:?}"
        );
    }
    let mut v = head.clone();
    v.extend([0, 0, 0, 1, b'c', 0xff, 0xff, 0xff, 0xff]);
    assert_eq!(
        Record::decode(&v),
        Err(RecordError::Oversized(Field::Protected))
    );
}

#[test]
fn blob_and_parent_name_are_bounded() {
    let good = tpm();
    // The protected part starts after the 4-byte length at PROTECTED_LEN_AT.
    let at = PROTECTED_LEN_AT + 4;
    let set_name_len = |len: u16| {
        let mut v = good.clone();
        v[at..at + 2].copy_from_slice(&len.to_be_bytes());
        v
    };
    assert_eq!(
        Record::decode(&set_name_len(
            u16::try_from(record::MAX_PARENT_NAME).unwrap() + 1
        )),
        Err(RecordError::Oversized(Field::ParentName))
    );
    assert_eq!(
        Record::decode(&set_name_len(u16::MAX)),
        Err(RecordError::Oversized(Field::ParentName))
    );
    assert!(Record::decode(&set_name_len(0)).is_err());
    // A name that eats into the blob leaves a blob that does not parse.
    assert!(matches!(
        Record::decode(&set_name_len(3)),
        Err(RecordError::Blob(_))
    ));
    // An empty name cannot be stored.
    let imported = Imported {
        blob: super::records::tpm_blob(),
        parent_name: Vec::new(),
    };
    assert_eq!(
        Protected::from_imported(&imported),
        Err(RecordError::Empty(Field::ParentName))
    );
    let imported = Imported {
        blob: super::records::tpm_blob(),
        parent_name: vec![1; record::MAX_PARENT_NAME + 1],
    };
    assert_eq!(
        Protected::from_imported(&imported),
        Err(RecordError::Oversized(Field::ParentName))
    );
    let imported = Imported {
        blob: super::records::tpm_blob(),
        parent_name: vec![1; record::MAX_PARENT_NAME],
    };
    assert!(Protected::from_imported(&imported).is_ok());
    assert_eq!(parent_name().len(), 34);
    // The blob inside: trailing bytes after it and a cut inside it are refused.
    let mut trailing = good.clone();
    trailing.push(9);
    let len = u32::from_be_bytes(trailing[PROTECTED_LEN_AT..at].try_into().unwrap());
    let trailing = with_u32(trailing, PROTECTED_LEN_AT, len + 1);
    assert_eq!(
        Record::decode(&trailing),
        Err(RecordError::Blob(BlobError::Trailing))
    );
    let cut = with_u32(good[..good.len() - 1].to_vec(), PROTECTED_LEN_AT, len - 1);
    assert!(matches!(Record::decode(&cut), Err(RecordError::Blob(_))));
}

#[test]
fn credential_framing_is_checked() {
    let good = host();
    let at = PROTECTED_LEN_AT + 4;
    // Cut inside the header: too short to name a binding.
    let v = with_u32(good[..at + 10].to_vec(), PROTECTED_LEN_AT, 10);
    assert_eq!(
        Record::decode(&v),
        Err(RecordError::Credential(HeaderError::TooShort))
    );
    // The null key and a PCR mask are refused when read back.
    let mut null = good.clone();
    null[at..at + 16].copy_from_slice(&crate::creds::header::NULL_ID);
    assert_eq!(
        Record::decode(&null),
        Err(RecordError::Credential(HeaderError::NullKey))
    );
    let mut pcr = good.clone();
    pcr[at..at + 16].fill(0x11);
    pcr[at + 48] = 1;
    assert_eq!(
        Record::decode(&pcr),
        Err(RecordError::Credential(HeaderError::PcrBound(1)))
    );
    // A credential past the bound is refused on the length alone.
    let big = with_u32(
        good,
        PROTECTED_LEN_AT,
        u32::try_from(record::MAX_CREDENTIAL + 1).unwrap(),
    );
    let mut big = big;
    big.resize(at + record::MAX_CREDENTIAL + 1, 0);
    assert!(Record::decode(&big).is_err());
    let oversized =
        Protected::credential_unchecked(vec![0; record::MAX_CREDENTIAL + 1], Binding::Host);
    let record = Record::new_unchecked(OWNER, "k", Kind::EncryptedHost, b"cert", oversized);
    assert_eq!(
        record.encode(),
        Err(RecordError::Oversized(Field::Protected))
    );
}

#[test]
fn the_path_decides_owner_and_id() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    store.put(&rec(OWNER, "mine", b"cert"))?;
    store.put(&rec(2000, "theirs", b"cert"))?;
    // A record copied into another owner's area, or under another id, is refused as a mismatch.
    let copy = |from: &Path, to: &Path| -> io::Result<()> {
        fs::create_dir_all(to.parent().unwrap())?;
        write_synced(to, &fs::read(from)?)
    };
    let other_area = store.dir().join("2000");
    copy(&area(&store).join("mine"), &other_area.join("mine"))?;
    assert!(matches!(
        store.get(2000, "mine"),
        Err(StoreError::Mismatch(_))
    ));
    copy(&area(&store).join("mine"), &area(&store).join("renamed"))?;
    assert!(matches!(
        store.get(OWNER, "renamed"),
        Err(StoreError::Mismatch(_))
    ));
    // The real ones still read.
    assert!(store.get(OWNER, "mine").is_ok());
    assert!(store.get(2000, "theirs").is_ok());
    Ok(())
}

#[test]
fn the_bounds_have_their_documented_values() {
    use crate::tpm::blob::{MAX_PRIVATE, MAX_PUBLIC};
    let cert = record::MAX_CERTIFICATE;
    // magic 8, version, tag, owner 4, id length, id 64, two length fields of 4.
    assert_eq!(
        record::MAX_RECORD,
        8 + 1 + 1 + 4 + 1 + 64 + 4 + cert + 4 + 16384
    );
    assert_eq!(record::MAX_CREDENTIAL, 16384);
    assert_eq!(record::MAX_PARENT_NAME, 68);
    // A TPM key (name length, name, blob with its two sizes) always fits the protected bound.
    const {
        assert!(
            2 + record::MAX_PARENT_NAME + 2 + MAX_PUBLIC + 2 + MAX_PRIVATE
                <= record::MAX_CREDENTIAL
        );
    }
    // A record of exactly the bound is read as a record, one byte more is too large.
    let tmp = tempfile::tempdir().unwrap();
    let store = KeyStore::open(tmp.path().join("s")).unwrap();
    let mut bytes = record::MAGIC.to_vec();
    bytes.resize(record::MAX_RECORD, 0);
    let path = tmp.path().join("s").join(OWNER.to_string());
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    for (len, too_large) in [(record::MAX_RECORD, false), (record::MAX_RECORD + 1, true)] {
        bytes.resize(len, 0);
        let file = path.join("k");
        std::fs::write(&file, &bytes).unwrap();
        std::fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        let got = store.get(OWNER, "k");
        assert_eq!(matches!(got, Err(StoreError::TooLarge)), too_large, "{len}");
        std::fs::remove_file(&file).unwrap();
    }
}

#[test]
fn record_errors_say_what_is_wrong() {
    for (error, text) in [
        (RecordError::Truncated, "truncated"),
        (RecordError::BadMagic, "bad magic"),
        (RecordError::UnknownVersion(9), "unknown version 9"),
        (RecordError::UnknownKind(7), "unknown kind tag 7"),
        (RecordError::Oversized(Field::Certificate), "Certificate"),
        (RecordError::Empty(Field::Protected), "empty"),
        (RecordError::Trailing, "trailing"),
        (RecordError::BadId, "invalid key id"),
        (RecordError::KindMismatch, "kind does not fit"),
    ] {
        assert!(error.to_string().contains(text), "{error:?}: {error}");
    }
    assert!(
        RecordError::Oversized(Field::Id)
            .to_string()
            .contains("oversized")
    );
}

#[test]
fn a_directory_sync_failure_is_reported() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(super::super::files::sync_dir(tmp.path()).is_ok());
    assert!(matches!(
        super::super::files::sync_dir(&tmp.path().join("missing")),
        Err(StoreError::SyncFailed(_))
    ));
}

/// The credential of the in-memory service for a key of `len` bytes.
fn credential_of(len: usize) -> crate::creds::Sealed {
    let key = secrecy::SecretSlice::from(vec![5_u8; len]);
    crate::creds::seal(&MemoryCreds::host(), "n", &key).unwrap()
}

#[test]
fn the_bounds_are_inclusive() {
    use crate::tpm::blob::Imported;
    let overhead = credential_of(0).credential().len();
    let max_cred = record::MAX_CREDENTIAL;
    let at = |extra: usize| {
        let sealed = credential_of(max_cred - overhead + extra);
        assert_eq!(sealed.credential().len(), max_cred + extra);
        Record::new(
            OWNER,
            &"i".repeat(64),
            Kind::EncryptedHost,
            &vec![0x30; record::MAX_CERTIFICATE],
            Protected::from_sealed(&sealed),
        )
    };
    // The largest credential, certificate and id: a record of exactly `MAX_RECORD` bytes.
    let biggest = at(0).unwrap();
    let bytes = biggest.encode().unwrap();
    assert_eq!(bytes.len(), record::MAX_RECORD);
    assert_eq!(Record::decode(&bytes).unwrap(), biggest);
    assert_eq!(at(1).unwrap_err(), RecordError::Oversized(Field::Protected));
    // A parent name of exactly the bound is stored and read back; one byte more is refused.
    let blob = tpm_blob();
    let named = |len: usize| {
        let imported = Imported {
            blob: blob.clone(),
            parent_name: vec![7; len],
        };
        Protected::from_imported(&imported)
    };
    let max_name = record::MAX_PARENT_NAME;
    let record = Record::new(OWNER, "k", Kind::Tpm, b"cert", named(max_name).unwrap()).unwrap();
    assert_eq!(Record::decode(&record.encode().unwrap()).unwrap(), record);
    assert_eq!(
        named(max_name + 1).unwrap_err(),
        RecordError::Oversized(Field::ParentName)
    );
}

#[test]
fn a_header_and_a_binding_that_disagree_are_refused() {
    let host = sealed_with(&MemoryCreds::host());
    let tpm = sealed_with(&MemoryCreds::tpm());
    for (kind, header_of, binding) in [
        (Kind::EncryptedHost, &host, Binding::Tpm),
        (Kind::EncryptedTpm, &tpm, Binding::Host),
    ] {
        let bytes = header_of.credential().unwrap().to_vec();
        let dressed = Protected::credential_unchecked(bytes, binding);
        let record = Record::new_unchecked(OWNER, "k", kind, b"cert", dressed);
        assert_eq!(record.encode().unwrap_err(), RecordError::KindMismatch);
    }
}

#[test]
fn debug_output_names_the_shape_and_no_bytes() {
    let tpm = Record::new(OWNER, "k", Kind::Tpm, b"cert", tpm_protected()).unwrap();
    let text = format!("{tpm:?}");
    assert!(
        text.starts_with("Record(owner 1000, id k, tpm, certificate 4 bytes, Protected::Tpm("),
        "{text}"
    );
    let host = Protected::from_sealed(&credential_of(10));
    let text = format!("{host:?}");
    assert!(
        text.starts_with("Protected::Credential(") && text.contains(" bytes, Host)"),
        "{text}"
    );
}
