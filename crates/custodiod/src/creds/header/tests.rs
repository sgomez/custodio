use super::*;

fn head(bytes: &[u8], n: usize) -> &[u8] {
    bytes.get(..n).unwrap_or_default()
}

const UNKNOWN: [u8; 16] = [7; 16];

/// A header-sized credential with this id and this mask at byte 48.
fn credential(id: [u8; 16], mask: u64) -> Vec<u8> {
    let mut bytes = id.to_vec();
    bytes.resize(48, 0xAA);
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(&[0xBB; 20]);
    bytes
}

#[test]
fn host_ids_are_host_bound() {
    assert_eq!(inspect(&credential(HOST_ID, 0)), Ok(Binding::Host));
    assert_eq!(inspect(&credential(HOST_SCOPED_ID, 0)), Ok(Binding::Host));
    // The mask place of a host credential holds an initialization vector, not a mask.
    assert_eq!(
        inspect(&credential(HOST_SCOPED_ID, u64::MAX)),
        Ok(Binding::Host)
    );
    // Nothing past the id is read for a host id.
    assert_eq!(inspect(&HOST_SCOPED_ID), Ok(Binding::Host));
    assert_eq!(inspect(&HOST_ID), Ok(Binding::Host));
}

#[test]
fn the_null_key_is_refused() {
    assert_eq!(inspect(&credential(NULL_ID, 0)), Err(HeaderError::NullKey));
    assert_eq!(inspect(&NULL_ID), Err(HeaderError::NullKey));
}

#[test]
fn a_tpm_credential_with_no_pcr_is_accepted() {
    assert_eq!(inspect(&credential(UNKNOWN, 0)), Ok(Binding::Tpm));
}

#[test]
fn any_pcr_in_the_mask_is_refused_with_the_mask() {
    for mask in [1u64, 0x80, 1 << 7, 1 << 31, 1 << 63, u64::MAX] {
        assert_eq!(
            inspect(&credential(UNKNOWN, mask)),
            Err(HeaderError::PcrBound(mask))
        );
    }
}

#[test]
fn the_mask_is_read_at_bytes_48_to_55_only() -> Result<(), &'static str> {
    for at in [47usize, 56] {
        let mut bytes = credential(UNKNOWN, 0);
        *bytes.get_mut(at).ok_or("short")? = 1;
        assert_eq!(inspect(&bytes), Ok(Binding::Tpm), "byte {at}");
    }
    for at in [48usize, 55] {
        let mut bytes = credential(UNKNOWN, 0);
        *bytes.get_mut(at).ok_or("short")? = 1;
        assert!(
            matches!(inspect(&bytes), Err(HeaderError::PcrBound(_))),
            "byte {at}"
        );
    }
    Ok(())
}

#[test]
fn a_short_credential_is_too_short() {
    let full = credential(UNKNOWN, 0);
    assert_eq!(inspect(&[]), Err(HeaderError::TooShort));
    assert_eq!(inspect(head(&full, 15)), Err(HeaderError::TooShort));
    assert_eq!(inspect(head(&full, 16)), Err(HeaderError::TooShort));
    assert_eq!(inspect(head(&full, 55)), Err(HeaderError::TooShort));
    assert_eq!(inspect(head(&full, 56)), Ok(Binding::Tpm));
}

#[test]
fn the_messages_say_what_and_no_more() {
    let all = [
        HeaderError::TooShort.to_string(),
        HeaderError::NullKey.to_string(),
        HeaderError::PcrBound(0x80).to_string(),
    ];
    assert!(all[0].contains("too short"));
    assert!(all[1].contains("null"));
    assert!(all[2].contains("0x80"));
    assert_ne!(all[0], all[1]);
}
