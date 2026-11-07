use super::*;

#[test]
fn known_strings_round_trip_exactly() {
    let want = [
        ("tpm", Kind::Tpm),
        ("encrypted-tpm", Kind::EncryptedTpm),
        ("encrypted-host", Kind::EncryptedHost),
    ];
    for (wire, kind) in want {
        assert_eq!(Kind::from_wire(wire), kind);
        assert_eq!(kind.wire(), wire);
        assert!(kind.is_known());
    }
}

#[test]
fn the_list_of_known_kinds_is_the_three_strings() {
    assert_eq!(KNOWN_KINDS, ["tpm", "encrypted-tpm", "encrypted-host"]);
    for wire in KNOWN_KINDS {
        assert!(Kind::from_wire(wire).is_known(), "{wire}");
    }
}

#[test]
fn an_unknown_string_keeps_its_text() {
    for text in ["secure-enclave", "", "TPM", "tpm ", "encrypted-tpm2"] {
        let kind = Kind::from_wire(text);
        assert_eq!(kind, Kind::Unknown(text.to_owned()));
        assert_eq!(kind.wire(), text);
        assert!(!kind.is_known());
    }
}
