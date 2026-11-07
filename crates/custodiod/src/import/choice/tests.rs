use super::*;
use crate::tpm::{Item, ResponseCode};

#[test]
fn ready_gives_the_tpm() {
    assert_eq!(choose(&Classification::Ready), Ok(Kind::Tpm));
}

#[test]
fn a_lack_gives_encrypted_tpm_bound_whatever_it_names() {
    for items in [
        vec![Item::AlgSha256],
        vec![Item::CmdImport, Item::CmdLoad, Item::AlgAes],
        vec![Item::EcdsaSha256Parms],
        vec![Item::CmdRsaDecrypt],
        vec![Item::Rsa2048Parms, Item::AlgRsa],
    ] {
        assert_eq!(
            choose(&Classification::Lacks(items.clone())),
            Ok(Kind::EncryptedTpm),
            "{items:?}"
        );
    }
}

#[test]
fn no_tpm_gives_encrypted_host_bound() {
    assert_eq!(choose(&Classification::Absent), Ok(Kind::EncryptedHost));
}

#[test]
fn every_error_is_a_refusal_carrying_the_error() {
    for e in [
        TpmError::ResourceManagerMissing,
        TpmError::OpenFailed,
        TpmError::Response(ResponseCode(0x921)),
        TpmError::Transport,
        TpmError::OwnerAuthSet,
        TpmError::OwnerDisabled,
        TpmError::TestTctiRefused,
    ] {
        assert_eq!(choose(&Classification::Error(e)), Err(e));
    }
}

#[test]
fn the_key_types_map_to_their_tpm_types() {
    assert_eq!(tpm_key_type(KeyKind::Rsa2048), KeyType::Rsa2048);
    assert_eq!(tpm_key_type(KeyKind::EcdsaP256), KeyType::EccP256);
}
