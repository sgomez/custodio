use super::*;
use crate::creds::HeaderError;
use crate::sign::SignError;
use crate::tpm::classify::{ResponseCode, TpmError};
use crate::tpm::list::Item;

fn rc() -> ResponseCode {
    ResponseCode(0x1c4)
}

#[test]
fn every_tpm_sign_error_has_its_class() {
    use ServiceError as S;
    use TpmSignError as T;
    let table = [
        (T::Refused(SignError::BadData), S::InvalidArgs),
        (T::Refused(SignError::MechanismMismatch), S::InvalidArgs),
        (T::Refused(SignError::BadKey), S::Internal),
        (T::Refused(SignError::Failed), S::Internal),
        (T::NoTpm, S::TemporarilyUnavailable),
        (T::Tpm(TpmError::OpenFailed), S::TemporarilyUnavailable),
        (T::Tpm(TpmError::Transport), S::TemporarilyUnavailable),
        (T::Lacks(Item::AlgRsa), S::TemporarilyUnavailable),
        (T::ParentMismatch, S::KeyLost),
        (T::LoadFailed(rc()), S::KeyLost),
        (T::BadResult, S::TemporarilyUnavailable),
        (T::Internal, S::Internal),
    ];
    for (error, class) in table {
        assert_eq!(ServiceError::from(&error), class, "{error:?}");
    }
}

#[test]
fn every_credential_error_has_its_class() {
    use CredsError as C;
    use ServiceError as S;
    let table = [
        (C::CannotDecrypt, S::KeyLost),
        (C::Unavailable, S::TemporarilyUnavailable),
        (C::Refused(HeaderError::NullKey), S::Internal),
        (C::BadRequest, S::Internal),
    ];
    for (error, class) in table {
        assert_eq!(ServiceError::from(&error), class, "{error:?}");
    }
}
