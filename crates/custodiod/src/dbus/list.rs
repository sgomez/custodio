//! The `ListKeys` listing, shared by the bus service and the snap socket.

use crate::error::ServiceError;
use crate::import::{KeyKind, certificate_kind};
use crate::store::{KeyStore, StoreError};

/// One element of the `ListKeys` reply: id, key type, storage kind, DER certificate.
pub type ListedKey = (String, String, String, Vec<u8>);

pub(super) fn kind_name(kind: KeyKind) -> &'static str {
    match kind {
        KeyKind::Rsa2048 => "rsa2048",
        KeyKind::EcdsaP256 => "ecdsa-p256",
    }
}

/// `(id, key type, storage kind, DER certificate)` of every key `owner` has, except one a delete has made unusable.
/// Both the bus service and the snap socket list through this (the socket has no delete in progress to ask).
///
/// # Errors
/// [`ServiceError::Internal`] if the store cannot be read or a key has no readable certificate or key type.
pub(super) fn list_owned(
    store: &KeyStore,
    owner: u32,
    unusable: &dyn Fn(&str) -> bool,
) -> Result<Vec<ListedKey>, ServiceError> {
    let ids = store.list(owner).map_err(|e| ServiceError::from(&e))?;
    let mut out = Vec::new();
    // A key a delete has made unusable is not listed, whatever is still on disk.
    let listed = ids.iter().filter(|i| !unusable(i));
    for id in listed {
        let record = match store.get(owner, id) {
            Ok(record) => record,
            // A key of the earlier format is not usable and not listed (the purge is F121).
            Err(StoreError::Legacy) => continue,
            Err(_) => return Err(ServiceError::Internal),
        };
        // The certificate was checked against the key when it was stored or replaced, so its
        // key type is the key's, and listing never decrypts or touches the TPM.
        let key_type = certificate_kind(record.certificate()).ok_or(ServiceError::Internal)?;
        out.push((
            id.clone(),
            kind_name(key_type).to_owned(),
            record.kind().wire().to_owned(),
            record.certificate().to_vec(),
        ));
    }
    Ok(out)
}

/// What `ListKeys` returns on a snap socket for the kernel uid `owner`: the same listing as on the bus.
///
/// # Errors
/// [`ServiceError::Internal`] if the store cannot be read or a key has no readable certificate or key type.
pub fn list_for_peer(store: &KeyStore, owner: u32) -> Result<Vec<ListedKey>, ServiceError> {
    list_owned(store, owner, &|_| false)
}
