//! The storage kinds and causes the code can emit, for the queries of `docs/audit.md`.
use super::*;

/// Every storage kind; the exhaustive match stops compiling when a variant is added.
pub(super) fn store_kinds() -> [StorageKind; 3] {
    match StorageKind::Tpm {
        StorageKind::Tpm | StorageKind::EncryptedTpm | StorageKind::EncryptedHost => [
            StorageKind::Tpm,
            StorageKind::EncryptedTpm,
            StorageKind::EncryptedHost,
        ],
    }
}

pub(super) fn cause_names() -> BTreeSet<&'static str> {
    let import = ImportCause::all().map(ImportCause::name);
    let sign = SignCause::all().map(SignCause::name);
    import.into_iter().chain(sign).collect()
}

/// A query by cause names its operation without saying so.
#[test]
fn import_and_sign_causes_share_no_name() {
    let import: BTreeSet<_> = ImportCause::all()
        .map(ImportCause::name)
        .into_iter()
        .collect();
    let sign: BTreeSet<_> = SignCause::all().map(SignCause::name).into_iter().collect();
    assert!(import.is_disjoint(&sign));
}
