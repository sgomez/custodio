//! The parent and the import, over a real `tss-esapi` context.
//!
//! The parent is the ECC P-256 primary of the TCG SRK template in the owner hierarchy, created for the call and flushed
//! before it returns, whatever happened in between (`docs/decisions.md`, "TPM parent"). It has no auth value, so the
//! commands that name it run with the password session.

use p256::elliptic_curve::Generate as _;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::handles::{KeyHandle, ObjectHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm, SymmetricMode};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::AesKeyBits;
use tss_esapi::interface_types::reserved_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    Digest, EccPoint, EccScheme, EncryptedSecret, KeyDerivationFunctionScheme, Private, Public,
    PublicBuilder, PublicEccParametersBuilder, SymmetricDefinitionObject,
};
use tss_esapi::traits::Marshall;

use super::{EsysSession, fault};
use crate::tpm::blob::{Blob, Imported};
use crate::tpm::classify::TpmError;
use crate::tpm::import::ImportError;
use crate::tpm::key::ImportKey;
use crate::tpm::wrap::{name_of, wrap};

/// The parent template: `fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt`, ECC P-256,
/// AES-128-CFB, SHA-256 name, empty policy and empty `unique`.
fn parent_template() -> Result<Public, tss_esapi::Error> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_auth_policy(Digest::default())
        .with_ecc_parameters(
            PublicEccParametersBuilder::new()
                .with_symmetric(SymmetricDefinitionObject::Aes {
                    key_bits: AesKeyBits::Aes128,
                    mode: SymmetricMode::Cfb,
                })
                .with_ecc_scheme(EccScheme::Null)
                .with_curve(EccCurve::NistP256)
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                .with_is_signing_key(false)
                .with_is_decryption_key(true)
                .with_restricted(true)
                .build()?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
}

/// A created parent: its handle and what the wrap needs from its public area.
pub(super) struct Parent {
    pub(super) handle: KeyHandle,
    x: Vec<u8>,
    y: Vec<u8>,
    pub(super) name: Vec<u8>,
}

impl EsysSession {
    fn create_parent(&mut self) -> Result<Parent, ImportError> {
        let template = parent_template().map_err(|_| ImportError::Internal)?;
        let created = self
            .context
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.create_primary(Hierarchy::Owner, template, None, None, None, None)
            })
            .map_err(|e| ImportError::Tpm(fault(e).into()))?;
        let handle = created.key_handle;
        let described = (|| {
            let Public::Ecc { unique, .. } = &created.out_public else {
                return None;
            };
            let name = name_of(&created.out_public.marshall().ok()?);
            Some(Parent {
                handle,
                x: unique.x().as_ref().to_vec(),
                y: unique.y().as_ref().to_vec(),
                name,
            })
        })();
        if let Some(parent) = described {
            return Ok(parent);
        }
        self.flush(handle)?;
        Err(ImportError::Tpm(TpmError::Transport))
    }

    pub(super) fn flush(&mut self, handle: KeyHandle) -> Result<(), ImportError> {
        self.context
            .flush_context(ObjectHandle::from(handle))
            .map_err(|e| ImportError::Tpm(fault(e).into()))
    }

    /// Runs `f` with a parent and flushes it afterwards. The first error wins; a flush that fails after success is reported.
    pub(super) fn with_parent<T, E: From<ImportError>>(
        &mut self,
        f: impl FnOnce(&mut Self, &Parent) -> Result<T, E>,
    ) -> Result<T, E> {
        let parent = self.create_parent()?;
        let result = f(self, &parent);
        let flushed = self.flush(parent.handle);
        match (result, flushed) {
            (Err(e), _) => Err(e),
            (Ok(_), Err(e)) => Err(e.into()),
            (Ok(value), Ok(())) => Ok(value),
        }
    }

    pub(super) fn parent_name_of(&mut self) -> Result<Vec<u8>, ImportError> {
        self.with_parent(|_, parent| Ok(parent.name.clone()))
    }

    pub(super) fn import_under_parent(&mut self, key: &ImportKey) -> Result<Imported, ImportError> {
        self.with_parent(|session, parent| {
            let ephemeral = p256::SecretKey::generate_from_rng(&mut rand::rng());
            let wrapped = wrap(key, &parent.x, &parent.y, &ephemeral, session.tap.as_ref())?;
            let public_area = wrapped
                .public
                .marshall()
                .map_err(|_| ImportError::Internal)?;
            let duplicate =
                Private::try_from(wrapped.duplicate).map_err(|_| ImportError::Internal)?;
            let seed =
                EncryptedSecret::try_from(wrapped.seed_point).map_err(|_| ImportError::Internal)?;
            let private = session
                .context
                .execute_with_session(Some(AuthSession::Password), |ctx| {
                    ctx.import(
                        ObjectHandle::from(parent.handle),
                        None,
                        wrapped.public,
                        duplicate,
                        seed,
                        SymmetricDefinitionObject::Null,
                    )
                })
                .map_err(|e| ImportError::Tpm(fault(e).into()))?;
            let blob = Blob::from_parts(&public_area, private.as_ref())
                .map_err(|_| ImportError::Tpm(TpmError::Transport))?;
            Ok(Imported {
                blob,
                parent_name: parent.name.clone(),
            })
        })
    }
}
