//! Loading a stored key under the parent and signing with it, over a real `tss-esapi` context.
//!
//! One call creates the parent, compares its name with the recorded one *before* anything is loaded, loads the key, runs
//! one signing command, flushes the key and flushes the parent. The private key is never in this process: the blob is the
//! TPM's own encrypted form. Neither the key nor the parent has an auth value, so the commands run with the password
//! session.

use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    Digest, HashScheme, Private, Public, PublicKeyRsa, RsaDecryptionScheme, Signature,
    SignatureScheme,
};

use super::primary::Parent;
use super::{EsysSession, fault};
use crate::tpm::blob::{Imported, same_name};
use crate::tpm::classify::{Fault, is_unsupported};
use crate::tpm::list::Item;
use crate::tpm::sign::block::DIGEST;
use crate::tpm::sign::{Prepared, TpmSignError};

/// `TPM_RC_COMMAND_CODE`: the TPM does not implement the command.
const RC_COMMAND_CODE: u32 = 0x143;

/// A fault of a signing command: the TPM saying it lacks the command (or, for `TPM2_Sign`, the scheme) is a lack of
/// `item`; any other answer stays a TPM error with its code.
fn lack_or_error(fault: Fault, command: Item, scheme: Option<Item>) -> TpmSignError {
    match (fault, scheme) {
        (Fault::Response(rc), _) if rc.0 == RC_COMMAND_CODE => TpmSignError::Lacks(command),
        (Fault::Response(rc), Some(item)) if is_unsupported(rc) => TpmSignError::Lacks(item),
        (other, _) => other.into(),
    }
}

impl EsysSession {
    pub(super) fn sign_under_parent(
        &mut self,
        imported: &Imported,
        prepared: &Prepared,
    ) -> Result<Vec<u8>, TpmSignError> {
        let public = imported
            .blob
            .public_area()
            .map_err(|_| TpmSignError::Internal)?;
        let private = imported
            .blob
            .private_bytes()
            .get(2..)
            .and_then(|content| Private::try_from(content.to_vec()).ok())
            .ok_or(TpmSignError::Internal)?;
        self.with_parent(|session, parent| {
            if !same_name(&imported.parent_name, &parent.name) {
                return Err(TpmSignError::ParentMismatch);
            }
            let key = session.load_under(parent, private, public.clone())?;
            let signed = session.operate(key, &public, prepared);
            let flushed = session.flush(key);
            match (signed, flushed) {
                (Err(e), _) => Err(e),
                (Ok(_), Err(e)) => Err(e.into()),
                (Ok(signature), Ok(())) => Ok(signature),
            }
        })
    }

    fn load_under(
        &mut self,
        parent: &Parent,
        private: Private,
        public: Public,
    ) -> Result<KeyHandle, TpmSignError> {
        self.context
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.load(parent.handle, private, public)
            })
            .map_err(|e| match fault(e) {
                Fault::Response(rc) if rc.0 != RC_COMMAND_CODE => TpmSignError::LoadFailed(rc),
                other => lack_or_error(other, Item::CmdLoad, None),
            })
    }

    fn operate(
        &mut self,
        key: KeyHandle,
        public: &Public,
        prepared: &Prepared,
    ) -> Result<Vec<u8>, TpmSignError> {
        match prepared {
            Prepared::Rsa(block) => {
                let cipher =
                    PublicKeyRsa::try_from(block.clone()).map_err(|_| TpmSignError::Internal)?;
                let raw = self
                    .context
                    .execute_with_session(Some(AuthSession::Password), |ctx| {
                        ctx.rsa_decrypt(key, cipher, RsaDecryptionScheme::Null, None)
                    })
                    .map_err(|e| lack_or_error(fault(e), Item::CmdRsaDecrypt, None))?;
                crate::tpm::sign::check::rsa_result(public, block, raw.as_bytes())
            }
            Prepared::Ecdsa(digest) => {
                let digest =
                    Digest::try_from(digest.clone()).map_err(|_| TpmSignError::Internal)?;
                let scheme = SignatureScheme::EcDsa {
                    scheme: HashScheme::new(HashingAlgorithm::Sha256),
                };
                let signature = self
                    .context
                    .execute_with_session(Some(AuthSession::Password), |ctx| {
                        ctx.sign(key, digest, scheme, None)
                    })
                    .map_err(|e| {
                        lack_or_error(fault(e), Item::CmdSign, Some(Item::EcdsaSha256Parms))
                    })?;
                let Signature::EcDsa(parts) = signature else {
                    return Err(TpmSignError::BadResult);
                };
                let mut out = Vec::with_capacity(2 * DIGEST);
                for part in [parts.signature_r(), parts.signature_s()] {
                    out.extend(crate::tpm::sign::check::left_pad(part.as_ref(), DIGEST)?);
                }
                Ok(out)
            }
        }
    }
}
