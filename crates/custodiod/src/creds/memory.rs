//! A credential service that works in memory, for tests and examples: never for the daemon.
//!
//! A credential is a header that [`super::header::inspect`] reads (the host id or a TPM-shaped one with a
//! zero PCR mask), the name it was made under, and the key masked with a stream derived from the name.
//! The key is not in it in clear, in hex or in base64, and it only opens under the same name.

use std::sync::atomic::{AtomicBool, Ordering};

use secrecy::{ExposeSecret, SecretSlice};
use sha2::{Digest, Sha256};

use super::header::HOST_SCOPED_ID;
use super::{Binding, Credentials, CredsError};

/// Where the masked key starts: after the id, the padding and the PCR mask.
const BODY: usize = 56;

/// See the module documentation.
#[derive(Debug)]
pub struct MemoryCreds {
    binding: Binding,
    broken: AtomicBool,
}

impl MemoryCreds {
    /// Credentials the header of which names the host key.
    #[must_use]
    pub fn host() -> Self {
        Self {
            binding: Binding::Host,
            broken: AtomicBool::new(false),
        }
    }

    /// Credentials the header of which names a TPM (and no PCR).
    #[must_use]
    pub fn tpm() -> Self {
        Self {
            binding: Binding::Tpm,
            broken: AtomicBool::new(false),
        }
    }

    /// While broken, both calls fail with [`CredsError::Unavailable`].
    pub fn set_broken(&self, broken: bool) {
        self.broken.store(broken, Ordering::SeqCst);
    }

    fn check(&self) -> Result<(), CredsError> {
        if self.broken.load(Ordering::SeqCst) {
            Err(CredsError::Unavailable)
        } else {
            Ok(())
        }
    }
}

/// XORs `data` with a stream of SHA-256 blocks of the name and a counter.
fn mask(name: &str, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for (counter, chunk) in (0_u32..).zip(data.chunks(32)) {
        let block = Sha256::new()
            .chain_update(name.as_bytes())
            .chain_update(counter.to_be_bytes())
            .finalize();
        out.extend(chunk.iter().zip(block.iter()).map(|(a, b)| a ^ b));
    }
    out
}

impl Credentials for MemoryCreds {
    fn encrypt(&self, name: &str, plaintext: &SecretSlice<u8>) -> Result<Vec<u8>, CredsError> {
        self.check()?;
        let mut out = vec![0x11_u8; BODY];
        if self.binding == Binding::Host {
            out.splice(..16, HOST_SCOPED_ID);
        }
        // The PCR mask of a TPM-shaped header: zero.
        out.splice(48..56, [0_u8; 8]);
        out.extend(mask(name, plaintext.expose_secret()));
        Ok(out)
    }

    fn decrypt(&self, name: &str, credential: &[u8]) -> Result<SecretSlice<u8>, CredsError> {
        self.check()?;
        let body = credential.get(BODY..).ok_or(CredsError::CannotDecrypt)?;
        let host = credential.get(..16) == Some(HOST_SCOPED_ID.as_slice());
        if host != (self.binding == Binding::Host) {
            return Err(CredsError::CannotDecrypt);
        }
        Ok(SecretSlice::from(mask(name, body)))
    }
}
