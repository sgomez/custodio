//! The PKCS#11 logic without any pointers: tokens, sessions, searches and signing, over a
//! [`Backend`]. `ffi` turns C arguments into calls to this and results back into `CK_RV`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use cryptoki_sys::{
    CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID, CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID, CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_CRYPTOKI_NOT_INITIALIZED,
    CKR_DATA_INVALID, CKR_DEVICE_ERROR, CKR_FUNCTION_FAILED, CKR_KEY_HANDLE_INVALID,
    CKR_KEY_TYPE_INCONSISTENT, CKR_OBJECT_HANDLE_INVALID, CKR_OPERATION_ACTIVE,
    CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID, CKR_SLOT_ID_INVALID,
};

mod mechanism;

use crate::backend::{Backend, BackendError};
use crate::token::{Attribute, CERT_HANDLE, KEY_HANDLE, Token, is_sensitive};
use mechanism::hash_message;
pub use mechanism::{Mechanism, mechanism_info, mechanisms};

/// A PKCS#11 result: the value, or the `CKR_*` code to return.
pub type Rv<T> = Result<T, CK_RV>;

/// Result of `C_Sign`.
#[derive(Debug, PartialEq, Eq)]
pub enum SignOutcome {
    /// The caller only asked for the length.
    Length(usize),
    /// The caller's buffer is too small; this is the size needed. The operation stays active.
    TooSmall(usize),
    Signature(Vec<u8>),
}

struct Session {
    slot: CK_SLOT_ID,
    token: Arc<Token>,
    /// Objects still to be returned by `C_FindObjects`; `None` when no search is active.
    find: Option<Vec<CK_OBJECT_HANDLE>>,
    sign: Option<Mechanism>,
}

struct State {
    /// Process that called `C_Initialize`; `None` before it.
    initialized_by: Option<u32>,
    tokens: Vec<Arc<Token>>,
    sessions: BTreeMap<CK_SESSION_HANDLE, Session>,
    next_session: CK_SESSION_HANDLE,
}

/// The state lock held across a `fork`, so the child never inherits it locked by another thread.
// The field is only held, never read.
#[allow(dead_code)]
pub(crate) struct ForkGuard<'a>(MutexGuard<'a, State>);

/// The module state. One global instance serves a process; tests build their own.
pub struct Module<B> {
    backend: B,
    state: Mutex<State>,
}

impl<B: Backend> Module<B> {
    #[must_use]
    pub const fn new(backend: B) -> Self {
        Self {
            backend,
            state: Mutex::new(State {
                initialized_by: None,
                tokens: Vec::new(),
                sessions: BTreeMap::new(),
                next_session: 1,
            }),
        }
    }

    /// Locks the state. A thread that panicked cannot leave it half-updated in a way that matters
    /// (every update is a single insert, remove or assignment), so poisoning is ignored.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes the lock for `fork`; the caller keeps the guard until the fork returns.
    pub(crate) fn lock_for_fork(&self) -> ForkGuard<'_> {
        ForkGuard(self.lock())
    }

    fn ready(&self) -> Rv<MutexGuard<'_, State>> {
        let state = self.lock();
        if state.initialized_by.is_none() {
            return Err(CKR_CRYPTOKI_NOT_INITIALIZED);
        }
        Ok(state)
    }

    /// `C_Initialize`. A process that is a fork of the initializing one starts afresh.
    ///
    /// # Errors
    /// `CKR_CRYPTOKI_ALREADY_INITIALIZED` when this process already initialized the module.
    pub fn initialize(&self) -> Rv<()> {
        let pid = std::process::id();
        let mut state = self.lock();
        if state.initialized_by == Some(pid) {
            return Err(CKR_CRYPTOKI_ALREADY_INITIALIZED);
        }
        state.initialized_by = Some(pid);
        state.tokens.clear();
        state.sessions.clear();
        Ok(())
    }

    /// `C_Finalize`.
    ///
    /// # Errors
    /// `CKR_CRYPTOKI_NOT_INITIALIZED`.
    pub fn finalize(&self) -> Rv<()> {
        let mut state = self.ready()?;
        state.initialized_by = None;
        state.tokens.clear();
        state.sessions.clear();
        Ok(())
    }

    /// `C_GetSlotList`: asks the service for the keys again. Without the service there are no
    /// tokens rather than an error, so a consumer keeps working with its other modules.
    ///
    /// # Errors
    /// `CKR_CRYPTOKI_NOT_INITIALIZED`.
    pub fn slot_list(&self) -> Rv<Vec<CK_SLOT_ID>> {
        drop(self.ready()?);
        let mut tokens: Vec<Arc<Token>> = self
            .backend
            .list_certificates()
            .unwrap_or_default()
            .iter()
            .filter_map(|(id, cert)| Token::parse(id, cert).map(Arc::new))
            .collect();
        tokens.sort_by(|a, b| a.id.cmp(&b.id));
        let mut state = self.ready()?;
        state.tokens = tokens;
        (0..state.tokens.len())
            .map(|i| CK_SLOT_ID::try_from(i).map_err(|_| CKR_DEVICE_ERROR))
            .collect()
    }

    /// The token in a slot of the last slot list.
    ///
    /// # Errors
    /// `CKR_SLOT_ID_INVALID`.
    pub fn token(&self, slot: CK_SLOT_ID) -> Rv<Arc<Token>> {
        let state = self.ready()?;
        usize::try_from(slot)
            .ok()
            .and_then(|i| state.tokens.get(i))
            .cloned()
            .ok_or(CKR_SLOT_ID_INVALID)
    }

    /// `C_OpenSession` (read-only; the caller has checked the flags).
    ///
    /// # Errors
    /// `CKR_SLOT_ID_INVALID`.
    pub fn open_session(&self, slot: CK_SLOT_ID) -> Rv<CK_SESSION_HANDLE> {
        let token = self.token(slot)?;
        let mut state = self.ready()?;
        let handle = state.next_session;
        state.next_session = handle.checked_add(1).ok_or(CKR_DEVICE_ERROR)?;
        state.sessions.insert(
            handle,
            Session {
                slot,
                token,
                find: None,
                sign: None,
            },
        );
        Ok(handle)
    }

    /// `C_CloseSession`.
    ///
    /// # Errors
    /// `CKR_SESSION_HANDLE_INVALID`.
    pub fn close_session(&self, session: CK_SESSION_HANDLE) -> Rv<()> {
        self.ready()?
            .sessions
            .remove(&session)
            .map(|_| ())
            .ok_or(CKR_SESSION_HANDLE_INVALID)
    }

    /// `C_CloseAllSessions`.
    ///
    /// # Errors
    /// `CKR_SLOT_ID_INVALID` (unknown slot).
    pub fn close_all_sessions(&self, slot: CK_SLOT_ID) -> Rv<()> {
        self.token(slot)?;
        self.ready()?.sessions.retain(|_, s| s.slot != slot);
        Ok(())
    }

    /// The slot a session belongs to.
    ///
    /// # Errors
    /// `CKR_SESSION_HANDLE_INVALID`.
    pub fn session_slot(&self, session: CK_SESSION_HANDLE) -> Rv<CK_SLOT_ID> {
        self.ready()?
            .sessions
            .get(&session)
            .map(|s| s.slot)
            .ok_or(CKR_SESSION_HANDLE_INVALID)
    }

    /// The attributes an object has, for `C_GetAttributeValue`.
    ///
    /// # Errors
    /// `CKR_SESSION_HANDLE_INVALID`, `CKR_OBJECT_HANDLE_INVALID`.
    pub fn object(
        &self,
        session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
    ) -> Rv<Vec<Attribute>> {
        let token = self.session_token(session)?;
        token.attributes(object).ok_or(CKR_OBJECT_HANDLE_INVALID)
    }

    /// How `C_GetAttributeValue` answers for an attribute the object does not have.
    #[must_use]
    pub fn missing_attribute(
        object: CK_OBJECT_HANDLE,
        attribute: cryptoki_sys::CK_ATTRIBUTE_TYPE,
    ) -> CK_RV {
        if object == KEY_HANDLE && is_sensitive(attribute) {
            CKR_ATTRIBUTE_SENSITIVE
        } else {
            CKR_ATTRIBUTE_TYPE_INVALID
        }
    }

    fn session_token(&self, session: CK_SESSION_HANDLE) -> Rv<Arc<Token>> {
        self.ready()?
            .sessions
            .get(&session)
            .map(|s| s.token.clone())
            .ok_or(CKR_SESSION_HANDLE_INVALID)
    }

    /// `C_FindObjectsInit`.
    ///
    /// # Errors
    /// `CKR_OPERATION_ACTIVE` when a search is already open.
    pub fn find_init(&self, session: CK_SESSION_HANDLE, template: &[Attribute]) -> Rv<()> {
        let mut state = self.ready()?;
        let s = state
            .sessions
            .get_mut(&session)
            .ok_or(CKR_SESSION_HANDLE_INVALID)?;
        if s.find.is_some() {
            return Err(CKR_OPERATION_ACTIVE);
        }
        s.find = Some(
            [CERT_HANDLE, KEY_HANDLE]
                .into_iter()
                .filter(|h| s.token.matches(*h, template))
                .collect(),
        );
        Ok(())
    }

    /// `C_FindObjects`: up to `max` more handles.
    ///
    /// # Errors
    /// `CKR_OPERATION_NOT_INITIALIZED` without a search.
    pub fn find(&self, session: CK_SESSION_HANDLE, max: usize) -> Rv<Vec<CK_OBJECT_HANDLE>> {
        let mut state = self.ready()?;
        let s = state
            .sessions
            .get_mut(&session)
            .ok_or(CKR_SESSION_HANDLE_INVALID)?;
        let pending = s.find.as_mut().ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        let n = max.min(pending.len());
        Ok(pending.drain(..n).collect())
    }

    /// `C_FindObjectsFinal`.
    ///
    /// # Errors
    /// `CKR_OPERATION_NOT_INITIALIZED` without a search.
    pub fn find_final(&self, session: CK_SESSION_HANDLE) -> Rv<()> {
        let mut state = self.ready()?;
        let s = state
            .sessions
            .get_mut(&session)
            .ok_or(CKR_SESSION_HANDLE_INVALID)?;
        s.find
            .take()
            .map(|_| ())
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)
    }

    /// `C_SignInit`.
    ///
    /// # Errors
    /// `CKR_KEY_HANDLE_INVALID` for anything but the private key object,
    /// `CKR_KEY_TYPE_INCONSISTENT` when the mechanism does not fit the key,
    /// `CKR_OPERATION_ACTIVE`.
    pub fn sign_init(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: Mechanism,
        key: CK_OBJECT_HANDLE,
    ) -> Rv<()> {
        let mut state = self.ready()?;
        let s = state
            .sessions
            .get_mut(&session)
            .ok_or(CKR_SESSION_HANDLE_INVALID)?;
        if key != KEY_HANDLE {
            return Err(CKR_KEY_HANDLE_INVALID);
        }
        if s.sign.is_some() {
            return Err(CKR_OPERATION_ACTIVE);
        }
        if !mechanism.fits(&s.token.kind) {
            return Err(CKR_KEY_TYPE_INCONSISTENT);
        }
        s.sign = Some(mechanism);
        Ok(())
    }

    /// `C_Sign`. `capacity` is the caller's buffer size, `None` for a length query. The service,
    /// and so polkit, is only called when the buffer can hold the signature; a refused or failed
    /// signature ends the operation, as the specification says for every error but a small buffer.
    ///
    /// # Errors
    /// `CKR_OPERATION_NOT_INITIALIZED`, `CKR_FUNCTION_FAILED` when the signature was refused,
    /// `CKR_DATA_INVALID` when the service rejects the data, `CKR_DEVICE_ERROR` when it is not
    /// reachable.
    pub fn sign(
        &self,
        session: CK_SESSION_HANDLE,
        data: &[u8],
        capacity: Option<usize>,
    ) -> Rv<SignOutcome> {
        let (token, mechanism) = {
            let mut state = self.ready()?;
            let s = state
                .sessions
                .get_mut(&session)
                .ok_or(CKR_SESSION_HANDLE_INVALID)?;
            let mechanism = s.sign.ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
            let needed = s.token.signature_len();
            match capacity {
                None => return Ok(SignOutcome::Length(needed)),
                Some(cap) if cap < needed => return Ok(SignOutcome::TooSmall(needed)),
                Some(_) => {}
            }
            // The operation ends here, before the (long, interactive) call, so a second thread
            // using the same session cannot start a second signature from the same init.
            s.sign = None;
            (s.token.clone(), mechanism)
        };
        // Past this point only owned values are used: the guard is gone, so hashing a large
        // message or waiting for the user never blocks other sessions.
        let params = mechanism.params()?;
        let signature = match mechanism {
            Mechanism::Composed(c) => self.backend.sign(&token.id, params, &hash_message(c, data)),
            _ => self.backend.sign(&token.id, params, data),
        }
        .map_err(|e| match e {
            BackendError::Denied => CKR_FUNCTION_FAILED,
            BackendError::Invalid => CKR_DATA_INVALID,
            BackendError::Unavailable => CKR_DEVICE_ERROR,
        })?;
        if signature.len() != token.signature_len() {
            return Err(CKR_FUNCTION_FAILED);
        }
        Ok(SignOutcome::Signature(signature))
    }
}

#[cfg(test)]
mod tests;
