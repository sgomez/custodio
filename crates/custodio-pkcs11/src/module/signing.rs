//! `C_SignInit`, `C_Sign`, `C_SignUpdate` and `C_SignFinal`: the sign operation of a session and
//! its hash state. The hash state belongs to the session; nothing outlives a call.

use cryptoki_sys::{
    CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CKR_DATA_INVALID, CKR_DEVICE_ERROR, CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED, CKR_KEY_HANDLE_INVALID, CKR_KEY_TYPE_INCONSISTENT,
    CKR_OPERATION_ACTIVE, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID,
};

use super::mechanism::hash_message;
use super::{Mechanism, Module, Rv, Session, SignOutcome};
use crate::backend::{Backend, BackendError, SignParams};
use crate::composed::{DigestHasher, sign_input};
use crate::token::{KEY_HANDLE, Token};

/// Where the hash of a multi-part operation is.
#[derive(Debug)]
enum Hash {
    /// No `C_SignUpdate` yet (or a raw mechanism, which never has a hash).
    Fresh,
    Ready(Box<DigestHasher>),
    /// A part is being hashed outside the lock; the hasher is out of the session.
    Busy,
    /// Another call found the session busy and ended the operation; the call in flight drops its
    /// hasher when it returns.
    Aborted,
}

/// The open sign operation of a session.
#[derive(Debug)]
pub(super) struct SignOp {
    mechanism: Mechanism,
    serial: u64,
    hash: Hash,
}

/// Feeds a part to the hash. A free function with no access to the module, so it cannot run under
/// the state lock.
pub(super) fn hash_part(hasher: &mut DigestHasher, part: &[u8]) {
    hasher.update(part);
}

/// What a call that needs the hash (`sign`, `sign_final`) finds in the session: the mechanism, or
/// the error. A session with a part in flight is marked aborted.
fn settle(session: &mut Session) -> Rv<(Mechanism, bool)> {
    let op = session.sign.as_mut().ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
    match op.hash {
        Hash::Busy => {
            op.hash = Hash::Aborted;
            Err(CKR_OPERATION_ACTIVE)
        }
        Hash::Aborted => Err(CKR_OPERATION_NOT_INITIALIZED),
        Hash::Fresh => Ok((op.mechanism, false)),
        Hash::Ready(_) => Ok((op.mechanism, true)),
    }
}

/// Calls the service once and checks what comes back.
fn sign_with<B: Backend>(
    backend: &B,
    token: &Token,
    params: SignParams,
    input: &[u8],
) -> Rv<SignOutcome> {
    let signature = backend
        .sign(&token.id, params, input)
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

impl<B: Backend> Module<B> {
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
        let serial = state.next_operation;
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
        s.sign = Some(SignOp {
            mechanism,
            serial,
            hash: Hash::Fresh,
        });
        state.next_operation = serial.wrapping_add(1);
        Ok(())
    }

    /// `C_Sign`. `capacity` is the caller's buffer size, `None` for a length query. The service,
    /// and so polkit, is only called when the buffer can hold the signature; a refused or failed
    /// signature ends the operation, as the specification says for every error but a small buffer.
    ///
    /// # Errors
    /// `CKR_OPERATION_NOT_INITIALIZED`, `CKR_OPERATION_ACTIVE` after a `C_SignUpdate` (the
    /// operation ends), `CKR_FUNCTION_FAILED` when the signature was refused,
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
            let (mechanism, updated) = settle(s)?;
            if updated {
                s.sign = None;
                return Err(CKR_OPERATION_ACTIVE);
            }
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
        match mechanism {
            Mechanism::Composed(c) => {
                sign_with(&self.backend, &token, params, &hash_message(c, data))
            }
            _ => sign_with(&self.backend, &token, params, data),
        }
    }

    /// The locked half of `C_SignUpdate`: takes the hasher out of the session and leaves the busy
    /// marker. Returns owned values only.
    pub(super) fn begin_update(&self, session: CK_SESSION_HANDLE) -> Rv<(u64, DigestHasher)> {
        let mut state = self.ready()?;
        let s = state
            .sessions
            .get_mut(&session)
            .ok_or(CKR_SESSION_HANDLE_INVALID)?;
        let op = s.sign.as_mut().ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        let Mechanism::Composed(c) = op.mechanism else {
            s.sign = None;
            return Err(CKR_FUNCTION_NOT_SUPPORTED);
        };
        match &op.hash {
            Hash::Busy => {
                op.hash = Hash::Aborted;
                return Err(CKR_OPERATION_ACTIVE);
            }
            Hash::Aborted => return Err(CKR_OPERATION_NOT_INITIALIZED),
            Hash::Fresh | Hash::Ready(_) => {}
        }
        let hasher = match std::mem::replace(&mut op.hash, Hash::Busy) {
            Hash::Ready(hasher) => *hasher,
            _ => DigestHasher::new(c.hash()),
        };
        Ok((op.serial, hasher))
    }

    /// The second half of `C_SignUpdate`: puts the hasher back, unless the operation was ended
    /// meanwhile (then it is dropped, and the operation with it) or is no longer the same one.
    pub(super) fn end_update(&self, session: CK_SESSION_HANDLE, serial: u64, hasher: DigestHasher) {
        let mut state = self.lock();
        let Some(s) = state.sessions.get_mut(&session) else {
            return;
        };
        let Some(op) = s.sign.as_mut().filter(|op| op.serial == serial) else {
            return;
        };
        match op.hash {
            Hash::Busy => op.hash = Hash::Ready(Box::new(hasher)),
            Hash::Aborted => s.sign = None,
            Hash::Fresh | Hash::Ready(_) => {}
        }
    }

    /// `C_SignUpdate`.
    ///
    /// # Errors
    /// `CKR_OPERATION_NOT_INITIALIZED`, `CKR_FUNCTION_NOT_SUPPORTED` for a raw mechanism (the
    /// operation ends), `CKR_OPERATION_ACTIVE` when another call is hashing a part of the same
    /// session (the operation ends).
    pub fn sign_update(&self, session: CK_SESSION_HANDLE, part: &[u8]) -> Rv<()> {
        let (serial, mut hasher) = self.begin_update(session)?;
        hash_part(&mut hasher, part);
        self.end_update(session, serial, hasher);
        Ok(())
    }

    /// `C_SignFinal`. `capacity` is the caller's buffer size, `None` for a length query. A length
    /// query or a small buffer keeps the hash and does not reach the service.
    ///
    /// # Errors
    /// As [`Module::sign`]; `CKR_FUNCTION_NOT_SUPPORTED` for a raw mechanism (the operation ends).
    pub fn sign_final(
        &self,
        session: CK_SESSION_HANDLE,
        capacity: Option<usize>,
    ) -> Rv<SignOutcome> {
        let (token, composed, hasher) = {
            let mut state = self.ready()?;
            let s = state
                .sessions
                .get_mut(&session)
                .ok_or(CKR_SESSION_HANDLE_INVALID)?;
            let (mechanism, _) = settle(s)?;
            let Mechanism::Composed(composed) = mechanism else {
                s.sign = None;
                return Err(CKR_FUNCTION_NOT_SUPPORTED);
            };
            let needed = s.token.signature_len();
            match capacity {
                None => return Ok(SignOutcome::Length(needed)),
                Some(cap) if cap < needed => return Ok(SignOutcome::TooSmall(needed)),
                Some(_) => {}
            }
            let hasher = match s.sign.take().map(|op| op.hash) {
                Some(Hash::Ready(hasher)) => *hasher,
                _ => DigestHasher::new(composed.hash()),
            };
            (s.token.clone(), composed, hasher)
        };
        let params = Mechanism::Composed(composed).params()?;
        sign_with(
            &self.backend,
            &token,
            params,
            &sign_input(composed, &hasher),
        )
    }
}
