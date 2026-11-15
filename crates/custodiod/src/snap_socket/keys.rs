//! What an accepted peer is served: the interface of the bus service, at the same name and path, with `ListKeys`
//! alone. The uid is the one the kernel gave for the connection; no argument and no handshake claim can change it.

use rustix::event::{PollFd, PollFlags, poll};
use rustix::io::retry_on_intr;
use std::os::unix::net::UnixStream;
use zbus::connection::{AuthMechanism, Builder};
use zbus::{Guid, block_on, interface};

use super::sign::Session;
use crate::dbus::{ListedKey, OBJECT_PATH, list_for_peer};
use crate::error::ServiceError;

/// The object of one peer.
struct PeerKeys {
    session: Session,
}

#[interface(name = "com.rfirma.Custodio1")]
impl PeerKeys {
    /// `(key id, key type, storage kind, DER certificate)` for every stored key of the peer's uid.
    fn list_keys(&self) -> Result<Vec<ListedKey>, ServiceError> {
        list_for_peer(&self.session.store, self.session.uid)
    }

    /// Signs `data` with key `id` of the peer's uid, after polkit approves this one call. Same arguments and
    /// errors as the bus method.
    // The `interface` macro cannot deserialize a borrowed `[u8]`, so the bytes are owned.
    #[allow(clippy::needless_pass_by_value)]
    async fn sign(
        &self,
        id: String,
        mechanism: u32,
        hash: u32,
        salt_len: u32,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, ServiceError> {
        self.session
            .sign(&id, mechanism, hash, salt_len, &data)
            .await
    }
}

/// Serves `stream` until the peer goes away. The handshake is `ANONYMOUS` only and sets no user id: a uid the peer
/// sends (`AUTH EXTERNAL`) is rejected unread, and nothing but `uid` decides whose keys are listed.
///
/// A failed handshake ends this connection only.
pub(super) fn serve_peer(stream: UnixStream, session: Session) {
    let Ok(watch) = stream.try_clone() else {
        return;
    };
    let built = block_on(async {
        Builder::unix_stream(stream)
            .server(Guid::generate())
            .p2p()
            .auth_mechanism(AuthMechanism::Anonymous)
            .serve_at(OBJECT_PATH, PeerKeys { session })
            .build()
            .await
    });
    let Ok(connection) = built else {
        return;
    };
    // zbus answers on its own threads; this one only waits for the peer to hang up. `poll` with no timeout returns
    // only when `RDHUP`, `HUP` or `ERR` is set on the descriptor, or when a signal interrupts it.
    let _ = retry_on_intr(|| poll(&mut [PollFd::new(&watch, PollFlags::RDHUP)], None));
    drop(connection);
}
