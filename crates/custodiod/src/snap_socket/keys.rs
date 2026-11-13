//! What an accepted peer is served: the interface of the bus service, at the same name and path, with `ListKeys`
//! alone. The uid is the one the kernel gave for the connection; no argument and no handshake claim can change it.

use std::os::unix::net::UnixStream;
use std::sync::Arc;

use rustix::event::{PollFd, PollFlags, poll};
use zbus::connection::{AuthMechanism, Builder};
use zbus::{Guid, block_on, interface};

use crate::dbus::{ListedKey, OBJECT_PATH, list_for_peer};
use crate::error::ServiceError;
use crate::store::KeyStore;

/// The object of one peer.
struct PeerKeys {
    store: Arc<KeyStore>,
    uid: u32,
}

#[interface(name = "com.rfirma.Custodio1")]
impl PeerKeys {
    /// `(key id, key type, storage kind, DER certificate)` for every stored key of the peer's uid.
    fn list_keys(&self) -> Result<Vec<ListedKey>, ServiceError> {
        list_for_peer(&self.store, self.uid)
    }
}

/// Serves `stream` until the peer goes away. The handshake is `ANONYMOUS` only and sets no user id: a uid the peer
/// sends (`AUTH EXTERNAL`) is rejected unread, and nothing but `uid` decides whose keys are listed.
///
/// A failed handshake ends this connection only.
pub fn serve_peer(stream: UnixStream, store: Arc<KeyStore>, uid: u32) {
    let Ok(watch) = stream.try_clone() else {
        return;
    };
    let built = block_on(async {
        Builder::unix_stream(stream)
            .server(Guid::generate())
            .p2p()
            .auth_mechanism(AuthMechanism::Anonymous)
            .serve_at(OBJECT_PATH, PeerKeys { store, uid })
            .build()
            .await
    });
    let Ok(connection) = built else {
        return;
    };
    // zbus answers on its own threads; this one only waits for the peer to hang up. `poll` with no timeout returns
    // only when `RDHUP`, `HUP` or `ERR` is set on the descriptor, or when a signal interrupts it.
    while poll(&mut [PollFd::new(&watch, PollFlags::RDHUP)], None) == Err(rustix::io::Errno::INTR) {
    }
    drop(connection);
}
