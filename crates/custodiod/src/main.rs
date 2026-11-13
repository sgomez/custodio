#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use custodiod::audit::JournalSink;
use custodiod::creds::systemd::SystemdCreds;
use custodiod::snap_socket::{self, Outcome};
use custodiod::startup::start;
use custodiod::store::KeyStore;
use custodiod::tpm::{TpmAccess, open::from_environment};
use zbus::{Connection, block_on};

/// State directory: systemd's `STATE_DIRECTORY` (`StateDirectory=custodio`).
fn state_dir(var: Option<OsString>) -> PathBuf {
    let dir = var.map_or_else(|| PathBuf::from("/var/lib/custodio"), PathBuf::from);
    // With DynamicUser= it is a root-made symlink into /var/lib/private; the store rejects symlinks.
    fs::canonicalize(&dir).unwrap_or(dir)
}

fn run() -> Result<(), Box<dyn Error>> {
    let store = Arc::new(KeyStore::open(state_dir(env::var_os("STATE_DIRECTORY")))?);
    block_on(async {
        // An import chooses TPM, encrypted TPM-bound or encrypted host-bound from what this access point finds.
        let tpm: Arc<dyn TpmAccess> = Arc::from(from_environment());
        let key_credentials = Arc::new(SystemdCreds::system());
        // The earlier format is purged, then the object is served and the name taken: `start` is the only path.
        let _connection = start(
            Arc::clone(&store),
            Connection::system(),
            Arc::new(JournalSink::default()),
            key_credentials,
            tpm,
        )
        .await?;
        // Refused listeners stay open in `unserved`: their connections wait, unserved, until the process ends.
        let log: snap_socket::Log = Arc::new(|line| eprintln!("{line}"));
        let snap_service = snap_socket::Service::new(Arc::clone(&store), log);
        let mut unserved = Vec::new();
        for (snap, listener) in snap_socket::take_from_environment() {
            let name = snap_socket::descriptor_name(snap);
            let dir = snap_socket::dir_to_check(snap);
            if let Outcome::Refused(listener, _) =
                snap_socket::serve(&name, listener, &dir, &mut std::io::stderr(), &snap_service)
            {
                unserved.push(listener);
            }
        }
        std::future::pending::<()>().await;
        Ok(())
    })
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{}: {e}", custodiod::SERVICE_NAME);
        std::process::exit(1);
    }
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
