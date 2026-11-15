#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use custodiod::audit::{AuditSink, JournalSink};
use custodiod::creds::Credentials;
use custodiod::creds::systemd::SystemdCreds;
use custodiod::polkit::PolkitAuthorizer;
use custodiod::snap_socket::{self, Signing};
use custodiod::startup::start;
use custodiod::storage::diagnose_state_dir;
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
        let journal: Arc<dyn AuditSink> = Arc::new(JournalSink::default());
        let connection = start(
            Arc::clone(&store),
            Connection::system(),
            Arc::clone(&journal),
            Arc::clone(&key_credentials) as Arc<dyn Credentials>,
            Arc::clone(&tpm),
            || diagnose_state_dir(env::var_os("STATE_DIRECTORY")),
        )
        .await?;
        // The socket asks the same polkit, over the same connection, about the peer's process.
        let signing = Signing {
            authorizer: Arc::new(PolkitAuthorizer::new(connection.clone())),
            sink: journal,
            key_creds: Some(key_credentials),
            tpm,
        };
        let log: snap_socket::Log = Arc::new(|line| eprintln!("{line}"));
        let snap_service = snap_socket::Service::new(Arc::clone(&store), log).with_signing(signing);
        // The refused listeners stay open until the process ends.
        let _unserved = snap_socket::serve_passed(
            snap_socket::take_from_environment(),
            snap_socket::dir_to_check,
            &mut std::io::stderr(),
            &snap_service,
        );
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
