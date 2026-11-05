#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use custodiod::audit::JournalSink;
use custodiod::creds::systemd::SystemdCreds;
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
        let key_credentials = Arc::new(SystemdCreds::system(None));
        // The earlier format is purged, then the object is served and the name taken: `start` is the only path.
        let _connection = start(
            store,
            Connection::system(),
            Arc::new(JournalSink::default()),
            key_credentials,
            tpm,
        )
        .await?;
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
