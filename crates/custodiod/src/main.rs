#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use custodiod::app_id_source::CgroupAppIdSource;
use custodiod::audit::JournalSink;
use custodiod::credentials::BusCredentials;
use custodiod::creds::Credentials;
use custodiod::creds::systemd::SystemdCreds;
use custodiod::dbus::{BUS_NAME, Custodio, OBJECT_PATH};
use custodiod::polkit::PolkitAuthorizer;
use custodiod::store::KeyStore;
use custodiod::tpm::{TpmAccess, open::from_environment};
use zbus::{Connection, block_on};

/// State directory: systemd's `STATE_DIRECTORY` (`StateDirectory=custodio`).
fn state_dir(var: Option<OsString>) -> PathBuf {
    let dir = var.map_or_else(|| PathBuf::from("/var/lib/custodio"), PathBuf::from);
    // With DynamicUser= it is a root-made symlink into /var/lib/private; the store rejects symlinks.
    fs::canonicalize(&dir).unwrap_or(dir)
}

/// The served object: real polkit, credentials from the bus and the journal as the audit trail.
fn build_service(
    store: Arc<KeyStore>,
    connection: &Connection,
    journal: JournalSink,
    key_credentials: Arc<dyn Credentials>,
    tpm: Arc<dyn TpmAccess>,
) -> Custodio<PolkitAuthorizer, BusCredentials> {
    Custodio::new(
        store,
        PolkitAuthorizer::new(connection.clone()),
        BusCredentials::new(connection.clone()),
        Arc::new(journal),
    )
    .with_app_id_source(CgroupAppIdSource::new())
    .with_key_credentials(key_credentials)
    .with_tpm(tpm)
}

/// Serves the object on `connection` and takes the bus name.
async fn serve(
    store: Arc<KeyStore>,
    connection: &Connection,
    journal: JournalSink,
    key_credentials: Arc<dyn Credentials>,
    tpm: Arc<dyn TpmAccess>,
) -> zbus::Result<()> {
    let service = build_service(store, connection, journal, key_credentials, tpm);
    connection.object_server().at(OBJECT_PATH, service).await?;
    connection.request_name(BUS_NAME).await
}

fn run() -> Result<(), Box<dyn Error>> {
    let store = Arc::new(KeyStore::open(state_dir(env::var_os("STATE_DIRECTORY")))?);
    block_on(async {
        // An import chooses TPM, encrypted TPM-bound or encrypted host-bound from what this access point finds.
        let tpm: Arc<dyn TpmAccess> = Arc::from(from_environment());
        let key_credentials = Arc::new(SystemdCreds::system(None));
        let connection = Connection::system().await?;
        serve(
            store,
            &connection,
            JournalSink::default(),
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
