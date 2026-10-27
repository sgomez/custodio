#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use custodiod::dbus::{BUS_NAME, Custodio, OBJECT_PATH};
use custodiod::polkit::PolkitAuthorizer;
use custodiod::store::KeyStore;
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
        let connection = Connection::system().await?;
        let service = Custodio::new(store, PolkitAuthorizer::new(connection.clone()));
        connection.object_server().at(OBJECT_PATH, service).await?;
        connection.request_name(BUS_NAME).await?;
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
