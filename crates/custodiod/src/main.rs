#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::sync::Arc;

use custodiod::dbus::{BUS_NAME, Custodio, OBJECT_PATH};
use custodiod::polkit::PolkitAuthorizer;
use custodiod::store::KeyStore;
use zbus::{Connection, block_on};

/// State directory: systemd's `STATE_DIRECTORY` (`StateDirectory=custodio`).
fn state_dir() -> String {
    env::var("STATE_DIRECTORY").unwrap_or_else(|_| "/var/lib/custodio".to_owned())
}

fn run() -> Result<(), Box<dyn Error>> {
    let store = Arc::new(KeyStore::open(state_dir())?);
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
