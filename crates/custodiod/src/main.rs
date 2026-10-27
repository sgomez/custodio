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
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn state_dir_resolves_the_dynamic_user_symlink() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let real = tmp.path().join("private").join("custodio");
        fs::create_dir_all(real.parent().ok_or("no parent")?)?;
        KeyStore::open(&real)?;
        let link = tmp.path().join("custodio");
        std::os::unix::fs::symlink(&real, &link)?;
        let dir = state_dir(Some(link.into()));
        assert_eq!(dir, fs::canonicalize(&real)?);
        KeyStore::open(dir)?;
        Ok(())
    }

    #[test]
    fn state_dir_defaults_and_keeps_a_missing_path() {
        assert_eq!(state_dir(None), PathBuf::from("/var/lib/custodio"));
        let missing = PathBuf::from("/nonexistent/custodio");
        assert_eq!(state_dir(Some(missing.clone().into())), missing);
    }
}
