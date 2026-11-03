//! Test-only server of `scripts/test-docs-api.sh`: the real `Custodio` service type on a private bus, with a fake polkit.
//!
//! It is not shipped: `custodiod` itself is wired to the system bus, the real polkit and the journal, and the container has
//! none of the three. Usage: `docs_api_server BUS_ADDRESS STATE_DIR CONTROL_DIR`. Before each polkit question the server reads
//! `CONTROL_DIR/mode` (`approve`, `deny` or `unreachable`; anything else is `unreachable`) and appends the action asked to
//! `CONTROL_DIR/asked`. It prints `ready` on stdout once it owns the bus name. The caller is identified by the real
//! `BusCredentials` (the bus uid and `ProcessFD`), so ownership works as on the system bus.

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use custodiod::audit::MemorySink;
use custodiod::credentials::BusCredentials;
use custodiod::dbus::{BUS_NAME, Custodio, OBJECT_PATH};
use custodiod::polkit::{AuthError, Authorizer};
use custodiod::store::KeyStore;
use zbus::block_on;
use zbus::connection::Builder;

/// Answers by the `mode` file of the control directory and records the actions it was asked under.
struct FilePolkit {
    control: PathBuf,
}

impl Authorizer for FilePolkit {
    fn authorize(
        &self,
        _sender: &str,
        action: &str,
    ) -> impl Future<Output = Result<(), AuthError>> + Send {
        let line = format!("{action}\n");
        let recorded = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.control.join("asked"))
            .and_then(|mut f| f.write_all(line.as_bytes()));
        let mode = fs::read_to_string(self.control.join("mode")).unwrap_or_default();
        let answer = match (recorded, mode.trim()) {
            (Ok(()), "approve") => Ok(()),
            (Ok(()), "deny") => Err(AuthError::Denied),
            _ => Err(AuthError::Unavailable("polkit is unreachable".to_owned())),
        };
        std::future::ready(answer)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let (Some(address), Some(state), Some(control)) = (args.next(), args.next(), args.next())
    else {
        return Err("usage: docs_api_server BUS_ADDRESS STATE_DIR CONTROL_DIR".into());
    };
    let store = Arc::new(KeyStore::open(PathBuf::from(state))?);
    block_on(async {
        let conn = Builder::address(address.as_str()).build().await?;
        let polkit = FilePolkit {
            control: PathBuf::from(control),
        };
        let credentials = BusCredentials::new(conn.clone());
        let object = Custodio::new(store, polkit, credentials, Arc::new(MemorySink::default()));
        conn.object_server().at(OBJECT_PATH, object).await?;
        conn.request_name(BUS_NAME).await?;
        println!("ready");
        std::future::pending::<()>().await;
        Ok(())
    })
}
