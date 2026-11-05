//! The real `systemd-creds` for the rows that need it: a credential bound to the `swtpm`, with a way to take its
//! launcher away.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use custodiod::creds::systemd::SystemdCreds;
use custodiod::creds::{Credentials, CredsError};
use secrecy::SecretSlice;

use crate::env::Daemon;
use crate::kit::{Setup, Storage};
use crate::rig::{Res, SpyCreds, Subject};

/// Encrypts with the real client, decrypts with the same one, or with one whose launcher is missing.
pub struct Switch {
    good: SystemdCreds,
    bad: SystemdCreds,
    missing: AtomicBool,
}

impl Switch {
    pub fn launcher_missing(&self, missing: bool) {
        self.missing.store(missing, Ordering::SeqCst);
    }
}

struct Shared(Arc<Switch>);

impl Credentials for Shared {
    fn encrypt(&self, name: &str, plaintext: &SecretSlice<u8>) -> Result<Vec<u8>, CredsError> {
        self.0.good.encrypt(name, plaintext)
    }

    fn decrypt(&self, name: &str, credential: &[u8]) -> Result<SecretSlice<u8>, CredsError> {
        let client = if self.0.missing.load(Ordering::SeqCst) {
            &self.0.bad
        } else {
            &self.0.good
        };
        client.decrypt(name, credential)
    }
}

/// What lives as long as the case.
pub struct Real {
    pub switch: Arc<Switch>,
    _daemon: Daemon,
}

/// A TPM-bound credential made by the real `systemd-creds` against the rig's `swtpm`.
pub async fn setup(subject: Subject) -> Res<(Setup, Real)> {
    let daemon = Daemon::start()?;
    let mut switch = None;
    let setup = Setup::with_creds(Storage::EncryptedTpm, subject, |rig| {
        let tcti = rig.tcti();
        let good = SystemdCreds::new(daemon.socket.clone(), daemon.wrapper(), Some(tcti));
        let bad = good
            .clone()
            .with_launcher(PathBuf::from("/nonexistent/launcher"));
        let made = Arc::new(Switch {
            good,
            bad,
            missing: AtomicBool::new(false),
        });
        switch = Some(made.clone());
        SpyCreds::new(Shared(made))
    })
    .await?;
    let switch = switch.unwrap();
    Ok((
        setup,
        Real {
            switch,
            _daemon: daemon,
        },
    ))
}
