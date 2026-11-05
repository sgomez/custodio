//! The service in each cell, and the script run on its real state directory.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::BTreeSet;
use std::path::Path;

use custodio_it::tpm_filter::TpmFilter;
use custodiod::creds::memory::MemoryCreds;
use custodiod::store::Kind;
use custodiod::tpm::open::{NoTpm, TestTcti};
use zbus::block_on;

use crate::bus::Answer;
use crate::common::SENTINEL_PASSWORD;
use crate::rig::{
    Counting, Res, Rig, SUBJECTS, SpyCreds, Subject, Svc, TestResult, lacks_mechanism,
};
use crate::script::{encodings, named, run_script};

#[derive(Clone, Copy)]
pub struct Cell {
    pub kind: Kind,
    pub subject: Subject,
}

impl Cell {
    pub fn name(self) -> String {
        format!("{} {}", self.kind.wire(), self.subject.reply)
    }
}

/// The six cells: each kind, then each key type.
pub fn cells() -> Vec<Cell> {
    let mut out = Vec::new();
    for kind in [Kind::Tpm, Kind::EncryptedTpm, Kind::EncryptedHost] {
        for subject in SUBJECTS {
            out.push(Cell { kind, subject });
        }
    }
    out
}

/// A service in a cell with the cell's key imported; fake polkit approves.
pub struct Running {
    pub cell: Cell,
    pub svc: Svc,
    _rig: Rig,
    _filter: Option<TpmFilter>,
}

impl Running {
    pub async fn start(cell: Cell) -> Res<Self> {
        let rig = Rig::new()?;
        let mut filter = None;
        let (tpm, creds) = match cell.kind {
            Kind::Tpm => (
                Counting::new(TestTcti::new(&rig.tcti())),
                SpyCreds::new(MemoryCreds::host()),
            ),
            Kind::EncryptedTpm => {
                let (f, _) = rig.filter(lacks_mechanism(cell.subject.reply == "rsa2048"))?;
                let tpm = Counting::new(TestTcti::new(&f.tcti()));
                filter = Some(f);
                (tpm, SpyCreds::new(MemoryCreds::tpm()))
            }
            Kind::EncryptedHost => (Counting::new(NoTpm), SpyCreds::new(MemoryCreds::host())),
        };
        let svc = Svc::start(tpm, creds, Answer::Yes).await?;
        let kind = svc.import_subject("k", cell.subject).await?;
        assert_eq!(kind, cell.subject.reply, "{}", cell.name());
        assert_eq!(svc.kind_of("k"), Some(cell.kind), "{}", cell.name());
        Ok(Self {
            cell,
            svc,
            _rig: rig,
            _filter: filter,
        })
    }

    /// The sentinel `.p12` of the cell as a file under `dir`.
    pub fn p12(&self, dir: &Path) -> std::path::PathBuf {
        let path = dir.join("key.p12");
        std::fs::write(&path, self.cell.subject.p12).unwrap();
        path
    }
}

#[test]
fn clean_after_import_each_kind() -> TestResult {
    let scratch = tempfile::tempdir()?;
    let mut ran = BTreeSet::new();
    for cell in cells() {
        block_on(async {
            let who = cell.name();
            let running = Running::start(cell).await?;
            let state = running.svc.state_dir();
            // The directory holds a key file: a search of an empty or wrong directory would pass vacuously.
            assert!(!running.svc.files().is_empty(), "{who}: no key file");
            assert!(
                running.svc.files().iter().all(|f| f.starts_with(state)),
                "{who}"
            );
            let p12 = running.p12(scratch.path());
            let out = run_script(state, &p12, SENTINEL_PASSWORD, None);
            assert_eq!(
                out.status.code(),
                Some(0),
                "{who}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(named(&out), Vec::<String>::new(), "{who}");
            ran.insert(who);
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    assert_eq!(ran.len(), 6, "{ran:?}");
    Ok(())
}

#[test]
fn plaintext_key_in_store_is_found() -> TestResult {
    let scratch = tempfile::tempdir()?;
    let cell = Cell {
        kind: Kind::EncryptedHost,
        subject: SUBJECTS[0],
    };
    block_on(async {
        let running = Running::start(cell).await?;
        let state = running.svc.state_dir();
        let p12 = running.p12(scratch.path());
        let pkcs8 = encodings(&p12, SENTINEL_PASSWORD)
            .into_iter()
            .find(|(n, _)| *n == "pkcs8")
            .unwrap()
            .1;
        let leak = running.svc.store.dir().join("leak.der");
        std::fs::write(&leak, pkcs8)?;
        let out = run_script(state, &p12, SENTINEL_PASSWORD, None);
        assert_eq!(out.status.code(), Some(1));
        assert_eq!(named(&out), vec![leak.display().to_string()]);
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}
