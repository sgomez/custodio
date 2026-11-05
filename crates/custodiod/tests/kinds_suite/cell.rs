//! The six cells (three storage kinds, both key types) and a service running in one.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::process::Command;

use custodio_it::tpm_filter::TpmFilter;
use custodiod::creds::memory::MemoryCreds;
use custodiod::store::Kind;
use custodiod::tpm::open::{NoTpm, TestTcti};

use crate::bus::Answer;
use crate::common::SENTINEL_PASSWORD;
use crate::kit::{der_to_pem, p12_certificate};
use crate::oracle::Row;
use crate::rig::{Counting, Res, Rig, SUBJECTS, SpyCreds, Subject, Svc, lacks_mechanism};
use crate::support::{Kind as KeyType, TestKey};

/// One storage kind with one key type.
#[derive(Clone, Copy)]
pub struct Cell {
    pub kind: Kind,
    pub subject: Subject,
}

impl Cell {
    pub fn rsa(self) -> bool {
        self.subject.reply == "rsa2048"
    }

    pub fn name(self) -> String {
        format!("{} {}", self.kind.wire(), self.subject.reply)
    }

    /// Every mechanism of the key type.
    pub fn rows(self) -> Vec<Row> {
        if self.rsa() {
            crate::oracle::rsa_rows()
        } else {
            crate::oracle::p256_rows()
        }
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

/// The service of a cell. Fake polkit approves.
pub struct Running {
    pub cell: Cell,
    pub rig: Rig,
    pub svc: Svc,
    /// The filter in front of the `swtpm` of the lacking cell; it stays in place for every call.
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
                let (f, _) = rig.filter(lacks_mechanism(cell.rsa()))?;
                let tpm = Counting::new(TestTcti::new(&f.tcti()));
                filter = Some(f);
                (tpm, SpyCreds::new(MemoryCreds::tpm()))
            }
            Kind::EncryptedHost => (Counting::new(NoTpm), SpyCreds::new(MemoryCreds::host())),
        };
        let svc = Svc::start(tpm, creds, Answer::Yes).await?;
        Ok(Self {
            cell,
            rig,
            svc,
            _filter: filter,
        })
    }

    /// `ImportP12` of the cell's key under `id`: the key type and the kind of the reply.
    pub async fn import(&self, id: &str) -> Result<(String, String), String> {
        let reply = self
            .svc
            .call_method(
                "ImportP12",
                &(id, self.cell.subject.p12.to_vec(), SENTINEL_PASSWORD),
            )
            .await?;
        reply.body().deserialize().map_err(|e| e.to_string())
    }

    /// `ListKeys`: `(id, key type, kind, certificate)`.
    pub async fn list(&self) -> Result<Vec<(String, String, String, Vec<u8>)>, String> {
        let reply = self.svc.call_method("ListKeys", &()).await?;
        reply.body().deserialize().map_err(|e| e.to_string())
    }

    /// `Sign` with the wire form of a row.
    pub async fn sign(&self, id: &str, row: &Row) -> Result<Vec<u8>, String> {
        let (mechanism, hash, salt) = crate::signs::wire(row.mechanism);
        let reply = self
            .svc
            .call_method("Sign", &(id, mechanism, hash, salt, row.data.clone()))
            .await?;
        reply.body().deserialize().map_err(|e| e.to_string())
    }

    pub async fn delete(&self, id: &str) -> Result<(), String> {
        self.svc.call_method("DeleteKey", &(id,)).await.map(drop)
    }

    pub async fn replace(&self, id: &str, certificate: &[u8]) -> Result<(), String> {
        self.svc
            .call_method("ReplaceCertificate", &(id, certificate.to_vec()))
            .await
            .map(drop)
    }

    /// The certificate of the listed key `id` as a PEM file.
    pub async fn cert_of(&self, id: &str, name: &str) -> Res<String> {
        let listed = self.list().await?;
        let entry = listed.iter().find(|e| e.0 == id).ok_or("not listed")?;
        Ok(der_to_pem(&self.rig, name, &entry.3))
    }

    /// The certificate of a key of the same type that is not the cell's, as a PEM file.
    pub fn other_key_cert(&self, name: &str) -> String {
        let key = TestKey::new(if self.cell.rsa() {
            KeyType::Rsa
        } else {
            KeyType::P256
        });
        let pem = self.rig.write(&format!("{name}.key"), &key.pem).unwrap();
        let cert = self.rig.path(name);
        let status = Command::new("openssl")
            .args(["req", "-new", "-x509", "-key", &pem, "-days", "2"])
            .args(["-subj", "/CN=other", "-out", &cert])
            .status()
            .unwrap();
        assert!(status.success());
        cert
    }

    /// The certificate of the other key type, from its sentinel `.p12`, as a PEM file.
    pub fn other_type_cert(&self, name: &str) -> String {
        let other = SUBJECTS
            .iter()
            .find(|s| s.reply != self.cell.subject.reply)
            .unwrap();
        der_to_pem(&self.rig, name, &p12_certificate(*other))
    }
}
