//! A service with one imported key of a chosen storage kind, and the calls and checks the rows share.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::cell::RefCell;
use std::process::Command;
use std::sync::Arc;

use custodio_it::tpm_filter::TpmFilter;
use custodiod::audit::Outcome;
use custodiod::creds::memory::MemoryCreds;
use custodiod::sign::PssHash;
use custodiod::store::Kind;
use custodiod::tpm::open::{NoTpm, TestTcti};

use crate::bus::Answer;
use crate::common::{
    CKM_ECDSA, CKM_RSA_PKCS, SENTINEL_PASSWORD, assert_entry, digest, digest_info, uid,
};
use crate::oracle::{digest_info_prefix, ecdsa_der, pss_opts, recovered, strs, verifies};
use crate::rig::{Counting, Res, Rig, SUBJECTS, SpyCreds, Subject, Svc, lacks_import};

pub const ID: &str = "k";
pub const CKM_RSA_PKCS_PSS: u32 = 0x000D;
pub const CKM_SHA256: u32 = 0x0250;
pub const PSS_SALT: u32 = 32;

pub const ERR_KEY_LOST: &str = custodio_client::ERROR_KEY_LOST;
pub const ERR_UNAVAILABLE: &str = custodio_client::ERROR_TEMPORARILY_UNAVAILABLE;
pub const ERR_INTERNAL: &str = custodio_client::ERROR_INTERNAL;
pub const ERR_DENIED: &str = custodio_client::ERROR_POLKIT_DENIED;
pub const ERR_NO_KEY: &str = custodio_client::ERROR_NO_SUCH_KEY;
pub const ERR_MISMATCH: &str = custodio_client::ERROR_CERTIFICATE_MISMATCH;

/// How the key is protected in the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    Tpm,
    EncryptedTpm,
    EncryptedHost,
}

pub const STORAGES: [Storage; 3] = [Storage::Tpm, Storage::EncryptedTpm, Storage::EncryptedHost];

impl Storage {
    pub fn kind(self) -> Kind {
        match self {
            Self::Tpm => Kind::Tpm,
            Self::EncryptedTpm => Kind::EncryptedTpm,
            Self::EncryptedHost => Kind::EncryptedHost,
        }
    }
}

/// One call of `Sign`: the mechanism family with its arguments, and what verifies the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    RsaPkcs,
    RsaPss,
    Ecdsa,
}

impl Family {
    pub fn of(subject: Subject) -> &'static [Family] {
        if subject.reply == "rsa2048" {
            &[Family::RsaPkcs, Family::RsaPss]
        } else {
            &[Family::Ecdsa]
        }
    }

    /// `(mechanism, hash, salt length, data)`.
    pub fn args(self) -> (u32, u32, u32, Vec<u8>) {
        match self {
            Self::RsaPkcs => (CKM_RSA_PKCS, 0, 0, digest_info()),
            Self::RsaPss => (CKM_RSA_PKCS_PSS, CKM_SHA256, PSS_SALT, digest()),
            Self::Ecdsa => (CKM_ECDSA, 0, 0, digest()),
        }
    }

    /// Whether `openssl` accepts `signature` for this family with the certificate file `cert`.
    pub fn verifies(self, rig: &Rig, cert: &str, signature: &[u8]) -> Res<bool> {
        match self {
            Self::RsaPkcs => {
                let want = [digest_info_prefix(PssHash::Sha256), digest()].concat();
                Ok(recovered(rig, cert, signature)? == Some(want))
            }
            Self::RsaPss => {
                let opts = pss_opts(PssHash::Sha256, PSS_SALT as usize);
                verifies(rig, cert, &digest(), signature, &strs(&opts))
            }
            Self::Ecdsa => {
                if signature.len() != 64 {
                    return Ok(false);
                }
                verifies(rig, cert, &digest(), &ecdsa_der(signature), &[])
            }
        }
    }
}

/// The counters of the two access points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub opens: usize,
    pub decrypts: usize,
    pub encrypts: usize,
}

/// The service with key [`ID`] imported as the chosen storage kind.
pub struct Setup {
    pub rig: Rig,
    pub svc: Svc,
    pub storage: Storage,
    pub subject: Subject,
    /// The filters in front of the `swtpm` that a row put in the way; they must outlive their use.
    pub filters: RefCell<Vec<TpmFilter>>,
}

impl Setup {
    /// A service whose credentials are the in-memory double of the storage kind.
    pub async fn new(storage: Storage, subject: Subject) -> Res<Self> {
        Self::with_creds(storage, subject, |_| {
            SpyCreds::new(match storage {
                Storage::EncryptedTpm => MemoryCreds::tpm(),
                _ => MemoryCreds::host(),
            })
        })
        .await
    }

    /// As [`Setup::new`], with these credentials (the real `systemd-creds` for the TPM-bound row).
    pub async fn with_creds(
        storage: Storage,
        subject: Subject,
        creds: impl FnOnce(&Rig) -> Arc<SpyCreds>,
    ) -> Res<Self> {
        let rig = Rig::new()?;
        let creds = creds(&rig);
        let mut filters = Vec::new();
        let tpm = match storage {
            Storage::Tpm => Counting::new(TestTcti::new(&rig.tcti())),
            // The TPM lacks Import: the choice is "encrypted, TPM-bound".
            Storage::EncryptedTpm => {
                let (filter, _) = rig.filter(lacks_import())?;
                let tpm = Counting::new(TestTcti::new(&filter.tcti()));
                filters.push(filter);
                tpm
            }
            Storage::EncryptedHost => Counting::new(NoTpm),
        };
        let svc = Svc::start(tpm, creds, Answer::Yes).await?;
        assert_eq!(svc.import_subject(ID, subject).await?, subject.reply);
        assert_eq!(svc.kind_of(ID), Some(storage.kind()));
        if storage == Storage::EncryptedTpm {
            // From here on the TPM serves everything; an encrypted key must not need it.
            svc.tpm.swap(TestTcti::new(&rig.tcti()));
        }
        Ok(Self {
            rig,
            svc,
            storage,
            subject,
            filters: RefCell::new(filters),
        })
    }

    pub fn counts(&self) -> Counts {
        Counts {
            opens: self.svc.tpm.opens(),
            decrypts: self.svc.creds.decrypts(),
            encrypts: self.svc.creds.encrypts(),
        }
    }

    /// `Sign` with the family's arguments.
    pub async fn sign(&self, family: Family) -> Result<Vec<u8>, String> {
        let (mechanism, hash, salt, data) = family.args();
        self.sign_as(ID, mechanism, hash, salt, data).await
    }

    pub async fn sign_as(
        &self,
        id: &str,
        mechanism: u32,
        hash: u32,
        salt: u32,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let reply = self
            .svc
            .call_method("Sign", &(id, mechanism, hash, salt, data))
            .await?;
        reply.body().deserialize().map_err(|e| e.to_string())
    }

    pub async fn list(&self) -> Result<Vec<(String, String, String, Vec<u8>)>, String> {
        let reply = self.svc.call_method("ListKeys", &()).await?;
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

    /// The bytes of the record file of key [`ID`]: there is exactly one file.
    pub fn record_bytes(&self) -> Vec<u8> {
        let files = self.svc.files();
        assert_eq!(files.len(), 1, "{files:?}");
        std::fs::read(&files[0]).unwrap()
    }

    /// The certificate the store holds for key [`ID`], as a PEM file in the rig's directory.
    pub fn cert_pem(&self, name: &str) -> String {
        let der = self
            .svc
            .store
            .get(uid(), ID)
            .unwrap()
            .certificate()
            .to_vec();
        der_to_pem(&self.rig, name, &der)
    }

    /// Verifies that the signature of `family` is by the key of the stored certificate, and by no other one.
    pub fn assert_signed_by_stored_key(&self, family: Family, signature: &[u8], context: &str) {
        let cert = self.cert_pem("stored.pem");
        assert!(
            family.verifies(&self.rig, &cert, signature).unwrap(),
            "{context}: {family:?}"
        );
        // Negative control: the certificate of the other key type does not verify it.
        let other = SUBJECTS
            .iter()
            .find(|s| s.reply != self.subject.reply)
            .unwrap();
        let other_cert = der_to_pem(&self.rig, "other.pem", &p12_certificate(*other));
        assert!(
            !family.verifies(&self.rig, &other_cert, signature).unwrap(),
            "{context}: {family:?} verified by the wrong key"
        );
    }

    /// The journal holds exactly `n` entries, the last of them for key [`ID`] with this outcome.
    pub fn assert_entries(&self, n: usize, family: Family, outcome: Outcome, context: &str) {
        let entries = self.svc.sink.entries();
        assert_eq!(entries.len(), n, "{context}");
        let mechanism = custodiod::audit::AuditMechanism::from(&mechanism_of(family));
        assert_entry(entries.last().unwrap(), ID, mechanism, outcome);
    }
}

fn mechanism_of(family: Family) -> custodiod::sign::Mechanism {
    use custodiod::sign::Mechanism;
    match family {
        Family::RsaPkcs => Mechanism::RsaPkcs,
        Family::RsaPss => Mechanism::RsaPkcsPss {
            hash: PssHash::Sha256,
            salt_len: PSS_SALT as usize,
        },
        Family::Ecdsa => Mechanism::Ecdsa,
    }
}

/// A DER certificate as a PEM file named `name` in the rig's directory.
pub fn der_to_pem(rig: &Rig, name: &str, der: &[u8]) -> String {
    let input = rig.write(&format!("{name}.der"), der).unwrap();
    let out = rig.path(name);
    let status = Command::new("openssl")
        .args(["x509", "-inform", "DER", "-in", &input, "-out", &out])
        .status()
        .unwrap();
    assert!(status.success());
    out
}

/// The certificate in the sentinel `.p12` of the subject, DER, read by `openssl`.
pub fn p12_certificate(subject: Subject) -> Vec<u8> {
    openssl_pkcs12(
        subject,
        &["-clcerts", "-nokeys"],
        &["x509", "-outform", "DER"],
    )
}

/// A second, different certificate for the key of the subject's `.p12`: same key, other subject name.
pub fn second_certificate(rig: &Rig, subject: Subject) -> Vec<u8> {
    let key = openssl_pkcs12(subject, &["-nodes", "-nocerts"], &["pkey"]);
    let key = rig.write("second.key.pem", &key).unwrap();
    let out = Command::new("openssl")
        .args(["req", "-new", "-x509", "-key", &key, "-days", "2"])
        .args(["-subj", "/CN=second", "-outform", "DER"])
        .output()
        .unwrap();
    assert!(out.status.success());
    out.stdout
}

/// `openssl pkcs12 <args>` on the subject's `.p12`, piped through `openssl <then>`.
fn openssl_pkcs12(subject: Subject, args: &[&str], then: &[&str]) -> Vec<u8> {
    use std::io::Write;
    use std::process::Stdio;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("k.p12");
    std::fs::write(&file, subject.p12).unwrap();
    let first = Command::new("openssl")
        .arg("pkcs12")
        .args(["-in"])
        .arg(&file)
        .args(["-passin", &format!("pass:{SENTINEL_PASSWORD}")])
        .args(args)
        .stdout(Stdio::piped())
        .output()
        .unwrap();
    assert!(first.status.success());
    let mut second = Command::new("openssl")
        .args(then)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    second
        .stdin
        .take()
        .unwrap()
        .write_all(&first.stdout)
        .unwrap();
    let out = second.wait_with_output().unwrap();
    assert!(out.status.success());
    out.stdout
}
