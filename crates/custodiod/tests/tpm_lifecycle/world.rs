//! The four-key store of the story, the `swtpm` and the real credential tool behind it, and what the cases read back.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use custodiod::creds::memory::MemoryCreds;
use custodiod::creds::{Binding, CredsError, header};
use custodiod::store::Kind;
use custodiod::tpm::open::TestTcti;

use crate::bus::Answer;
use crate::common::{SENTINEL_PASSWORD, uid};
use crate::env::Daemon;
use crate::kit::{Family, der_to_pem, p12_certificate};
use crate::rig::{Counting, Res, SUBJECTS, SpyCreds, Subject, Svc, TestResult, lacks_import};
use crate::support::Rig;

/// The PCRs the story extends: 0, 2, 4 and 7, and one of the 16-23 range.
pub const PCRS: [u32; 5] = [0, 2, 4, 7, 16];

/// A key of the story.
#[derive(Clone, Copy)]
pub struct Key {
    pub id: &'static str,
    pub kind: Kind,
    pub subject: Subject,
}

pub const KEYS: [Key; 4] = [
    Key {
        id: "tpm-rsa",
        kind: Kind::Tpm,
        subject: SUBJECTS[0],
    },
    Key {
        id: "tpm-p256",
        kind: Kind::Tpm,
        subject: SUBJECTS[1],
    },
    Key {
        id: "etpm-rsa",
        kind: Kind::EncryptedTpm,
        subject: SUBJECTS[0],
    },
    Key {
        id: "etpm-p256",
        kind: Kind::EncryptedTpm,
        subject: SUBJECTS[1],
    },
];

pub type Listed = Vec<(String, String, String, Vec<u8>)>;

/// The service with its four keys, the `swtpm` behind it and the real credential tool (only to make PCR-bound
/// credentials as a test tool; the service seals with in-memory TPM credentials).
pub struct World {
    pub rig: Rig,
    pub svc: Svc,
    pub daemon: Daemon,
}

/// The `swtpm`, in-memory TPM credentials, and a service that imported the four keys through the bus. The
/// `tpm` keys are imported while the TPM serves everything, the `encrypted-tpm` ones while it lacks `Import`.
pub async fn world() -> Res<World> {
    let rig = Rig::new()?;
    let daemon = Daemon::start()?;
    let tpm = Counting::new(TestTcti::new(&rig.tcti()));
    let svc = Svc::start(tpm, SpyCreds::new(MemoryCreds::tpm()), Answer::Yes).await?;
    for key in KEYS.iter().filter(|k| k.kind == Kind::Tpm) {
        let got = svc
            .import(key.id, key.subject.p12, SENTINEL_PASSWORD)
            .await?;
        assert_eq!(got, key.subject.reply);
    }
    let (filter, _) = rig.filter(lacks_import())?;
    svc.tpm.swap(TestTcti::new(&filter.tcti()));
    for key in KEYS.iter().filter(|k| k.kind == Kind::EncryptedTpm) {
        let got = svc
            .import(key.id, key.subject.p12, SENTINEL_PASSWORD)
            .await?;
        assert_eq!(got, key.subject.reply);
    }
    // From here on the TPM serves everything again.
    svc.tpm.swap(TestTcti::new(&rig.tcti()));
    drop(filter);
    Ok(World { rig, svc, daemon })
}

impl World {
    pub async fn list(&self) -> Res<Listed> {
        let reply = self.svc.call_method("ListKeys", &()).await?;
        let mut listed: Listed = reply.body().deserialize()?;
        listed.sort();
        Ok(listed)
    }

    pub async fn sign_raw(&self, key: Key, family: Family) -> Result<Vec<u8>, (String, String)> {
        let (mechanism, hash, salt, data) = family.args();
        let reply = self
            .svc
            .call_error("Sign", &(key.id, mechanism, hash, salt, data))
            .await?;
        reply
            .body()
            .deserialize()
            .map_err(|e| (e.to_string(), String::new()))
    }

    /// Every key signs with every mechanism of its type, and `openssl` verifies the signature with the certificate
    /// the service lists; the certificate of the other key type does not.
    pub async fn assert_all_sign(&self, context: &str) -> TestResult {
        let listed = self.list().await?;
        for key in KEYS {
            let cert = &listed.iter().find(|l| l.0 == key.id).unwrap().3;
            let pem = der_to_pem(&self.rig, &format!("{}.pem", key.id), cert);
            let other = SUBJECTS
                .iter()
                .find(|s| s.reply != key.subject.reply)
                .unwrap();
            let other_pem = der_to_pem(&self.rig, "other.pem", &p12_certificate(*other));
            for family in Family::of(key.subject) {
                let who = format!("{context}: {} {family:?}", key.id);
                let signature = self
                    .sign_raw(key, *family)
                    .await
                    .map_err(|e| format!("{who}: {e:?}"))?;
                assert!(family.verifies(&self.rig, &pem, &signature)?, "{who}");
                assert!(
                    !family.verifies(&self.rig, &other_pem, &signature)?,
                    "{who}: verified by the wrong key"
                );
            }
        }
        Ok(())
    }

    /// Every file of the store with its bytes, by name relative to the store.
    pub fn snapshot(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        let root = self.svc.store.dir().to_owned();
        self.svc
            .files()
            .into_iter()
            .map(|f| {
                (
                    f.strip_prefix(&root).unwrap().to_owned(),
                    std::fs::read(&f).unwrap(),
                )
            })
            .collect()
    }

    /// Clears the `swtpm`. A credential bound to it can no longer be opened, which the in-memory credentials cannot show
    /// by themselves: they are told to fail every decryption as `CannotDecrypt`, the answer of the daemon.
    pub fn clear_tpm(&self) -> Res<()> {
        self.rig.tpm.clear()?;
        self.svc
            .creds
            .fail_decrypt_with(Some(CredsError::CannotDecrypt));
        Ok(())
    }

    pub fn pcrs(&self) -> BTreeMap<u32, String> {
        pcr_values(&self.rig)
    }

    /// A credential made by the real `systemd-creds` bound to PCR 7 (named `k`, secret `lifecycle`).
    pub fn pcr7_credential(&self) -> Vec<u8> {
        let mut child = Command::new(self.daemon.wrapper())
            .args(["encrypt", "--name=k", "--with-key=tpm2", "--tpm2-pcrs=7"])
            .arg(format!("--tpm2-device={}", self.rig.tcti()))
            .args(["-", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(b"lifecycle").unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        let mut decoder = Command::new("base64")
            .arg("-d")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        decoder
            .stdin
            .take()
            .unwrap()
            .write_all(&out.stdout)
            .unwrap();
        let raw = decoder.wait_with_output().unwrap();
        assert!(raw.status.success());
        raw.stdout
    }

    /// The real tool decrypts `credential` (the service's own client refuses a PCR-bound one, so the tool is run here).
    pub fn decrypts(&self, credential: &[u8]) -> Option<Vec<u8>> {
        let mut encoder = Command::new("base64")
            .arg("-w0")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        encoder.stdin.take().unwrap().write_all(credential).unwrap();
        let text = encoder.wait_with_output().unwrap().stdout;
        let mut child = Command::new(self.daemon.wrapper())
            .args(["decrypt", "--name=k"])
            .arg(format!("--tpm2-device={}", self.rig.tcti()))
            .args(["-", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&text).unwrap();
        let out = child.wait_with_output().unwrap();
        out.status.success().then_some(out.stdout)
    }
}

/// `tpm2_pcrread` of the story's PCRs in the SHA-256 bank.
pub fn pcr_values(rig: &Rig) -> BTreeMap<u32, String> {
    let list = PCRS.map(|p| p.to_string()).join(",");
    let out = rig
        .tpm
        .tool_ok("tpm2_pcrread", [format!("sha256:{list}")])
        .unwrap();
    let values: BTreeMap<u32, String> = out
        .lines()
        .filter_map(|l| {
            let (index, value) = l.split_once(": 0x")?;
            Some((index.trim().parse().ok()?, value.trim().to_owned()))
        })
        .collect();
    assert_eq!(values.len(), PCRS.len(), "{out}");
    values
}

/// Extends each PCR of the story with a digest of its own.
pub fn extend_all(rig: &Rig) {
    for p in PCRS {
        rig.tpm
            .extend_pcr(p, &format!("{p:02x}").repeat(32))
            .unwrap();
    }
}

/// Whether `credential` is a TPM credential with an empty PCR mask: the header names a TPM key (not the host key, not
/// the null key), the mask at offset 48 is zero, and the sealed key follows.
pub fn is_tpm_credential(credential: &[u8]) -> bool {
    let mask: Option<[u8; 8]> = credential.get(48..56).and_then(|b| b.try_into().ok());
    header::inspect(credential) == Ok(Binding::Tpm) && mask == Some([0; 8]) && credential.len() > 56
}

/// The message `docs/api.md` documents for an error: the text after "Message" in its bullet.
pub fn documented_message(error: &str) -> String {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/api.md")).unwrap();
    let line = text
        .lines()
        .find(|l| l.starts_with("- error `") && l.contains(&format!("`{error}`")))
        .unwrap_or_else(|| panic!("no bullet for {error}"));
    let after = line.rsplit_once("Message `").unwrap().1;
    after.split_once('`').unwrap().0.to_owned()
}

pub fn credentials_of(w: &World, key: Key) -> Option<Vec<u8>> {
    w.svc
        .store
        .get(uid(), key.id)
        .unwrap()
        .protected()
        .credential()
        .map(<[u8]>::to_vec)
}
