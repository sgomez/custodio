//! The ways a stored key stops working (F118), as scenarios shared by the tests of the failures and of the journal.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use custodio_it::tpm_filter::cc;
use custodiod::creds::CredsError;
use custodiod::tpm::open::{NoTpm, TestTcti};

use crate::kit::{ERR_KEY_LOST, ERR_UNAVAILABLE, Setup, Storage};
use crate::rig::{Subject, fault};

/// A way the key stops working.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fail {
    /// The `swtpm` is cleared under a TPM key.
    TpmClearedUnderTpmKey,
    /// The `swtpm` is cleared under a credential bound to it (the real `systemd-creds`).
    TpmClearedUnderCredential,
    /// The launcher of the real `systemd-creds` is gone.
    MissingLauncher,
    /// The credential cannot be decrypted any more (the host key changed).
    HostKeyChanged,
    /// The private area of the stored blob is damaged.
    DamagedBlob,
    TpmAbsent,
    TpmFaulted,
    TpmLacksTheMechanism,
    CredentialsDown,
}

impl Fail {
    pub const ALL: [Fail; 9] = [
        Self::TpmClearedUnderTpmKey,
        Self::TpmClearedUnderCredential,
        Self::MissingLauncher,
        Self::HostKeyChanged,
        Self::DamagedBlob,
        Self::TpmAbsent,
        Self::TpmFaulted,
        Self::TpmLacksTheMechanism,
        Self::CredentialsDown,
    ];

    pub fn storage(self) -> Storage {
        match self {
            Self::TpmClearedUnderTpmKey
            | Self::DamagedBlob
            | Self::TpmAbsent
            | Self::TpmFaulted
            | Self::TpmLacksTheMechanism => Storage::Tpm,
            Self::TpmClearedUnderCredential | Self::MissingLauncher => Storage::EncryptedTpm,
            Self::HostKeyChanged | Self::CredentialsDown => Storage::EncryptedHost,
        }
    }

    /// The documented error name of the failed signature.
    pub fn error(self) -> &'static str {
        match self {
            Self::TpmClearedUnderTpmKey
            | Self::TpmClearedUnderCredential
            | Self::HostKeyChanged
            | Self::DamagedBlob => ERR_KEY_LOST,
            _ => ERR_UNAVAILABLE,
        }
    }

    /// Whether the key can never sign again.
    pub fn lost(self) -> bool {
        self.error() == ERR_KEY_LOST
    }
}

/// A running scenario: the service, with the real `systemd-creds` and its `swtpm` when the row needs them.
pub struct Case {
    pub setup: Setup,
    pub fail: Fail,
    pub subject: Subject,
    /// The real `systemd-creds` and its host daemon, which live as long as the case.
    pub real: Option<crate::real::Real>,
}

impl Case {
    pub async fn new(fail: Fail, subject: Subject) -> Result<Self, Box<dyn std::error::Error>> {
        if !matches!(
            fail,
            Fail::TpmClearedUnderCredential | Fail::MissingLauncher
        ) {
            let setup = Setup::new(fail.storage(), subject).await?;
            return Ok(Self {
                setup,
                fail,
                subject,
                real: None,
            });
        }
        let (setup, real) = crate::real::setup(subject).await?;
        Ok(Self {
            setup,
            fail,
            subject,
            real: Some(real),
        })
    }

    /// Makes the key stop working.
    pub fn break_it(&self) {
        let setup = &self.setup;
        match self.fail {
            Fail::TpmClearedUnderTpmKey | Fail::TpmClearedUnderCredential => {
                setup.rig.tpm.clear().unwrap();
            }
            Fail::MissingLauncher => self.real.as_ref().unwrap().switch.launcher_missing(true),
            Fail::HostKeyChanged => setup
                .svc
                .creds
                .fail_decrypt_with(Some(CredsError::CannotDecrypt)),
            Fail::DamagedBlob => {
                let files = setup.svc.files();
                let mut bytes = std::fs::read(&files[0]).unwrap();
                // The record ends with the private area of the blob: its last byte is part of the integrity-protected
                // data, so the TPM refuses to load it while the record still parses.
                *bytes.last_mut().unwrap() ^= 0x01;
                std::fs::write(&files[0], bytes).unwrap();
            }
            Fail::TpmAbsent => setup.svc.tpm.swap(NoTpm),
            Fail::TpmFaulted => {
                let (filter, _) = setup.rig.filter(fault(cc::GET_CAPABILITY, 0x101)).unwrap();
                setup.svc.tpm.swap(TestTcti::new(&filter.tcti()));
                setup.filters.borrow_mut().push(filter);
            }
            Fail::TpmLacksTheMechanism => {
                // The command of the key type's mechanism answers "command code not supported" (TPM_RC_COMMAND_CODE).
                let command = if self.subject.reply == "rsa2048" {
                    cc::RSA_DECRYPT
                } else {
                    cc::SIGN
                };
                let (filter, _) = setup.rig.filter(fault(command, 0x143)).unwrap();
                setup.svc.tpm.swap(TestTcti::new(&filter.tcti()));
                setup.filters.borrow_mut().push(filter);
            }
            Fail::CredentialsDown => setup
                .svc
                .creds
                .fail_decrypt_with(Some(CredsError::Unavailable)),
        }
    }

    /// Repairs a transient failure.
    pub fn heal(&self) {
        assert!(!self.fail.lost(), "a lost key is not healed");
        match self.fail {
            Fail::TpmAbsent | Fail::TpmFaulted | Fail::TpmLacksTheMechanism => self
                .setup
                .svc
                .tpm
                .swap(TestTcti::new(&self.setup.rig.tcti())),
            Fail::MissingLauncher => self.real.as_ref().unwrap().switch.launcher_missing(false),
            _ => self.setup.svc.creds.fail_decrypt_with(None),
        }
    }
}
