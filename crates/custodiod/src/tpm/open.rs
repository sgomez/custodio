//! The ways to reach a TPM: the production one, which opens `/dev/tpmrm0` and nothing else, the one test-only variable the
//! shipped binary reads (F108 route 2), and a free TCTI string for tests.
//!
//! `docs/decisions.md` ("the test-only TPM socket variable") records why the variable exists and what it refuses.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use super::classify::TpmError;
use super::esys::EsysSession;
use super::{OpenError, Session, TpmAccess};

/// The one variable the shipped binary reads to reach a test TPM. It accepts only `swtpm:path=<absolute socket>`. No
/// packaged unit or file sets it; the e2e cases do through a drop-in that is not shipped.
pub const TEST_SOCKET_VARIABLE: &str = "CUSTODIOD_TEST_SWTPM_TCTI";

/// The kernel resource manager, relative to the root. The only node the service opens.
const RESOURCE_MANAGER: &str = "dev/tpmrm0";
/// The raw node. Only ever `stat`ed, to tell "a TPM without a resource manager" from "no TPM"; never opened.
const RAW_NODE: &str = "dev/tpm0";
const SWTPM_PREFIX: &str = "swtpm:path=";

fn open_tcti(tcti: &str) -> Result<Box<dyn Session>, OpenError> {
    EsysSession::open(tcti)
        .map(|s| Box::new(s) as Box<dyn Session>)
        .map_err(|_| OpenError::Failed(TpmError::OpenFailed))
}

/// The production access point: `/dev/tpmrm0` through the TSS device TCTI.
#[derive(Debug, Clone)]
pub struct Production {
    root: PathBuf,
}

impl Production {
    /// The real `/dev`.
    #[must_use]
    pub fn new() -> Self {
        Self::under(Path::new("/"))
    }

    /// A directory standing in for `/`, so a test can lay out `dev/tpmrm0` and `dev/tpm0`.
    #[must_use]
    pub fn under(root: &Path) -> Self {
        Self {
            root: root.to_owned(),
        }
    }

    /// The TCTI configuration this opens: `device:` and the resource manager.
    #[must_use]
    pub fn conf(&self) -> String {
        format!("device:{}", self.root.join(RESOURCE_MANAGER).display())
    }
}

impl Default for Production {
    fn default() -> Self {
        Self::new()
    }
}

fn exists(path: &Path) -> Result<bool, OpenError> {
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(OpenError::Failed(TpmError::OpenFailed)),
    }
}

impl TpmAccess for Production {
    fn open(&self) -> Result<Box<dyn Session>, OpenError> {
        if !exists(&self.root.join(RESOURCE_MANAGER))? {
            return Err(if exists(&self.root.join(RAW_NODE))? {
                OpenError::Failed(TpmError::ResourceManagerMissing)
            } else {
                OpenError::NoDevice
            });
        }
        open_tcti(&self.conf())
    }
}

/// A software TPM on a unix socket, from the test-only variable. A missing socket is "no TPM" (a machine whose TPM is
/// gone, F108's "No TPM" case); a path that is not a socket is refused.
#[derive(Debug, Clone)]
pub struct SwtpmSocket {
    path: PathBuf,
}

impl TpmAccess for SwtpmSocket {
    fn open(&self) -> Result<Box<dyn Session>, OpenError> {
        match fs::symlink_metadata(&self.path) {
            Ok(m) if m.file_type().is_socket() => {
                open_tcti(&format!("{SWTPM_PREFIX}{}", self.path.display()))
            }
            Ok(_) => Err(OpenError::Failed(TpmError::TestTctiRefused)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(OpenError::NoDevice),
            Err(_) => Err(OpenError::Failed(TpmError::OpenFailed)),
        }
    }
}

/// A value of the variable that is not `swtpm:path=<absolute path>`: every attempt to open it is an error.
#[derive(Debug, Clone, Copy)]
struct Refused;

impl TpmAccess for Refused {
    fn open(&self) -> Result<Box<dyn Session>, OpenError> {
        Err(OpenError::Failed(TpmError::TestTctiRefused))
    }
}

/// Any TCTI string, for tests that substitute a TPM (a software TPM, the F107 filter, a faulty one). Nothing in the
/// shipped binary constructs it.
#[derive(Debug, Clone)]
pub struct TestTcti {
    tcti: String,
    page: Option<u32>,
    tap: Option<super::wrap::Tap>,
}

impl TestTcti {
    #[must_use]
    pub fn new(tcti: &str) -> Self {
        Self {
            tcti: tcti.to_owned(),
            page: None,
            tap: None,
        }
    }

    /// Collects the seed and the keys derived from it during an import.
    #[must_use]
    pub fn with_tap(mut self, tap: super::wrap::Tap) -> Self {
        self.tap = Some(tap);
        self
    }

    /// Asks the TPM for at most `page` entries per capability answer, to exercise paging.
    #[must_use]
    pub fn with_page(mut self, page: u32) -> Self {
        self.page = Some(page);
        self
    }
}

impl TpmAccess for TestTcti {
    fn open(&self) -> Result<Box<dyn Session>, OpenError> {
        if let Some(tap) = &self.tap {
            return EsysSession::open(&self.tcti)
                .map(|s| Box::new(s.with_tap(tap.clone())) as Box<dyn Session>)
                .map_err(|_| OpenError::Failed(TpmError::OpenFailed));
        }
        match self.page {
            None => open_tcti(&self.tcti),
            Some(page) => EsysSession::open_paged(&self.tcti, page)
                .map(|s| Box::new(s) as Box<dyn Session>)
                .map_err(|_| OpenError::Failed(TpmError::OpenFailed)),
        }
    }
}

/// The access point for the value of [`TEST_SOCKET_VARIABLE`]. Unset: production. Anything but a well-formed
/// `swtpm:path=<absolute path>` is refused, never a fallback to the real device.
#[must_use]
pub fn from_value(value: Option<&OsStr>) -> Box<dyn TpmAccess> {
    let Some(value) = value else {
        return Box::new(Production::new());
    };
    let path = value
        .to_str()
        .and_then(|v| v.strip_prefix(SWTPM_PREFIX))
        .filter(|p| p.starts_with('/') && !p.contains([',', '\0']));
    match path {
        Some(path) => Box::new(SwtpmSocket { path: path.into() }),
        None => Box::new(Refused),
    }
}

/// The access point of this process: [`from_value`] of the environment.
#[must_use]
pub fn from_environment() -> Box<dyn TpmAccess> {
    from_value(std::env::var_os(TEST_SOCKET_VARIABLE).as_deref())
}
