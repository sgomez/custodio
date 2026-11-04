//! The collection through a scripted access point, the document, and the production access point.

use std::sync::{Arc, Mutex};

use super::*;
use crate::tpm::list::ALL;

/// An access point that answers from a script and records the `TestParms` it was asked.
struct Scripted {
    asked: Arc<Mutex<Vec<Parms>>>,
    opened: Opened,
}

struct ScriptedSession(Scripted);

impl Session for ScriptedSession {
    fn owner(&mut self) -> Result<Owner, Fault> {
        self.0.opened.owner
    }
    fn algorithms(&mut self) -> Result<Vec<u16>, Fault> {
        self.0.opened.algorithms.clone()
    }
    fn ecc_curves(&mut self) -> Result<Vec<u16>, Fault> {
        self.0.opened.curves.clone()
    }
    fn commands(&mut self) -> Result<Vec<u32>, Fault> {
        self.0.opened.commands.clone()
    }
    fn test_parms(&mut self, parms: Parms) -> Result<(), Fault> {
        self.0
            .asked
            .lock()
            .map_err(|_| Fault::Transport)?
            .push(parms);
        Ok(())
    }
}

impl TpmAccess for Scripted {
    fn open(&self) -> Result<Box<dyn Session>, OpenError> {
        Ok(Box::new(ScriptedSession(Self {
            asked: self.asked.clone(),
            opened: self.opened.clone(),
        })))
    }
}

fn asked(key: KeyType, opened: Opened) -> Vec<Parms> {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let access = Scripted {
        asked: asked.clone(),
        opened,
    };
    let _ = collect(&access, key);
    let list = asked.lock().map(|l| l.clone());
    list.unwrap_or_default()
}

#[test]
fn test_parms_is_asked_only_for_the_key_type_and_when_made_of_present_items() {
    assert_eq!(
        asked(KeyType::Rsa2048, complete()),
        vec![Parms::Parent, Parms::Rsa2048]
    );
    assert_eq!(
        asked(KeyType::EccP256, complete()),
        vec![Parms::Parent, Parms::EcdsaSha256]
    );
    assert_eq!(asked(KeyType::EccP256, without_alg(0x0023)), vec![]);
    assert_eq!(
        asked(KeyType::Rsa2048, without_alg(0x0023)),
        vec![Parms::Rsa2048]
    );
    assert_eq!(
        asked(KeyType::Rsa2048, without_alg(0x0001)),
        vec![Parms::Parent]
    );
    assert_eq!(
        asked(KeyType::EccP256, without_alg(0x000b)),
        vec![Parms::Parent]
    );
    assert_eq!(
        asked(KeyType::EccP256, without_alg(0x0006)),
        vec![Parms::EcdsaSha256]
    );
    let no_curve = Opened {
        curves: Ok(vec![]),
        ..complete()
    };
    assert_eq!(asked(KeyType::EccP256, no_curve), vec![]);
    let failed = Opened {
        algorithms: Err(Fault::Transport),
        ..complete()
    };
    assert_eq!(
        asked(KeyType::EccP256, failed),
        vec![],
        "no list, nothing is known to be present"
    );
}

#[test]
fn assess_classifies_what_collect_gathered() {
    let access = Scripted {
        asked: Arc::default(),
        opened: complete(),
    };
    assert_eq!(assess(&access, KeyType::Rsa2048), Classification::Ready);
    let access = Scripted {
        asked: Arc::default(),
        opened: without_alg(0x0001),
    };
    assert_eq!(
        assess(&access, KeyType::Rsa2048),
        Classification::Lacks(vec![Item::AlgRsa])
    );
}

/// The rows of the document's table: item name, query, RSA 2048 and ECC P-256 columns.
fn document_rows() -> Vec<(String, bool, bool)> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/api.md");
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let section = text
        .split("\n## ")
        .find(|s| s.starts_with("TPM capabilities"))
        .unwrap_or_default();
    section
        .lines()
        .filter(|l| l.starts_with("| `"))
        .map(|l| {
            let cells: Vec<&str> = l.split('|').map(str::trim).collect();
            let name = cells
                .get(1)
                .map(|c| c.trim_matches('`').to_owned())
                .unwrap_or_default();
            let yes = |i: usize| cells.get(i).is_some_and(|c| *c == "yes");
            (name, yes(4), yes(5))
        })
        .collect()
}

#[test]
fn list_matches_document() {
    let rows = document_rows();
    let in_code: Vec<(String, bool, bool)> = ALL
        .iter()
        .map(|i| {
            (
                i.name().to_owned(),
                KeyType::Rsa2048.items().contains(i),
                KeyType::EccP256.items().contains(i),
            )
        })
        .collect();
    assert_eq!(
        rows, in_code,
        "docs/api.md \"TPM capabilities\" and the code's list differ"
    );
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/api.md");
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let section = text
        .split("\n## ")
        .find(|s| s.starts_with("TPM capabilities"))
        .unwrap_or_default();
    assert!(section.contains("## F107"), "the document names its source");
    for hash in ["SHA-384", "SHA-512"] {
        assert!(
            !rows.iter().any(|r| r.0.contains(hash)),
            "{hash} is on no list"
        );
    }
    // The code's list: every item of each key type is in `ALL`, once.
    for key in BOTH {
        let items = key.items();
        assert!(items.iter().all(|i| ALL.contains(i)));
        assert_eq!(
            items.len(),
            ALL.iter().filter(|i| items.contains(i)).count()
        );
    }
    // The queries of every item are distinct.
    for (n, a) in ALL.iter().enumerate() {
        for b in ALL.iter().skip(n + 1) {
            assert_ne!(a.query(), b.query(), "{a:?} {b:?}");
            assert_ne!(a.name(), b.name());
        }
    }
}

#[test]
fn production_opens_only_tpmrm0() {
    assert_eq!(open::Production::new().conf(), "device:/dev/tpmrm0");
    assert_eq!(
        open::Production::under(std::path::Path::new("/x")).conf(),
        "device:/x/dev/tpmrm0"
    );
    // The raw node's name is in the module twice: its definition and the one `stat`.
    let source = include_str!("../open.rs");
    let code = source.split("#[cfg(test)]").next().unwrap_or(source);
    assert_eq!(
        code.matches("RAW_NODE").count(),
        2,
        "the raw node is only ever stat-ed"
    );
    assert_eq!(code.matches("\"dev/tpm0\"").count(), 1);
    assert_eq!(
        code.matches("fs::metadata").count(),
        1,
        "stat only, in one place"
    );
    assert!(!code.contains("File::open") && !code.contains("OpenOptions"));
}

#[test]
fn the_variable_accepts_only_an_absolute_swtpm_socket() {
    use std::ffi::OsStr;
    let refused = |v: &str| {
        matches!(
            open::from_value(Some(OsStr::new(v))).open(),
            Err(OpenError::Failed(TpmError::TestTctiRefused))
        )
    };
    for v in [
        "",
        "/dev/tpmrm0",
        "device:/dev/tpmrm0",
        "mssim:host=localhost",
        "tabrmd:",
        "swtpm:",
        "swtpm:path=relative/sock",
        "swtpm:host=localhost,port=2321",
        "swtpm:path=",
        "swtpm:path=/a,host=b",
        "SWTPM:path=/a",
        " swtpm:path=/a",
    ] {
        // A path that is a regular file is refused too (below); here only the form decides.
        if v.starts_with("swtpm:path=/") {
            assert!(
                refused(v)
                    || matches!(
                        open::from_value(Some(OsStr::new(v))).open(),
                        Err(OpenError::NoDevice)
                    ),
                "{v}"
            );
        } else {
            assert!(refused(v), "{v:?}");
        }
    }
    // A well-formed value naming nothing is "no TPM".
    assert!(matches!(
        open::from_value(Some(OsStr::new("swtpm:path=/nonexistent/custodio/sock"))).open(),
        Err(OpenError::NoDevice)
    ));
}
