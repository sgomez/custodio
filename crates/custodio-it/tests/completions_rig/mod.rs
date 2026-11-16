//! What the completion tests share: the real `custodio` binary, the rig's bus as its system bus,
//! and a snapshot of a directory.

use std::collections::BTreeMap;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Once;

use super::list_rig::Rig;

static BUILT: Once = Once::new();

/// Builds the binary (cargo does not build the binary of another package for these tests) and
/// returns `target/<profile>/custodio-cli`, next to the `deps` directory of this test binary.
pub fn binary() -> Result<PathBuf, Box<dyn Error>> {
    let exe = std::env::current_exe()?;
    let dir = exe
        .parent()
        .and_then(Path::parent)
        .ok_or("no target dir")?
        .to_path_buf();
    let target = dir.parent().ok_or("no target dir")?.to_path_buf();
    BUILT.call_once(|| {
        let mut build = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
        build.args(["build", "--quiet", "--locked", "-p", "custodio-cli"]);
        build.arg("--target-dir").arg(&target);
        if !cfg!(debug_assertions) {
            build.arg("--release");
        }
        assert!(
            build.status().is_ok_and(|s| s.success()),
            "building custodio-cli failed"
        );
    });
    let path = dir.join("custodio-cli");
    assert!(path.exists(), "{} was not built", path.display());
    Ok(path)
}

/// `custodio __key-ids` with `address` as the system bus.
pub fn key_ids(address: &str) -> Result<Output, Box<dyn Error>> {
    Ok(Command::new(binary()?)
        .arg("__key-ids")
        .env_clear()
        .env("DBUS_SYSTEM_BUS_ADDRESS", address)
        .stdin(Stdio::null())
        .output()?)
}

/// Every file under `dir` with its bytes, and every directory: equal before and after means
/// nothing was written.
/// A path with its bytes, or `None` for a directory.
pub type Snapshot = BTreeMap<PathBuf, Option<Vec<u8>>>;

pub fn snapshot(dir: &Path) -> Result<Snapshot, Box<dyn Error>> {
    let mut all = BTreeMap::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        for entry in std::fs::read_dir(&d)? {
            let path = entry?.path();
            if path.is_dir() {
                all.insert(path.clone(), None);
                todo.push(path);
            } else {
                all.insert(path.clone(), Some(std::fs::read(&path)?));
            }
        }
    }
    Ok(all)
}

/// The state directory of the rig's service.
pub fn state_dir(rig: &Rig) -> PathBuf {
    rig.dir.path().join("state")
}
