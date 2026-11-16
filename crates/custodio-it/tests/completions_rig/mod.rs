//! What the completion tests share: the real `custodio` binary, the rig's bus as its system bus,
//! and a snapshot of a directory.

use std::collections::BTreeMap;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Once;
use std::time::{Duration, Instant};

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

#[derive(Clone, Copy, Debug)]
pub enum Shell {
    Bash,
}

impl Shell {
    /// The file of `packaging/completions/` for this shell.
    pub fn file(self) -> &'static str {
        match self {
            Self::Bash => "custodio.bash",
        }
    }

    /// Text of the real completion file.
    pub fn text(self) -> Result<String, Box<dyn Error>> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/completions")
            .join(self.file());
        Ok(std::fs::read_to_string(path)?)
    }
}

/// What a shell offered for one command line, and what it wrote besides.
#[derive(Debug)]
pub struct Offer {
    pub items: Vec<String>,
    pub stderr: String,
    pub took: Duration,
}

/// A private world for one shell: a `HOME`, a `PATH` directory with a `custodio`, the completion
/// file installed where the shell loads it, and the system bus the `custodio` talks to.
pub struct Setup {
    pub shell: Shell,
    pub home: tempfile::TempDir,
    pub files: tempfile::TempDir,
    pub bindir: tempfile::TempDir,
    pub address: String,
}

impl Setup {
    /// The real `custodio` on `address`, with `completion` as the completion file's text.
    pub fn new(shell: Shell, address: &str, completion: &str) -> Result<Self, Box<dyn Error>> {
        let setup = Self {
            shell,
            home: tempfile::tempdir()?,
            files: tempfile::tempdir()?,
            bindir: tempfile::tempdir()?,
            address: address.to_owned(),
        };
        std::os::unix::fs::symlink(binary()?, setup.bindir.path().join("custodio"))?;
        match shell {
            Shell::Bash => {
                // Where bash-completion's on-demand loader looks first: the user directory.
                let dir = setup.files.path().join("completions");
                std::fs::create_dir(&dir)?;
                std::fs::write(dir.join("custodio"), completion)?;
            }
        }
        Ok(setup)
    }

    /// Replaces `custodio` on `PATH` by a script with this body.
    pub fn stand_in(&self, body: &str) -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt;
        let path = self.bindir.path().join("custodio");
        std::fs::remove_file(&path)?;
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n"))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
        Ok(())
    }

    /// What the shell offers for the words (the last one is the one being completed).
    pub fn offer(&self, words: &[&str]) -> Result<Offer, Box<dyn Error>> {
        let path = format!("{}:/usr/bin:/bin", self.bindir.path().display());
        let mut cmd = match self.shell {
            Shell::Bash => {
                let mut c = Command::new("bash");
                c.args(["--noprofile", "--norc", "-c", BASH_DRIVER, "driver"])
                    .args(words);
                c.env_clear()
                    .env("BASH_COMPLETION_USER_DIR", self.files.path());
                c
            }
        };
        let start = Instant::now();
        let out = cmd
            .current_dir(self.home.path())
            .env("PATH", path)
            .env("HOME", self.home.path())
            .env("DBUS_SYSTEM_BUS_ADDRESS", &self.address)
            .stdin(Stdio::null())
            .output()?;
        let took = start.elapsed();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        Ok(Offer {
            items: String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(str::to_owned)
                .collect(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            took,
        })
    }
}

/// Loads the completion the way a user's bash does (the default loader of bash-completion finds
/// `completions/custodio`), then calls the function it registered for `custodio` with the words as
/// bash would set them.
const BASH_DRIVER: &str = r#"
source /usr/share/bash-completion/bash_completion
read -ra def <<<"$(complete -p -D)"
for i in "${!def[@]}"; do [[ ${def[i]} == -F ]] && loader=${def[i + 1]}; done
COMP_WORDS=("$@")
COMP_CWORD=$(($# - 1))
COMP_LINE="$*"
COMP_POINT=${#COMP_LINE}
"$loader" custodio
read -ra reg <<<"$(complete -p custodio)"
for i in "${!reg[@]}"; do [[ ${reg[i]} == -F ]] && fn=${reg[i + 1]}; done
[[ -n ${fn-} ]] || { echo "no completion registered for custodio" >&2; exit 1; }
COMPREPLY=()
"$fn" custodio "${COMP_WORDS[COMP_CWORD]}" "${COMP_WORDS[COMP_CWORD - 1]}"
((${#COMPREPLY[@]})) && printf '%s\n' "${COMPREPLY[@]}"
exit 0
"#;
