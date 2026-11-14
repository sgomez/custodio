//! A fixture `/proc` and `/sys` tree for `state_storage`.

use std::error::Error;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use custodiod::storage::{StateStorage, classify_with};

type Res = Result<(), Box<dyn Error>>;

/// A fixture root: `proc/self/mountinfo`, `sys/devices/**`, `sys/dev/block/*`, and a state directory.
pub struct Tree {
    pub root: tempfile::TempDir,
    pub mounts: Vec<String>,
}

impl Tree {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        fs::create_dir_all(root.path().join("proc/self"))?;
        fs::create_dir_all(root.path().join("sys/dev/block"))?;
        fs::create_dir_all(root.path().join("state"))?;
        Ok(Self {
            root,
            mounts: Vec::new(),
        })
    }

    pub fn path(&self) -> PathBuf {
        self.root.path().to_path_buf()
    }

    pub fn state(&self) -> PathBuf {
        self.root.path().join("state")
    }

    pub fn node(&self, rel: &str, mm: &str) -> Result<PathBuf, Box<dyn Error>> {
        let dir = self.root.path().join("sys/devices").join(rel);
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("dev"), format!("{mm}\n"))?;
        symlink(&dir, self.root.path().join("sys/dev/block").join(mm))?;
        Ok(dir)
    }

    /// A physical disk (hardware `device` link).
    pub fn disk(&self, name: &str, mm: &str) -> Result<PathBuf, Box<dyn Error>> {
        let dir = self.node(&format!("pci/{name}"), mm)?;
        fs::create_dir(dir.join("device"))?;
        Ok(dir)
    }

    pub fn part(&self, disk: &str, name: &str, mm: &str) -> Result<PathBuf, Box<dyn Error>> {
        let dir = self.node(&format!("pci/{disk}/{name}"), mm)?;
        fs::write(dir.join("partition"), "1\n")?;
        Ok(dir)
    }

    pub fn link_slaves(dir: &Path, slaves: &[&Path]) -> Res {
        fs::create_dir_all(dir.join("slaves"))?;
        for (i, s) in slaves.iter().enumerate() {
            symlink(s, dir.join("slaves").join(format!("s{i}")))?;
        }
        Ok(())
    }

    pub fn dm(
        &self,
        name: &str,
        mm: &str,
        uuid: &str,
        slaves: &[&Path],
    ) -> Result<PathBuf, Box<dyn Error>> {
        let dir = self.node(&format!("virtual/block/{name}"), mm)?;
        fs::create_dir(dir.join("dm"))?;
        fs::write(dir.join("dm/uuid"), format!("{uuid}\n"))?;
        Self::link_slaves(&dir, slaves)?;
        Ok(dir)
    }

    pub fn md(&self, name: &str, mm: &str, slaves: &[&Path]) -> Result<PathBuf, Box<dyn Error>> {
        let dir = self.node(&format!("virtual/block/{name}"), mm)?;
        fs::create_dir(dir.join("md"))?;
        Self::link_slaves(&dir, slaves)?;
        Ok(dir)
    }

    /// A mount entry as the kernel writes it (`point` already escaped by the caller).
    pub fn mount(&mut self, point: &str, mm: &str, fstype: &str) {
        let id = self.mounts.len() + 10;
        self.mounts.push(format!(
            "{id} 1 {mm} / {point} rw,relatime shared:1 - {fstype} /dev/whatever rw"
        ));
    }

    /// The state directory is mounted from `mm` as `fstype`; writes the table.
    pub fn on(&mut self, mm: &str, fstype: &str) -> Result<&Self, Box<dyn Error>> {
        let point = self.state().to_string_lossy().into_owned();
        self.mount(&point, mm, fstype);
        self.write()?;
        Ok(self)
    }

    pub fn write(&self) -> Res {
        fs::write(
            self.root.path().join("proc/self/mountinfo"),
            self.mounts.join("\n") + "\n",
        )?;
        Ok(())
    }

    pub fn verdict(&self) -> StateStorage {
        classify_with(&self.path(), &self.state(), &|_| Ok(false))
    }
}
