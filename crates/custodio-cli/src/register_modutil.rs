//! Running NSS's `modutil` for `custodio register`, and asking it whether the system NSS loads the p11-kit proxy.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::list::escape;
use crate::register_native::{Options, Outcome};

/// How much of each output stream of `modutil` is kept; the rest is read and dropped.
const OUTPUT_LIMIT: u64 = 64 * 1024;

fn read_bounded_stream(mut stream: impl Read) -> Vec<u8> {
    let mut kept = Vec::new();
    let _ = stream.by_ref().take(OUTPUT_LIMIT).read_to_end(&mut kept);
    let _ = io::copy(&mut stream, &mut io::sink());
    kept
}

/// Run `modutil -dbdir sql:DIR ARGS` with stdin from `/dev/null`; its stdout, bounded.
pub(crate) fn modutil(program: &OsStr, dir: &Path, args: &[&OsStr]) -> Result<Vec<u8>, String> {
    let mut db = OsString::from("sql:");
    db.push(dir);
    let cannot_run = |e: io::Error| format!("cannot run modutil: {e}");
    let mut child = Command::new(program)
        .arg("-dbdir")
        .arg(db)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(cannot_run)?;
    let (stdout, stderr) = (child.stdout.take(), child.stderr.take());
    // Both pipes are drained together, so a full one never blocks modutil.
    let (stdout, stderr) = std::thread::scope(|s| {
        let stderr = s.spawn(|| stderr.map(read_bounded_stream).unwrap_or_default());
        let stdout = stdout.map(read_bounded_stream).unwrap_or_default();
        (stdout, stderr.join().unwrap_or_default())
    });
    let status = child.wait().map_err(cannot_run)?;
    if status.success() {
        return Ok(stdout);
    }
    let text = String::from_utf8_lossy(&stderr);
    let first = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let shown: String = escape(first.trim()).chars().take(300).collect();
    Err(format!("modutil failed ({status}): {shown}"))
}

/// Why native profiles are skipped when the system NSS loads the p11-kit proxy.
const P11_KIT: &str = "the system NSS loads the p11-kit proxy (modutil lists p11-kit-proxy in a new database), which \
                       already shows Custodio";

/// A new private directory under the temporary directory, removed on drop.
struct ScratchDb(PathBuf);

impl ScratchDb {
    fn create() -> Result<Self, String> {
        let base = std::env::temp_dir();
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        for n in 0..100 {
            let path = base.join(format!(
                "custodio-nss-probe-{}-{stamp}-{n}",
                std::process::id()
            ));
            // `create` fails on anything already there, so nothing planted is followed.
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(format!("cannot create {}: {e}", path.display())),
            }
        }
        Err(format!(
            "cannot create a new directory in {}",
            base.display()
        ))
    }
}

impl Drop for ScratchDb {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Whether the system NSS loads the p11-kit proxy: whether `modutil` lists it in a new database.
fn nss_loads_p11_kit(program: &OsStr) -> Result<bool, String> {
    let db = ScratchDb::create()?;
    modutil(
        program,
        &db.0,
        &[OsStr::new("-create"), OsStr::new("-force")],
    )?;
    let listing = modutil(program, &db.0, &[OsStr::new("-list")])?;
    Ok(String::from_utf8_lossy(&listing).contains("p11-kit-proxy"))
}

/// What every native profile gets instead of registration, if anything.
pub(crate) fn instead_of_registering(options: &Options) -> Option<Outcome> {
    match nss_loads_p11_kit(&options.modutil) {
        Ok(true) => Some(Outcome::Skipped(P11_KIT.to_owned())),
        Ok(false) => None,
        Err(why) => Some(Outcome::Failed(format!(
            "cannot tell whether the system NSS loads the p11-kit proxy: {why}"
        ))),
    }
}
