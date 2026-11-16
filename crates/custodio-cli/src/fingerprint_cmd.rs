//! `custodio fingerprint enable` and `disable`: observes the system, asks [`crate::fingerprint_decide`]
//! what to do and applies it.
//!
//! The only file written is `/etc/pam.d/polkit-1`, as a whole or not at all. With the cargo feature
//! `fixture-root` (tests only, never in what ships; `just fixture-seams` checks it) every path is
//! read under a fixture root, the uid can be overridden and a step can be made to fail.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use zbus::{Connection, block_on};

use crate::fingerprint_decide::{
    DisableDecision, EnableDecision, FileState, LOCK_NOTE, NO_READER_WARNING, Observed,
    POLKIT_FILE, Refusal, VendorState, dconf_disables_fingerprint, decide_disable, decide_enable,
    family_from_os_release, file_bytes,
};

/// What the person asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Enable,
    Disable,
}

/// Why the command did not succeed.
#[derive(Debug)]
pub enum Failure {
    Refused(Refusal),
    /// A system call failed; `what` says which step. On `enable` a failed step leaves no file; on `disable` the file may remain.
    Io {
        what: &'static str,
        error: io::Error,
    },
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(r) => write!(f, "{r}"),
            Self::Io { what, error } => write!(f, "custodio fingerprint: {what}: {error}"),
        }
    }
}

impl std::error::Error for Failure {}

const READER_PROBE_LIMIT: Duration = Duration::from_millis(1500);
const READ_LIMIT: u64 = 1 << 20;
const PAM_DIR: &str = "etc/pam.d";
const POLKIT_NAME: &str = "polkit-1";
const FPRINTD_SERVICE: &str = "usr/share/dbus-1/system-services/net.reactivated.Fprint.service";
const LOGIN_SCHEMA: &str = "usr/share/glib-2.0/schemas/org.gnome.login-screen.gschema.xml";

/// Where a failure is injected (the seam only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fail {
    Rename,
    Flush,
    Label,
}

/// The root every path is under, the uid, and the injected failure.
struct Env {
    root: PathBuf,
    euid: u32,
    fail: Option<Fail>,
    /// Real system: owner and label are applied.
    real: bool,
}

#[cfg(feature = "fixture-root")]
fn env() -> Env {
    let root = std::env::var_os("CUSTODIO_FIXTURE_ROOT").map(PathBuf::from);
    let euid = std::env::var("CUSTODIO_FIXTURE_EUID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| rustix::process::geteuid().as_raw());
    let fail = match std::env::var("CUSTODIO_FIXTURE_FAIL").as_deref() {
        Ok("rename") => Some(Fail::Rename),
        Ok("label") => Some(Fail::Label),
        Ok("flush") => Some(Fail::Flush),
        _ => None,
    };
    Env {
        real: root.is_none(),
        root: root.unwrap_or_else(|| PathBuf::from("/")),
        euid,
        fail,
    }
}

#[cfg(not(feature = "fixture-root"))]
fn env() -> Env {
    Env {
        root: PathBuf::from("/"),
        euid: rustix::process::geteuid().as_raw(),
        fail: None,
        real: true,
    }
}

fn read_text(path: &Path) -> Option<String> {
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(READ_LIMIT)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn file_state(path: &Path) -> FileState {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => FileState::Missing,
        Ok(m) if m.file_type().is_file() => {
            let mut bytes = Vec::new();
            match File::open(path).and_then(|f| f.take(READ_LIMIT).read_to_end(&mut bytes)) {
                Ok(_) => FileState::Regular(bytes),
                Err(_) => FileState::NotRegular,
            }
        }
        _ => FileState::NotRegular,
    }
}

fn vendor_state(path: &Path) -> VendorState {
    match fs::metadata(path) {
        Err(_) => VendorState::Missing,
        Ok(m) if m.is_file() => VendorState::Regular,
        Ok(_) => VendorState::NotRegular,
    }
}

/// `pam_fprintd.so` in any of the directories PAM modules live in: `security` under `lib`, `lib64`
/// and one level of multiarch directories, in `/usr` and at the top.
fn module_present(root: &Path) -> bool {
    let mut dirs = Vec::new();
    for lib in ["usr/lib", "usr/lib64", "lib", "lib64"] {
        let lib = root.join(lib);
        dirs.push(lib.join("security"));
        if let Ok(entries) = fs::read_dir(&lib) {
            dirs.extend(entries.flatten().map(|e| e.path().join("security")));
        }
    }
    dirs.iter()
        .any(|d| fs::metadata(d.join("pam_fprintd.so")).is_ok_and(|m| m.is_file()))
}

/// Whether a `*.d` directory of the dconf databases has a file that turns the login-screen
/// fingerprint off.
fn dconf_disables(root: &Path) -> bool {
    let Ok(dbs) = fs::read_dir(root.join("etc/dconf/db")) else {
        return false;
    };
    dbs.flatten()
        .filter(|d| d.file_name().to_string_lossy().ends_with(".d"))
        .filter_map(|d| fs::read_dir(d.path()).ok())
        .flat_map(Iterator::flatten)
        .filter_map(|f| read_text(&f.path()))
        .any(|t| dconf_disables_fingerprint(&t))
}

/// Whether `fprintd` knows of a reader. Asking is `GetDevices`, which needs no authorization. No
/// answer within the limit, or no service, is "no reader", never a refusal.
fn reader_present() -> bool {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(ask_devices());
    });
    rx.recv_timeout(READER_PROBE_LIMIT).unwrap_or(false)
}

fn ask_devices() -> bool {
    block_on(async {
        let connection = Connection::system().await.ok()?;
        let reply = connection
            .call_method(
                Some("net.reactivated.Fprint"),
                "/net/reactivated/Fprint/Manager",
                Some("net.reactivated.Fprint.Manager"),
                "GetDevices",
                &(),
            )
            .await
            .ok()?;
        let devices: Vec<zbus::OwnedObjectPath> = reply.body().deserialize().ok()?;
        Some(!devices.is_empty())
    })
    .unwrap_or(false)
}

fn observe(env: &Env) -> Observed {
    let root = env.root.as_path();
    let text = |p: &str| read_text(&root.join(p));
    Observed {
        euid: env.euid,
        family: family_from_os_release(
            &text("etc/os-release")
                .or_else(|| text("usr/lib/os-release"))
                .unwrap_or_default(),
        ),
        polkit_file: file_state(&root.join(PAM_DIR).join(POLKIT_NAME)),
        vendor: vendor_state(&root.join("usr/lib/pam.d").join(POLKIT_NAME)),
        module_present: module_present(root),
        fprintd_present: root.join(FPRINTD_SERVICE).exists(),
        reader_present: true,
        common_auth: text("etc/pam.d/common-auth"),
        authselect: text("etc/authselect/authselect.conf"),
        system_auth: text("etc/pam.d/system-auth"),
        sudo: text("etc/pam.d/sudo"),
        gnome_login_schema: root.join(LOGIN_SCHEMA).exists(),
        dconf_disables_login_fingerprint: dconf_disables(root),
    }
}

/// Run the command, writing what it did to `out` and warnings to `err`.
///
/// # Errors
/// A [`Failure`]: a refusal, or a step that failed.
pub fn run<W: Write, E: Write>(action: Action, out: &mut W, err: &mut E) -> Result<(), Failure> {
    let env = env();
    let mut observed = observe(&env);
    match action {
        Action::Enable => enable(&env, &mut observed, out, err),
        Action::Disable => disable(&env, &observed, out),
    }
}

fn enable<W: Write, E: Write>(
    env: &Env,
    observed: &mut Observed,
    out: &mut W,
    err: &mut E,
) -> Result<(), Failure> {
    let mut decision = decide_enable(observed);
    if matches!(decision, EnableDecision::Write { .. }) && !reader_present() {
        observed.reader_present = false;
        decision = decide_enable(observed);
    }
    match decision {
        EnableDecision::Refuse(r) => Err(Failure::Refused(r)),
        EnableDecision::AlreadyEnabled => {
            let _ = writeln!(
                out,
                "{POLKIT_FILE} is already Custodio's file: nothing was changed.\n\
To undo it: sudo custodio fingerprint disable"
            );
            Ok(())
        }
        EnableDecision::Write {
            warn_no_reader,
            lock_note,
        } => {
            write_file(env)?;
            let _ = writeln!(
                out,
                "Wrote {POLKIT_FILE}. Every polkit dialog (the ones that ask for your password, Custodio's among them) \
now accepts a finger.\n\
A wrong finger, or 10 s without a touch, falls back to the password. sudo and the login are unchanged.\n\
To undo it: sudo custodio fingerprint disable"
            );
            if lock_note {
                let _ = writeln!(out, "{LOCK_NOTE}");
            }
            if warn_no_reader {
                let _ = writeln!(err, "{NO_READER_WARNING}");
            }
            Ok(())
        }
    }
}

fn disable<W: Write>(env: &Env, observed: &Observed, out: &mut W) -> Result<(), Failure> {
    match decide_disable(observed) {
        DisableDecision::Refuse(r) => Err(Failure::Refused(r)),
        DisableDecision::NothingToDisable => {
            let _ = writeln!(
                out,
                "{POLKIT_FILE} does not exist: nothing to disable, nothing was changed."
            );
            Ok(())
        }
        DisableDecision::Remove => {
            fs::remove_file(env.root.join(PAM_DIR).join(POLKIT_NAME)).map_err(|error| {
                Failure::Io {
                    what: "cannot remove the file",
                    error,
                }
            })?;
            let _ = writeln!(
                out,
                "Removed {POLKIT_FILE}. Polkit dialogs ask for the password only.\n\
To turn it on again: sudo custodio fingerprint enable"
            );
            Ok(())
        }
    }
}

fn io_failure(what: &'static str) -> impl FnOnce(io::Error) -> Failure {
    move |error| Failure::Io { what, error }
}

/// Write the file next to its place, flushed, then rename it in. A failure at any step removes
/// what was made.
fn write_file(env: &Env) -> Result<(), Failure> {
    let dir = env.root.join(PAM_DIR);
    let tmp = dir.join(format!(".{POLKIT_NAME}.custodio-{}", std::process::id()));
    let result = write_temp(env, &tmp).and_then(|()| put_in_place(env, &tmp, &dir));
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn write_temp(env: &Env, tmp: &Path) -> Result<(), Failure> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(tmp)
        .map_err(io_failure("cannot create the temporary file in /etc/pam.d"))?;
    // The umask may have cleared bits: the mode is set, not asked for.
    file.set_permissions(fs::Permissions::from_mode(0o644))
        .map_err(io_failure("cannot set the mode"))?;
    if env.real {
        apply_owner(&file).map_err(io_failure("cannot make root the owner"))?;
    }
    file.write_all(file_bytes())
        .and_then(|()| file.sync_all())
        .map_err(io_failure("cannot write the temporary file"))
}

fn put_in_place(env: &Env, tmp: &Path, dir: &Path) -> Result<(), Failure> {
    let target = dir.join(POLKIT_NAME);
    if env.fail == Some(Fail::Rename) {
        return Err(io_failure("cannot move the file into place")(
            io::Error::other("injected failure"),
        ));
    }
    // Never replace a file that appeared since it was looked at.
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        tmp,
        rustix::fs::CWD,
        &target,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|e| io_failure("cannot move the file into place")(e.into()))?;
    if let Err(failure) = label_step(env, &target) {
        let _ = fs::remove_file(&target);
        return Err(failure);
    }
    // The rename is only durable once the directory is.
    let flushed = if env.fail == Some(Fail::Flush) {
        Err(io::Error::other("injected failure"))
    } else {
        File::open(dir).and_then(|d| d.sync_all())
    };
    if let Err(error) = flushed {
        // The change is not known to be durable: take it back, as the label step does.
        let _ = fs::remove_file(&target);
        return Err(io_failure("cannot flush /etc/pam.d")(error));
    }
    Ok(())
}

fn label_step(env: &Env, target: &Path) -> Result<(), Failure> {
    if env.fail == Some(Fail::Label) {
        return Err(io_failure("cannot label the file")(io::Error::other(
            "injected failure",
        )));
    }
    if env.real {
        apply_label(target).map_err(io_failure("cannot give the file its SELinux label"))?;
    }
    Ok(())
}

/// `root:root`. Proven on a real `/etc` by F199 (a test here would need root); excluded from `mutants`.
fn apply_owner(file: &File) -> io::Result<()> {
    rustix::fs::fchown(
        file,
        Some(rustix::fs::Uid::ROOT),
        Some(rustix::fs::Gid::ROOT),
    )
    .map_err(Into::into)
}

/// An absolute path, so a caller's `PATH` cannot choose the binary run as root.
fn restorecon_path() -> &'static str {
    if Path::new("/usr/sbin/restorecon").exists() {
        "/usr/sbin/restorecon"
    } else {
        "/sbin/restorecon"
    }
}

/// The label the policy gives a file at that path, where `SELinux` is enforcing. Proven on fedora and
/// alma by F199 (a test here would need `SELinux`); excluded from `mutants`.
fn apply_label(target: &Path) -> io::Result<()> {
    let enforcing = fs::read_to_string("/sys/fs/selinux/enforce").is_ok_and(|s| s.trim() == "1");
    if !enforcing {
        return Ok(());
    }
    let status = std::process::Command::new(restorecon_path())
        .arg("-F")
        .arg(target)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other("restorecon failed"))
    }
}
