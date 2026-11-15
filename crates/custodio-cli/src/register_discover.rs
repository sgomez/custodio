//! Which browser profiles exist: the data table of F172 applied to a home directory, read-only.

use std::ffi::OsString;
use std::fmt;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use crate::browser_files::{
    FileError, LockState, lock_state, parse_profiles_ini, read_bounded, real_directories,
};

/// Where a root is, relative to what.
#[derive(Debug, Clone, Copy)]
pub enum Base {
    /// Under the home directory.
    Home(&'static str),
    /// Under `$XDG_CONFIG_HOME`, else `~/.config`.
    XdgConfig(&'static str),
    /// Under `~/.config`, whatever `$XDG_CONFIG_HOME` says.
    DotConfig(&'static str),
}

/// A browser of the table of F172 ("Data the command reads").
#[derive(Debug, Clone, Copy)]
pub struct Browser {
    pub name: &'static str,
    /// In lookup order; each root that holds a `profiles.ini` counts.
    pub roots: &'static [Base],
}

/// The native browsers. Zen, Mullvad, Tor, Flatpak and `AppImage` are left out on purpose (F172).
pub const BROWSERS: &[Browser] = &[
    Browser {
        name: "Firefox",
        roots: &[
            Base::Home(".mozilla/firefox"),
            Base::XdgConfig("mozilla/firefox"),
        ],
    },
    Browser {
        name: "Thunderbird",
        roots: &[Base::Home(".thunderbird"), Base::XdgConfig("thunderbird")],
    },
    Browser {
        name: "LibreWolf",
        roots: &[
            Base::Home(".librewolf"),
            Base::DotConfig("librewolf/librewolf"),
        ],
    },
    Browser {
        name: "Floorp",
        roots: &[Base::Home(".floorp")],
    },
    Browser {
        name: "Waterfox",
        roots: &[Base::Home(".waterfox")],
    },
];

/// The Firefox snap's root, under the home directory.
pub const SNAP_ROOT: &str = "snap/firefox/common/.mozilla/firefox";
/// The name the snap's profiles are listed under.
pub const SNAP_NAME: &str = "Firefox (snap)";
/// The file that makes the system NSS load p11-kit.
pub const NSS_CONFIG: &str = "/etc/crypto-policies/back-ends/nss.config";

/// What discovery reads from outside: passed in, never taken from the process.
#[derive(Debug, Clone)]
pub struct Environment {
    pub home: PathBuf,
    /// `$XDG_CONFIG_HOME`, if set.
    pub xdg_config_home: Option<OsString>,
    pub nss_config: PathBuf,
    /// This host's address, as written in `lock` (see `browser_files::local_address`).
    pub local_address: Ipv4Addr,
}

/// Why a native profile is not registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skipped {
    /// The system NSS loads the p11-kit proxy into every database, so Custodio is already visible.
    P11Kit,
}

impl fmt::Display for Skipped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::P11Kit => f.write_str(
                "the system NSS loads p11-kit (library=p11-kit-proxy.so in nss.config), which already shows Custodio",
            ),
        }
    }
}

/// A profile directory found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub browser: &'static str,
    pub snap: bool,
    /// The directory holding the `profiles.ini` that names it, as reached.
    pub root: PathBuf,
    /// The real path.
    pub path: PathBuf,
    pub lock: LockState,
    pub skipped: Option<Skipped>,
}

fn root_dir(env: &Environment, base: Base) -> PathBuf {
    let config = || match &env.xdg_config_home {
        Some(x) if !x.is_empty() && Path::new(x).is_absolute() => PathBuf::from(x),
        _ => env.home.join(".config"),
    };
    match base {
        Base::Home(rel) => env.home.join(rel),
        Base::XdgConfig(rel) => config().join(rel),
        Base::DotConfig(rel) => env.home.join(".config").join(rel),
    }
}

/// Whether the system NSS config has the line `library=p11-kit-proxy.so`.
///
/// # Errors
/// The file exists and cannot be read.
pub fn system_loads_p11_kit(path: &Path) -> Result<bool, FileError> {
    Ok(read_bounded(path)?.is_some_and(|bytes| {
        bytes
            .split(|b| *b == b'\n')
            .any(|l| l.trim_ascii() == b"library=p11-kit-proxy.so")
    }))
}

fn index_dirs(root: &Path) -> Result<Vec<PathBuf>, FileError> {
    let file = root.join("profiles.ini");
    let Some(bytes) = read_bounded(&file)? else {
        return Ok(Vec::new());
    };
    let index = parse_profiles_ini(&file.display().to_string(), &bytes)?;
    Ok(real_directories(index.directories(root)))
}

/// Every profile of the native browsers and of the Firefox snap, each with its lock state, deduplicated by real path.
///
/// # Errors
/// A `profiles.ini` that is malformed or unreadable, or an unreadable `nss.config`; the error names the file.
pub fn discover(env: &Environment) -> Result<Vec<Profile>, FileError> {
    let p11_kit = system_loads_p11_kit(&env.nss_config)?;
    let mut profiles: Vec<Profile> = Vec::new();
    let mut add = |browser: &'static str, snap: bool, root: &Path, dirs: Vec<PathBuf>| {
        for path in dirs {
            if profiles.iter().any(|p| p.path == path) {
                continue;
            }
            let lock = lock_state(&path, env.local_address);
            let skipped = (p11_kit && !snap).then_some(Skipped::P11Kit);
            profiles.push(Profile {
                browser,
                snap,
                root: root.to_owned(),
                path,
                lock,
                skipped,
            });
        }
    };
    for browser in BROWSERS {
        for base in browser.roots {
            let root = root_dir(env, *base);
            add(browser.name, false, &root, index_dirs(&root)?);
        }
    }
    let root = env.home.join(SNAP_ROOT);
    add(SNAP_NAME, true, &root, index_dirs(&root)?);
    Ok(profiles)
}
