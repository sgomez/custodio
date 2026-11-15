//! Which browser profiles exist: the data table of F172 applied to a home directory, read-only.

use std::ffi::OsString;
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

/// What discovery reads from outside: passed in, never taken from the process.
#[derive(Debug, Clone)]
pub struct Environment {
    pub home: PathBuf,
    /// `$XDG_CONFIG_HOME`, if set.
    pub xdg_config_home: Option<OsString>,
    /// This host's address, as written in `lock` (see `browser_files::local_address`).
    pub local_address: Ipv4Addr,
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
/// A `profiles.ini` that is malformed or unreadable; the error names the file.
pub fn discover(env: &Environment) -> Result<Vec<Profile>, FileError> {
    let mut profiles: Vec<Profile> = Vec::new();
    let mut add = |browser: &'static str, snap: bool, root: &Path, dirs: Vec<PathBuf>| {
        for path in dirs {
            if profiles.iter().any(|p| p.path == path) {
                continue;
            }
            let lock = lock_state(&path, env.local_address);
            profiles.push(Profile {
                browser,
                snap,
                root: root.to_owned(),
                path,
                lock,
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
