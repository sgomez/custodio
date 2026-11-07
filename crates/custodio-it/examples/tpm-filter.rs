//! A TPM that lacks something, as a program (F131). `tpm-filter UPSTREAM LISTEN [alg=ID | curve=ID]...` puts the filter of
//! `custodio_it::tpm_filter` in front of the `swtpm` data socket UPSTREAM and listens on LISTEN (and `LISTEN.ctrl`). `ID` is a
//! `TPM_ALG_ID` or a `TPM_ECC_CURVE`, decimal or `0x` hexadecimal; `alg=0x16` is `RSAPSS`, as in `docs/findings/F108.md`.
//!
//! Both sockets are made world-writable after the start (test only): the end-to-end unit runs as a dynamic user and the filter as
//! root, and `TpmFilter::start` binds with the default umask. It prints `ready` once they are, and runs until it is killed.
//! Not shipped: the end-to-end harness builds it (`just e2e-tpm-filter`) and mounts it into the target containers.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use custodio_it::tpm_filter::{Lacks, TpmFilter};

fn number(text: &str) -> Option<u16> {
    match text.strip_prefix("0x") {
        Some(hex) => u16::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// The lacking identifiers of the arguments after the two sockets.
fn parse_lacks(args: &[String]) -> Result<Lacks, String> {
    let mut lacks = Lacks::default();
    for arg in args {
        let (kind, id) = arg
            .split_once('=')
            .ok_or_else(|| format!("'{arg}' is not alg=ID or curve=ID"))?;
        let id = number(id).ok_or_else(|| format!("'{id}' is not a number"))?;
        match kind {
            "alg" => lacks.algorithms.push(id),
            "curve" => lacks.curves.push(id),
            _ => return Err(format!("'{arg}' is not alg=ID or curve=ID")),
        }
    }
    Ok(lacks)
}

fn world_writable(path: &Path) -> std::io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o666))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [upstream, listen, rest @ ..] = args.as_slice() else {
        eprintln!("usage: tpm-filter UPSTREAM LISTEN [alg=ID | curve=ID]...");
        return ExitCode::from(2);
    };
    let lacks = match parse_lacks(rest) {
        Ok(l) if !l.algorithms.is_empty() || !l.curves.is_empty() => l,
        Ok(_) => {
            eprintln!("tpm-filter: nothing is lacking; give at least one alg=ID or curve=ID");
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("tpm-filter: {e}");
            return ExitCode::from(2);
        }
    };
    let listen = PathBuf::from(listen);
    let filter = match TpmFilter::start(Path::new(upstream), &listen, lacks) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("tpm-filter: cannot listen on {}: {e}", listen.display());
            return ExitCode::FAILURE;
        }
    };
    let mut ctrl = listen.clone().into_os_string();
    ctrl.push(".ctrl");
    for path in [listen.as_path(), Path::new(&ctrl)] {
        if let Err(e) = world_writable(path) {
            eprintln!("tpm-filter: cannot chmod {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    }
    println!("ready {}", filter.tcti());
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
