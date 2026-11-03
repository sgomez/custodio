//! A TPM that lacks an algorithm or a curve, simulated (F107).
//!
//! The installed `swtpm` 0.7.1 (libtpms 0.9.2) has no profile or algorithm switch (`docs/findings.md`, `## F107`), so a test
//! that needs "the TPM answered a capability query and the capability is absent" puts this filter between the client and
//! `swtpm`. It listens on a unix socket, speaks the framing of the `swtpm` TCTI on both sides (command `8`, locality, length,
//! TPM command; reply length, TPM response, acknowledgement) and changes what the client sees:
//!
//! - `TPM2_GetCapability` for algorithms and ECC curves: the lacking entries are removed from the answer.
//! - `TPM2_TestParms`: a lacking algorithm (key type, symmetric, scheme or hash) or curve gets the format-one response code
//!   the TPM spec gives that kind of fault (`TPM_RC_TYPE`, `TPM_RC_SCHEME`, `TPM_RC_HASH`, `TPM_RC_CURVE`) for parameter 1.
//! - `TPM2_Sign` and `TPM2_RSA_Decrypt`: a lacking scheme or hash in the `inScheme` argument (parameter 2) gets the same codes.
//!
//! Everything else is passed through untouched, so key creation, loading and import still reach the real TPM. Std only, no `unsafe`.

use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const CC_TEST_PARMS: u32 = 0x18a;
const CC_GET_CAPABILITY: u32 = 0x17a;
const CC_SIGN: u32 = 0x15d;
const CC_RSA_DECRYPT: u32 = 0x159;
const CAP_ALGS: u32 = 0;
const CAP_ECC_CURVES: u32 = 8;
const ALG_ECC: u16 = 0x0023;
const ALG_NULL: u16 = 0x0010;
const RC_TYPE: u32 = 0x08a;
const RC_HASH: u32 = 0x083;
const RC_SCHEME: u32 = 0x092;
const RC_CURVE: u32 = 0x0a6;
/// Format-one response code: `P` bit (the number counts parameters) and the 1-based parameter number.
const fn param_error(rc: u32, parameter: u32) -> u32 {
    rc | 0x40 | (parameter << 8)
}

/// What the simulated TPM lacks.
#[derive(Debug, Clone, Default)]
pub struct Lacks {
    /// `TPM_ALG_ID` values: a key type, a scheme, a hash, a symmetric algorithm.
    pub algorithms: Vec<u16>,
    /// `TPM_ECC_CURVE` values.
    pub curves: Vec<u16>,
}

/// `TPM_ALG_RSAPSS`, `TPM_ALG_SHA384` and the other identifiers the tests name.
pub mod alg {
    pub const SHA1: u16 = 0x0004;
    pub const SHA256: u16 = 0x000b;
    pub const SHA384: u16 = 0x000c;
    pub const SHA512: u16 = 0x000d;
    pub const RSASSA: u16 = 0x0014;
    pub const RSAES: u16 = 0x0015;
    pub const RSAPSS: u16 = 0x0016;
    pub const ECDSA: u16 = 0x0018;
    /// `TPM_ECC_NIST_P256`.
    pub const CURVE_P256: u16 = 0x0003;
}

/// A running filter. Dropping it stops the thread and removes the socket.
#[derive(Debug)]
pub struct TpmFilter {
    socket: PathBuf,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl TpmFilter {
    /// Listens on `socket` and forwards to the `swtpm` data socket `upstream`.
    ///
    /// # Errors
    /// The socket cannot be created.
    pub fn start(upstream: &Path, socket: &Path, lacks: Lacks) -> io::Result<Self> {
        let ctrl_path = ctrl_of(socket);
        for stale in [socket, ctrl_path.as_path()] {
            let _ = std::fs::remove_file(stale);
        }
        let listener = UnixListener::bind(socket)?;
        listener.set_nonblocking(true)?;
        let ctrl = UnixListener::bind(&ctrl_path)?;
        ctrl.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let (flag, up) = (stop.clone(), upstream.to_owned());
        let up_ctrl = ctrl_of(upstream);
        // The TCTI also opens `<path>.ctrl`; its bytes go through untouched. Its own thread: the command loop blocks.
        let ctrl_flag = stop.clone();
        let ctrl_thread = thread::spawn(move || {
            while !ctrl_flag.load(Ordering::SeqCst) {
                match ctrl.accept() {
                    Ok((client, _)) => {
                        let _ = pump(client, &up_ctrl);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        let thread = thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((client, _)) => {
                        let _ = client.set_nonblocking(false);
                        // A failed connection ends that client only.
                        let _ = serve(&client, &up, &lacks);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            socket: socket.to_owned(),
            stop,
            threads: vec![thread, ctrl_thread],
        })
    }

    /// The TCTI string for `tss-esapi` and `tpm2-tools`.
    #[must_use]
    pub fn tcti(&self) -> String {
        format!("swtpm:path={}", self.socket.display())
    }
}

impl Drop for TpmFilter {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        for path in [self.socket.clone(), ctrl_of(&self.socket)] {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn ctrl_of(socket: &Path) -> PathBuf {
    let mut name = socket.as_os_str().to_owned();
    name.push(".ctrl");
    PathBuf::from(name)
}

/// Copies both directions between a client and the upstream control socket until either side closes.
fn pump(client: UnixStream, upstream: &Path) -> io::Result<()> {
    client.set_nonblocking(false)?;
    let up = UnixStream::connect(upstream)?;
    for (mut from, mut to) in [(client.try_clone()?, up.try_clone()?), (up, client)] {
        thread::spawn(move || {
            let _ = io::copy(&mut from, &mut to);
            let _ = to.shutdown(std::net::Shutdown::Both);
        });
    }
    Ok(())
}

/// One TPM message: the 10-byte header (tag, size, code) and the rest, as the size field says.
fn read_message(s: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 10];
    s.read_exact(&mut header)?;
    let size = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
    let mut message = header.to_vec();
    message.resize(size.max(10), 0);
    s.read_exact(&mut message[10..])?;
    Ok(message)
}

fn serve(client: &UnixStream, upstream: &Path, lacks: &Lacks) -> io::Result<()> {
    let mut up = UnixStream::connect(upstream)?;
    let (mut c_in, mut c_out) = (client, client);
    loop {
        let Ok(command) = read_message(&mut c_in) else {
            return Ok(());
        };
        let response = if let Some(rc) = refuse(&command, lacks) {
            error_response(rc)
        } else {
            up.write_all(&command)?;
            rewrite(&command, read_message(&mut up)?, lacks)
        };
        c_out.write_all(&response)?;
    }
}

fn error_response(rc: u32) -> Vec<u8> {
    let mut v = vec![0x80, 0x01, 0, 0, 0, 10];
    v.extend(rc.to_be_bytes());
    v
}

/// Big-endian reader over a command; any short read ends the inspection (the command then passes through).
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn u16(&mut self) -> Option<u16> {
        let b = self.data.get(self.pos..self.pos + 2)?;
        self.pos += 2;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        let b = self.data.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        (self.pos + n <= self.data.len()).then(|| self.pos += n)
    }
}

/// A `TPMT_*_SCHEME`: algorithm, then a hash unless it is null.
fn scheme(c: &mut Cursor) -> Option<(u16, Option<u16>)> {
    let a = c.u16()?;
    if a == ALG_NULL {
        return Some((a, None));
    }
    Some((a, Some(c.u16()?)))
}

/// The response code for the first lacking item of `TPM2_TestParms`, `TPM2_Sign` or `TPM2_RSA_Decrypt`, if any.
fn refuse(command: &[u8], lacks: &Lacks) -> Option<u32> {
    let mut c = Cursor {
        data: command,
        pos: 6,
    };
    let cc = c.u32()?;
    let has = |a: u16| lacks.algorithms.contains(&a);
    let scheme_rc = |s: (u16, Option<u16>), parameter: u32| {
        if has(s.0) && s.0 != ALG_NULL {
            Some(param_error(RC_SCHEME, parameter))
        } else if s.1.is_some_and(has) {
            Some(param_error(RC_HASH, parameter))
        } else {
            None
        }
    };
    match cc {
        CC_TEST_PARMS => {
            let kind = c.u16()?;
            if has(kind) {
                return Some(param_error(RC_TYPE, 1));
            }
            let sym = c.u16()?;
            if sym != ALG_NULL {
                if has(sym) {
                    return Some(param_error(RC_TYPE, 1));
                }
                c.skip(4)?; // key bits and mode
            }
            let s = scheme(&mut c)?;
            if let Some(rc) = scheme_rc(s, 1) {
                return Some(rc);
            }
            match kind {
                ALG_ECC => lacks
                    .curves
                    .contains(&c.u16()?)
                    .then(|| param_error(RC_CURVE, 1)),
                _ => None,
            }
        }
        CC_SIGN | CC_RSA_DECRYPT => {
            c.skip(4)?; // the key handle
            let auth = c.u32()? as usize;
            c.skip(auth)?;
            let first = usize::from(c.u16()?); // digest or cipher text
            c.skip(first)?;
            scheme_rc(scheme(&mut c)?, 2)
        }
        _ => None,
    }
}

/// Removes the lacking entries from a `TPM2_GetCapability` answer.
fn rewrite(command: &[u8], response: Vec<u8>, lacks: &Lacks) -> Vec<u8> {
    let mut c = Cursor {
        data: command,
        pos: 6,
    };
    if c.u32() != Some(CC_GET_CAPABILITY) {
        return response;
    }
    let (Some(cap), Some(rc)) = (c.u32(), response.get(6..10)) else {
        return response;
    };
    if rc != [0, 0, 0, 0] || response.len() < 19 {
        return response;
    }
    let (entry, lacking): (usize, &[u16]) = match cap {
        CAP_ALGS => (6, &lacks.algorithms),
        CAP_ECC_CURVES => (2, &lacks.curves),
        _ => return response,
    };
    // header 10, moreData 1, capability 4, count 4, then the entries.
    let body = &response[19..];
    let kept: Vec<u8> = body
        .chunks_exact(entry)
        .filter(|e| !lacking.contains(&u16::from_be_bytes([e[0], e[1]])))
        .flatten()
        .copied()
        .collect();
    let count = u32::try_from(kept.len() / entry).unwrap_or(0);
    let mut out = response[..15].to_vec();
    out.extend(count.to_be_bytes());
    out.extend(kept);
    let size = u32::try_from(out.len()).unwrap_or(0);
    out[2..6].copy_from_slice(&size.to_be_bytes());
    out
}

#[cfg(test)]
mod tests;
