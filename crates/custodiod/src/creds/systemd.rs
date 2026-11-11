//! The real client: the Varlink interface `io.systemd.Credentials` of `systemd-creds`, scope `user`,
//! no `withKey`, as `docs/findings/F110.md` decided. The user-scoped daemon binds a new credential to
//! the TPM when it finds one and to the host key otherwise; this client does not choose, and starts
//! no process.
//!
//! The plaintext goes to the daemon in the Varlink request, never in an argument, the environment
//! or a file, and every buffer that holds it is zeroized.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretSlice};
use zeroize::{Zeroize, Zeroizing};

use super::{Credentials, CredsError, header};

/// The socket of the daemon (`systemd-creds.socket`).
pub const SOCKET: &str = "/run/systemd/io.systemd.Credentials";
/// The most a reply may hold.
const MAX_REPLY: usize = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The client of `systemd-creds`.
#[derive(Debug, Clone)]
pub struct SystemdCreds {
    socket: PathBuf,
}

/// Reads until the first NUL, at most `MAX_REPLY` bytes; the NUL and what follows are dropped.
/// A read cut short by a signal is repeated.
fn read_reply(stream: &mut impl Read) -> Result<Zeroizing<Vec<u8>>, CredsError> {
    let mut reply = Zeroizing::new(Vec::with_capacity(MAX_REPLY));
    let mut chunk = Zeroizing::new([0u8; 4096]);
    // Bounded: every read takes at least a byte of the reply or is a repeated interruption.
    for _ in 0..=MAX_REPLY {
        let n = match stream.read(chunk.as_mut_slice()) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(CredsError::Unavailable),
        };
        let got = chunk.get(..n).unwrap_or_default();
        if let Some(end) = got.iter().position(|&b| b == 0) {
            reply.extend_from_slice(got.get(..end).unwrap_or_default());
            return Ok(reply);
        }
        if n == 0 || reply.len() + n > MAX_REPLY {
            return Err(CredsError::Unavailable);
        }
        reply.extend_from_slice(got);
    }
    Err(CredsError::Unavailable)
}

impl SystemdCreds {
    /// A client of the daemon listening on `socket`.
    #[must_use]
    pub fn new(socket: PathBuf) -> Self {
        Self { socket }
    }

    /// The system's socket.
    #[must_use]
    pub fn system() -> Self {
        Self::new(PathBuf::from(SOCKET))
    }

    /// One Varlink call; returns the reply line. `Err(Unavailable)` when the socket cannot be used.
    fn varlink(&self, request: &[u8]) -> Result<Zeroizing<Vec<u8>>, CredsError> {
        let mut stream = UnixStream::connect(&self.socket).map_err(|_| CredsError::Unavailable)?;
        stream
            .set_read_timeout(Some(TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(TIMEOUT)))
            .and_then(|()| stream.write_all(request))
            .map_err(|_| CredsError::Unavailable)?;
        read_reply(&mut stream)
    }

    fn encrypt_varlink(&self, name: &str, plaintext: &[u8]) -> Result<Vec<u8>, CredsError> {
        let request = request("Encrypt", name, "data", plaintext);
        let reply = self.varlink(&request)?;
        match error_name(&reply) {
            Some(b"org.varlink.service.InvalidParameter") => Err(CredsError::BadRequest),
            Some(_) => Err(CredsError::Unavailable),
            None => {
                let blob = field(&reply, "blob").ok_or(CredsError::Unavailable)?;
                base64_decode(blob).ok_or(CredsError::Unavailable)
            }
        }
    }

    fn decrypt_varlink(
        &self,
        name: &str,
        credential: &[u8],
    ) -> Result<SecretSlice<u8>, CredsError> {
        let request = request("Decrypt", name, "blob", credential);
        let mut reply = self.varlink(&request)?;
        if error_name(&reply).is_some() {
            return Err(CredsError::CannotDecrypt);
        }
        take_data(&mut reply).ok_or(CredsError::CannotDecrypt)
    }
}

impl Credentials for SystemdCreds {
    fn encrypt(&self, name: &str, plaintext: &SecretSlice<u8>) -> Result<Vec<u8>, CredsError> {
        if !valid_name(name) {
            return Err(CredsError::BadRequest);
        }
        self.encrypt_varlink(name, plaintext.expose_secret())
    }

    fn decrypt(&self, name: &str, credential: &[u8]) -> Result<SecretSlice<u8>, CredsError> {
        if !valid_name(name) {
            return Err(CredsError::BadRequest);
        }
        header::inspect(credential).map_err(|_| CredsError::CannotDecrypt)?;
        self.decrypt_varlink(name, credential)
    }
}

/// A credential name is put in JSON as it is: letters, digits, `.`, `_`, `-`.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The Varlink request line, scope `user`, `key` holding `value` in base64; ends with the NUL.
fn request(method: &str, name: &str, key: &str, value: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut line = Zeroizing::new(Vec::with_capacity(
        256 + name.len() + value.len().div_ceil(3) * 4,
    ));
    line.extend_from_slice(
        format!("{{\"method\":\"io.systemd.Credentials.{method}\",\"parameters\":{{\"name\":\"{name}\",\"{key}\":\"")
            .as_bytes(),
    );
    base64_encode(&mut line, value);
    line.extend_from_slice(b"\",\"scope\":\"user\"}}\0");
    line
}

/// The name of the error in a reply, when it is one.
fn error_name(reply: &[u8]) -> Option<&[u8]> {
    let range = value_range(reply, "error")?;
    reply.get(range)
}

/// The string value of `key` in a reply.
fn field<'a>(reply: &'a [u8], key: &str) -> Option<&'a [u8]> {
    let range = value_range(reply, key)?;
    reply.get(range)
}

fn value_range(reply: &[u8], key: &str) -> Option<std::ops::Range<usize>> {
    let needle = format!("\"{key}\":\"");
    let start = reply
        .windows(needle.len())
        .position(|w| w == needle.as_bytes())?
        + needle.len();
    let len = reply.get(start..)?.iter().position(|&b| b == b'"')?;
    Some(start..start + len)
}

/// The `data` of a `Decrypt` reply as a secret. The reply is zeroized in place.
fn take_data(reply: &mut [u8]) -> Option<SecretSlice<u8>> {
    let range = value_range(reply, "data")?;
    let plain = reply.get(range).and_then(base64_decode).map(Zeroizing::new);
    reply.zeroize();
    plain.map(|bytes| secret(&bytes))
}

/// An exact-size copy, so that turning it into a boxed slice never leaves an unzeroized copy.
fn secret(bytes: &[u8]) -> SecretSlice<u8> {
    SecretSlice::new(Box::from(bytes))
}

fn base64_encode(out: &mut Vec<u8>, data: &[u8]) {
    for chunk in data.chunks(3) {
        let at = |i: usize| chunk.get(i).copied().unwrap_or(0);
        let group = u32::from_be_bytes([0, at(0), at(1), at(2)]);
        let sextets = [group >> 18, group >> 12, group >> 6, group].map(|g| g & 63);
        for (i, s) in sextets.into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(
                    ALPHABET
                        .get(usize::try_from(s).unwrap_or(64))
                        .copied()
                        .unwrap_or(b'='),
                );
            } else {
                out.push(b'=');
            }
        }
    }
}

fn sextet(c: u8) -> Option<u8> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    })
}

/// Standard base64 with padding; white space is ignored (the command ends its output with a newline).
fn base64_decode(text: &[u8]) -> Option<Vec<u8>> {
    let signs = || text.iter().copied().filter(|c| !c.is_ascii_whitespace());
    let pad = signs().rev().take_while(|&c| c == b'=').count();
    let digits = signs().count() - pad;
    if pad > 2 || digits % 4 == 1 || (pad > 0 && (digits + pad) % 4 != 0) {
        return None;
    }
    let mut out = Vec::with_capacity(digits * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in signs().take(digits) {
        acc = (acc << 6) + u32::from(sextet(c)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from(acc >> bits & 0xff).ok()?);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests;
