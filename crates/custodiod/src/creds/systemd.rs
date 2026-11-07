//! The real client: the Varlink interface `io.systemd.Credentials` of `systemd-creds` for the
//! host-bound credential, the `systemd-creds` command with an explicit TPM device for the TPM-bound
//! one. Both as `docs/findings/F110.md` decided: scope `user`, no `withKey`.
//!
//! The TPM is chosen from one input, the configured TPM device: none means host-bound. The
//! plaintext goes to the daemon in the Varlink request or to the child's standard input, never in
//! an argument, the environment or a file, and every buffer that holds it is zeroized.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use secrecy::{ExposeSecret, SecretSlice};
use zeroize::{Zeroize, Zeroizing};

use super::{Binding, Credentials, CredsError, header};

/// The socket of the daemon (`systemd-creds.socket`).
pub const SOCKET: &str = "/run/systemd/io.systemd.Credentials";
/// The command, found through `PATH`.
pub const PROGRAM: &str = "systemd-creds";
/// Runs the command with every descriptor above 2 closed (see [`SystemdCreds::run`]).
pub const LAUNCHER: &str = "/usr/bin/bash";
/// `bash -c`: closes every inherited descriptor above 2, then replaces itself with the command (`"$@"`). The command
/// and its arguments are never part of the script text.
const CLOSE_FDS: &str = "for f in /proc/self/fd/*; do n=${f##*/}; [ \"$n\" -gt 2 ] && eval \"exec $n>&-\"; done 2>/dev/null; exec \"$@\"";
/// What a shell exits with when it cannot run the command it was asked to `exec` (not executable, not found).
const SHELL_CANNOT_RUN: [i32; 2] = [126, 127];
/// The most a reply or the output of the command may hold.
const MAX_REPLY: usize = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The client of `systemd-creds`.
#[derive(Debug, Clone)]
pub struct SystemdCreds {
    socket: PathBuf,
    program: PathBuf,
    launcher: PathBuf,
    tpm: Option<String>,
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
    /// `tpm` is the TPM device or TCTI string (`--tpm2-device=`): with one, new credentials are bound
    /// to the TPM; without, to the host key.
    #[must_use]
    pub fn new(socket: PathBuf, program: PathBuf, tpm: Option<String>) -> Self {
        Self {
            socket,
            program,
            launcher: PathBuf::from(LAUNCHER),
            tpm,
        }
    }

    /// Starts the command through another launcher (tests: one that does not exist).
    #[must_use]
    pub fn with_launcher(mut self, launcher: PathBuf) -> Self {
        self.launcher = launcher;
        self
    }

    /// The system's socket and command.
    #[must_use]
    pub fn system(tpm: Option<String>) -> Self {
        Self::new(PathBuf::from(SOCKET), PathBuf::from(PROGRAM), tpm)
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

    /// Runs the command with `stdin`; its output on success.
    ///
    /// The child inherits no descriptor above 2. The TSS libraries open their TPM connection without close-on-exec, so a
    /// child forked while another thread of the service talks to the TPM would keep that connection open for its whole
    /// life (`docs/findings/F118.md`). The service has `forbid(unsafe_code)`, so the descriptors are not closed in the
    /// forked child (`pre_exec`): a launcher closes them before it executes the command. A launcher that is missing
    /// makes the start fail, which is [`CredsError::Unavailable`], never a signature.
    fn run(&self, args: &[OsString], stdin: &[u8]) -> Result<Zeroizing<Vec<u8>>, Failure> {
        let mut child = Command::new(&self.launcher)
            .args(["-c", CLOSE_FDS, "close-fds"])
            .arg(&self.program)
            .args(args)
            .env_remove("BASH_ENV")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| Failure::Spawn)?;
        if let Some(mut pipe) = child.stdin.take() {
            // A child that quit early shows in its exit status; the broken pipe says nothing more.
            let _ = pipe.write_all(stdin);
        }
        let mut out = Zeroizing::new(Vec::with_capacity(MAX_REPLY));
        if let Some(pipe) = child.stdout.take() {
            let limit = u64::try_from(MAX_REPLY).unwrap_or(u64::MAX);
            let _ = pipe.take(limit).read_to_end(&mut out);
        }
        match child.wait() {
            Ok(status) if status.success() => Ok(out),
            // The launcher could not execute the command: as a command that could not be started.
            Ok(status) if status.code().is_some_and(|c| SHELL_CANNOT_RUN.contains(&c)) => {
                Err(Failure::Spawn)
            }
            _ => Err(Failure::Exit),
        }
    }

    fn tpm_args(verb: &str, name: &str, device: &str) -> Vec<OsString> {
        let mut args = vec![
            OsString::from(verb),
            OsString::from(format!("--name={name}")),
        ];
        if verb == "encrypt" {
            // An empty mask is the explicit "no PCR", whatever the default of this systemd.
            args.push(OsString::from("--with-key=tpm2"));
            args.push(OsString::from("--tpm2-pcrs="));
        }
        args.push(OsString::from(format!("--tpm2-device={device}")));
        args.push(OsString::from("-"));
        args.push(OsString::from("-"));
        args
    }

    fn encrypt_cli(
        &self,
        name: &str,
        plaintext: &[u8],
        device: &str,
    ) -> Result<Vec<u8>, CredsError> {
        let args = Self::tpm_args("encrypt", name, device);
        let out = self
            .run(&args, plaintext)
            .map_err(|_| CredsError::Unavailable)?;
        base64_decode(&out).ok_or(CredsError::Unavailable)
    }

    fn decrypt_cli(
        &self,
        name: &str,
        credential: &[u8],
        device: &str,
    ) -> Result<SecretSlice<u8>, CredsError> {
        let args = Self::tpm_args("decrypt", name, device);
        let mut text = Vec::with_capacity(credential.len().div_ceil(3) * 4 + 1);
        base64_encode(&mut text, credential);
        let out = self.run(&args, &text).map_err(|failure| match failure {
            Failure::Spawn => CredsError::Unavailable,
            Failure::Exit => CredsError::CannotDecrypt,
        })?;
        Ok(secret(&out))
    }
}

/// Why the command gave no output.
#[derive(Debug, Clone, Copy)]
enum Failure {
    /// It could not be started.
    Spawn,
    /// It started and did not succeed.
    Exit,
}

impl Credentials for SystemdCreds {
    fn encrypt(&self, name: &str, plaintext: &SecretSlice<u8>) -> Result<Vec<u8>, CredsError> {
        if !valid_name(name) {
            return Err(CredsError::BadRequest);
        }
        match &self.tpm {
            None => self.encrypt_varlink(name, plaintext.expose_secret()),
            Some(device) => self.encrypt_cli(name, plaintext.expose_secret(), device),
        }
    }

    fn decrypt(&self, name: &str, credential: &[u8]) -> Result<SecretSlice<u8>, CredsError> {
        if !valid_name(name) {
            return Err(CredsError::BadRequest);
        }
        let binding = header::inspect(credential).map_err(|_| CredsError::CannotDecrypt)?;
        match (&self.tpm, binding) {
            (Some(device), Binding::Tpm) => self.decrypt_cli(name, credential, device),
            _ => self.decrypt_varlink(name, credential),
        }
    }
}

/// A credential name is put in JSON and in an argument as it is: letters, digits, `.`, `_`, `-`.
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
