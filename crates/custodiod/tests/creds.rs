//! Encrypted key storage with the real `systemd-creds` through the user-scope daemon (Varlink). No
//! fake of the tool; the failures the real thing cannot show on demand are injected through the
//! access point. The daemon cannot reach a `swtpm`, so TPM-bound and PCR-bound headers are built here
//! from the layout of `docs/findings/F153.md`, and the null key is made by the root command as a test tool.

#[path = "creds/env.rs"]
mod env;

use std::io::Write;
use std::process::{Command, Stdio};

use custodiod::creds::systemd::SystemdCreds;
use custodiod::creds::{
    Binding, Credentials, CredsError, HeaderError, Sealed, header, seal, with_key,
};
use secrecy::{ExposeSecret, SecretSlice};
use zeroize::ZeroizeOnDrop;

use env::{Daemon, TestResult, files_holding, varlink_as_uid};

const KEY: &[u8] = b"CREDS-TEST-KEY-0123456789abcdef";
/// The key id of a credential encrypted with the host key and the uid.
const HOST_SCOPED_ID: [u8; 16] = [
    0x55, 0xb9, 0xed, 0x1d, 0x38, 0x59, 0x4d, 0x43, 0xa8, 0x31, 0x9d, 0x2e, 0xbb, 0x33, 0x2a, 0xc6,
];

fn secret(bytes: &[u8]) -> SecretSlice<u8> {
    SecretSlice::new(Box::from(bytes))
}

fn host_client(daemon: &Daemon) -> SystemdCreds {
    SystemdCreds::new(daemon.socket.clone())
}

/// A header of a TPM-bound credential as F153 lays it out: a key id that is none of the host, scoped
/// host or null ids, filler up to byte 48, then the PCR mask as a little-endian `u64`, then filler.
fn tpm_header(mask: u64) -> Vec<u8> {
    let mut credential = vec![0x42u8; 48];
    credential.extend_from_slice(&mask.to_le_bytes());
    credential.extend_from_slice(&[0; 32]);
    credential
}

/// The first 16 bytes: the key id.
fn id_of(credential: &[u8]) -> &[u8] {
    credential.get(..16).unwrap_or_default()
}

/// Raw bytes of a credential that `systemd-creds` printed in base64.
fn raw(base64: &[u8]) -> TestResult<Vec<u8>> {
    let mut child = Command::new("base64")
        .arg("-d")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    child.stdin.take().ok_or("no stdin")?.write_all(base64)?;
    let out = child.wait_with_output()?;
    assert!(out.status.success());
    Ok(out.stdout)
}

#[test]
fn host_bound_round_trip() -> TestResult {
    let daemon = Daemon::start()?;
    let client = host_client(&daemon);
    let sealed = seal(&client, "k", &secret(KEY))?;
    assert_eq!(sealed.binding(), Binding::Host);
    assert_eq!(
        id_of(sealed.credential()),
        HOST_SCOPED_ID,
        "the scoped host id"
    );
    assert_eq!(
        client.decrypt("k", sealed.credential())?.expose_secret(),
        KEY
    );
    // The same bytes under another name do not open (the name is part of the credential).
    assert_eq!(
        client.decrypt("other", sealed.credential()).err(),
        Some(CredsError::CannotDecrypt)
    );
    // Another uid of the namespace: the control opens its own, not the service's. The daemon resolves
    // the uid through the host's passwd, and uid 1 is in every one.
    let blob = raw_blob_json(&sealed)?;
    let (opened, text) = varlink_as_uid(1, &daemon.socket, "Decrypt", &blob)?;
    assert!(!opened && text.contains("BadFormat"), "{text}");
    let (ok, text) = varlink_as_uid(
        1,
        &daemon.socket,
        "Encrypt",
        r#"{"name":"k","data":"TUFSSw==","scope":"user"}"#,
    )?;
    assert!(ok, "control: uid 1 can use the daemon: {text}");
    Ok(())
}

/// base64 of `bytes` by the `base64` tool, not by the code under test.
fn base64_of(bytes: &[u8]) -> TestResult<String> {
    let mut child = Command::new("base64")
        .arg("-w0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    child.stdin.take().ok_or("no stdin")?.write_all(bytes)?;
    Ok(String::from_utf8(child.wait_with_output()?.stdout)?)
}

fn raw_blob_json(sealed: &Sealed) -> TestResult<String> {
    Ok(format!(
        r#"{{"name":"k","blob":"{}","scope":"user"}}"#,
        base64_of(sealed.credential())?
    ))
}

#[test]
fn credential_names_no_pcr() -> TestResult {
    let daemon = Daemon::start()?;
    // A TPM header with an empty mask is a TPM binding; the real host credential is a host binding.
    assert_eq!(header::inspect(&tpm_header(0)), Ok(Binding::Tpm));
    let on_host = seal(&host_client(&daemon), "k", &secret(KEY))?;
    assert_eq!(header::inspect(on_host.credential()), Ok(Binding::Host));
    Ok(())
}

#[test]
fn pcr_guard_refuses() -> TestResult {
    let daemon = Daemon::start()?;
    // A header that names PCR 7 is refused; the same header with an empty mask is accepted.
    assert_eq!(
        header::inspect(&tpm_header(1 << 7)),
        Err(HeaderError::PcrBound(1 << 7))
    );
    assert_eq!(header::inspect(&tpm_header(0)), Ok(Binding::Tpm));
    // The null key is not encryption (made by the root command, as a test tool).
    let mut child = Command::new(daemon.wrapper())
        .args(["encrypt", "--name=k", "--with-key=null", "-", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    child.stdin.take().ok_or("no stdin")?.write_all(KEY)?;
    let out = child.wait_with_output()?;
    assert!(out.status.success());
    assert_eq!(
        header::inspect(&raw(&out.stdout)?),
        Err(HeaderError::NullKey)
    );
    Ok(())
}

/// A client that returns what the test gives it, to see what `seal` does with a real header.
struct Fixed(Vec<u8>);

impl Credentials for Fixed {
    fn encrypt(&self, _: &str, _: &SecretSlice<u8>) -> Result<Vec<u8>, CredsError> {
        Ok(self.0.clone())
    }
    fn decrypt(&self, _: &str, _: &[u8]) -> Result<SecretSlice<u8>, CredsError> {
        Err(CredsError::CannotDecrypt)
    }
}

#[test]
fn seal_refuses_a_pcr_bound_credential() {
    assert_eq!(
        seal(&Fixed(tpm_header(1 << 7)), "k", &secret(KEY)),
        Err(CredsError::Refused(HeaderError::PcrBound(1 << 7)))
    );
}

#[test]
fn no_plaintext_outside_memory() -> TestResult {
    // Made at run time: a log or a transcript that holds this source must not hold the marker.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let marker_text = format!("nofile-{}-{nanos:x}-plaintext", std::process::id());
    let marker: &[u8] = marker_text.as_bytes();
    let marker_b64 = base64_of(marker)?.into_bytes();
    let daemon = Daemon::start()?;
    let on_host = seal(&host_client(&daemon), "k", &secret(marker))?;
    // The command's arguments and environment, as recorded by the wrapper before it ran the tool.
    let calls = daemon.calls_log();
    assert!(
        !calls.contains(&marker_text) && !calls.contains(&String::from_utf8(marker_b64.clone())?)
    );
    // No file anywhere it could have been left, and not in what came back.
    let cwd = std::env::current_dir()?;
    let roots = [
        std::path::Path::new("/tmp"),
        std::path::Path::new("/var/tmp"),
        daemon.dir.path(),
        cwd.as_path(),
    ];
    let found = files_holding(&roots, &[marker, &marker_b64]);
    // The test's own source and binary hold the literal; a leftover file would be somewhere else.
    let leaked: Vec<_> = found
        .iter()
        .filter(|p| !p.starts_with(cwd.join("tests")))
        .collect();
    assert!(leaked.is_empty(), "plaintext in {leaked:?}");
    // Control: the search does find a file that holds the marker.
    std::fs::write(daemon.dir.path().join("control"), marker)?;
    assert_eq!(files_holding(&[daemon.dir.path()], &[marker]).len(), 1);
    assert!(
        !on_host
            .credential()
            .windows(marker.len())
            .any(|w| w == marker)
    );
    Ok(())
}

#[test]
fn decrypt_returns_secret() -> TestResult {
    fn zeroizes<T: ZeroizeOnDrop>(_: &T) {}
    let daemon = Daemon::start()?;
    let client = host_client(&daemon);
    let sealed = seal(&client, "k", &secret(KEY))?;
    let key = client.decrypt("k", sealed.credential())?;
    zeroizes(&key);
    assert!(!format!("{key:?}").contains("CREDS-TEST"));
    assert_eq!(
        with_key(&client, "k", sealed.credential(), <[u8]>::to_vec)?,
        KEY
    );
    Ok(())
}

#[test]
fn host_key_changed_cannot_decrypt() -> TestResult {
    let daemon = Daemon::start()?;
    let client = host_client(&daemon);
    let sealed = seal(&client, "k", &secret(KEY))?;
    assert_eq!(
        client.decrypt("k", sealed.credential())?.expose_secret(),
        KEY
    );
    daemon.replace_host_secret()?;
    assert_eq!(
        client.decrypt("k", sealed.credential()).err(),
        Some(CredsError::CannotDecrypt)
    );
    Ok(())
}

#[test]
fn unavailable_vs_cannot_decrypt() -> TestResult {
    let daemon = Daemon::start()?;
    let client = host_client(&daemon);
    let sealed = seal(&client, "k", &secret(KEY))?;
    // (d) a corrupted credential, header kept: the daemon says BadFormat.
    let mut corrupted = sealed.credential().to_vec();
    *corrupted.last_mut().ok_or("empty")? ^= 0xFF;
    assert_eq!(
        client.decrypt("k", &corrupted).err(),
        Some(CredsError::CannotDecrypt)
    );
    let truncated = sealed
        .credential()
        .get(..sealed.credential().len() - 20)
        .ok_or("short")?;
    assert_eq!(
        client.decrypt("k", truncated).err(),
        Some(CredsError::CannotDecrypt)
    );
    // (c) a reachable daemon that has no host secret cannot encrypt: unavailable, not cannot-decrypt.
    let bare = Daemon::without_host_secret()?;
    assert_eq!(
        seal(&host_client(&bare), "k", &secret(KEY)).err(),
        Some(CredsError::Unavailable)
    );
    // (a) the socket gone, for both operations.
    std::fs::remove_file(&daemon.socket)?;
    assert_eq!(
        client.encrypt("k", &secret(KEY)).err(),
        Some(CredsError::Unavailable)
    );
    assert_eq!(
        client.decrypt("k", sealed.credential()).err(),
        Some(CredsError::Unavailable)
    );
    assert_ne!(CredsError::Unavailable, CredsError::CannotDecrypt);
    assert_ne!(
        CredsError::Unavailable.to_string(),
        CredsError::CannotDecrypt.to_string()
    );
    Ok(())
}

/// A client that fails every call with one error.
struct Failing(CredsError);

impl Credentials for Failing {
    fn encrypt(&self, _: &str, _: &SecretSlice<u8>) -> Result<Vec<u8>, CredsError> {
        Err(self.0)
    }
    fn decrypt(&self, _: &str, _: &[u8]) -> Result<SecretSlice<u8>, CredsError> {
        Err(self.0)
    }
}

fn injected(error: CredsError) {
    let client = Failing(error);
    assert_eq!(seal(&client, "k", &secret(KEY)), Err(error));
    let mut called = false;
    assert_eq!(
        with_key(&client, "k", &[0; 64], |_| called = true),
        Err(error)
    );
    assert!(!called, "no key, no signature");
}

#[test]
fn injected_unavailable() {
    injected(CredsError::Unavailable);
}

#[test]
fn injected_cannot_decrypt() {
    injected(CredsError::CannotDecrypt);
}
