//! Encrypted key storage with the real `systemd-creds`: host-bound through the user-scope daemon
//! (Varlink), TPM-bound through the command with an explicit `swtpm` device. No fake of the tool; the
//! failures the real thing cannot show on demand are injected through the access point.

#[path = "creds/env.rs"]
mod env;

use std::io::Write;
use std::process::{Command, Stdio};

use custodio_it::swtpm::Swtpm;
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
    SystemdCreds::new(daemon.socket.clone(), "systemd-creds".into(), None)
}

fn tpm_client(daemon: &Daemon, tpm: &Swtpm) -> SystemdCreds {
    SystemdCreds::new(daemon.socket.clone(), daemon.wrapper(), Some(tpm.tcti()))
}

/// The mask in the header, read here and not by the code under test.
fn mask_at_48(credential: &[u8]) -> TestResult<u64> {
    let bytes: [u8; 8] = credential.get(48..56).ok_or("short")?.try_into()?;
    Ok(u64::from_le_bytes(bytes))
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

/// A credential made by the real command with these extra arguments (swtpm, root of a namespace).
fn made_with(daemon: &Daemon, tpm: &Swtpm, args: &[&str]) -> TestResult<Vec<u8>> {
    let mut child = Command::new(daemon.wrapper())
        .args(["encrypt", "--name=k"])
        .args(args)
        .arg(format!("--tpm2-device={}", tpm.tcti()))
        .args(["-", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    child.stdin.take().ok_or("no stdin")?.write_all(KEY)?;
    let out = child.wait_with_output()?;
    assert!(out.status.success(), "{args:?}");
    raw(&out.stdout)
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
    // Another uid of the namespace: the control opens its own, not the service's.
    let blob = raw_blob_json(&sealed)?;
    let (opened, text) = varlink_as_uid(42, &daemon.socket, "Decrypt", &blob)?;
    assert!(!opened && text.contains("BadFormat"), "{text}");
    let (ok, text) = varlink_as_uid(
        42,
        &daemon.socket,
        "Encrypt",
        r#"{"name":"k","data":"TUFSSw==","scope":"user"}"#,
    )?;
    assert!(ok, "control: uid 42 can use the daemon: {text}");
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
fn tpm_bound_round_trip() -> TestResult {
    let daemon = Daemon::start()?;
    let tpm = Swtpm::start()?;
    let client = tpm_client(&daemon, &tpm);
    let sealed = seal(&client, "k", &secret(KEY))?;
    assert_eq!(sealed.binding(), Binding::Tpm);
    assert_ne!(
        id_of(sealed.credential()),
        HOST_SCOPED_ID,
        "the TPM id differs from the host one"
    );
    assert_eq!(
        client.decrypt("k", sealed.credential())?.expose_secret(),
        KEY
    );
    // The decision is the configured path: the same setup with none is host-bound.
    let host = seal(&host_client(&daemon), "k", &secret(KEY))?;
    assert_eq!(host.binding(), Binding::Host);
    assert_eq!(id_of(host.credential()), HOST_SCOPED_ID);
    Ok(())
}

#[test]
fn credential_names_no_pcr() -> TestResult {
    let daemon = Daemon::start()?;
    let tpm = Swtpm::start()?;
    let on_tpm = seal(&tpm_client(&daemon, &tpm), "k", &secret(KEY))?;
    assert_eq!(mask_at_48(on_tpm.credential())?, 0);
    assert_eq!(header::inspect(on_tpm.credential()), Ok(Binding::Tpm));
    let on_host = seal(&host_client(&daemon), "k", &secret(KEY))?;
    assert_eq!(header::inspect(on_host.credential()), Ok(Binding::Host));
    Ok(())
}

#[test]
fn pcr_guard_refuses() -> TestResult {
    let daemon = Daemon::start()?;
    let tpm = Swtpm::start()?;
    // Negative control: the tool's own default or an explicit PCR 7 names a PCR, the guard sees it.
    let pcr7 = made_with(&daemon, &tpm, &["--with-key=tpm2", "--tpm2-pcrs=7"])?;
    assert_eq!(mask_at_48(&pcr7)?, 1 << 7);
    assert_eq!(header::inspect(&pcr7), Err(HeaderError::PcrBound(1 << 7)));
    // The control for the control: the empty mask is accepted by the same reader.
    let none = made_with(&daemon, &tpm, &["--with-key=tpm2", "--tpm2-pcrs="])?;
    assert_eq!(header::inspect(&none), Ok(Binding::Tpm));
    // The null key is not encryption.
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
fn seal_refuses_a_real_pcr_bound_credential() -> TestResult {
    let daemon = Daemon::start()?;
    let tpm = Swtpm::start()?;
    let pcr7 = made_with(&daemon, &tpm, &["--with-key=tpm2", "--tpm2-pcrs=7"])?;
    assert_eq!(
        seal(&Fixed(pcr7), "k", &secret(KEY)),
        Err(CredsError::Refused(HeaderError::PcrBound(1 << 7)))
    );
    Ok(())
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
    let tpm = Swtpm::start()?;
    let on_tpm = seal(&tpm_client(&daemon, &tpm), "k", &secret(marker))?;
    let on_host = seal(&host_client(&daemon), "k", &secret(marker))?;
    // The command's arguments and environment, as recorded by the wrapper before it ran the tool.
    let calls = daemon.calls_log();
    assert!(
        calls.contains("ARG --tpm2-pcrs="),
        "the wrapper recorded the call: {calls}"
    );
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
    for sealed in [&on_tpm, &on_host] {
        assert!(
            !sealed
                .credential()
                .windows(marker.len())
                .any(|w| w == marker)
        );
    }
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
fn cleared_tpm_cannot_decrypt() -> TestResult {
    let daemon = Daemon::start()?;
    let tpm = Swtpm::start()?;
    let client = tpm_client(&daemon, &tpm);
    let sealed = seal(&client, "k", &secret(KEY))?;
    assert_eq!(
        client.decrypt("k", sealed.credential())?.expose_secret(),
        KEY,
        "control: before the clear"
    );
    tpm.clear()?;
    assert_eq!(
        client.decrypt("k", sealed.credential()).err(),
        Some(CredsError::CannotDecrypt)
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
    // (b) the command missing, with a TPM configured.
    let tpm = Swtpm::start()?;
    let no_command = SystemdCreds::new(
        daemon.socket.clone(),
        "/nonexistent/systemd-creds".into(),
        Some(tpm.tcti()),
    );
    assert_eq!(
        no_command.encrypt("k", &secret(KEY)).err(),
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
