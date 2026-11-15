use super::*;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn a_socketpair_peer_is_this_process() -> TestResult {
    let (a, _b) = UnixStream::pair()?;
    let peer = read(&a);
    assert_eq!(peer.uid, Some(std::fs::metadata("/proc/self")?.uid()));
    assert!(peer.pidfd.is_some());
    assert_eq!(peer.pid, Some(std::process::id()));
    Ok(())
}

/// The connecting side is a child (this test binary run again, told by the environment to connect and wait), so the
/// kernel records the child's pid; a socketpair would record ours.
#[test]
fn the_pid_is_the_process_holding_the_other_end() -> TestResult {
    const SOCKET_VAR: &str = "CUSTODIO_PEER_TEST_CONNECT";
    if let Some(path) = std::env::var_os(SOCKET_VAR) {
        let stream = UnixStream::connect(path)?;
        // Held until the parent kills this process.
        std::io::Read::read(&mut &stream, &mut [0u8; 1])?;
        return Ok(());
    }
    let dir = std::env::temp_dir().join(format!("custodio-peer-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("s");
    let listener = std::os::unix::net::UnixListener::bind(&path)?;
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "tests::the_pid_is_the_process_holding_the_other_end",
            "--nocapture",
        ])
        .env(SOCKET_VAR, &path)
        .spawn()?;
    let (accepted, _) = listener.accept()?;
    let peer = read(&accepted);
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(peer.pid, Some(child.id()));
    assert_ne!(peer.pid, Some(std::process::id()));
    Ok(())
}

#[test]
fn a_descriptor_that_is_no_socket_reads_nothing() -> TestResult {
    let peer = read(&File::open("/dev/null")?);
    assert!(
        peer.uid.is_none() && peer.pid.is_none() && peer.pidfd.is_none() && peer.label.is_none()
    );
    Ok(())
}

#[test]
fn debug_does_not_show_the_label() {
    let peer = Peer {
        uid: Some(1),
        pid: Some(7),
        pidfd: None,
        label: Some(b"secret-label".to_vec()),
    };
    let shown = format!("{peer:?}");
    assert!(!shown.contains("secret"));
    assert!(shown.contains("Peer") && shown.contains("uid: Some(1)"));
}

#[test]
fn the_label_is_what_the_kernel_says_and_no_longer() -> TestResult {
    let (a, _b) = UnixStream::pair()?;
    // Without a security module the read fails and there is nothing to compare; with one, a connected pair of this
    // process shows this process's own label.
    let own = std::fs::read("/proc/self/attr/current").unwrap_or_default();
    let own = own.strip_suffix(&[0]).unwrap_or(&own);
    let own = own.strip_suffix(b"\n").unwrap_or(own);
    if own.is_empty() {
        return Ok(());
    }
    assert_eq!(read(&a).label.as_deref(), Some(own));
    Ok(())
}
