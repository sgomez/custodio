use std::time::Instant;

use super::*;

const LONG: Duration = Duration::from_secs(10);

#[test]
fn a_closed_write_end_ends_the_wait_at_once() {
    let (read, write) = notify_pipe().unwrap();
    drop(write);
    let start = Instant::now();
    wait_for_close(&read, LONG);
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn data_on_the_pipe_does_not_end_the_wait() {
    let (read, write) = notify_pipe().unwrap();
    rustix::io::write(&write, b"ready").unwrap();
    let closer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        drop(write);
    });
    let start = Instant::now();
    wait_for_close(&read, LONG);
    let waited = start.elapsed();
    closer.join().unwrap();
    assert!(
        waited >= Duration::from_millis(300),
        "returned after {waited:?}"
    );
    assert!(waited < Duration::from_secs(5), "returned after {waited:?}");
}

#[test]
fn an_open_write_end_ends_the_wait_at_the_timeout() {
    let (read, _write) = notify_pipe().unwrap();
    let start = Instant::now();
    wait_for_close(&read, Duration::from_millis(200));
    let waited = start.elapsed();
    assert!(
        waited >= Duration::from_millis(200),
        "returned after {waited:?}"
    );
    assert!(waited < Duration::from_secs(5), "returned after {waited:?}");
}

#[test]
fn a_child_that_closes_its_stdout_ends_the_wait() {
    let (read, write) = notify_pipe().unwrap();
    let mut child = Command::new("sh")
        .args(["-c", "exec 1>&-; sleep 5"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(write))
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let start = Instant::now();
    wait_for_close(&read, LONG);
    let waited = start.elapsed();
    let _ = child.kill();
    let _ = child.wait();
    assert!(waited < Duration::from_secs(2), "returned after {waited:?}");
}
