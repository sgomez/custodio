use super::*;
use rustix::fs::{CWD, FileType, Mode, mknodat};
use std::sync::mpsc;

fn quick_reader(tree: &Tree, deadline: Duration, cap: usize) -> CgroupAppIdSource {
    CgroupAppIdSource::with_root(tree.root().to_path_buf(), deadline, cap)
        .with_pid_reader(Arc::new(|_| Some(PID)))
}

#[test]
fn fifo_cgroup_procs_is_undetermined_within_bound() -> TestResult {
    let tree = Tree::new()?;
    let dir = tree.slice(UID).join(FLATPAK);
    fs::create_dir(&dir)?;
    mknodat(
        CWD,
        dir.join("cgroup.procs"),
        FileType::Fifo,
        Mode::from_bits_truncate(0o644),
        0,
    )?;
    let source = quick_reader(&tree, Duration::from_secs(5), 4);
    let started = Instant::now();
    assert_eq!(lookup_of(&source, UID)?, AppIdOutcome::Undetermined);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    Ok(())
}

/// A valid pid list of exactly `len` bytes with the caller's pid on the last line.
fn procs_of(len: usize) -> Vec<u8> {
    // `len - 8` bytes of "1\n" lines (even), one line of 3 or 4 bytes, then "4242\n".
    let (pairs, odd): (usize, &[u8]) = if len.is_multiple_of(2) {
        ((len - 8) / 2, b"12\n")
    } else {
        ((len - 9) / 2, b"123\n")
    };
    let mut out = "1\n".repeat(pairs).into_bytes();
    out.extend_from_slice(odd);
    out.extend_from_slice(b"4242\n");
    assert_eq!(out.len(), len);
    out
}

#[test]
fn oversized_cgroup_procs_is_undetermined() -> TestResult {
    for (len, want) in [
        (MAX_PROCS_BYTES - 1, read("org.example.App")?),
        (MAX_PROCS_BYTES, read("org.example.App")?),
        (MAX_PROCS_BYTES + 1, AppIdOutcome::Undetermined),
        (MAX_PROCS_BYTES + 2, AppIdOutcome::Undetermined),
    ] {
        let tree = Tree::new()?;
        tree.scope_in(UID, FLATPAK, &procs_of(len))?;
        assert_eq!(lookup_of(&reader(&tree), UID)?, want, "{len}");
    }
    Ok(())
}

#[test]
fn too_many_children_is_undetermined() -> TestResult {
    for (count, want) in [
        (MAX_CHILDREN, AppIdOutcome::None),
        (MAX_CHILDREN + 1, AppIdOutcome::Undetermined),
    ] {
        let tree = Tree::new()?;
        for i in 0..count {
            fs::create_dir(tree.slice(UID).join(format!("c{i}")))?;
        }
        assert_eq!(lookup_of(&reader(&tree), UID)?, want, "{count}");
    }
    Ok(())
}

#[test]
fn blocked_reader_returns_undetermined_within_bound() -> TestResult {
    let tree = Tree::new()?;
    tree.scope(FLATPAK, "4242\n")?;
    let (tx, rx) = mpsc::channel::<()>();
    let rx = std::sync::Mutex::new(rx);
    let source =
        quick_reader(&tree, Duration::from_millis(60), 2).with_before_scan(Arc::new(move || {
            let _ = rx.lock().map(|rx| rx.recv());
        }));
    let started = Instant::now();
    assert_eq!(lookup_of(&source, UID)?, AppIdOutcome::Undetermined);
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(60) && took < Duration::from_millis(1500),
        "{took:?}"
    );
    drop(tx);
    Ok(())
}

#[test]
fn stuck_reader_cap_refuses_without_a_thread_and_recovers() -> TestResult {
    let tree = Tree::new()?;
    tree.scope(FLATPAK, "4242\n")?;
    let (tx, rx) = mpsc::channel::<()>();
    let rx = std::sync::Mutex::new(rx);
    let block = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let flag = Arc::clone(&block);
    let source =
        quick_reader(&tree, Duration::from_millis(80), 1).with_before_scan(Arc::new(move || {
            if flag.load(Ordering::SeqCst) {
                let _ = rx.lock().map(|rx| rx.recv());
            }
        }));
    assert_eq!(lookup_of(&source, UID)?, AppIdOutcome::Undetermined);
    // At the cap: refused at once, although the tree holds a valid scope and the hook no longer blocks.
    block.store(false, Ordering::SeqCst);
    let t = Instant::now();
    assert_eq!(lookup_of(&source, UID)?, AppIdOutcome::Undetermined);
    assert!(t.elapsed() < Duration::from_millis(40), "{:?}", t.elapsed());
    drop(tx);
    let until = Instant::now() + Duration::from_secs(10);
    while source.limiter.live() != 0 {
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(lookup_of(&source, UID)?, read("org.example.App")?);
    Ok(())
}
