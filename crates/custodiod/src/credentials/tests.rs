use super::*;

fn own_pid() -> u32 {
    std::process::id()
}

type R = Result<(), Box<dyn std::error::Error>>;

fn fd_variant(fd: std::os::fd::OwnedFd) -> Result<OwnedVariant, Box<dyn std::error::Error>> {
    Ok(OwnedVariant::try_from(zbus::Variant::from(Fd::from(fd)))?)
}

fn pidfd_of(pid: u32) -> Result<OwnedVariant, Box<dyn std::error::Error>> {
    let pid = rustix::process::Pid::from_raw(i32::try_from(pid)?).ok_or("pid 0")?;
    fd_variant(rustix::process::pidfd_open(
        pid,
        rustix::process::PidfdFlags::empty(),
    )?)
}

fn map(uid: Option<OwnedVariant>, pid: Option<OwnedVariant>) -> HashMap<String, OwnedVariant> {
    let mut m = HashMap::new();
    if let Some(v) = uid {
        m.insert("UnixUserID".to_owned(), v);
    }
    if let Some(v) = pid {
        m.insert("ProcessID".to_owned(), v);
    }
    m
}

/// A complete map for the test process itself, then `edit`ed.
fn full(
    edit: impl FnOnce(&mut HashMap<String, OwnedVariant>),
) -> Result<HashMap<String, OwnedVariant>, Box<dyn std::error::Error>> {
    let mut m = map(Some(num(1_234_567)), Some(num(own_pid())));
    m.insert("ProcessFD".to_owned(), pidfd_of(own_pid())?);
    edit(&mut m);
    Ok(m)
}

fn num(v: u32) -> OwnedVariant {
    OwnedVariant::from(v)
}

#[test]
fn complete_map_with_real_pidfd() -> R {
    assert_eq!(
        caller_from(&full(|_| {})?),
        Ok(Caller {
            uid: 1_234_567,
            pid: own_pid()
        })
    );
    Ok(())
}

#[test]
fn missing_process_fd() -> R {
    let m = full(|m| {
        m.remove("ProcessFD");
    })?;
    assert_eq!(caller_from(&m), Err(CredentialsError::Missing));
    Ok(())
}

#[test]
fn process_fd_of_wrong_type() -> R {
    for v in [num(3), OwnedVariant::from(true)] {
        let m = full(|m| {
            m.insert("ProcessFD".to_owned(), v);
        })?;
        assert_eq!(caller_from(&m), Err(CredentialsError::Missing));
    }
    Ok(())
}

#[test]
fn pidfd_of_another_process_is_refused() -> R {
    let parent = std::os::unix::process::parent_id();
    assert_ne!(parent, own_pid());
    let other = pidfd_of(parent)?;
    let m = full(|m| {
        m.insert("ProcessFD".to_owned(), other);
    })?;
    assert_eq!(caller_from(&m), Err(CredentialsError::Missing));
    Ok(())
}

#[test]
fn process_fd_that_is_not_a_pidfd_is_refused() -> R {
    // /dev/null has no `Pid:` line in its fdinfo.
    let null = fd_variant(std::fs::File::open("/dev/null")?.into())?;
    let m = full(|m| {
        m.insert("ProcessFD".to_owned(), null);
    })?;
    assert_eq!(caller_from(&m), Err(CredentialsError::Missing));
    Ok(())
}

#[test]
fn pidfd_info_parser() {
    let ok = "pos:\t0\nflags:\t02000002\nPid:\t4242\nNSpid:\t4242\n";
    assert_eq!(check_pidfd_info(ok, 4242), Ok(()));
    assert_eq!(check_pidfd_info(ok, 4243), Err(CredentialsError::Missing));
    for bad in [
        "Pid:\t-1\n",
        "pos:\t0\nflags:\t0\n",
        "Pid:\tabc\n",
        "Pid:\t\n",
        "",
    ] {
        assert_eq!(check_pidfd_info(bad, 4242), Err(CredentialsError::Missing));
    }
    assert_eq!(check_pidfd_info("Pid:\t0\n", 0), Ok(()));
}

#[test]
fn errors_name_no_fd() {
    for e in [CredentialsError::Missing, CredentialsError::Bus] {
        let text = format!("{e} {e:?}");
        assert!(!text.chars().any(|c| c.is_ascii_digit()), "{text}");
    }
}

#[test]
fn caller_from_both_fields() -> R {
    let got = caller_from(&full(|m| {
        m.insert("UnixUserID".to_owned(), num(7_654_321));
    })?);
    assert_eq!(
        got,
        Ok(Caller {
            uid: 7_654_321,
            pid: own_pid()
        })
    );
    Ok(())
}

#[test]
fn caller_from_missing_pid() -> R {
    let m = full(|m| {
        m.remove("ProcessID");
    })?;
    assert_eq!(caller_from(&m), Err(CredentialsError::Missing));
    Ok(())
}

#[test]
fn caller_from_missing_uid() -> R {
    let m = full(|m| {
        m.remove("UnixUserID");
    })?;
    assert_eq!(caller_from(&m), Err(CredentialsError::Missing));
    Ok(())
}

#[test]
fn caller_from_wrong_types() -> R {
    for name in ["UnixUserID", "ProcessID"] {
        let m = full(|m| {
            m.insert(name.to_owned(), OwnedVariant::from(true));
        })?;
        assert_eq!(caller_from(&m), Err(CredentialsError::Missing));
    }
    Ok(())
}

#[test]
fn caller_from_empty_map() {
    assert_eq!(caller_from(&HashMap::new()), Err(CredentialsError::Missing));
}

#[test]
fn errors_display() {
    assert_eq!(
        CredentialsError::Missing.to_string(),
        "bus credentials incomplete"
    );
    assert_eq!(
        CredentialsError::Bus.to_string(),
        "bus credentials unavailable"
    );
}
