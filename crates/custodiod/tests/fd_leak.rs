//! `BusCredentials` and `caller_from` close every fd they receive or open. One test in its own
//! binary, so no parallel test opens or closes fds while the count is taken.

#[path = "audit/bus.rs"]
#[allow(
    dead_code,
    reason = "only Fixture is used; the file is shared with the audit tests"
)]
mod bus;

use std::collections::HashMap;
use std::sync::Arc;

use custodiod::audit::MemorySink;
use custodiod::credentials::{BusCredentials, CallerCredentials, CredentialsError, caller_from};
use zbus::{Connection, Fd, OwnedVariant, Variant, block_on};

use bus::{Answer, Fixture, TestResult};

fn open_fds() -> Result<usize, std::io::Error> {
    Ok(std::fs::read_dir("/proc/self/fd")?.count())
}

fn pidfd_of(pid: u32) -> Result<OwnedVariant, Box<dyn std::error::Error>> {
    let pid = rustix::process::Pid::from_raw(i32::try_from(pid)?).ok_or("pid 0")?;
    let fd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())?;
    Ok(OwnedVariant::try_from(Variant::from(Fd::from(fd)))?)
}

#[test]
fn credential_reading_leaks_no_fd() -> TestResult {
    block_on(async {
        let sink = Arc::new(MemorySink::default());
        let f = Fixture::start(
            Answer::Yes,
            |c: &Connection| BusCredentials::new(c.clone()),
            sink,
        )
        .await?;
        let creds = BusCredentials::new(f.client.clone());
        let me = f.client.unique_name().ok_or("no name")?.to_string();
        creds.credentials(&me).await?; // warm-up: connection-internal fds settle
        let parent = std::os::unix::process::parent_id();
        let refused =
            |pid: u32| -> Result<HashMap<String, OwnedVariant>, Box<dyn std::error::Error>> {
                Ok(HashMap::from([
                    ("UnixUserID".to_owned(), OwnedVariant::from(1u32)),
                    ("ProcessID".to_owned(), OwnedVariant::from(pid)),
                    ("ProcessFD".to_owned(), pidfd_of(parent)?),
                ]))
            };
        caller_from(&refused(std::process::id())?).err(); // warm-up
        let before = open_fds()?;
        for _ in 0..200 {
            assert!(creds.credentials(&me).await.is_ok());
            assert_eq!(
                caller_from(&refused(std::process::id())?),
                Err(CredentialsError::Missing)
            );
        }
        assert_eq!(open_fds()?, before);
        Ok(())
    })
}
