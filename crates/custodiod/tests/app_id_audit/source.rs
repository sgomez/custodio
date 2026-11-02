//! What the source is given, and how long it may take.

use std::time::{Duration, Instant};

use super::*;

#[test]
fn source_is_asked_with_the_callers_uid_and_pidfd() -> TestResult {
    zbus::block_on(async {
        for op in Operation::all() {
            let sink = Arc::new(Sink::default());
            let probe = Probe::new(AppIdOutcome::None);
            let f = start(
                op,
                Answer::Yes,
                &sink,
                Some(GuardedSource::new(probe.clone())),
            )
            .await?;
            drive(&f, op, Fail::No).await?;
            // Once per call, for the uid the bus named and the process it pinned.
            assert_eq!(probe.calls(), vec![(uid(), Some(std::process::id()))]);
            let all = sink.fields();
            let entry = all.first().ok_or("entry")?;
            assert_eq!(
                field(entry, "CUSTODIO_PID"),
                Some(std::process::id().to_string().as_str())
            );
        }
        Ok(())
    })
}

#[test]
fn source_gets_the_pidfd_the_credentials_checked() -> TestResult {
    use common::{Reply, pidfd};
    zbus::block_on(async {
        let mut child = std::process::Command::new("sleep").arg("30").spawn()?;
        let pid = child.id();
        let sink = Arc::new(Sink::default());
        let probe = Probe::new(AppIdOutcome::None);
        let f = Fixture::start_full(
            Answer::Yes,
            |_: &Connection| {
                Reply(
                    move |m: &mut std::collections::HashMap<String, zbus::OwnedVariant>| {
                        m.insert("ProcessID".to_owned(), zbus::OwnedVariant::from(pid));
                        if let Ok(fd) = pidfd(pid) {
                            m.insert("ProcessFD".to_owned(), fd);
                        }
                    },
                )
            },
            sink.clone(),
            None,
            Some(GuardedSource::new(probe.clone())),
        )
        .await?;
        let reply = drive(&f, Operation::Import, Fail::No).await;
        let _ = child.kill();
        let _ = child.wait();
        reply?;
        // The entry's pid and the source's pidfd are the pinned child, not the test process.
        assert_eq!(probe.calls(), vec![(uid(), Some(pid))]);
        let all = sink.fields();
        let entry = all.first().ok_or("entry")?;
        assert_eq!(field(entry, "CUSTODIO_PID"), Some(pid.to_string().as_str()));
        Ok(())
    })
}

/// Credentials that report another uid, set between calls.
struct Switch(BusCredentials, Arc<std::sync::atomic::AtomicU32>);

impl custodiod::credentials::CallerCredentials for Switch {
    async fn credentials(
        &self,
        sender: &str,
    ) -> Result<custodiod::audit::Caller, custodiod::credentials::CredentialsError> {
        self.pinned_credentials(sender).await.map(|(c, _)| c)
    }

    async fn pinned_credentials(
        &self,
        sender: &str,
    ) -> Result<
        (custodiod::audit::Caller, Option<std::os::fd::OwnedFd>),
        custodiod::credentials::CredentialsError,
    > {
        let (mut caller, fd) = self.0.pinned_credentials(sender).await?;
        caller.uid = self.1.load(Ordering::SeqCst);
        Ok((caller, fd))
    }
}

#[test]
fn each_caller_is_asked_with_their_own_uid() -> TestResult {
    zbus::block_on(async {
        let uids = Arc::new(std::sync::atomic::AtomicU32::new(uid() + 5));
        let sink = Arc::new(Sink::default());
        let probe = Probe::new(AppIdOutcome::None);
        let shared = uids.clone();
        let f = Fixture::start_full(
            Answer::Yes,
            move |c: &Connection| Switch(BusCredentials::new(c.clone()), shared),
            sink.clone(),
            None,
            Some(GuardedSource::new(probe.clone())),
        )
        .await?;
        let client = &f.client;
        let import = |id: &'static str| async move {
            let body = (id, RSA_P12.to_vec(), PASSWORD);
            call(client, "ImportP12", &body).await
        };
        import("a").await?;
        uids.store(uid() + 6, Ordering::SeqCst);
        import("b").await?;
        let seen: Vec<u32> = probe.calls().into_iter().map(|(u, _)| u).collect();
        assert_eq!(seen, vec![uid() + 5, uid() + 6]);
        Ok(())
    })
}

/// The time of one approved call of `op` with `probe`.
async fn timed(op: Operation, probe: Option<Probe>) -> Result<(Duration, Sink3), Box<dyn Error>> {
    let sink = Arc::new(Sink::default());
    let f = start(op, Answer::Yes, &sink, probe.map(GuardedSource::new)).await?;
    let begin = Instant::now();
    let reply = drive(&f, op, Fail::No).await;
    let took = begin.elapsed();
    reply?;
    Ok((took, sink.fields()))
}

type Sink3 = Vec<Vec<(&'static str, String)>>;

#[test]
fn slow_source_delays_by_no_more_than_the_bound() -> TestResult {
    zbus::block_on(async {
        let (plain, _) = timed(Operation::Delete, None).await?;
        // A fast source adds far less than the bound.
        let (fast, _) = timed(Operation::Delete, Some(Probe::new(AppIdOutcome::None))).await?;
        assert!(
            fast < plain + Duration::from_millis(700),
            "{fast:?} {plain:?}"
        );
        // A source that does not return: undetermined, the normal reply, within the deadline and a margin.
        let (release, hang) = std::sync::mpsc::channel();
        let mut slow = Probe::new(AppIdOutcome::None);
        slow.hang = Some(Arc::new(Mutex::new(hang)));
        let (took, entries) = timed(Operation::Delete, Some(slow)).await?;
        drop(release);
        let bound = custodiod::app_id_source::LOOKUP_DEADLINE;
        assert!(took < bound + plain + Duration::from_secs(2), "{took:?}");
        assert!(took >= bound.mul_f32(0.9), "{took:?}");
        assert_case(
            entries.first().map(Vec::as_slice).ok_or("entry")?,
            &AppIdOutcome::Undetermined,
        );
        // A source that panics does not take the call down.
        let mut bad = Probe::new(AppIdOutcome::None);
        bad.panics = true;
        let (_, entries) = timed(Operation::Sign, Some(bad)).await?;
        assert_case(
            entries.first().map(Vec::as_slice).ok_or("entry")?,
            &AppIdOutcome::Undetermined,
        );
        Ok(())
    })
}
