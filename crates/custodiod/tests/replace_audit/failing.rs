//! Failing sink: the old certificate stays, the restore may fail, the store comes before the entry.

use super::*;

#[test]
fn replace_failing_sink_keeps_the_old_certificate() -> TestResult {
    block_on(async {
        let public = rsa_public()?;
        for (answer, cert, make, _, outcome) in cases() {
            if !matches!(make, Make::Plain) {
                // Store failures are covered below with the files they leave.
                continue;
            }
            let (f, sink) = start(answer).await?;
            put_rsa(&f, "k")?;
            let before = snapshot(&area(&f))?;
            let old = listed_cert(&f.client, "k").await?;
            sink.failing(true);
            assert_eq!(
                replace(&f.client, "k", cert).await,
                Err(ERROR_AUDIT_UNAVAILABLE.to_owned()),
                "{outcome}"
            );
            assert_eq!(sink.attempts(), 1, "{outcome}");
            assert_eq!(sink.inner.operation_entries().len(), 0, "{outcome}");
            assert_eq!(snapshot(&area(&f))?, before, "{outcome}");
            assert_eq!(listed_cert(&f.client, "k").await?, old, "{outcome}");
            f.set_answer(Answer::Yes);
            verifies(&public, &sign_rsa(&f.client, "k").await?)?;
            // Later, with a working sink, a replace succeeds with its own one entry.
            sink.failing(false);
            replace(&f.client, "k", NEWER).await?;
            assert_eq!(listed_cert(&f.client, "k").await?, NEWER, "{outcome}");
            assert_eq!(sink.inner.operation_entries().len(), 1, "{outcome}");
            assert_eq!(sink.replaced(), 1, "{outcome}");
        }
        if !running_as_root() {
            // The store failed after approval and the entry fails too: the audit error wins.
            let (f, sink) = start(Answer::Yes).await?;
            put_rsa(&f, "k")?;
            let dir = area(&f);
            f.on_request(move || {
                let _ = set_mode(&dir, 0o500);
            });
            sink.failing(true);
            assert_eq!(
                replace(&f.client, "k", NEW).await,
                Err(ERROR_AUDIT_UNAVAILABLE.to_owned())
            );
            set_mode(&area(&f), 0o700)?;
            assert_eq!(sink.attempts(), 1);
        }
        Ok(())
    })
}

#[test]
fn replace_restore_failure_still_reports_audit_unavailable() -> TestResult {
    if running_as_root() {
        eprintln!("skipped: needs a user that mode bits bind");
        return Ok(());
    }
    block_on(async {
        // The sink refuses; when it does, the area is made read-only, so the temporary file of the
        // restore cannot be written. Control: the same refusal without that sabotage restores the
        // old certificate, so the restore does run, and the difference below is the sabotage.
        for sabotage in [false, true] {
            let (f, sink) = start(Answer::Yes).await?;
            put_rsa(&f, "k")?;
            let old = fs::read(cert_path(&f, "k"))?;
            let dir = area(&f);
            if sabotage {
                sink.on_fail(move || {
                    let _ = set_mode(&dir, 0o500);
                });
            }
            sink.failing(true);
            assert_eq!(
                replace(&f.client, "k", NEW).await,
                Err(ERROR_AUDIT_UNAVAILABLE.to_owned()),
                "sabotage={sabotage}"
            );
            set_mode(&area(&f), 0o700)?;
            let on_disk = fs::read(cert_path(&f, "k"))?;
            if sabotage {
                assert_eq!(on_disk, NEW, "the store refused the restore");
            } else {
                assert_eq!(on_disk, old, "the restore ran");
            }
            assert_eq!(sink.inner.operation_entries().len(), 0);
            assert_eq!(sink.attempts(), 1);
            assert_eq!(f.asked().len(), 1);
        }
        Ok(())
    })
}

#[test]
fn replace_stores_before_it_submits() -> TestResult {
    block_on(async {
        let (f, sink) = start(Answer::Yes).await?;
        put_rsa(&f, "k")?;
        sink.watch(cert_path(&f, "k"));
        replace(&f.client, "k", NEW).await?;
        assert_eq!(sink.watched(), [Some(NEW.to_vec())]);
        // The same when the entry is refused: the sink saw the new certificate, then it was undone.
        sink.failing(true);
        let old = fs::read(cert_path(&f, "k"))?;
        assert_eq!(
            replace(&f.client, "k", NEWER).await,
            Err(ERROR_AUDIT_UNAVAILABLE.to_owned())
        );
        assert_eq!(sink.watched().last(), Some(&Some(NEWER.to_vec())));
        assert_eq!(fs::read(cert_path(&f, "k"))?, old);
        Ok(())
    })
}
