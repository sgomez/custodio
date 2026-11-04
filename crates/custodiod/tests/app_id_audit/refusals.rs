//! A call that leaves no entry makes no source call.

use super::*;

#[test]
fn app_id_not_asked_for_refusals() -> TestResult {
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
            // A key of another user, and one that does not exist.
            custodiod::import::import_p12(
                &f.store,
                &custodiod::creds::memory::MemoryCreds::host(),
                uid() + 1,
                "foreign",
                RSA_P12,
                &secrecy::SecretString::from(PASSWORD.to_owned()),
            )?;
            let call_with = |id: &'static str| {
                let c = &f.client;
                async move {
                    match op {
                        Operation::Sign => {
                            sign(c, id, CKM_RSA_PKCS, &digest_info()).await.map(|_| ())
                        }
                        Operation::Import => {
                            call(c, "ImportP12", &(id, RSA_P12.to_vec(), PASSWORD))
                                .await
                                .map(|_| ())
                        }
                        Operation::Delete => call(c, "DeleteKey", &(id,)).await.map(|_| ()),
                        Operation::ReplaceCertificate => {
                            call(c, "ReplaceCertificate", &(id, NEW.to_vec()))
                                .await
                                .map(|_| ())
                        }
                    }
                    .map_err(|e| error_name(&e))
                }
            };
            let mut refused = vec![("not a valid id!", "InvalidArgs")];
            if op == Operation::Import {
                // The caller's own id is taken.
                put_rsa(&f, "taken")?;
                refused.push(("taken", "KeyIdTaken"));
            } else {
                refused.push(("missing", "NoSuchKey"));
                refused.push(("foreign", "NoSuchKey"));
            }
            for (id, want) in refused {
                let got = call_with(id).await.err().ok_or("it worked")?;
                assert!(got.ends_with(want), "{op:?} {id}: {got}");
            }
            assert!(sink.fields().is_empty(), "{op:?}");
            assert!(probe.calls().is_empty(), "{op:?}");
            assert_eq!(f.asked(), Vec::<String>::new());
        }
        Ok(())
    })
}

#[test]
fn app_id_not_asked_for_a_pending_delete_id() -> TestResult {
    use std::sync::mpsc::channel;
    use std::time::Duration;
    use zbus::block_on;
    let sink = Arc::new(Sink::default());
    let probe = Probe::new(AppIdOutcome::None);
    let source = Some(GuardedSource::new(probe.clone()));
    let f = block_on(start(Operation::Delete, Answer::Yes, &sink, source))?;
    let (entered_tx, entered) = channel();
    let (release_tx, release) = channel();
    *sink.gate.lock().unwrap_or_else(PoisonError::into_inner) = Some(Gate {
        entered: entered_tx,
        release,
    });
    let client = f.client.clone();
    let deleting =
        std::thread::spawn(move || block_on(call(&client, "DeleteKey", &("k",))).map(|_| ()));
    entered.recv_timeout(Duration::from_secs(5))?;
    // The delete's entry is held: the key is unusable, and its lookup has happened once.
    let entries = sink.fields().len();
    let asks = f.asked().len();
    assert_eq!((entries, probe.calls().len()), (1, 1));
    let other = block_on(f.bus.connect())?;
    let digest = digest_info();
    let replies = [
        (
            "Sign",
            block_on(sign(&other, "k", CKM_RSA_PKCS, &digest)).map(|_| ()),
        ),
        (
            "ReplaceCertificate",
            block_on(call(&other, "ReplaceCertificate", &("k", NEW.to_vec()))).map(|_| ()),
        ),
        (
            "DeleteKey",
            block_on(call(&other, "DeleteKey", &("k",))).map(|_| ()),
        ),
    ];
    for (what, reply) in replies {
        let got = reply.err().map(|e| error_name(&e));
        assert!(
            got.as_ref().is_some_and(|n| n.ends_with("NoSuchKey")),
            "{what}: {got:?}"
        );
    }
    assert_eq!(sink.fields().len(), entries, "no new entry");
    assert_eq!(probe.calls().len(), 1, "no new source call");
    assert_eq!(f.asked().len(), asks, "no new polkit ask");
    release_tx.send(())?;
    deleting
        .join()
        .map_err(|_| "panic")?
        .map_err(|e| error_name(&e))?;
    Ok(())
}
