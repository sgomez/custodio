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
