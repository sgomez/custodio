//! A sink that cannot record withholds the reply, whatever the outcome.

use std::sync::Arc;

use custodiod::audit::{FailingSink, JournalSink, MemorySink};
use custodiod::credentials::BusCredentials;
use zbus::{Connection, block_on};

use super::bus::{Answer, Fixture, TestResult, call, error_name};
use super::common::*;
use super::scan;
use super::{bus::sign, failed};

#[test]
fn failing_sink_withholds_the_signature() -> TestResult {
    block_on(async {
        let sink = Arc::new(MemorySink::default());
        let f = fixture(Answer::Yes, &sink).await?;
        import(&f, "rsa", RSA_P12).await?;
        let data = digest_info();
        let signature = sign(&f.client, "rsa", CKM_RSA_PKCS, &data).await?;

        let failing = Fixture::start(
            Answer::Yes,
            |c: &Connection| BusCredentials::new(c.clone()),
            Arc::new(FailingSink),
        )
        .await?;
        import(&failing, "rsa", RSA_P12).await?;
        let reply = call(
            &failing.client,
            "Sign",
            &("rsa", CKM_RSA_PKCS, 0u32, 0u32, data.clone()),
        )
        .await;
        let err = reply.err().ok_or("a reply came back")?;
        assert_eq!(error_name(&err), ERR_AUDIT);
        let text = format!("{err:?} {err}");
        assert!(text.contains("audit unavailable"));
        for value in [&signature, &data] {
            assert_eq!(scan::leaks(text.as_bytes(), value), Vec::<&str>::new());
        }
        Ok(())
    })
}

#[test]
fn failing_sink_fails_every_outcome() -> TestResult {
    block_on(async {
        for answer in [Answer::Yes, Answer::No, Answer::Fail] {
            let f = Fixture::start(
                answer,
                |c: &Connection| BusCredentials::new(c.clone()),
                Arc::new(FailingSink),
            )
            .await?;
            import(&f, "ec", EC_P12).await?;
            for (id, mechanism) in [("ec", CKM_ECDSA), ("ec", CKM_RSA_PKCS)] {
                let err = failed(sign(&f.client, id, mechanism, &digest()).await)?;
                assert!(format!("{err}").contains("audit unavailable"), "{err}");
            }
            // No entry is written for a missing key, so the sink is never asked.
            let err = failed(sign(&f.client, "gone", CKM_ECDSA, &digest()).await)?;
            assert_eq!(error_name(&err), custodio_client::ERROR_NO_SUCH_KEY);
        }
        let f = Fixture::start(
            Answer::Yes,
            |_: &Connection| NoCredentials,
            Arc::new(FailingSink),
        )
        .await?;
        import(&f, "ec", EC_P12).await?;
        let err = failed(sign(&f.client, "ec", CKM_ECDSA, &digest()).await)?;
        assert!(format!("{err}").contains("audit unavailable"), "{err}");
        Ok(())
    })
}

#[test]
fn missing_journal_socket_withholds_the_signature() -> TestResult {
    block_on(async {
        let dir = tempfile::tempdir()?;
        let sink = Arc::new(JournalSink::new(dir.path().join("none.sock")));
        let f = Fixture::start(
            Answer::Yes,
            |c: &Connection| BusCredentials::new(c.clone()),
            sink,
        )
        .await?;
        import(&f, "ec", EC_P12).await?;
        let err = failed(sign(&f.client, "ec", CKM_ECDSA, &digest()).await)?;
        assert!(format!("{err}").contains("audit unavailable"));
        Ok(())
    })
}
