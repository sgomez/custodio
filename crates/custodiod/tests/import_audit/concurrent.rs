//! Two imports of one id at once: one key, one success entry, one failure entry.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::Poll;

use custodio_client::ERROR_KEY_ID_TAKEN;
use custodiod::audit::{AuditKeyType, MemorySink};
use custodiod::credentials::BusCredentials;
use custodiod::import::{ImportError, P12Decoder, ParsedP12, RealDecoder};
use secrecy::SecretString;
use zbus::{Connection, block_on};

use super::bus::{Answer, Fixture, TestResult, call, error_name};
use super::common::{EC_P12, PASSWORD, uid};

/// The real decoder, counting nothing: here to keep the trait in use for the concurrent test.
struct Plain;

impl P12Decoder for Plain {
    fn decode(&self, data: &[u8], password: &SecretString) -> Result<ParsedP12, ImportError> {
        RealDecoder.decode(data, password)
    }
}

#[test]
fn concurrent_imports_leave_one_key_one_success() -> TestResult {
    block_on(async {
        let sink = Arc::new(MemorySink::default());
        let f = Fixture::start_with(
            Answer::Yes,
            |c: &Connection| BusCredentials::new(c.clone()),
            sink.clone(),
            Some(Arc::new(Plain)),
        )
        .await?;
        let second = f.bus.connect().await?;
        for round in 0..20_usize {
            let id = format!("r{round}");
            // The double answers when both calls of this round have asked, so both are past the own-id
            // check and polkit before either one stores. A server that handles calls one at a time
            // never gets two requests: the double gives up after its limit and the asserts fail.
            f.hold.store(2 * (round + 1), Ordering::SeqCst);
            // Both calls are polled by this one task: the connections are driven by the thread that
            // waits, so it must not be blocked.
            let (a, b) = join2(call_import(&f.client, &id), call_import(&second, &id)).await;
            assert_eq!(f.asked().len(), 2 * (round + 1), "round {round}");
            let (ok, err): (Vec<_>, Vec<_>) = [a, b].into_iter().partition(Result::is_ok);
            assert_eq!(ok.len(), 1, "round {round}: one success");
            assert_eq!(
                err,
                [Err(ERROR_KEY_ID_TAKEN.to_owned())],
                "round {round}: one KeyIdTaken"
            );
            assert!(f.store.list(uid())?.contains(&id));
            let mut outcomes: Vec<(&str, Option<AuditKeyType>)> = sink
                .operation_entries()
                .iter()
                .filter(|e| e.key_id().as_str() == id)
                .map(|e| (e.outcome_name(), e.key_type()))
                .collect();
            outcomes.sort_by_key(|o| o.0);
            let ec = Some(AuditKeyType::EcdsaP256);
            assert_eq!(
                outcomes,
                [("storage_failure", ec), ("stored", ec)],
                "round {round}"
            );
            assert_eq!(sink.operation_entries().len(), 2 * (round + 1));
        }
        // 20 ids, each one record; nothing doubled.
        assert_eq!(f.store.list(uid())?.len(), 20);
        Ok(())
    })
}

/// Polls both futures from one task until both are done.
async fn join2<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
    let (mut a, mut b) = (Box::pin(a), Box::pin(b));
    let (mut done_a, mut done_b) = (None, None);
    std::future::poll_fn(|cx| {
        if done_a.is_none()
            && let Poll::Ready(v) = a.as_mut().poll(cx)
        {
            done_a = Some(v);
        }
        if done_b.is_none()
            && let Poll::Ready(v) = b.as_mut().poll(cx)
        {
            done_b = Some(v);
        }
        match (done_a.take(), done_b.take()) {
            (Some(x), Some(y)) => Poll::Ready((x, y)),
            (x, y) => {
                done_a = x;
                done_b = y;
                Poll::Pending
            }
        }
    })
    .await
}

async fn call_import(client: &Connection, id: &str) -> Result<String, String> {
    let reply = call(client, "ImportP12", &(id, EC_P12.to_vec(), PASSWORD))
        .await
        .map_err(|e| error_name(&e))?;
    reply.body().deserialize().map_err(|e| e.to_string())
}
