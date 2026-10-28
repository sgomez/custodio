//! The entry is recorded before the reply, and a blocked sink does not stall the service.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use custodiod::audit::{AuditError, AuditSink, Entry, MemorySink};
use zbus::{Connection, block_on};

use super::bus::{Answer, Fixture, TestResult, call, sign};
use super::common::{CKM_ECDSA, EC_P12, digest, import};

/// Stores the entry, announces it, then blocks until released.
struct GateSink {
    inner: MemorySink,
    clock: Arc<AtomicUsize>,
    stamp: AtomicUsize,
    entered: Mutex<Sender<()>>,
    release: Mutex<Receiver<()>>,
}

impl AuditSink for GateSink {
    fn record(&self, entry: &Entry) -> Result<(), AuditError> {
        self.inner.record(entry)?;
        self.stamp.store(
            self.clock.fetch_add(1, Ordering::SeqCst) + 1,
            Ordering::SeqCst,
        );
        let _ = self
            .entered
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .send(());
        let _ = self
            .release
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .recv();
        Ok(())
    }
}

#[test]
fn entry_is_recorded_before_the_reply() -> TestResult {
    let clock = Arc::new(AtomicUsize::new(0));
    let (entered_tx, entered_rx) = channel();
    let (release_tx, release_rx) = channel();
    let sink = Arc::new(GateSink {
        inner: MemorySink::default(),
        clock: clock.clone(),
        stamp: AtomicUsize::new(0),
        entered: Mutex::new(entered_tx),
        release: Mutex::new(release_rx),
    });
    let f = block_on(Fixture::start(
        Answer::Yes,
        |c: &Connection| custodiod::credentials::BusCredentials::new(c.clone()),
        sink.clone(),
    ))?;
    block_on(import(&f, "ec", EC_P12))?;

    let client = f.client.clone();
    let (reply_tx, reply_rx) = channel();
    let stamp_clock = clock.clone();
    let caller = thread::spawn(move || {
        let r = block_on(sign(&client, "ec", CKM_ECDSA, &digest())).map_err(|e| e.to_string());
        let received = stamp_clock.fetch_add(1, Ordering::SeqCst) + 1;
        let _ = reply_tx.send((r, received));
    });

    entered_rx.recv_timeout(Duration::from_secs(5))?;
    assert_eq!(sink.inner.entries().len(), 1);
    assert!(matches!(
        reply_rx.recv_timeout(Duration::from_millis(200)),
        Err(RecvTimeoutError::Timeout)
    ));

    // The service is alive while `record` is blocked.
    let other = block_on(f.bus.connect())?;
    let (list_tx, list_rx) = channel();
    let lister = thread::spawn(move || {
        let _ = list_tx.send(block_on(call(&other, "ListKeys", &())).is_ok());
    });
    assert_eq!(list_rx.recv_timeout(Duration::from_secs(2)), Ok(true));
    let _ = lister.join();

    release_tx.send(())?;
    let (result, received) = reply_rx.recv_timeout(Duration::from_secs(5))?;
    assert!(result.is_ok(), "{result:?}");
    let stored = sink.stamp.load(Ordering::SeqCst);
    assert!(stored != 0 && stored < received, "{stored} < {received}");
    let _ = caller.join();
    Ok(())
}
