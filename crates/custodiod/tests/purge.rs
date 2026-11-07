//! The purge of the earlier format at start-up (F121): an M3-format state, the real start-up function on a private bus
//! with fake polkit, and a journal sink the test can block or fail.

// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

// The shared helpers are used in full by other tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/bus.rs"]
mod bus;
// The shared helpers are used in full by other tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/common.rs"]
mod common;

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use custodiod::audit::{JournalSink, MemorySink, Operation};
use custodiod::startup::{PurgeError, StartError};
use custodiod::store::{KeyStore, StoreError};
use zbus::block_on;

use crate::bus::{call, error_name, sign};
use crate::common::{CKM_ECDSA, EC_P12, PASSWORD, digest, uid};

#[path = "purge/rig.rs"]
mod rig;

use rig::*;

const NO_SUCH_KEY: &str = custodio_client::ERROR_NO_SUCH_KEY;

#[test]
fn state_is_empty_after_start() -> TestResult {
    let env = Env::start(None)?;
    m3_state(&env.root())?;
    let _service = env.serve(Arc::new(MemorySink::default()))?;
    // No file of the earlier format is left; the key of the current format is untouched.
    assert_eq!(names(&env.root().join(uid().to_string()))?, ["fresh"]);
    assert_eq!(names(&env.root().join("2000"))?, Vec::<String>::new());
    assert_eq!(names(&env.root().join("3000"))?, Vec::<String>::new());
    assert_eq!(
        names(&env.root())?,
        BTreeSet::from([uid().to_string(), "2000".to_owned(), "3000".to_owned()])
            .into_iter()
            .collect::<Vec<_>>()
    );
    let store = KeyStore::open(env.root())?;
    assert!(store.get(uid(), "fresh").is_ok());
    assert_eq!(store.legacy_all()?, []);
    Ok(())
}

#[test]
fn purged_keys_are_not_listed() -> TestResult {
    let env = Env::start(None)?;
    m3_state(&env.root())?;
    let _service = env.serve(Arc::new(MemorySink::default()))?;
    block_on(async {
        // The key of the current format is still there; the purged ones are not listed.
        let ids: Vec<_> = env.listed().await?.into_iter().map(|k| k.0).collect();
        assert_eq!(ids, ["fresh"]);
        // `Sign` on a purged id answers "no such key", which a file of the earlier format did not.
        for id in ["alpha", "beta", "ghost"] {
            let err = sign(&env.client, id, CKM_ECDSA, &digest()).await.err();
            assert_eq!(
                err.map(|e| error_name(&e)).as_deref(),
                Some(NO_SUCH_KEY),
                "{id}"
            );
        }
        Ok::<_, String>(())
    })?;
    Ok(())
}

#[test]
fn one_entry_per_key() -> TestResult {
    let env = Env::start(None)?;
    m3_state(&env.root())?;
    let sink = Arc::new(MemorySink::default());
    let _service = env.serve(sink.clone())?;
    // One entry per key (a key and its certificate are one), none for the key of the current format.
    assert_eq!(
        find_entries(&sink),
        expected()
            .into_iter()
            .map(|(o, i)| (o, i.to_owned()))
            .collect::<Vec<_>>()
    );
    for e in sink.operation_entries() {
        assert_eq!(e.operation(), Operation::Purge);
        assert_eq!(e.outcome_name(), "purged");
        assert_eq!(e.caller(), None);
    }
    assert_eq!(sink.entries(), []);
    Ok(())
}

#[test]
fn entries_reach_the_journal_with_the_documented_fields() -> TestResult {
    let env = Env::start(None)?;
    m3_state(&env.root())?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("journal.sock");
    let socket = UnixDatagram::bind(&path)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    let _service = env.serve(Arc::new(JournalSink::new(&path)))?;
    let mut seen = Vec::new();
    for _ in expected() {
        let mut buf = vec![0u8; 65536];
        let n = socket.recv(&mut buf)?;
        let text = String::from_utf8(buf[..n].to_vec())?;
        let line = |name: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(&format!("{name}=")))
                .map(str::to_owned)
        };
        assert_eq!(
            line("MESSAGE_ID").as_deref(),
            Some("8e1f5a6c0b3d4972a4c6d58f31b7e902")
        );
        assert_eq!(line("PRIORITY").as_deref(), Some("4"));
        assert_eq!(line("CUSTODIO_OPERATION").as_deref(), Some("purge"));
        assert_eq!(line("CUSTODIO_OUTCOME").as_deref(), Some("purged"));
        assert_eq!(line("SYSLOG_IDENTIFIER").as_deref(), Some("custodiod"));
        assert_eq!(line("CUSTODIO_UID"), None, "{text}");
        assert_eq!(line("CUSTODIO_PID"), None, "{text}");
        seen.push((
            line("CUSTODIO_OWNER_UID").unwrap().parse::<u32>()?,
            line("CUSTODIO_KEY_ID").unwrap(),
        ));
    }
    assert_eq!(
        seen,
        expected()
            .into_iter()
            .map(|(o, i)| (o, i.to_owned()))
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn entries_hold_no_key_bytes() -> TestResult {
    let env = Env::start(None)?;
    m3_state(&env.root())?;
    let sink = Arc::new(MemorySink::default());
    let _service = env.serve(sink.clone())?;
    let shown = sink
        .operation_entries()
        .iter()
        .map(|e| format!("{e:?} {} {:?}", e.message(), e.fields()))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(shown.contains("alpha"), "the scan has something to read");
    for sentinel in ["SENTINEL", "d41f", "9b27", "KEY-", "CERT-"] {
        assert!(!shown.contains(sentinel), "{sentinel} in {shown}");
    }
    Ok(())
}

#[test]
fn same_ids_import_again() -> TestResult {
    let env = Env::start(None)?;
    m3_state(&env.root())?;
    let _service = env.serve(Arc::new(MemorySink::default()))?;
    block_on(async {
        for id in ["alpha", "beta", "ghost"] {
            let reply = call(&env.client, "ImportP12", &(id, EC_P12.to_vec(), PASSWORD))
                .await
                .map_err(|e| error_name(&e))?;
            let (key_type, kind) = reply
                .body()
                .deserialize::<(String, String)>()
                .map_err(|e| e.to_string())?;
            assert_eq!(
                (key_type.as_str(), kind.as_str()),
                ("ecdsa-p256", "encrypted-host"),
                "{id}"
            );
        }
        let listed: Vec<_> = env
            .listed()
            .await?
            .into_iter()
            .map(|k| (k.0, k.2))
            .collect();
        assert_eq!(
            listed,
            ["alpha", "beta", "fresh", "ghost"]
                .map(|id| (id.to_owned(), "encrypted-host".to_owned()))
        );
        for id in ["alpha", "beta", "ghost"] {
            let signature = sign(&env.client, id, CKM_ECDSA, &digest())
                .await
                .map_err(|e| error_name(&e))?;
            assert!(!signature.is_empty(), "{id}");
        }
        Ok::<_, String>(())
    })?;
    Ok(())
}

/// Names on the bus: the bus itself and fake polkit; connections: fake polkit's and the client's only.
async fn only_the_tests_connections(env: &Env) -> TestResult {
    let reply = env
        .client
        .call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "ListNames",
            &(),
        )
        .await?;
    let listed: Vec<String> = reply.body().deserialize()?;
    let well_known: BTreeSet<_> = listed
        .iter()
        .filter(|n| !n.starts_with(':'))
        .cloned()
        .collect();
    assert_eq!(
        well_known,
        BTreeSet::from([
            "org.freedesktop.DBus".to_owned(),
            "org.freedesktop.PolicyKit1".to_owned()
        ])
    );
    assert_eq!(
        listed.iter().filter(|n| n.starts_with(':')).count(),
        2,
        "{listed:?}"
    );
    Ok(())
}

/// With the sink blocked on the entry `at`: the name has no owner, no call is answered, and no connection but the test's
/// own exists. Then released: the name is taken and the calls are answered.
fn blocked_at(at: usize) -> TestResult {
    let env = Env::start(None)?;
    m3_state(&env.root())?;
    let gate = Gate::handle(Some(at), None);
    let handle = env.spawn(gate.sink.clone())?;
    assert_eq!(gate.entered.recv_timeout(Duration::from_secs(20))?, at);
    // The entry of this key is written and its files are still there; the keys before it are gone.
    let order = expected();
    let root = env.root();
    let on_disk = |owner: u32, name: &str| root.join(owner.to_string()).join(name).exists();
    for (i, (owner, id)) in order.iter().enumerate() {
        for (o, file) in legacy_files() {
            if o == *owner && (file == *id || file == format!("{id}-cert")) {
                assert_eq!(
                    on_disk(o, file),
                    i >= at,
                    "{o}/{file} while blocked at {at}"
                );
            }
        }
    }
    block_on(async {
        assert_eq!(env.owner_of_name().await, Ok(false));
        let owner = env
            .client
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "GetNameOwner",
                &(custodiod::dbus::BUS_NAME,),
            )
            .await
            .err()
            .map(|e| error_name(&e));
        assert!(owner.is_some_and(|n| NO_SERVICE.contains(&n.as_str())));
        let calls: [(&str, Result<zbus::Message, zbus::Error>); 3] = [
            ("ListKeys", call(&env.client, "ListKeys", &()).await),
            (
                "Sign",
                call(
                    &env.client,
                    "Sign",
                    &("fresh", CKM_ECDSA, 0u32, 0u32, digest()),
                )
                .await,
            ),
            (
                "ImportP12",
                call(
                    &env.client,
                    "ImportP12",
                    &("alpha", EC_P12.to_vec(), PASSWORD),
                )
                .await,
            ),
        ];
        for (name, result) in calls {
            let err = result.err().map(|e| error_name(&e));
            assert!(
                err.as_deref().is_some_and(|n| NO_SERVICE.contains(&n)),
                "{name} while blocked: {err:?}"
            );
        }
        only_the_tests_connections(&env).await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    gate.release.send(())?;
    let _service = handle
        .join()
        .map_err(|_| "panic")?
        .map_err(|e| e.to_string())?;
    block_on(async {
        assert_eq!(env.owner_of_name().await, Ok(true));
        let ids: Vec<_> = env.listed().await?.into_iter().map(|k| k.0).collect();
        assert_eq!(ids, ["fresh"]);
        Ok::<_, String>(())
    })?;
    Ok(())
}

#[test]
fn no_call_before_purge_complete() -> TestResult {
    // The first entry and the last: the name must not be taken between the two either.
    blocked_at(0)?;
    blocked_at(expected().len() - 1)
}

/// Every file of the fixture that is still on disk.
fn remaining(root: &Path) -> BTreeSet<(u32, String)> {
    legacy_files()
        .into_iter()
        .filter(|(o, f)| root.join(o.to_string()).join(f).exists())
        .map(|(o, f)| (o, f.to_owned()))
        .collect()
}

fn all_files() -> BTreeSet<(u32, String)> {
    legacy_files()
        .into_iter()
        .map(|(o, f)| (o, f.to_owned()))
        .collect()
}

#[test]
fn refuses_and_does_not_start() -> TestResult {
    // A symlink named like a legacy key, in the area of the last owner: nothing is removed anywhere, not even the
    // normal keys of the owners before it, and the symlink and its target stay.
    let env = Env::start(None)?;
    m3_state(&env.root())?;
    let outside = env.state.path().join("outside");
    fs::write(&outside, b"target")?;
    let link = env.root().join("3000").join("link");
    std::os::unix::fs::symlink(&outside, &link)?;
    let sink = Arc::new(MemorySink::default());
    let failure = env.spawn(sink.clone())?.join().map_err(|_| "panic")?.err();
    assert!(
        matches!(
            failure,
            Some(StartError::Purge(PurgeError::Store(
                StoreError::BadFileType(_)
            )))
        ),
        "{failure:?}"
    );
    assert_eq!(remaining(&env.root()), all_files());
    assert!(fs::symlink_metadata(&link)?.is_symlink());
    assert_eq!(fs::read(&outside)?, b"target");
    assert_eq!(sink.operation_entries(), []);
    block_on(async { assert_eq!(env.owner_of_name().await, Ok(false)) });

    // A sink that fails on the first entry: every file of the first key is still on disk, nothing was removed.
    for fail_at in [0, 2] {
        let env = Env::start(None)?;
        m3_state(&env.root())?;
        let gate = Gate::handle(None, Some(fail_at));
        let failure = env
            .spawn(gate.sink.clone())?
            .join()
            .map_err(|_| "panic")?
            .err();
        assert!(
            matches!(failure, Some(StartError::Purge(PurgeError::Audit(_)))),
            "{failure:?}"
        );
        // The keys before the failing one are gone, with their files; it and the ones after it are whole.
        let order = expected();
        let gone: BTreeSet<_> = legacy_files()
            .into_iter()
            .filter(|(o, f)| {
                order
                    .iter()
                    .take(fail_at)
                    .any(|(oo, id)| oo == o && (*f == *id || *f == format!("{id}-cert")))
            })
            .map(|(o, f)| (o, f.to_owned()))
            .collect();
        let want: BTreeSet<_> = all_files().difference(&gone).cloned().collect();
        assert_eq!(remaining(&env.root()), want, "failing at {fail_at}");
        assert_eq!(find_entries(&gate.sink.inner).len(), fail_at);
        block_on(async { assert_eq!(env.owner_of_name().await, Ok(false)) });
    }
    Ok(())
}

#[test]
fn second_start_purges_nothing() -> TestResult {
    let first = Env::start(None)?;
    m3_state(&first.root())?;
    let sink = Arc::new(MemorySink::default());
    let service = first.serve(sink.clone())?;
    assert_eq!(sink.operation_entries().len(), expected().len());
    let before = (
        names(&first.root().join(uid().to_string()))?,
        fs::read(first.root().join(uid().to_string()).join("fresh"))?,
    );
    drop(service);
    // The same state, another service on another bus.
    let second = Env::start(Some(first.state))?;
    let again = Arc::new(MemorySink::default());
    let _service = second.serve(again.clone())?;
    assert_eq!(again.operation_entries(), []);
    let after = (
        names(&second.root().join(uid().to_string()))?,
        fs::read(second.root().join(uid().to_string()).join("fresh"))?,
    );
    assert_eq!(before, after);
    block_on(async { assert_eq!(second.owner_of_name().await, Ok(true)) });

    // A service started without an upgrade: no file of the earlier format at all. It writes no entry and serves.
    let fresh = Env::start(None)?;
    let none = Arc::new(MemorySink::default());
    let _service = fresh.serve(none.clone())?;
    assert_eq!(none.operation_entries(), []);
    block_on(async {
        assert_eq!(fresh.owner_of_name().await, Ok(true));
        assert_eq!(fresh.listed().await, Ok(Vec::new()));
    });
    Ok(())
}

#[test]
fn top_level_keys_of_the_m0_to_m2_layout_are_purged_without_an_owner() -> TestResult {
    let env = Env::start(None)?;
    let root = env.root();
    KeyStore::open(&root)?;
    put_file(&root, "rsa", &key_bytes("rsa"))?;
    put_file(&root, "rsa-cert", &cert_bytes("rsa"))?;
    put_file(&root, "p256", &key_bytes("p256"))?;
    legacy_key(&root, 2000, "delta", true)?;
    let sink = Arc::new(MemorySink::default());
    let _service = env.serve(sink.clone())?;
    assert_eq!(names(&root)?, ["2000"]);
    assert_eq!(names(&root.join("2000"))?, Vec::<String>::new());
    let seen: Vec<_> = sink
        .operation_entries()
        .iter()
        .map(|e| (e.owner(), e.key_id().as_str().to_owned()))
        .collect();
    assert_eq!(
        seen,
        [
            (None, "p256".to_owned()),
            (None, "rsa".to_owned()),
            (Some(2000), "delta".to_owned())
        ]
    );
    for e in sink
        .operation_entries()
        .iter()
        .filter(|e| e.owner().is_none())
    {
        assert!(e.fields().iter().all(|(n, _)| *n != "CUSTODIO_OWNER_UID"));
        assert!(!format!("{:?}", e.fields()).contains("SENTINEL"));
    }
    Ok(())
}
