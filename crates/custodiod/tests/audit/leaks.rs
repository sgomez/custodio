//! What an entry may contain, who the caller is, and the real journal writer.

use std::io::ErrorKind;
use std::os::unix::net::UnixDatagram;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use custodiod::audit::{Entry, JournalSink, MemorySink, Outcome};
use zbus::{Connection, block_on};

use super::bus::{Answer, Fixture, TestResult, call, error_name, sign};
use super::common::{
    CKM_ECDSA, CKM_RSA_PKCS, EC_P12, EC_SENTINEL_P12, RSA_SENTINEL_P12, SENTINEL_PASSWORD, digest,
    digest_info, fixture, import, import_with, uid,
};
use super::scan::{base64, hex, leaks};

const CHILD_ENV: &str = "CUSTODIO_AUDIT_CHILD";

/// The three texts an entry has: `Debug`, `message()` and the datagram `JournalSink` sends.
fn texts(entry: &Entry) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("j.sock");
    let socket = UnixDatagram::bind(&path)?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    JournalSink::new(&path).record_entry(entry)?;
    let mut buf = vec![0u8; 65536];
    let n = socket.recv(&mut buf)?;
    buf.truncate(n);
    Ok(vec![
        format!("{entry:?}").into_bytes(),
        entry.message().into_bytes(),
        buf,
    ])
}

trait RecordEntry {
    fn record_entry(&self, entry: &Entry) -> Result<(), custodiod::audit::AuditError>;
}

impl RecordEntry for JournalSink {
    fn record_entry(&self, entry: &Entry) -> Result<(), custodiod::audit::AuditError> {
        custodiod::audit::AuditSink::record(self, entry)
    }
}

/// An import, then one call per outcome with `key` and `mechanism`; no value may appear.
async fn no_secrets(
    key: &str,
    p12: &[u8],
    mechanism: u32,
    other: u32,
    data: &[u8],
    extra: &[Vec<u8>],
) -> TestResult {
    let sink = Arc::new(MemorySink::default());
    let f = fixture(Answer::Yes, &sink).await?;
    import_with(&f, key, p12, SENTINEL_PASSWORD).await?;
    let signature = sign(&f.client, key, mechanism, data).await?;
    sign(&f.client, key, other, data)
        .await
        .err()
        .ok_or("mismatch signed")?;
    f.set_answer(Answer::No);
    sign(&f.client, key, mechanism, data)
        .await
        .err()
        .ok_or("denied signed")?;
    f.set_answer(Answer::Fail);
    sign(&f.client, key, mechanism, data)
        .await
        .err()
        .ok_or("unavailable signed")?;
    let entries = sink.entries();
    let outcomes: Vec<_> = entries.iter().map(Entry::outcome).collect();
    assert_eq!(
        outcomes,
        [
            Outcome::Signed,
            Outcome::SigningFailed,
            Outcome::Denied,
            Outcome::AuthorizationUnavailable
        ]
    );
    let mut values: Vec<Vec<u8>> = vec![
        data.to_vec(),
        signature,
        SENTINEL_PASSWORD.as_bytes().to_vec(),
    ];
    values.extend_from_slice(extra);
    for entry in &entries {
        for text in texts(entry)? {
            for value in &values {
                assert_eq!(leaks(&text, value), Vec::<&str>::new());
            }
        }
    }
    Ok(())
}

#[test]
fn entries_contain_no_secrets() -> TestResult {
    block_on(async {
        no_secrets(
            "ec",
            EC_SENTINEL_P12,
            CKM_ECDSA,
            CKM_RSA_PKCS,
            &digest(),
            &[],
        )
        .await?;
        no_secrets(
            "rsa",
            RSA_SENTINEL_P12,
            CKM_RSA_PKCS,
            CKM_ECDSA,
            &digest_info(),
            &[digest()],
        )
        .await
    })
}

#[test]
fn rejected_id_is_not_copied() -> TestResult {
    block_on(async {
        let sink = Arc::new(MemorySink::default());
        let f = fixture(Answer::Yes, &sink).await?;
        for id in ["bad/LEAK-sentinel".to_owned(), "a".repeat(65)] {
            let err = sign(&f.client, &id, CKM_ECDSA, &digest())
                .await
                .err()
                .ok_or("signed")?;
            assert_eq!(error_name(&err), "org.freedesktop.DBus.Error.InvalidArgs");
        }
        assert_eq!(f.asked(), Vec::<String>::new());
        for entry in sink.entries() {
            for text in texts(&entry)? {
                assert_eq!(leaks(&text, b"LEAK-sentinel"), Vec::<&str>::new());
                assert_eq!(leaks(&text, "a".repeat(65).as_bytes()), Vec::<&str>::new());
            }
        }
        Ok(())
    })
}

#[test]
fn sign_has_no_uid_or_pid_argument() -> TestResult {
    block_on(async {
        let sink = Arc::new(MemorySink::default());
        let f = fixture(Answer::Yes, &sink).await?;
        import(&f, "ec", EC_P12).await?;
        let reply = f
            .client
            .call_method(
                Some("com.rfirma.Custodio1"),
                "/com/rfirma/Custodio1",
                Some("org.freedesktop.DBus.Introspectable"),
                "Introspect",
                &(),
            )
            .await?;
        let xml: String = reply.body().deserialize()?;
        let start = xml.find("<method name=\"Sign\">").ok_or("no Sign")?;
        let block = xml
            .get(start..)
            .and_then(|s| s.split("</method>").next())
            .ok_or("no end")?;
        let args: Vec<&str> = block
            .split("<arg ")
            .skip(1)
            .filter(|a| a.contains("direction=\"in\""))
            .filter_map(|a| a.split("name=\"").nth(1)?.split('"').next())
            .collect();
        assert_eq!(args, ["id", "mechanism", "hash", "salt_len", "data"]);
        let reply = call(
            &f.client,
            "Sign",
            &("ec", CKM_ECDSA, 0u32, 0u32, digest(), 1u32, 2u32),
        )
        .await;
        assert!(reply.is_err());
        assert_eq!(sink.entries(), Vec::new());
        assert_eq!(f.asked(), Vec::<String>::new());
        Ok(())
    })
}

/// Entry point of the child process of `entry_names_the_caller_not_the_service`.
#[test]
fn child_client() -> TestResult {
    let Some(address) = std::env::var_os(CHILD_ENV) else {
        return Ok(());
    };
    let address = address.to_string_lossy().into_owned();
    block_on(async {
        let client = zbus::connection::Builder::address(address.as_str())
            .method_timeout(Duration::from_secs(10))
            .build()
            .await?;
        sign(&client, "ec", CKM_ECDSA, &digest()).await?;
        Ok(())
    })
}

/// Waits for the child up to `limit`, then kills it and fails, so a stuck call cannot hang the run.
fn wait_bounded(
    child: &mut std::process::Child,
    limit: Duration,
) -> Result<std::process::ExitStatus, Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if std::time::Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err("child client did not finish in time".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn entry_names_the_caller_not_the_service() -> TestResult {
    let sink = Arc::new(MemorySink::default());
    // The service runs on its own connection; waiting for the child happens outside `block_on`.
    let f = block_on(fixture(Answer::Yes, &sink))?;
    block_on(import(&f, "ec", EC_P12))?;
    let mut pids = Vec::new();
    for _ in 0..2 {
        let mut child = Command::new(std::env::current_exe()?)
            .args(["--exact", "leaks::child_client", "--test-threads=1"])
            .env(CHILD_ENV, &f.bus.address)
            .stdout(std::process::Stdio::null())
            .spawn()?;
        pids.push(child.id());
        assert!(wait_bounded(&mut child, Duration::from_secs(30))?.success());
    }
    let entries = sink.entries();
    assert_eq!(entries.len(), 2);
    for (entry, pid) in entries.iter().zip(&pids) {
        let caller = entry.caller().ok_or("no caller")?;
        assert_eq!(caller.pid, *pid);
        assert_ne!(caller.pid, std::process::id());
        assert_eq!(caller.uid, uid());
    }
    assert_ne!(pids.first(), pids.get(1));
    Ok(())
}

#[test]
fn journal_sink_datagram_per_call() -> TestResult {
    block_on(async {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("j.sock");
        let socket = UnixDatagram::bind(&path)?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        let f = Fixture::start(
            Answer::Yes,
            |c: &Connection| custodiod::credentials::BusCredentials::new(c.clone()),
            Arc::new(JournalSink::new(&path)),
        )
        .await?;
        import(&f, "ec", EC_P12).await?;
        sign(&f.client, "ec", CKM_ECDSA, &digest()).await?;
        let mut buf = vec![0u8; 65536];
        let n = socket.recv(&mut buf)?;
        let text = String::from_utf8(buf.get(..n).ok_or("short")?.to_vec())?;
        let lines: Vec<&str> = text.lines().collect();
        for want in [
            format!("CUSTODIO_UID={}", uid()),
            format!("CUSTODIO_PID={}", std::process::id()),
            "CUSTODIO_KEY_ID=ec".to_owned(),
            "CUSTODIO_OUTCOME=signed".to_owned(),
            format!("MESSAGE_ID={}", custodiod::audit::MESSAGE_ID),
        ] {
            assert!(lines.contains(&want.as_str()), "{want} in {lines:?}");
        }
        socket.set_nonblocking(true)?;
        let again = socket.recv(&mut buf).err().ok_or("a second datagram")?;
        assert_eq!(again.kind(), ErrorKind::WouldBlock);
        Ok(())
    })
}

#[test]
fn encoders_match_fixed_vectors() {
    let std_padded = [
        "", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy",
    ];
    let std_plain = ["", "Zg", "Zm8", "Zm9v", "Zm9vYg", "Zm9vYmE", "Zm9vYmFy"];
    for (n, (padded, plain)) in std_padded.iter().zip(std_plain).enumerate() {
        let input = b"foobar".get(..n).unwrap_or_default();
        assert_eq!(base64(input, false, true), *padded);
        assert_eq!(base64(input, false, false), plain);
        assert_eq!(base64(input, true, true), *padded);
    }
    assert_eq!(base64(&[0xfb, 0xff, 0xbe], true, true), "-_--");
    assert_eq!(base64(&[0xfb, 0xff, 0xbe], false, true), "+/++");
    assert_eq!(base64(&[0xfb, 0xff], true, false), "-_8");
    assert_eq!(base64(&[0xfb, 0xff], true, true), "-_8=");
    assert_eq!(base64(&[0xfb, 0xff], false, true), "+/8=");
    assert_eq!(hex(&[0x00, 0xab, 0xCD, 0xff], false), "00abcdff");
    assert_eq!(hex(&[0x00, 0xab, 0xCD, 0xff], true), "00ABCDFF");
}

#[test]
fn leak_scanner_detects_planted_values() {
    // (value, form name, literal form)
    let planted: [(&[u8], &str, &[u8]); 12] = [
        (b"foo", "raw", b"foo"),
        (b"foo", "hex-lower", b"666f6f"),
        (b"foo", "hex-upper", b"666F6F"),
        (b"foo", "b64-std", b"Zm9v"),
        (b"foob", "b64-std-pad", b"Zm9vYg=="),
        (b"foob", "b64-std", b"Zm9vYg"),
        (b"foob", "hex-lower", b"666f6f62"),
        (b"fooba", "b64-std-pad", b"Zm9vYmE="),
        (b"fooba", "b64-url", b"Zm9vYmE"),
        (b"fooba", "hex-upper", b"666F6F6261"),
        (&[0xfb, 0xff, 0xbe], "b64-url-pad", b"-_--"),
        (&[0xfb, 0xff, 0xbe], "b64-std", b"+/++"),
    ];
    for (value, form, literal) in planted {
        let mut buf = b"noise ".to_vec();
        buf.extend_from_slice(literal);
        buf.extend_from_slice(b" noise");
        assert!(leaks(&buf, value).contains(&form), "{form}");
    }
    assert_eq!(leaks(b"nothing to see here", b"foo"), Vec::<&str>::new());
}
