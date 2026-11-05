//! The datagram the journal sink sends, and hostile scope names.

use std::os::unix::net::UnixDatagram;
use std::time::Duration;

use custodiod::app_id_source::CgroupAppIdSource;
use custodiod::audit::JournalSink;

use super::*;

/// Runs `op` with the journal sink on a private socket; the datagram sent.
async fn datagram(op: Operation, source: GuardedSource) -> Result<Vec<u8>, Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("j.sock");
    let socket = UnixDatagram::bind(&path)?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    let f = Fixture::start_full(
        Answer::Yes,
        |c: &Connection| BusCredentials::new(c.clone()),
        Arc::new(JournalSink::new(&path)),
        None,
        Some(source),
    )
    .await?;
    if op != Operation::Import {
        put_rsa(&f, "k")?;
    }
    drive(&f, op, Fail::No).await?;
    let mut buf = vec![0u8; 65536];
    let n = socket.recv(&mut buf)?;
    Ok(buf.get(..n).ok_or("short")?.to_vec())
}

#[test]
fn journal_sink_datagram_names_the_app_id() -> TestResult {
    zbus::block_on(async {
        for op in Operation::requests() {
            for case in answers()? {
                let text = String::from_utf8(
                    datagram(op, GuardedSource::new(Probe::new(case.clone()))).await?,
                )?;
                let lines: Vec<&str> = text.lines().collect();
                let mut want = vec![
                    format!("CUSTODIO_APP_ID_STATE={}", app_id_state(&case)),
                    format!("CUSTODIO_UID={}", uid()),
                    format!("CUSTODIO_PID={}", std::process::id()),
                    "CUSTODIO_KEY_ID=k".to_owned(),
                    "PRIORITY=6".to_owned(),
                    "CUSTODIO_OUTCOME=".to_owned() + outcome_of(op),
                    format!("CUSTODIO_OPERATION={}", op.name()),
                    format!("MESSAGE_ID={}", op.message_id()),
                ];
                if let AppIdOutcome::Read(id) = &case {
                    want.push(format!("CUSTODIO_APP_ID={}", id.as_str()));
                }
                for w in &want {
                    assert!(lines.contains(&w.as_str()), "{w} in {lines:?}");
                }
                let ids = lines
                    .iter()
                    .filter(|l| l.starts_with("CUSTODIO_APP_ID="))
                    .count();
                assert_eq!(ids, usize::from(matches!(case, AppIdOutcome::Read(_))));
            }
        }
        Ok(())
    })
}

/// The outcome name of the approved call of `op`.
fn outcome_of(op: Operation) -> &'static str {
    match op {
        Operation::Sign => "signed",
        Operation::Import => "stored",
        Operation::Delete => "deleted",
        Operation::ReplaceCertificate => "replaced",
        Operation::Purge => "purged",
    }
}

/// A fixture cgroup tree in which this process is in the scope `name`.
fn tree_with(name: &[u8]) -> Result<tempfile::TempDir, Box<dyn Error>> {
    use std::os::unix::ffi::OsStrExt;
    let root = tempfile::tempdir()?;
    let u = uid();
    let app = root.path().join(format!(
        "user.slice/user-{u}.slice/user@{u}.service/app.slice"
    ));
    let scope = app.join(std::ffi::OsStr::from_bytes(name));
    fs::create_dir_all(&scope)?;
    fs::write(
        scope.join("cgroup.procs"),
        format!("{}\n", std::process::id()),
    )?;
    Ok(root)
}

#[test]
fn hostile_values_never_reach_an_entry() -> TestResult {
    zbus::block_on(async {
        // A directory name holds no NUL byte and at most 255 bytes, so those two cannot be offered;
        // the last name is the longest that stays well past an app id.
        let hostile: [&[u8]; 6] = [
            b"app-flatpak-org.a.INJECT\nCUSTODIO_UID=0-1.scope",
            b"app-flatpak-org.a.INJECT=b-1.scope",
            b"app-flatpak-org.a.INJECT\xff\xfe-1.scope",
            b"app-flatpak-org.a.INJECT -1.scope",
            b"app-flatpak-org.a.INJECT-1.scope ",
            // The longest name a directory takes, far past an app id.
            &[
                b"app-flatpak-org.a.INJECT.9".as_slice(),
                &[b'x'; 220],
                b"-1.scope",
            ]
            .concat(),
        ];
        for (name, op) in hostile
            .into_iter()
            .flat_map(|n| Operation::requests().map(move |op| (n, op)))
        {
            let root = tree_with(name)?;
            let reader =
                CgroupAppIdSource::with_root(root.path().to_path_buf(), Duration::from_secs(5), 8);
            let bytes = datagram(
                op,
                GuardedSource::with_limits(reader, Duration::from_secs(5), 8),
            )
            .await?;
            let text = String::from_utf8_lossy(&bytes).into_owned();
            assert!(!text.contains("INJECT"), "{text}");
            assert!(!text.contains("CUSTODIO_APP_ID="), "{text}");
            assert_eq!(
                text.lines()
                    .filter(|l| l.starts_with("CUSTODIO_UID="))
                    .count(),
                1
            );
            assert!(
                text.contains("CUSTODIO_APP_ID_STATE=undetermined"),
                "{text}"
            );
        }
        // The same tree with a valid name is read.
        let root = tree_with(b"app-flatpak-org.example.App-1.scope")?;
        let reader =
            CgroupAppIdSource::with_root(root.path().to_path_buf(), Duration::from_secs(5), 8);
        let bytes = datagram(
            Operation::Import,
            GuardedSource::with_limits(reader, Duration::from_secs(5), 8),
        )
        .await?;
        let text = String::from_utf8(bytes)?;
        assert!(text.contains("CUSTODIO_APP_ID=org.example.App\n"), "{text}");
        Ok(())
    })
}
