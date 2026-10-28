use super::*;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn state_dir_resolves_the_dynamic_user_symlink() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let real = tmp.path().join("private").join("custodio");
    fs::create_dir_all(real.parent().ok_or("no parent")?)?;
    KeyStore::open(&real)?;
    let link = tmp.path().join("custodio");
    std::os::unix::fs::symlink(&real, &link)?;
    let dir = state_dir(Some(link.into()));
    assert_eq!(dir, fs::canonicalize(&real)?);
    KeyStore::open(dir)?;
    Ok(())
}

#[test]
fn state_dir_defaults_and_keeps_a_missing_path() {
    assert_eq!(state_dir(None), PathBuf::from("/var/lib/custodio"));
    let missing = PathBuf::from("/nonexistent/custodio");
    assert_eq!(state_dir(Some(missing.clone().into())), missing);
}

mod wiring {
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixDatagram;
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    use custodiod::import::import_p12;
    use secrecy::SecretString;
    use zbus::connection::Builder;
    use zbus::{OwnedVariant, interface};

    use super::*;

    struct Bus(Child);

    impl Drop for Bus {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    struct Approving;

    #[interface(name = "org.freedesktop.PolicyKit1.Authority")]
    impl Approving {
        // The `interface` macro needs owned argument types and a `&self` receiver; this fake ignores both.
        #[allow(clippy::needless_pass_by_value, clippy::unused_self)]
        fn check_authorization(
            &self,
            subject: (String, HashMap<String, OwnedVariant>),
            action_id: String,
            details: HashMap<String, String>,
            flags: u32,
            cancellation_id: String,
        ) -> (bool, bool, HashMap<String, String>) {
            let _ = (subject, action_id, details, flags, cancellation_id);
            (true, false, HashMap::new())
        }
    }

    #[test]
    fn service_is_built_with_journal_sink_and_bus_credentials() -> TestResult {
        let mut child = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .spawn()?;
        let mut address = String::new();
        BufReader::new(child.stdout.take().ok_or("no stdout")?).read_line(&mut address)?;
        let _bus = Bus(child);
        let address = address.trim().to_owned();

        let dir = tempfile::tempdir()?;
        let journal = dir.path().join("journal.sock");
        let socket = UnixDatagram::bind(&journal)?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        let store = Arc::new(KeyStore::open(dir.path().join("keys"))?);
        let password = SecretString::from("test-password".to_owned());
        import_p12(
            &store,
            "ec",
            include_bytes!("../tests/fixtures/p256.p12"),
            &password,
        )?;

        block_on(async {
            let polkit = Builder::address(address.as_str()).build().await?;
            let path = "/org/freedesktop/PolicyKit1/Authority";
            polkit.object_server().at(path, Approving).await?;
            polkit.request_name("org.freedesktop.PolicyKit1").await?;
            let conn = Builder::address(address.as_str()).build().await?;
            let service = build_service(store, &conn, JournalSink::new(&journal));
            conn.object_server().at(OBJECT_PATH, service).await?;
            conn.request_name(BUS_NAME).await?;
            let client = Builder::address(address.as_str()).build().await?;
            let body = ("ec", 0x1041u32, 0u32, 0u32, vec![7u8; 32]);
            client
                .call_method(
                    Some(BUS_NAME),
                    OBJECT_PATH,
                    Some("com.rfirma.Custodio1"),
                    "Sign",
                    &body,
                )
                .await?;
            Ok::<_, Box<dyn Error>>(())
        })?;
        let mut buf = vec![0u8; 65536];
        let n = socket.recv(&mut buf)?;
        let text = String::from_utf8(buf.get(..n).ok_or("short")?.to_vec())?;
        let uid = rustix::process::getuid().as_raw();
        assert!(text.contains(&format!("CUSTODIO_UID={uid}\n")), "{text}");
        assert!(
            text.contains(&format!("CUSTODIO_PID={}\n", std::process::id())),
            "{text}"
        );
        assert!(text.contains("CUSTODIO_OUTCOME=signed\n"), "{text}");
        Ok(())
    }
}
