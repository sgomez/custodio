//! What a replace entry holds: no certificate or key bytes, and the fields on the wire.

use std::io::ErrorKind;
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

use custodiod::audit::{Operation, OperationEntry, ReplaceOutcome};
use custodiod::credentials::BusCredentials;
use x509_cert::Certificate;
use x509_cert::der::Decode;
use zbus::{Connection, block_on};

use super::bus::{Fixture, TestResult};
use super::common::{PASSWORD, RSA_P12, digest, digest_info, uid};
use super::{Make, NEW, OTHER_KEY, cases, cert_of, put_rsa, replace, running_as_root, scan, start};
use std::sync::Arc;

/// Everything an entry can show.
fn text_of(e: &OperationEntry) -> String {
    format!(
        "{} {e:?} {} {} {:?} {:?}",
        e.message(),
        e.outcome_name(),
        e.key_id().as_str(),
        e.caller(),
        e.operation()
    )
}

fn strings_of(cert: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let c = Certificate::from_der(cert)?;
    Ok(vec![
        c.tbs_certificate().subject().to_string().into_bytes(),
        format!("{:?}", c.tbs_certificate().serial_number()).into_bytes(),
    ])
}

#[test]
fn replace_entries_hold_no_secrets() -> TestResult {
    block_on(async {
        let key = custodiod::import::parse_p12(
            RSA_P12,
            &secrecy::SecretString::from(PASSWORD.to_owned()),
        )?;
        let mut secrets = vec![
            key.certificate.clone(),
            NEW.to_vec(),
            OTHER_KEY.to_vec(),
            secrecy::ExposeSecret::expose_secret(&key.key).to_vec(),
            PASSWORD.as_bytes().to_vec(),
            digest(),
            digest_info(),
        ];
        secrets.extend(strings_of(&key.certificate)?);
        secrets.extend(strings_of(NEW)?);
        // The scan can see a leak.
        let leaking = format!("x {}", scan::base64(NEW, false, true));
        assert_ne!(scan::leaks(leaking.as_bytes(), NEW).len(), 0);
        let subject = strings_of(NEW)?.remove(0);
        assert_ne!(
            scan::leaks(&[b"x ".as_slice(), &subject].concat(), &subject).len(),
            0
        );

        let mut texts = Vec::new();
        for (answer, cert, make, _, outcome) in cases() {
            if !matches!(make, Make::Plain) && running_as_root() {
                continue;
            }
            for fail in [false, true] {
                let (f, sink) = start(answer).await?;
                put_rsa(&f, "k")?;
                make.arm(&f);
                sink.failing(fail);
                let _ = replace(&f.client, "k", cert).await;
                let _ = std::fs::set_permissions(
                    super::area(&f),
                    std::os::unix::fs::PermissionsExt::from_mode(0o700),
                );
                // What the failing sink was handed counts too.
                let offered = sink.offered.operation_entries();
                assert_eq!(offered.len(), 1, "{outcome}");
                for e in &offered {
                    assert!(
                        e.fields()
                            .contains(&("CUSTODIO_APP_ID", "org.example.App".to_owned())),
                        "the scan sees the app-id"
                    );
                }
                texts.extend(offered.iter().map(text_of));
            }
        }
        assert_eq!(texts.len() % 2, 0);
        assert!(texts.len() >= 10);
        for text in &texts {
            for secret in &secrets {
                assert_eq!(scan::leaks(text.as_bytes(), secret), Vec::<&str>::new());
            }
        }
        Ok(())
    })
}

#[test]
fn journal_sink_datagram_for_replace() -> TestResult {
    block_on(async {
        for (answer, cert, make, _, outcome) in cases() {
            if !matches!(make, Make::Plain) {
                continue;
            }
            let dir = tempfile::tempdir()?;
            let path = dir.path().join("j.sock");
            let socket = UnixDatagram::bind(&path)?;
            socket.set_read_timeout(Some(Duration::from_secs(2)))?;
            let f = Fixture::start(
                answer,
                |c: &Connection| BusCredentials::new(c.clone()),
                Arc::new(custodiod::audit::JournalSink::new(&path)),
            )
            .await?;
            put_rsa(&f, "k")?;
            let old = cert_of(&f, "k")?;
            let _ = replace(&f.client, "k", cert).await;
            let mut buf = vec![0u8; 65536];
            let n = socket.recv(&mut buf)?;
            let datagram = buf.get(..n).ok_or("short")?.to_vec();
            let text = String::from_utf8(datagram.clone())?;
            let lines: Vec<&str> = text.lines().collect();
            let priority = ReplaceOutcome::all()
                .into_iter()
                .find(|o| o.name() == outcome)
                .ok_or("outcome")?
                .priority();
            for want in [
                format!("CUSTODIO_UID={}", uid()),
                format!("CUSTODIO_PID={}", std::process::id()),
                "CUSTODIO_KEY_ID=k".to_owned(),
                "CUSTODIO_OPERATION=replace_certificate".to_owned(),
                format!("CUSTODIO_OUTCOME={outcome}"),
                format!("PRIORITY={priority}"),
                format!("MESSAGE_ID={}", Operation::ReplaceCertificate.message_id()),
            ] {
                assert!(lines.contains(&want.as_str()), "{want} in {lines:?}");
            }
            assert_eq!(
                lines
                    .iter()
                    .filter(|l| l.starts_with("MESSAGE_ID="))
                    .count(),
                1
            );
            for secret in [NEW, OTHER_KEY, &old] {
                assert_eq!(scan::leaks(&datagram, secret), Vec::<&str>::new());
            }
            socket.set_nonblocking(true)?;
            let again = socket.recv(&mut buf).err().ok_or("a second datagram")?;
            assert_eq!(again.kind(), ErrorKind::WouldBlock);
        }
        Ok(())
    })
}
