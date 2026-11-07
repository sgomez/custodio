//! Import, list, delete and replace the certificate under every cell.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::BTreeSet;

use zbus::block_on;

use crate::cell::{Running, cells};
use crate::kit::{ERR_MISMATCH, ERR_NO_KEY, ID, p12_certificate, second_certificate};
use crate::rig::TestResult;

#[test]
fn import_each_kind() -> TestResult {
    let mut ran = BTreeSet::new();
    for cell in cells() {
        block_on(async {
            let who = cell.name();
            let running = Running::start(cell).await?;
            let (key_type, kind) = running.import(ID).await?;
            assert_eq!(key_type, cell.subject.reply, "{who}");
            assert_eq!(kind, cell.kind.wire(), "{who}");
            assert_eq!(running.svc.kind_of(ID), Some(cell.kind), "{who}");
            // The kinds that depend on a TPM asked it: the lacking one through its filter.
            if cell.kind != custodiod::store::Kind::EncryptedHost {
                assert!(running.svc.tpm.opens() > 0, "{who}");
            }
            ran.insert((kind, key_type));
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    // Six distinct cells ran; the lacking ones are `encrypted-tpm`, not `tpm` and not `encrypted-host`.
    assert_eq!(ran.len(), 6, "{ran:?}");
    assert!(ran.contains(&("encrypted-tpm".to_owned(), "rsa2048".to_owned())));
    assert!(ran.contains(&("encrypted-tpm".to_owned(), "ecdsa-p256".to_owned())));
    Ok(())
}

#[test]
fn list_each_kind() -> TestResult {
    for cell in cells() {
        block_on(async {
            let who = cell.name();
            let running = Running::start(cell).await?;
            assert!(running.list().await?.is_empty(), "{who}: nothing yet");
            running.import("a").await?;
            running.import("b").await?;
            let listed = running.list().await?;
            let certificate = p12_certificate(cell.subject);
            let expected = ["a", "b"].map(|id| {
                (
                    id.to_owned(),
                    cell.subject.reply.to_owned(),
                    cell.kind.wire().to_owned(),
                    certificate.clone(),
                )
            });
            assert_eq!(listed, expected, "{who}");
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}

#[test]
fn delete_each_kind() -> TestResult {
    for cell in cells() {
        block_on(async {
            let who = cell.name();
            let running = Running::start(cell).await?;
            let rows = cell.rows();
            running.import(ID).await?;
            running.import("keep").await?;
            running.sign(ID, &rows[0]).await?;
            running.delete(ID).await?;
            // Gone from the list; the other key stays; the signature fails; nothing of it is left in the store.
            let ids: Vec<String> = running.list().await?.into_iter().map(|e| e.0).collect();
            assert_eq!(ids, ["keep"], "{who}");
            assert_eq!(
                running.sign(ID, &rows[0]).await,
                Err(ERR_NO_KEY.to_owned()),
                "{who}"
            );
            assert_eq!(
                running.delete(ID).await,
                Err(ERR_NO_KEY.to_owned()),
                "{who}"
            );
            running.delete("keep").await?;
            running.svc.assert_empty(&who);
            // The same id imports again, under the same kind, and signs.
            let (key_type, kind) = running.import(ID).await?;
            assert_eq!(
                (key_type.as_str(), kind.as_str()),
                (cell.subject.reply, cell.kind.wire()),
                "{who}"
            );
            let cert = running.cert_of(ID, "again.pem").await?;
            let signature = running.sign(ID, &rows[0]).await?;
            assert!(rows[0].accepts(&running.rig, &cert, &signature)?, "{who}");
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}

#[test]
fn replace_each_kind() -> TestResult {
    for cell in cells() {
        block_on(async {
            let who = cell.name();
            let running = Running::start(cell).await?;
            running.import(ID).await?;
            let first = p12_certificate(cell.subject);
            let second = second_certificate(&running.rig, cell.subject);
            assert_ne!(first, second, "{who}");

            // The recertificate of the same key is accepted, the kind stays, and a signature verifies with it.
            running.replace(ID, &second).await?;
            let listed = running.list().await?;
            assert_eq!(listed.len(), 1, "{who}");
            assert_eq!(listed[0].2, cell.kind.wire(), "{who}");
            assert_eq!(listed[0].3, second, "{who}");
            let cert = running.cert_of(ID, "second.pem").await?;
            for row in cell.rows() {
                let signature = running.sign(ID, &row).await?;
                assert!(
                    row.accepts(&running.rig, &cert, &signature)?,
                    "{who}: {}",
                    row.label
                );
            }

            // Another key's certificate fails with the mismatch name and changes nothing.
            let other = crate::rig::SUBJECTS
                .iter()
                .find(|s| s.reply != cell.subject.reply)
                .unwrap();
            let before = running.svc.files();
            let bytes: Vec<Vec<u8>> = before.iter().map(|f| std::fs::read(f).unwrap()).collect();
            assert_eq!(
                running.replace(ID, &p12_certificate(*other)).await,
                Err(ERR_MISMATCH.to_owned()),
                "{who}"
            );
            let after = running.svc.files();
            assert_eq!(after, before, "{who}");
            let kept: Vec<Vec<u8>> = after.iter().map(|f| std::fs::read(f).unwrap()).collect();
            assert_eq!(kept, bytes, "{who}");
            assert_eq!(running.list().await?[0].3, second, "{who}");
            assert_eq!(running.svc.kind_of(ID), Some(cell.kind), "{who}");
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}
