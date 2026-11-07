//! Every mechanism of the table under every cell, verified by `openssl` with the key's certificate.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use custodiod::sign::{Mechanism, PssHash};
use zbus::block_on;

use crate::cell::{Running, cells};
use crate::common::{CKM_ECDSA, CKM_RSA_PKCS};
use crate::kit::{CKM_RSA_PKCS_PSS, CKM_SHA256, ID};
use crate::oracle::{flip, p256_rows, rsa_rows};
use crate::rig::TestResult;

/// `(mechanism, hash, salt length)` as `Sign` takes them.
pub fn wire(mechanism: Mechanism) -> (u32, u32, u32) {
    match mechanism {
        Mechanism::RsaPkcs => (CKM_RSA_PKCS, 0, 0),
        Mechanism::Ecdsa => (CKM_ECDSA, 0, 0),
        Mechanism::RsaPkcsPss { hash, salt_len } => {
            let hash = match hash {
                PssHash::Sha256 => CKM_SHA256,
                PssHash::Sha384 => 0x0260,
                PssHash::Sha512 => 0x0270,
            };
            (CKM_RSA_PKCS_PSS, hash, u32::try_from(salt_len).unwrap())
        }
    }
}

#[test]
fn sign_every_mechanism_verifies() -> TestResult {
    let mut accepted_rsa = 0;
    let mut accepted_p256 = 0;
    for cell in cells() {
        block_on(async {
            let who = cell.name();
            let running = Running::start(cell).await?;
            let (_, kind) = running.import(ID).await?;
            assert_eq!(kind, cell.kind.wire(), "{who}");
            let cert = running.cert_of(ID, "own.pem").await?;
            let same_type = running.other_key_cert("same-type.pem");
            let other_type = running.other_type_cert("other-type.pem");
            let mut count = 0;
            for row in cell.rows() {
                let ctx = format!("{who}: {}", row.label);
                let signature = running.sign(ID, &row).await?;
                assert!(row.accepts(&running.rig, &cert, &signature)?, "{ctx}");
                // Controls: another key's certificate, the other key type's certificate and a flipped bit.
                for wrong in [&same_type, &other_type] {
                    assert!(!row.accepts(&running.rig, wrong, &signature)?, "{ctx}");
                }
                assert!(
                    !row.accepts(&running.rig, &cert, &flip(&signature))?,
                    "{ctx}"
                );
                count += 1;
            }
            if cell.rsa() {
                accepted_rsa += count;
            } else {
                accepted_p256 += count;
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    // Three cells of each key type: a row skipped on any cell fails here.
    assert_eq!(accepted_rsa, 3 * rsa_rows().len());
    assert_eq!(accepted_p256, 3 * p256_rows().len());
    Ok(())
}
