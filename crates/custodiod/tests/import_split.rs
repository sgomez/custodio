//! `ImportP12` over a private bus with real `.p12` files: a wrong password with a MAC, a file that is not usable
//! whatever the password, and a file without a MAC that does not decrypt are three different errors and, in the
//! journal, `wrong_password`, `unreadable_file` and `wrong_password` (docs/findings/F195.md has the cells). A refused
//! request never reaches the decoder.

// The two shared support files serve the whole `it` binary; this one uses a part of them.
#![allow(
    dead_code,
    unused_imports,
    reason = "bus.rs and common.rs are shared with the `it` binary, which uses all of them"
)]

#[path = "audit/bus.rs"]
mod bus;
#[path = "audit/common.rs"]
mod common;

use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use custodio_client::{
    ERROR_AUTHORIZATION_UNAVAILABLE, ERROR_POLKIT_DENIED, ERROR_UNREADABLE_P12,
    ERROR_WRONG_PASSWORD, ERROR_WRONG_PASSWORD_OR_BAD_P12,
};
use custodiod::audit::MemorySink;
use custodiod::credentials::BusCredentials;
use custodiod::import::{ImportError, P12Decoder, ParsedP12, RealDecoder};
use secrecy::SecretString;
use zbus::{Connection, block_on};

use bus::{Answer, Fixture, TestResult, call, error_name};

const RIGHT: &str = "test-password";
const WRONG: &str = "wrong";

/// The real decoder that counts its calls.
struct Counting(Arc<AtomicUsize>);

impl P12Decoder for Counting {
    fn decode(&self, data: &[u8], password: &SecretString) -> Result<ParsedP12, ImportError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        RealDecoder.decode(data, password)
    }
}

struct Rig {
    f: Fixture,
    sink: Arc<MemorySink>,
    decoded: Arc<AtomicUsize>,
}

impl Rig {
    async fn start(answer: Answer) -> Result<Self, Box<dyn Error>> {
        let decoded = Arc::new(AtomicUsize::new(0));
        let sink = Arc::new(MemorySink::default());
        let f = Fixture::start_with(
            answer,
            |c: &Connection| BusCredentials::new(c.clone()),
            sink.clone(),
            Some(Arc::new(Counting(decoded.clone()))),
        )
        .await?;
        Ok(Self { f, sink, decoded })
    }

    async fn import(&self, p12: &[u8], password: &str) -> Result<(), String> {
        call(&self.f.client, "ImportP12", &("k", p12.to_vec(), password))
            .await
            .map(|_| ())
            .map_err(|e| error_name(&e))
    }

    async fn stored(&self) -> Result<usize, Box<dyn Error>> {
        let keys: Vec<(String, String, String, Vec<u8>)> = call(&self.f.client, "ListKeys", &())
            .await?
            .body()
            .deserialize()?;
        Ok(keys.len())
    }

    fn outcomes(&self) -> Vec<&'static str> {
        self.sink
            .operation_entries()
            .iter()
            .map(custodiod::audit::OperationEntry::outcome_name)
            .collect()
    }
}

fn fixture(name: &str) -> Result<Vec<u8>, std::io::Error> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
}

const A: (&str, &str) = (ERROR_WRONG_PASSWORD, "wrong_password");
const B: (&str, &str) = (ERROR_UNREADABLE_P12, "unreadable_file");
const C: (&str, &str) = (ERROR_WRONG_PASSWORD_OR_BAD_P12, "wrong_password");

/// File, and the error and journal outcome with the right and with a wrong password (`None` = it imports).
type Cell = Option<(&'static str, &'static str)>;
const CELLS: [(&str, Cell, Cell); 10] = [
    ("p256.p12", None, Some(A)),
    ("rsa2048-nss.p12", None, Some(A)),
    ("good-nomac.p12", None, Some(C)),
    ("nokey.p12", Some(B), Some(A)),
    ("nokey-nomac.p12", Some(B), Some(B)),
    ("nocert.p12", Some(B), Some(A)),
    ("nocert-nomac.p12", Some(B), Some(C)),
    ("twokeys.p12", Some(B), Some(A)),
    ("twokeys-nomac.p12", Some(B), Some(C)),
    ("notp12.bin", Some(B), Some(B)),
];

#[test]
fn every_file_and_password_gets_the_error_and_outcome_of_its_cell() -> TestResult {
    block_on(async {
        for (name, right, wrong) in CELLS {
            let data = fixture(name)?;
            for (password, cell) in [(RIGHT, right), (WRONG, wrong)] {
                let r = Rig::start(Answer::Yes).await?;
                let got = r.import(&data, password).await;
                let what = format!("{name} with {password}");
                if let Some((error, outcome)) = cell {
                    assert_eq!(got, Err(error.to_owned()), "{what}");
                    assert_eq!(r.outcomes(), [outcome], "{what}");
                    assert_eq!(r.stored().await?, 0, "{what}");
                } else {
                    assert_eq!(got, Ok(()), "{what}");
                    assert_eq!(r.outcomes(), ["stored"], "{what}");
                }
                assert_eq!(r.decoded.load(Ordering::SeqCst), 1, "{what}");
            }
        }
        Ok(())
    })
}

#[test]
fn a_refused_request_never_opens_the_file() -> TestResult {
    block_on(async {
        for (answer, error, outcome) in [
            (Answer::No, ERROR_POLKIT_DENIED, "denied"),
            (
                Answer::Fail,
                ERROR_AUTHORIZATION_UNAVAILABLE,
                "authorization_unavailable",
            ),
        ] {
            // One file of each kind: (a) wrong password with a MAC, (b) not PKCS#12, (c) no MAC, wrong password.
            for (name, password) in [
                ("p256.p12", WRONG),
                ("notp12.bin", RIGHT),
                ("good-nomac.p12", WRONG),
            ] {
                let r = Rig::start(answer).await?;
                let got = r.import(&fixture(name)?, password).await;
                assert_eq!(got, Err(error.to_owned()), "{name}");
                assert_eq!(r.decoded.load(Ordering::SeqCst), 0, "{name}");
                assert_eq!(r.f.asked().len(), 1, "{name}");
                assert_eq!(r.outcomes(), [outcome], "{name}");
                assert_eq!(r.stored().await?, 0, "{name}");
            }
        }
        Ok(())
    })
}
