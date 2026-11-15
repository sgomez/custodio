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

type Cell = Option<(&'static str, &'static str)>;

/// One import of `name` with `password` (`None` expected = it imports).
fn import_case(name: &str, password: &str, cell: Cell) -> TestResult {
    block_on(async {
        let data = fixture(name)?;
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
        Ok(())
    })
}

/// A refused request for `name`: the decoder is never called.
fn refused_case(
    answer: Answer,
    error: &str,
    outcome: &str,
    name: &str,
    password: &str,
) -> TestResult {
    block_on(async {
        let r = Rig::start(answer).await?;
        let got = r.import(&fixture(name)?, password).await;
        assert_eq!(got, Err(error.to_owned()), "{name}");
        assert_eq!(r.decoded.load(Ordering::SeqCst), 0, "{name}");
        assert_eq!(r.f.asked().len(), 1, "{name}");
        assert_eq!(r.outcomes(), [outcome], "{name}");
        assert_eq!(r.stored().await?, 0, "{name}");
        Ok(())
    })
}

/// Each file of docs/findings/F195.md: one test per password, so that libtest runs them in parallel.
macro_rules! cells {
    ($($test:ident: $file:literal, $right:expr, $wrong:expr;)*) => {$(
        mod $test {
            use super::*;
            #[test]
            fn right_password() -> TestResult { import_case($file, RIGHT, $right) }
            #[test]
            fn wrong_password() -> TestResult { import_case($file, WRONG, $wrong) }
        }
    )*};
}

cells! {
    p256: "p256.p12", None, Some(A);
    rsa2048_nss: "rsa2048-nss.p12", None, Some(A);
    good_nomac: "good-nomac.p12", None, Some(C);
    nokey: "nokey.p12", Some(B), Some(A);
    nokey_nomac: "nokey-nomac.p12", Some(B), Some(B);
    nocert: "nocert.p12", Some(B), Some(A);
    nocert_nomac: "nocert-nomac.p12", Some(B), Some(C);
    twokeys: "twokeys.p12", Some(B), Some(A);
    twokeys_nomac: "twokeys-nomac.p12", Some(B), Some(C);
    notp12: "notp12.bin", Some(B), Some(B);
}

/// One file of each kind: (a) wrong password with a MAC, (b) not PKCS#12, (c) no MAC, wrong password.
macro_rules! refused {
    ($($test:ident: $answer:expr, $error:expr, $outcome:literal;)*) => {$(
        mod $test {
            use super::*;
            #[test]
            fn wrong_password_with_mac() -> TestResult {
                refused_case($answer, $error, $outcome, "p256.p12", WRONG)
            }
            #[test]
            fn not_pkcs12() -> TestResult {
                refused_case($answer, $error, $outcome, "notp12.bin", RIGHT)
            }
            #[test]
            fn no_mac_wrong_password() -> TestResult {
                refused_case($answer, $error, $outcome, "good-nomac.p12", WRONG)
            }
        }
    )*};
}

refused! {
    denied: Answer::No, ERROR_POLKIT_DENIED, "denied";
    unavailable: Answer::Fail, ERROR_AUTHORIZATION_UNAVAILABLE, "authorization_unavailable";
}
