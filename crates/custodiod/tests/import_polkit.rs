//! `ImportP12` over a private bus: arguments, the caller's own id, then polkit once under the import
//! action, and only after approval the decoding of the `.p12`. A counting decoder proves when it runs.

// The shared helpers are used in full by the audit tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/bus.rs"]
mod bus;
#[allow(dead_code, unused_imports)]
#[path = "audit/common.rs"]
mod common;

use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use custodio_client::{
    ERROR_AUTHORIZATION_UNAVAILABLE, ERROR_INVALID_ARGS, ERROR_KEY_ID_TAKEN, ERROR_POLKIT_DENIED,
    ERROR_UNSUPPORTED_KEY_TYPE, ERROR_WRONG_PASSWORD_OR_BAD_P12, MAX_P12_LEN,
};
use custodiod::audit::MemorySink;
use custodiod::credentials::BusCredentials;
use custodiod::import::{ImportError, P12Decoder, ParsedP12, RealDecoder};
use custodiod::polkit::{ACTION_ID, IMPORT_ACTION_ID};
use secrecy::SecretString;
use zbus::{Connection, block_on};

use bus::{Answer, Fixture, TestResult, call, error_name, sign};
use common::{CKM_ECDSA, EC_P12, PASSWORD, RSA_P12, digest};

/// The real decoder that counts its calls.
struct Counting(Arc<AtomicUsize>);

impl P12Decoder for Counting {
    fn decode(&self, data: &[u8], password: &SecretString) -> Result<ParsedP12, ImportError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        RealDecoder.decode(data, password)
    }
}

type Listed = Vec<(String, String, Vec<u8>)>;

struct Rig {
    f: Fixture,
    decoded: Arc<AtomicUsize>,
}

impl Rig {
    async fn start(answer: Answer) -> Result<Self, Box<dyn Error>> {
        let decoded = Arc::new(AtomicUsize::new(0));
        let f = Fixture::start_with(
            answer,
            |c: &Connection| BusCredentials::new(c.clone()),
            Arc::new(MemorySink::default()),
            Some(Arc::new(Counting(decoded.clone()))),
        )
        .await?;
        Ok(Self { f, decoded })
    }

    async fn import(&self, id: &str, p12: &[u8], password: &str) -> Result<String, String> {
        let reply = call(&self.f.client, "ImportP12", &(id, p12.to_vec(), password))
            .await
            .map_err(|e| error_name(&e))?;
        reply.body().deserialize().map_err(|e| e.to_string())
    }

    fn polkit_calls(&self) -> usize {
        self.f.asked().len()
    }

    fn decoder_calls(&self) -> usize {
        self.decoded.load(Ordering::SeqCst)
    }

    async fn list(&self) -> Result<Vec<(String, String, Vec<u8>)>, Box<dyn Error>> {
        let mut keys: Vec<(String, String, Vec<u8>)> = call(&self.f.client, "ListKeys", &())
            .await?
            .body()
            .deserialize()?;
        keys.sort();
        Ok(keys)
    }
}

fn fx(name: &str) -> Result<Vec<u8>, std::io::Error> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}.p12",
        env!("CARGO_MANIFEST_DIR")
    ))
}

/// Every path under `dir`, relative, sorted.
fn tree(dir: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), std::io::Error> {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            out.push(path.strip_prefix(base).unwrap_or(&path).to_path_buf());
            if path.is_dir() {
                walk(base, &path, out)?;
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out)?;
    out.sort();
    Ok(out)
}

#[test]
fn import_refuses_bad_arguments_first() -> TestResult {
    block_on(async {
        let big = vec![0u8; MAX_P12_LEN + 1];
        let long_password = "p".repeat(1025);
        for answer in [Answer::Yes, Answer::No] {
            let r = Rig::start(answer).await?;
            // The caller already holds `k`: a bad argument must still win over `KeyIdTaken`.
            common::import(&r.f, "k", EC_P12).await?;
            let cases: [(&str, &[u8], &str); 3] = [
                ("bad id!", EC_P12, PASSWORD),
                ("k", &big, PASSWORD),
                ("k", EC_P12, &long_password),
            ];
            for (id, data, password) in cases {
                let got = r.import(id, data, password).await;
                assert_eq!(got, Err(ERROR_INVALID_ARGS.to_owned()), "{id}");
            }
            assert_eq!(r.polkit_calls(), 0);
            assert_eq!(r.decoder_calls(), 0);
        }
        Ok(())
    })
}

#[test]
fn import_own_id_taken_asks_no_polkit() -> TestResult {
    block_on(async {
        let r = Rig::start(Answer::Yes).await?;
        assert_eq!(
            r.import("k", EC_P12, PASSWORD).await,
            Ok("ecdsa-p256".into())
        );
        assert_eq!((r.polkit_calls(), r.decoder_calls()), (1, 1));
        for answer in [Answer::Yes, Answer::No] {
            r.f.set_answer(answer);
            let got = r.import("k", EC_P12, PASSWORD).await;
            assert_eq!(got, Err(ERROR_KEY_ID_TAKEN.to_owned()));
            assert_eq!((r.polkit_calls(), r.decoder_calls()), (1, 1));
        }
        // A name ending in `-cert` is never a client id.
        let got = r.import("k-cert", EC_P12, PASSWORD).await;
        assert_eq!(got, Err(ERROR_INVALID_ARGS.to_owned()));
        Ok(())
    })
}

#[test]
fn import_asks_polkit_once_for_the_import_action() -> TestResult {
    block_on(async {
        let r = Rig::start(Answer::Yes).await?;
        r.import("k", EC_P12, PASSWORD).await?;
        let requests = r.f.requests.lock().map_err(|_| "poisoned")?.clone();
        assert_eq!(
            requests,
            vec![("com.rfirma.custodio.import-certificate".to_owned(), 1)]
        );
        assert_eq!(
            requests.first().map(|r| r.0.as_str()),
            Some(IMPORT_ACTION_ID)
        );
        assert_ne!(IMPORT_ACTION_ID, ACTION_ID);
        Ok(())
    })
}

#[test]
fn import_wrong_password_is_denied_not_tried() -> TestResult {
    block_on(async {
        for (answer, want) in [
            (Answer::No, ERROR_POLKIT_DENIED),
            (Answer::Challenge, ERROR_POLKIT_DENIED),
            (Answer::Fail, ERROR_AUTHORIZATION_UNAVAILABLE),
        ] {
            let r = Rig::start(answer).await?;
            let got = r.import("k", RSA_P12, "wrong").await;
            assert_eq!(got, Err(want.to_owned()));
            assert_eq!((r.polkit_calls(), r.decoder_calls()), (1, 0));
        }
        // Control: once approved, the same call reaches the decoder exactly once.
        let r = Rig::start(Answer::Yes).await?;
        let got = r.import("k", RSA_P12, "wrong").await;
        assert_eq!(got, Err(ERROR_WRONG_PASSWORD_OR_BAD_P12.to_owned()));
        assert_eq!(r.decoder_calls(), 1);
        Ok(())
    })
}

#[test]
fn import_after_approval_errors() -> TestResult {
    block_on(async {
        let r = Rig::start(Answer::Yes).await?;
        let cases = [
            (
                "a",
                RSA_P12.to_vec(),
                "wrong",
                ERROR_WRONG_PASSWORD_OR_BAD_P12,
            ),
            (
                "b",
                b"not a p12".to_vec(),
                PASSWORD,
                ERROR_WRONG_PASSWORD_OR_BAD_P12,
            ),
            ("c", fx("rsa3072")?, PASSWORD, ERROR_UNSUPPORTED_KEY_TYPE),
            ("d", fx("ed25519")?, PASSWORD, ERROR_UNSUPPORTED_KEY_TYPE),
        ];
        for (n, (id, data, password, want)) in cases.iter().enumerate() {
            let got = r.import(id, data, password).await;
            assert_eq!(got, Err((*want).to_owned()), "{id}");
            assert_eq!(r.polkit_calls(), n + 1);
            assert_eq!(r.decoder_calls(), n + 1);
        }
        assert_ne!(ERROR_WRONG_PASSWORD_OR_BAD_P12, ERROR_UNSUPPORTED_KEY_TYPE);
        assert_ne!(ERROR_WRONG_PASSWORD_OR_BAD_P12, ERROR_POLKIT_DENIED);
        assert_ne!(ERROR_UNSUPPORTED_KEY_TYPE, ERROR_POLKIT_DENIED);
        assert_eq!(r.list().await?, Listed::new());
        Ok(())
    })
}

#[test]
fn import_asks_again_on_every_call() -> TestResult {
    block_on(async {
        let r = Rig::start(Answer::Yes).await?;
        assert!(r.import("a", EC_P12, PASSWORD).await.is_ok());
        assert_eq!(r.polkit_calls(), 1);
        assert!(r.import("x", RSA_P12, "wrong").await.is_err());
        assert_eq!(r.polkit_calls(), 2);
        assert!(r.import("b", RSA_P12, PASSWORD).await.is_ok());
        assert_eq!(r.polkit_calls(), 3);
        // Nothing is remembered: approve, then deny.
        assert!(r.import("c", EC_P12, PASSWORD).await.is_ok());
        r.f.set_answer(Answer::No);
        let got = r.import("e", EC_P12, PASSWORD).await;
        assert_eq!(got, Err(ERROR_POLKIT_DENIED.to_owned()));
        assert_eq!(r.polkit_calls(), 5);
        Ok(())
    })
}

#[test]
fn import_refusal_leaves_state_unchanged() -> TestResult {
    block_on(async {
        let r = Rig::start(Answer::Yes).await?;
        r.import("keep", EC_P12, PASSWORD).await?;
        let before = (r.list().await?, tree(r.f.store.dir())?);
        for (answer, want) in [
            (Answer::No, ERROR_POLKIT_DENIED),
            (Answer::Fail, ERROR_AUTHORIZATION_UNAVAILABLE),
        ] {
            r.f.set_answer(answer);
            let got = r.import("k", RSA_P12, PASSWORD).await;
            assert_eq!(got, Err(want.to_owned()));
            assert_eq!((r.list().await?, tree(r.f.store.dir())?), before);
        }
        r.f.set_answer(Answer::Yes);
        assert_eq!(r.import("k", RSA_P12, PASSWORD).await, Ok("rsa2048".into()));
        Ok(())
    })
}

#[test]
fn import_returns_the_key_type() -> TestResult {
    block_on(async {
        let r = Rig::start(Answer::Yes).await?;
        assert_eq!(r.import("r", RSA_P12, PASSWORD).await, Ok("rsa2048".into()));
        assert_eq!(
            r.import("e", EC_P12, PASSWORD).await,
            Ok("ecdsa-p256".into())
        );
        let listed = r.list().await?;
        let kinds: Vec<(&str, &str)> = listed
            .iter()
            .map(|(i, k, _)| (i.as_str(), k.as_str()))
            .collect();
        assert_eq!(kinds, vec![("e", "ecdsa-p256"), ("r", "rsa2048")]);
        let cert = custodiod::import::parse_p12(EC_P12, &SecretString::from(PASSWORD.to_owned()))?
            .certificate;
        assert_eq!(listed.first().map(|k| k.2.clone()), Some(cert));
        let signature = sign(&r.f.client, "e", CKM_ECDSA, &digest()).await?;
        assert_ne!(signature.len(), 0);
        Ok(())
    })
}
