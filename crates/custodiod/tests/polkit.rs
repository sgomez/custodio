//! polkit authorization against a private `dbus-daemon` with a fake polkit authority that
//! approves or denies on demand and records what it was asked.

use std::collections::HashMap;
use std::error::Error;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use custodiod::polkit::{AuthError, Authorizer, PolkitAuthorizer};
use zbus::OwnedVariant;
use zbus::connection::Builder;
use zbus::{Connection, block_on, interface};

type TestResult = Result<(), Box<dyn Error>>;

struct Bus {
    child: Child,
    address: String,
}

impl Bus {
    fn start() -> Result<Self, Box<dyn Error>> {
        let mut child = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .spawn()?;
        let mut address = String::new();
        BufReader::new(child.stdout.take().ok_or("no stdout")?).read_line(&mut address)?;
        Ok(Self {
            child,
            address: address.trim().to_owned(),
        })
    }

    async fn connect(&self) -> Result<Connection, Box<dyn Error>> {
        Ok(Builder::address(self.address.as_str()).build().await?)
    }
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Call {
    kind: String,
    name: String,
    action: String,
    details: usize,
    flags: u32,
    cancellation_id: String,
}

#[derive(Clone, Copy)]
enum Answer {
    Yes,
    No,
    Challenge,
    Fail,
}

struct FakePolkit {
    answer: Answer,
    calls: Arc<Mutex<Vec<Call>>>,
}

#[interface(name = "org.freedesktop.PolicyKit1.Authority")]
impl FakePolkit {
    // The `interface` macro needs owned argument types to deserialize the D-Bus message.
    #[allow(clippy::needless_pass_by_value)]
    fn check_authorization(
        &self,
        subject: (String, HashMap<String, OwnedVariant>),
        action_id: String,
        details: HashMap<String, String>,
        flags: u32,
        cancellation_id: String,
    ) -> zbus::fdo::Result<(bool, bool, HashMap<String, String>)> {
        let name = subject
            .1
            .get("name")
            .and_then(|v| <&str>::try_from(v).ok())
            .unwrap_or_default()
            .to_owned();
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(Call {
                kind: subject.0,
                name,
                action: action_id,
                details: details.len(),
                flags,
                cancellation_id,
            });
        }
        match self.answer {
            Answer::Yes => Ok((true, false, HashMap::new())),
            Answer::No => Ok((false, false, HashMap::new())),
            Answer::Challenge => Ok((false, true, HashMap::new())),
            Answer::Fail => Err(zbus::fdo::Error::Failed("boom".into())),
        }
    }
}

/// Results of each `authorize`, the calls the fake saw, and the client's bus name.
type Outcome = (Vec<Result<(), AuthError>>, Vec<Call>, String);

/// Starts a bus with the fake authority, calls `authorize` from a second connection.
fn run(answers: &[Answer]) -> Result<Outcome, Box<dyn Error>> {
    let bus = Bus::start()?;
    block_on(async {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut results = Vec::new();
        let client = bus.connect().await?;
        let sender = client
            .unique_name()
            .ok_or("no unique name")?
            .as_str()
            .to_owned();
        let authorizer = PolkitAuthorizer::new(client);
        for answer in answers {
            let server = bus.connect().await?;
            server
                .object_server()
                .at(
                    "/org/freedesktop/PolicyKit1/Authority",
                    FakePolkit {
                        answer: *answer,
                        calls: calls.clone(),
                    },
                )
                .await?;
            server.request_name("org.freedesktop.PolicyKit1").await?;
            results.push(authorizer.authorize(&sender).await);
            drop(server);
        }
        let calls = calls.lock().map_err(|_| "poisoned")?.clone();
        Ok((results, calls, sender))
    })
}

#[test]
fn approval_passes_and_request_is_well_formed() -> TestResult {
    let (results, calls, sender) = run(&[Answer::Yes])?;
    assert!(matches!(results.as_slice(), [Ok(())]));
    assert_eq!(
        calls,
        vec![Call {
            kind: "system-bus-name".into(),
            name: sender,
            action: "com.rfirma.custodio.sign".into(),
            details: 0,
            flags: 1,
            cancellation_id: String::new(),
        }]
    );
    Ok(())
}

#[test]
fn denial_challenge_and_errors_all_refuse() -> TestResult {
    let (results, _, _) = run(&[Answer::No, Answer::Challenge, Answer::Fail])?;
    assert!(matches!(
        results.as_slice(),
        [
            Err(AuthError::Denied),
            Err(AuthError::Denied),
            Err(AuthError::Unavailable(_))
        ]
    ));
    Ok(())
}

#[test]
fn every_signature_asks_again() -> TestResult {
    let (results, calls, _) = run(&[Answer::Yes, Answer::Yes, Answer::No])?;
    assert!(matches!(
        results.as_slice(),
        [Ok(()), Ok(()), Err(AuthError::Denied)]
    ));
    assert_eq!(calls.len(), 3);
    Ok(())
}

#[test]
fn no_polkit_on_the_bus_is_a_refusal() -> TestResult {
    let bus = Bus::start()?;
    let result = block_on(async {
        let client = bus.connect().await?;
        let sender = client.unique_name().ok_or("no name")?.to_string();
        Ok::<_, Box<dyn Error>>(PolkitAuthorizer::new(client).authorize(&sender).await)
    })?;
    assert!(matches!(result, Err(AuthError::Unavailable(_))));
    Ok(())
}

#[test]
fn bad_sender_never_reaches_polkit() -> TestResult {
    let bus = Bus::start()?;
    let result = block_on(async {
        let client = bus.connect().await?;
        Ok::<_, Box<dyn Error>>(
            PolkitAuthorizer::new(client)
                .authorize("org.freedesktop.DBus")
                .await,
        )
    })?;
    assert!(matches!(result, Err(AuthError::BadSender)));
    Ok(())
}
