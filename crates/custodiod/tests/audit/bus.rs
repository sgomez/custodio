//! Private bus, fake polkit and the service under test.

use std::collections::HashMap;
use std::error::Error;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};

use custodiod::audit::AuditSink;
use custodiod::credentials::CallerCredentials;
use custodiod::dbus::{BUS_NAME, Custodio, OBJECT_PATH};
use custodiod::polkit::PolkitAuthorizer;
use custodiod::store::KeyStore;
use zbus::connection::Builder;
use zbus::{Connection, OwnedVariant, interface};

pub type TestResult = Result<(), Box<dyn Error>>;

pub struct Bus {
    child: Child,
    pub address: String,
}

impl Bus {
    pub fn start() -> Result<Self, Box<dyn Error>> {
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

    pub async fn connect(&self) -> Result<Connection, Box<dyn Error>> {
        Ok(Builder::address(self.address.as_str()).build().await?)
    }
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Clone, Copy)]
pub enum Answer {
    Yes,
    No,
    Challenge,
    Fail,
}

/// Fake polkit: answers as told and records the bus name of every subject.
pub struct FakePolkit {
    pub answer: Arc<Mutex<Answer>>,
    pub asked: Arc<Mutex<Vec<String>>>,
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
        let _ = (action_id, details, flags, cancellation_id);
        let name = subject
            .1
            .get("name")
            .and_then(|v| <&str>::try_from(v).ok())
            .unwrap_or_default()
            .to_owned();
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(name);
        let answer = *self.answer.lock().unwrap_or_else(PoisonError::into_inner);
        match answer {
            Answer::Yes => Ok((true, false, HashMap::new())),
            Answer::No => Ok((false, false, HashMap::new())),
            Answer::Challenge => Ok((false, true, HashMap::new())),
            Answer::Fail => Err(zbus::fdo::Error::Failed("boom".into())),
        }
    }
}

/// A bus with fake polkit, the service and a client.
pub struct Fixture {
    pub bus: Bus,
    pub _state: tempfile::TempDir,
    pub _store: Arc<KeyStore>,
    pub polkit: Connection,
    pub _service: Connection,
    pub client: Connection,
    pub answer: Arc<Mutex<Answer>>,
    pub asked: Arc<Mutex<Vec<String>>>,
}

impl Fixture {
    /// `credentials` is built from the service's connection.
    pub async fn start<C>(
        answer: Answer,
        credentials: impl FnOnce(&Connection) -> C,
        sink: Arc<dyn AuditSink>,
    ) -> Result<Self, Box<dyn Error>>
    where
        C: CallerCredentials + Send + Sync + 'static,
    {
        let bus = Bus::start()?;
        let answer = Arc::new(Mutex::new(answer));
        let asked = Arc::new(Mutex::new(Vec::new()));
        let polkit = bus.connect().await?;
        polkit
            .object_server()
            .at(
                "/org/freedesktop/PolicyKit1/Authority",
                FakePolkit {
                    answer: answer.clone(),
                    asked: asked.clone(),
                },
            )
            .await?;
        polkit.request_name("org.freedesktop.PolicyKit1").await?;

        let state = tempfile::tempdir()?;
        let store = Arc::new(KeyStore::open(state.path().join("keys"))?);
        let service = bus.connect().await?;
        let object = Custodio::new(
            store.clone(),
            PolkitAuthorizer::new(service.clone()),
            credentials(&service),
            sink,
        );
        service.object_server().at(OBJECT_PATH, object).await?;
        service.request_name(BUS_NAME).await?;
        let client = bus.connect().await?;
        Ok(Self {
            bus,
            _state: state,
            _store: store,
            polkit,
            _service: service,
            client,
            answer,
            asked,
        })
    }

    pub fn set_answer(&self, answer: Answer) {
        *self.answer.lock().unwrap_or_else(PoisonError::into_inner) = answer;
    }

    pub fn asked(&self) -> Vec<String> {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Calls a method of the service on `client`.
pub async fn call<B>(client: &Connection, method: &str, body: &B) -> zbus::Result<zbus::Message>
where
    B: zbus::export::serde::Serialize + zbus::zvariant::DynamicType,
{
    client
        .call_method(
            Some(BUS_NAME),
            OBJECT_PATH,
            Some("com.rfirma.Custodio1"),
            method,
            body,
        )
        .await
}

/// `Sign(id, mechanism, 0, 0, data)` on `client`; the signature or the error.
pub async fn sign(
    client: &Connection,
    id: &str,
    mechanism: u32,
    data: &[u8],
) -> zbus::Result<Vec<u8>> {
    let reply = call(client, "Sign", &(id, mechanism, 0u32, 0u32, data.to_vec())).await?;
    reply.body().deserialize()
}

pub fn error_name(e: &zbus::Error) -> String {
    match e {
        zbus::Error::MethodError(name, _, _) => name.as_str().to_owned(),
        other => format!("{other}")
            .split(": ")
            .next()
            .unwrap_or_default()
            .to_owned(),
    }
}
