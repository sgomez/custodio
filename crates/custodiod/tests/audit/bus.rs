//! Private bus, fake polkit and the service under test.

use std::collections::HashMap;
use std::error::Error;
use std::future::Future;
use std::io::{BufRead, BufReader};
use std::pin::Pin;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use custodiod::audit::AuditSink;
use custodiod::credentials::CallerCredentials;
use custodiod::dbus::{BUS_NAME, Custodio, OBJECT_PATH};
use custodiod::import::P12Decoder;
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
        // Not a plain `Command`: the daemon would inherit other tests' TPM connections (`custodio_it::spawn`).
        let mut child = custodio_it::spawn::closed_fds("dbus-daemon")
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

/// A callback the polkit double runs on every request, after it has recorded it.
pub type Hook = Arc<dyn Fn() + Send + Sync>;

/// Pending once, then ready: lets the other tasks of the executor run without a timer.
struct YieldNow(bool);

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            return Poll::Ready(());
        }
        self.0 = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// How long the double holds a request for the others before it gives up.
const HOLD_LIMIT: Duration = Duration::from_secs(10);

/// Fake polkit: answers as told and records the bus name of every subject.
pub struct FakePolkit {
    pub answer: Arc<Mutex<Answer>>,
    pub asked: Arc<Mutex<Vec<String>>>,
    /// `(action id, flags)` of every request.
    pub requests: Arc<Mutex<Vec<(String, u32)>>>,
    /// When not 0, a request is not answered until this many have arrived (or `HOLD_LIMIT` passed,
    /// then it fails), so concurrent calls are all past polkit before any of them goes on.
    pub hold: Arc<AtomicUsize>,
    pub hook: Arc<Mutex<Option<Hook>>>,
}

#[interface(name = "org.freedesktop.PolicyKit1.Authority")]
impl FakePolkit {
    // The `interface` macro needs owned argument types to deserialize the D-Bus message.
    #[allow(clippy::needless_pass_by_value)]
    async fn check_authorization(
        &self,
        subject: (String, HashMap<String, OwnedVariant>),
        action_id: String,
        details: HashMap<String, String>,
        flags: u32,
        cancellation_id: String,
    ) -> zbus::fdo::Result<(bool, bool, HashMap<String, String>)> {
        let _ = (details, cancellation_id);
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((action_id, flags));
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
        let hook = self
            .hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(hook) = hook {
            hook();
        }
        let start = Instant::now();
        // `hold` is read again at every turn, so a test can let a held request go by setting it to 0.
        while self.hold.load(Ordering::SeqCst) > 0
            && self.asked.lock().map_or(0, |a| a.len()) < self.hold.load(Ordering::SeqCst)
        {
            if start.elapsed() > HOLD_LIMIT {
                return Err(zbus::fdo::Error::Failed("held too long".into()));
            }
            YieldNow(false).await;
        }
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
    pub store: Arc<KeyStore>,
    pub polkit: Connection,
    pub _service: Connection,
    pub client: Connection,
    pub answer: Arc<Mutex<Answer>>,
    pub asked: Arc<Mutex<Vec<String>>>,
    // Read by `tests/import_polkit.rs`, which includes this file; the other test files do not need it.
    #[allow(dead_code)]
    pub requests: Arc<Mutex<Vec<(String, u32)>>>,
    // Used by `tests/import_audit.rs`, which includes this file.
    #[allow(dead_code)]
    pub hold: Arc<AtomicUsize>,
    #[allow(dead_code)]
    pub hook: Arc<Mutex<Option<Hook>>>,
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
        Self::start_with(answer, credentials, sink, None).await
    }

    /// As [`Fixture::start`], with a replacement `.p12` decoder.
    pub async fn start_with<C>(
        answer: Answer,
        credentials: impl FnOnce(&Connection) -> C,
        sink: Arc<dyn AuditSink>,
        decoder: Option<Arc<dyn P12Decoder>>,
    ) -> Result<Self, Box<dyn Error>>
    where
        C: CallerCredentials + Send + Sync + 'static,
    {
        Self::start_full(answer, credentials, sink, decoder, None).await
    }

    /// As [`Fixture::start`], with a source that answers a read app-id (`org.example.App`), so the
    /// entries carry the id field.
    pub async fn start_reading<C>(
        answer: Answer,
        credentials: impl FnOnce(&Connection) -> C,
        sink: Arc<dyn AuditSink>,
    ) -> Result<Self, Box<dyn Error>>
    where
        C: CallerCredentials + Send + Sync + 'static,
    {
        let fake = custodiod::app_id_source::FakeAppIdSource::reading("org.example.App")
            .ok_or("fake source")?;
        let source = custodiod::app_id_source::GuardedSource::new(fake);
        Self::start_full(answer, credentials, sink, None, Some(source)).await
    }

    /// As [`Fixture::start_with`], with an app-id source (already guarded).
    pub async fn start_full<C>(
        answer: Answer,
        credentials: impl FnOnce(&Connection) -> C,
        sink: Arc<dyn AuditSink>,
        decoder: Option<Arc<dyn P12Decoder>>,
        source: Option<custodiod::app_id_source::GuardedSource>,
    ) -> Result<Self, Box<dyn Error>>
    where
        C: CallerCredentials + Send + Sync + 'static,
    {
        let bus = Bus::start()?;
        let answer = Arc::new(Mutex::new(answer));
        let asked = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let hold = Arc::new(AtomicUsize::new(0));
        let hook = Arc::new(Mutex::new(None));
        let polkit = bus.connect().await?;
        polkit
            .object_server()
            .at(
                "/org/freedesktop/PolicyKit1/Authority",
                FakePolkit {
                    answer: answer.clone(),
                    asked: asked.clone(),
                    requests: requests.clone(),
                    hold: hold.clone(),
                    hook: hook.clone(),
                },
            )
            .await?;
        polkit.request_name("org.freedesktop.PolicyKit1").await?;

        let state = tempfile::tempdir()?;
        let store = Arc::new(KeyStore::open(state.path().join("keys"))?);
        let service = bus.connect().await?;
        let mut object = Custodio::new(
            store.clone(),
            PolkitAuthorizer::new(service.clone()),
            credentials(&service),
            sink,
        )
        .with_key_credentials(std::sync::Arc::new(
            custodiod::creds::memory::MemoryCreds::host(),
        ));
        if let Some(decoder) = decoder {
            object = object.with_decoder(decoder);
        }
        if let Some(source) = source {
            object = object.with_guarded_app_id_source(source);
        }
        service.object_server().at(OBJECT_PATH, object).await?;
        service.request_name(BUS_NAME).await?;
        let client = bus.connect().await?;
        Ok(Self {
            bus,
            _state: state,
            store,
            polkit,
            _service: service,
            client,
            answer,
            asked,
            requests,
            hold,
            hook,
        })
    }

    // Used by `tests/errors.rs`, which includes this file; the audit tests do not need it.
    #[allow(dead_code)]
    pub fn store_dir(&self) -> &std::path::Path {
        self.store.dir()
    }

    pub fn set_answer(&self, answer: Answer) {
        *self.answer.lock().unwrap_or_else(PoisonError::into_inner) = answer;
    }

    // Used by `tests/import_audit.rs`, which includes this file.
    #[allow(dead_code)]
    /// Runs `hook` at every polkit request, while the request is being answered.
    pub fn on_request(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self.hook.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(hook));
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
