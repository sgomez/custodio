//! `a_current_service_answers_the_pinned_calls` (F178): the real service on both transports against the pin of
//! `module_compat.rs`.

use std::error::Error;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use custodio_client::{BUS_NAME, OBJECT_PATH};
use custodiod::audit::{Caller, MemorySink};
use custodiod::credentials::{CallerCredentials, CredentialsError};
use custodiod::creds::memory::MemoryCreds;
use custodiod::dbus::Custodio;
use custodiod::polkit::{AuthError, Authorizer};
use zbus::block_on;
use zbus::connection::{AuthMechanism, Builder};

use super::snap_rig::{self, Answer as PolkitAnswer, Rig, TestResult, UID};
use super::{ERRORS, PINNED};

struct Allow(Arc<AtomicBool>);

impl Authorizer for Allow {
    fn authorize(
        &self,
        _sender: &str,
        _action: &str,
    ) -> impl Future<Output = Result<(), AuthError>> + Send {
        std::future::ready(if self.0.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(AuthError::Denied)
        })
    }
}

struct FixedCaller;

impl CallerCredentials for FixedCaller {
    fn credentials(
        &self,
        _sender: &str,
    ) -> impl Future<Output = Result<Caller, CredentialsError>> + Send {
        std::future::ready(Ok(Caller {
            uid: UID,
            pid: std::process::id(),
        }))
    }
}

/// The `in` and `out` argument types of `method` in introspection XML.
fn signature_of(xml: &str, method: &str) -> Result<(String, String), Box<dyn Error>> {
    let start = xml
        .find(&format!("<method name=\"{method}\""))
        .ok_or("method not introspected")?;
    let body = &xml[start..start + xml[start..].find("</method>").ok_or("unclosed")?];
    let types = |direction: &str| -> String {
        body.split("<arg ")
            .skip(1)
            .filter(|a| a.contains(&format!("direction=\"{direction}\"")))
            .filter_map(|a| a.split("type=\"").nth(1)?.split('"').next())
            .collect()
    };
    Ok((types("in"), types("out")))
}

/// What the service says and answers on one connection: introspection, reply signatures, error names.
/// `polkit(true)` makes the next signature allowed, `polkit(false)` refuses it.
fn ask_the_service(
    client: &zbus::Connection,
    destination: Option<&str>,
    polkit: &dyn Fn(bool),
) -> TestResult {
    fn call<B: zbus::export::serde::Serialize + zbus::zvariant::DynamicType>(
        client: &zbus::Connection,
        destination: Option<&str>,
        iface: &str,
        member: &str,
        body: &B,
    ) -> zbus::Result<zbus::Message> {
        block_on(client.call_method(destination, OBJECT_PATH, Some(iface), member, body))
    }
    let sign = |id: &str, mechanism: u32| {
        call(
            client,
            destination,
            BUS_NAME,
            "Sign",
            &(id, mechanism, 0u32, 0u32, &[7u8; 32][..]),
        )
    };
    let name_of = |r: zbus::Result<zbus::Message>| match r {
        Err(zbus::Error::MethodError(name, _, _)) => Ok(name.as_str().to_owned()),
        other => Err(format!("not an error reply: {other:?}")),
    };
    // Introspection says the pinned argument and reply types.
    let xml: String = call(
        client,
        destination,
        "org.freedesktop.DBus.Introspectable",
        "Introspect",
        &(),
    )?
    .body()
    .deserialize()?;
    for pin in PINNED {
        assert_eq!(
            signature_of(&xml, pin.3)?,
            (pin.4.to_owned(), pin.5.to_owned()),
            "{}",
            pin.3
        );
    }
    // The replies carry them.
    let listed = call(client, destination, BUS_NAME, "ListKeys", &())?;
    assert_eq!(listed.body().signature().to_string(), PINNED[0].5);
    polkit(true);
    let signed = sign("ec", 0x1041)?;
    assert_eq!(signed.body().signature().to_string(), PINNED[1].5);
    // The error names the module maps are the ones the service gives.
    polkit(false);
    assert_eq!(name_of(sign("ec", 0x1041))?, ERRORS[0].0);
    polkit(true);
    assert_eq!(name_of(sign("ec", 0xdead_beef))?, ERRORS[1].0);
    polkit(true);
    assert_eq!(name_of(sign("nobody", 0x1041))?, ERRORS[2].0);
    Ok(())
}

/// The real service, on both transports, answers what the pinned calls expect: introspected types, reply signatures
/// and error names. It fails the day the service changes one of them without the pin being edited.
#[test]
fn a_current_service_answers_the_pinned_calls() -> TestResult {
    // The snap socket.
    let rig = Rig::start("firefox", 0o700)?;
    let stream = std::os::unix::net::UnixStream::connect(
        rig.base.path().join("snap.firefox/custodio.sock"),
    )?;
    let client = block_on(
        Builder::unix_stream(stream)
            .p2p()
            .auth_mechanism(AuthMechanism::Anonymous)
            .build(),
    )?;
    ask_the_service(&client, None, &|yes| {
        rig.answers(&[if yes {
            PolkitAnswer::Yes
        } else {
            PolkitAnswer::No
        }]);
    })?;
    // The bus: the `Custodio` object owning the service's name on a private bus.
    let bus = snap_rig::polkit::Bus::start()?;
    let (_dir, store) = snap_rig::make_store()?;
    let allow = Arc::new(AtomicBool::new(true));
    let (_service, client) = block_on(async {
        let service = bus.connect().await?;
        let object = Custodio::new(
            store,
            Allow(Arc::clone(&allow)),
            FixedCaller,
            Arc::new(MemorySink::default()),
        )
        .with_key_credentials(Arc::new(MemoryCreds::host()));
        service.object_server().at(OBJECT_PATH, object).await?;
        service.request_name(BUS_NAME).await?;
        Ok::<_, Box<dyn Error>>((service, bus.connect().await?))
    })?;
    ask_the_service(&client, Some(BUS_NAME), &|yes| {
        allow.store(yes, Ordering::SeqCst);
    })?;
    Ok(())
}
