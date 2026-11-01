//! polkit authorization. Every signature asks polkit; nothing is cached.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;

use zbus::Variant;
use zbus::names::UniqueName;
use zbus::{Connection, Message};

/// polkit action that guards every signature.
pub const ACTION_ID: &str = "com.rfirma.custodio.sign";
/// polkit action that guards every import of a `.p12`.
pub const IMPORT_ACTION_ID: &str = "com.rfirma.custodio.import-certificate";
/// polkit action that guards every deletion of a key.
pub const DELETE_ACTION_ID: &str = "com.rfirma.custodio.delete-certificate";
/// polkit action that guards every replacement of a key.
pub const REPLACE_ACTION_ID: &str = "com.rfirma.custodio.replace-certificate";

const POLKIT_NAME: &str = "org.freedesktop.PolicyKit1";
const POLKIT_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const POLKIT_INTERFACE: &str = "org.freedesktop.PolicyKit1.Authority";

/// `CheckAuthorizationFlags::AllowUserInteraction`.
const ALLOW_USER_INTERACTION: u32 = 1;

/// Why a call was not authorized.
#[derive(Debug)]
pub enum AuthError {
    /// The sender is not a unique D-Bus name such as `:1.42`.
    BadSender,
    /// polkit answered and refused (or needs an authentication it was not allowed to ask for).
    Denied,
    /// polkit could not be asked or its answer was not understood. Treated as a refusal.
    Unavailable(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadSender => f.write_str("sender is not a unique bus name"),
            Self::Denied => f.write_str("not authorized"),
            Self::Unavailable(why) => write!(f, "polkit unavailable: {why}"),
        }
    }
}

impl std::error::Error for AuthError {}

/// Decides whether the D-Bus sender may make one call under a polkit action. Tests use fakes.
pub trait Authorizer {
    /// Returns `Ok(())` only if the person approved this one call under `action`.
    fn authorize(
        &self,
        sender: &str,
        action: &str,
    ) -> impl Future<Output = Result<(), AuthError>> + Send;
}

/// Real polkit on the system bus (or any bus given to [`PolkitAuthorizer::new`]).
#[derive(Debug, Clone)]
pub struct PolkitAuthorizer {
    connection: Connection,
}

impl PolkitAuthorizer {
    #[must_use]
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }
}

/// Arguments of `CheckAuthorization`: subject, action, details, flags, cancellation id.
type Request<'a> = (
    (&'static str, HashMap<&'static str, Variant<'a>>),
    &'a str,
    HashMap<&'static str, &'static str>,
    u32,
    &'static str,
);

/// Builds the `CheckAuthorization` arguments for the sender: a `system-bus-name` subject, so
/// polkit resolves the caller itself, and `AllowUserInteraction`.
fn request<'a>(sender: &'a str, action: &'a str) -> Result<Request<'a>, AuthError> {
    // `UniqueName` also accepts some well-known-looking names, so require the `:` explicitly.
    if !sender.starts_with(':') || UniqueName::try_from(sender).is_err() {
        return Err(AuthError::BadSender);
    }
    let subject = (
        "system-bus-name",
        HashMap::from([("name", Variant::from(sender))]),
    );
    Ok((subject, action, HashMap::new(), ALLOW_USER_INTERACTION, ""))
}

/// Reads the `(is_authorized, is_challenge, details)` reply. Only a plain "authorized" passes.
fn interpret(reply: &Message) -> Result<(), AuthError> {
    let (authorized, _challenge, _details): (bool, bool, HashMap<String, String>) = reply
        .body()
        .deserialize()
        .map_err(|e| AuthError::Unavailable(e.to_string()))?;
    if authorized {
        Ok(())
    } else {
        Err(AuthError::Denied)
    }
}

impl Authorizer for PolkitAuthorizer {
    async fn authorize(&self, sender: &str, action: &str) -> Result<(), AuthError> {
        let body = request(sender, action)?;
        let reply = self
            .connection
            .call_method(
                Some(POLKIT_NAME),
                POLKIT_PATH,
                Some(POLKIT_INTERFACE),
                "CheckAuthorization",
                &body,
            )
            .await
            .map_err(|e| AuthError::Unavailable(e.to_string()))?;
        interpret(&reply)
    }
}

#[cfg(test)]
mod tests;
