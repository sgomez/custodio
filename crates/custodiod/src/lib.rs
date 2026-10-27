//! Custodio signing service.
#![forbid(unsafe_code)]

pub mod dbus;
pub mod import;
pub mod polkit;
pub mod sign;
pub mod store;

/// Name of the service, used in logs and on the bus.
pub const SERVICE_NAME: &str = "custodiod";

#[cfg(test)]
mod tests;
