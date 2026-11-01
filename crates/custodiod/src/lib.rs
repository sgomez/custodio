//! Custodio signing service.
#![forbid(unsafe_code)]

pub mod app_id;
pub mod audit;
pub mod credentials;
pub mod dbus;
pub mod error;
pub mod import;
mod offload;
pub mod polkit;
pub mod sign;
pub mod store;

/// Name of the service, used in logs and on the bus.
pub const SERVICE_NAME: &str = "custodiod";

#[cfg(test)]
mod tests;
