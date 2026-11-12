//! Custodio signing service.
#![forbid(unsafe_code)]

// The `test-seam` feature lets the directory check be pointed at another directory. It must never reach a shipped
// binary: it is switched on only by the dev-dependency on this crate, and does not build in release.
#[cfg(all(feature = "test-seam", not(debug_assertions)))]
compile_error!(
    "feature `test-seam` changes which directory the snap socket check inspects and must not be built in release"
);

pub mod app_id;
pub mod app_id_source;
pub mod audit;
pub mod credentials;
pub mod creds;
pub mod dbus;
pub mod error;
pub mod import;
mod offload;
pub mod polkit;
pub mod sign;
pub mod snap_socket;
pub mod startup;
pub mod store;
pub mod tpm;

/// Name of the service, used in logs and on the bus.
pub const SERVICE_NAME: &str = "custodiod";

#[cfg(test)]
mod tests;
