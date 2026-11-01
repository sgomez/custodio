//! What the clients (`custodio-cli`, `custodio-pkcs11`) and the service (`custodiod`) agree on.
//!
//! Only the bus name, the object path and the documented bounds live here, so the clients never
//! link the service.
#![forbid(unsafe_code)]

/// Well-known bus name of the service.
pub const BUS_NAME: &str = "com.rfirma.Custodio1";
/// Object path of the service.
pub const OBJECT_PATH: &str = "/com/rfirma/Custodio1";
/// Largest `.p12` accepted. Real files are a few kilobytes.
pub const MAX_P12_LEN: usize = 1024 * 1024;
