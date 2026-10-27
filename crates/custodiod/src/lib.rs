//! Custodio signing service.
#![forbid(unsafe_code)]

pub mod import;
pub mod store;

/// Name of the service, used in logs and on the bus.
pub const SERVICE_NAME: &str = "custodiod";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_name_is_stable() {
        assert_eq!(SERVICE_NAME, "custodiod");
    }
}
