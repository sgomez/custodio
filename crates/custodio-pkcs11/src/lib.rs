//! Custodio PKCS#11 module.
//!
//! This is the only crate allowed to contain `unsafe` code (the PKCS#11 FFI layer).

/// Name of the module, reported in the token info.
pub const MODULE_NAME: &str = "custodio-pkcs11";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_name_is_stable() {
        assert_eq!(MODULE_NAME, "custodio-pkcs11");
    }
}
