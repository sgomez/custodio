#![forbid(unsafe_code)]

use super::*;

#[test]
fn module_name_is_stable() {
    assert_eq!(MODULE_NAME, "custodio-pkcs11");
}
