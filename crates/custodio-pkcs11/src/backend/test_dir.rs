//! The base directory of the snap socket, overridable for tests. Compiled only with the `test-socket-dir` feature,
//! which no shipped build enables; `scripts/check-test-socket-dir.sh` proves it.
use std::path::PathBuf;

/// The variable a test sets to replace `/run`.
pub const BASE_DIR_VAR: &str = "CUSTODIO_TEST_SOCKET_BASE_DIR";

pub fn base_dir() -> Option<PathBuf> {
    std::env::var_os(BASE_DIR_VAR).map(PathBuf::from)
}
