//! A read app-id for the queries of `docs/audit.md`.

use super::*;

/// A read app-id, so that the entries carry every field.
pub(super) fn app() -> AppIdOutcome {
    crate::app_id::validate(b"org.example.App")
        .map_or(AppIdOutcome::Undetermined, AppIdOutcome::Read)
}
