//! Sign, delete and replace a certificate for every storage kind (F118): the real service on a private bus with fake
//! polkit, a software TPM, the real `systemd-creds` where a row needs it and a credential double elsewhere.
//!
//! The TPM and the credential service are the two access points the service takes; the lost and transient failures are
//! made through them (a cleared `swtpm`, a damaged blob, a faulty or absent TPM, a credential that cannot be decrypted).

// The shared helpers are used in full by other tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/bus.rs"]
mod bus;
// The shared helpers are used in full by other tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/common.rs"]
mod common;
// Shared with `creds`: this target does not use every helper of it.
#[path = "sign_kinds/case.rs"]
mod case;
// Shared with `creds`: this target does not use every helper of it.
#[path = "sign_kinds/descriptor.rs"]
mod descriptor;
#[allow(dead_code)]
#[path = "creds/env.rs"]
mod env;
#[path = "sign_kinds/failures.rs"]
mod failures;
#[path = "sign_kinds/kit.rs"]
mod kit;
// Shared with `tpm_sign`: this target does not use every helper of it.
#[allow(dead_code)]
#[path = "tpm_sign/oracle.rs"]
mod oracle;
#[path = "sign_kinds/real.rs"]
mod real;
// Shared with `storage_choice`: this target does not use every helper of it.
#[allow(dead_code)]
#[path = "storage_choice/rig.rs"]
mod rig;
#[path = "sign_kinds/signs.rs"]
mod signs;
// Shared with `tpm_import`: this target does not use every helper of it.
#[allow(dead_code)]
#[path = "tpm_import/support.rs"]
mod support;
