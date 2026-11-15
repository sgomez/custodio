//! Sign, delete and replace a certificate for every storage kind (F118): the real service on a private bus with fake
//! polkit, a software TPM, and a credential double.
//!
//! The TPM and the credential service are the two access points the service takes; the lost and transient failures are
//! made through them (a cleared `swtpm`, a damaged blob, a faulty or absent TPM, a credential that cannot be decrypted).

use crate::bus;
use crate::case;
use crate::common;
#[path = "sign_kinds/failures.rs"]
mod failures;
use crate::kit;
use crate::rig;
#[path = "sign_kinds/signs.rs"]
mod signs;
