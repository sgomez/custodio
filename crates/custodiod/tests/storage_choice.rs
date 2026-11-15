//! The storage kind chosen at import and the fail-closed rule (F117): the real import path on a private bus with fake
//! polkit, a software TPM (ready, lacking, faulty or absent) and a credential double.
//!
//! The TPM and the credential service are the two access points the service takes; every reason is injected through
//! them. The store, the journal and the TPM are read back afterwards.

use crate::bus;
use crate::common;
#[path = "storage_choice/fails_closed.rs"]
mod fails_closed;
#[path = "storage_choice/kinds.rs"]
mod kinds;
#[path = "storage_choice/order.rs"]
mod order;
use crate::rig;
#[path = "storage_choice/row.rs"]
mod row;
