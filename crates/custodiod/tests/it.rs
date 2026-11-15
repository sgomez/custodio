//! The integration tests of the service in one binary: one link per build (and per mutant) instead of one per file.
//! `fd_leak` stays a binary of its own: it counts the descriptors of its process; `import_split` is one too (F195).

// Support shared by several of the modules below, compiled once.
#[path = "audit/bus.rs"]
mod bus;
#[path = "sign_kinds/case.rs"]
mod case;
#[path = "audit/common.rs"]
mod common;
#[path = "audit/deadline.rs"]
mod deadline;
#[path = "creds/env.rs"]
mod env;
#[path = "sign_kinds/kit.rs"]
mod kit;
#[path = "tpm_sign/oracle.rs"]
mod oracle;
#[path = "storage_choice/rig.rs"]
mod rig;
#[path = "audit/scan.rs"]
mod scan;
#[path = "snap_socket_sign/polkit.rs"]
mod snap_polkit;
#[path = "tpm_import/support.rs"]
mod support;

#[path = "api_contract.rs"]
mod api_contract;
#[path = "api_kind.rs"]
mod api_kind;
#[path = "app_id_audit.rs"]
mod app_id_audit;
#[path = "audit.rs"]
mod audit;
#[path = "creds.rs"]
mod creds;
#[path = "dbus.rs"]
mod dbus;
#[path = "delete.rs"]
mod delete;
#[path = "delete_audit.rs"]
mod delete_audit;
#[path = "errors.rs"]
mod errors;
#[path = "import.rs"]
mod import;
#[path = "import_audit.rs"]
mod import_audit;
#[path = "import_polkit.rs"]
mod import_polkit;
#[path = "kind_audit.rs"]
mod kind_audit;
#[path = "kinds_suite.rs"]
mod kinds_suite;
#[path = "no_plaintext.rs"]
mod no_plaintext;
#[path = "owners.rs"]
mod owners;
#[path = "peer_label.rs"]
mod peer_label;
#[path = "policy.rs"]
mod policy;
#[path = "polkit.rs"]
mod polkit;
#[path = "purge.rs"]
mod purge;
#[path = "replace.rs"]
mod replace;
#[path = "replace_audit.rs"]
mod replace_audit;
#[path = "sign.rs"]
mod sign;
#[path = "sign_kinds.rs"]
mod sign_kinds;
#[path = "snap_socket_dir.rs"]
mod snap_socket_dir;
#[path = "snap_socket_limits.rs"]
mod snap_socket_limits;
#[path = "snap_socket_peer.rs"]
mod snap_socket_peer;
#[path = "snap_socket_sign.rs"]
mod snap_socket_sign;
#[path = "snap_socket_surface.rs"]
mod snap_socket_surface;
#[path = "state_format.rs"]
mod state_format;
#[path = "storage_choice.rs"]
mod storage_choice;
#[path = "tpm_access.rs"]
mod tpm_access;
#[path = "tpm_duplicate.rs"]
mod tpm_duplicate;
#[path = "tpm_import.rs"]
mod tpm_import;
#[path = "tpm_lifecycle.rs"]
mod tpm_lifecycle;
#[path = "tpm_resources.rs"]
mod tpm_resources;
#[path = "tpm_sign.rs"]
mod tpm_sign;

/// With `autotests = false` a file that is not listed above is never compiled, and its tests never run.
#[test]
fn every_test_file_is_a_module_here() -> Result<(), Box<dyn std::error::Error>> {
    let listed = include_str!("it.rs");
    for entry in std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/tests"))? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if path.extension().is_some_and(|e| e == "rs")
            && name != "it.rs"
            && name != "fd_leak.rs"
            && name != "import_split.rs"
            && name != "state_storage.rs"
            && name != "storage_api.rs"
            && name != "storage_stability.rs"
        {
            assert!(
                listed.contains(&format!("#[path = \"{name}\"]")),
                "{name} is not a module of tests/it.rs"
            );
        }
    }
    Ok(())
}
