//! `custodio list` on the documented API: the real service on a private `dbus-daemon`, a fake
//! polkit that counts its calls, and a credentials double that says which uid is calling.

use std::sync::atomic::Ordering;

use custodio_cli::cert_text::fields;
use custodio_cli::list::{NO_KEYS, NONE_HINT, WEAKER_NOTE};
use custodio_cli::{CliError, ListFailure, ServiceFailure};
use custodio_client::{BUS_NAME, OBJECT_PATH};

mod list_rig;
use list_rig::{
    P256_OTHER_P12, P256_P12, P256_RECERT, RSA2048_P12, Rig, TestResult, UID_A, UID_B, UID_C,
    expected_row, rows,
};

/// The rig has no TPM, so every key it imports is `encrypted-host`: the rows are followed by the one note.
fn ends_with_note(stdout: &str) -> bool {
    stdout.ends_with(&format!("\n\n{WEAKER_NOTE}\n"))
}

/// The ids and the (type, kind) of each row.
fn ids_types_kinds(stdout: &str) -> Vec<(String, String, String)> {
    rows(stdout)
        .into_iter()
        .map(|r| (r[0].clone(), r[1].clone(), r[2].clone()))
        .collect()
}

fn owned(rows: &[(&str, &str, &str)]) -> Vec<(String, String, String)> {
    rows.iter()
        .map(|(a, b, c)| ((*a).to_owned(), (*b).to_owned(), (*c).to_owned()))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

#[test]
fn several_keys_show_their_own_id_type_subject_and_end_of_validity() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("rsa", RSA2048_P12)?;
    rig.import("ec", P256_P12)?;
    // Another certificate for the same key: a different subject and a different end of validity.
    rig.replace_certificate("ec", P256_RECERT)?;
    let before = rig.polkit_calls();
    assert_eq!(before, 3, "the imports and the replace asked polkit");

    let listed = rig.list();
    assert!(listed.result.is_ok());
    assert_eq!(listed.status, 0);
    assert_eq!(listed.stderr, "");
    // Sorted by id; each key keeps its own subject and end of validity.
    assert_eq!(
        ids_types_kinds(&listed.stdout),
        owned(&[
            ("ec", "ecdsa-p256", "encrypted-host"),
            ("rsa", "rsa2048", "encrypted-host")
        ])
    );
    let recert = fields(P256_RECERT);
    let ec = &rows(&listed.stdout)[0];
    assert_eq!(ec[3], recert.subject_short, "the new certificate's subject");
    assert!(
        recert.not_after.starts_with(&ec[4]),
        "the new certificate's end"
    );
    assert!(ends_with_note(&listed.stdout), "{}", listed.stdout);
    assert!(!listed.stdout.contains(NO_KEYS));
    // Certificate bytes are read, never shown.
    assert!(!listed.stdout.contains(&hex(P256_RECERT)));
    assert!(!listed.stdout.contains(&hex(&P256_RECERT[..32])));
    // Asking again gives the same list, and polkit is never asked by `list`.
    assert_eq!(rig.list().stdout, listed.stdout);
    assert_eq!(rig.polkit_calls(), before);
    Ok(())
}

#[test]
fn no_keys_says_so_with_status_0_and_nothing_on_stderr() -> TestResult {
    let rig = Rig::start(true)?;
    let listed = rig.list();
    assert!(listed.result.is_ok());
    assert_eq!(listed.status, 0);
    assert_eq!(listed.stdout, format!("{NO_KEYS}\n{NONE_HINT}\n"));
    assert_eq!(listed.stderr, "");
    assert_eq!(rig.polkit_calls(), 0);
    Ok(())
}

#[test]
fn a_service_error_shows_the_message_of_its_name_and_no_key_line() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("ec", P256_P12)?;
    let asked = rig.polkit_calls();
    // The caller cannot be identified: the service answers AuthorizationUnavailable, never a list.
    rig.broken.store(true, Ordering::SeqCst);
    let listed = rig.list();
    assert!(matches!(
        listed.result,
        Err(CliError::List(ListFailure::Service(
            ServiceFailure::AuthorizationUnavailable
        )))
    ));
    assert_eq!(listed.status, 1);
    assert_eq!(listed.stdout, "");
    assert!(
        listed
            .stderr
            .contains(&ServiceFailure::AuthorizationUnavailable.message())
    );
    assert!(!listed.stderr.contains("ec "));
    assert_eq!(rig.polkit_calls(), asked);
    Ok(())
}

#[test]
fn an_unavailable_service_is_status_1_with_the_cannot_talk_message() -> TestResult {
    let rig = Rig::start(false)?;
    let listed = rig.list();
    assert!(matches!(
        listed.result,
        Err(CliError::List(ListFailure::Service(
            ServiceFailure::ServiceAbsent
        )))
    ));
    assert_eq!(listed.status, 1);
    assert_eq!(listed.stdout, "");
    assert!(
        listed.stderr.contains("cannot talk to the service"),
        "{}",
        listed.stderr
    );
    Ok(())
}

#[test]
fn two_uids_see_only_their_own_keys_even_with_the_same_id() -> TestResult {
    let rig = Rig::start(true)?;
    rig.as_uid(UID_A);
    rig.import("shared", P256_P12)?;
    rig.import("only-a", RSA2048_P12)?;
    rig.as_uid(UID_B);
    rig.import("shared", P256_OTHER_P12)?;
    let asked = rig.polkit_calls();
    assert_eq!(asked, 3);

    rig.as_uid(UID_A);
    let a = rig.list();
    rig.as_uid(UID_B);
    let b = rig.list();
    assert_eq!(
        ids_types_kinds(&a.stdout),
        owned(&[
            ("only-a", "rsa2048", "encrypted-host"),
            ("shared", "ecdsa-p256", "encrypted-host")
        ])
    );
    assert_eq!(
        ids_types_kinds(&b.stdout),
        owned(&[("shared", "ecdsa-p256", "encrypted-host")])
    );
    assert!(ends_with_note(&a.stdout) && ends_with_note(&b.stdout));
    // The same id, two people: each row is the certificate of that person's own key.
    assert_ne!(rows(&a.stdout)[1][3], rows(&b.stdout)[0][3]);
    let asked_before_truth = rig.polkit_calls();
    rig.as_uid(UID_A);
    assert_eq!(
        rows(&a.stdout),
        rig.keys().iter().map(expected_row).collect::<Vec<_>>()
    );
    rig.as_uid(UID_B);
    assert_eq!(
        rows(&b.stdout),
        rig.keys().iter().map(expected_row).collect::<Vec<_>>()
    );
    assert_eq!(rig.polkit_calls(), asked_before_truth);
    rig.as_uid(UID_C);
    let c = rig.list();
    assert_eq!(c.stdout, format!("{NO_KEYS}\n{NONE_HINT}\n"));
    assert_eq!((a.status, b.status, c.status), (0, 0, 0));
    assert_eq!(
        rig.polkit_calls(),
        asked,
        "three lists asked polkit nothing"
    );
    Ok(())
}

#[test]
fn list_makes_exactly_one_call_list_keys_without_arguments() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("ec", P256_P12)?;
    let imports = rig.calls(1).len();
    let listed = rig.list();
    assert_eq!(listed.status, 0);
    let all = rig.calls(imports + 1);
    let calls: Vec<_> = all[imports..]
        .iter()
        .filter(|c| c.0 == BUS_NAME || c.3 == "ListKeys" || c.1 == OBJECT_PATH)
        .cloned()
        .collect();
    let want = (
        BUS_NAME.to_owned(),
        OBJECT_PATH.to_owned(),
        BUS_NAME.to_owned(),
        "ListKeys".to_owned(),
        String::new(),
    );
    assert_eq!(calls, [want]);
    // Nothing else of any kind went to polkit or the service during the list.
    assert_eq!(all.len(), imports + 1, "{:?}", &all[imports..]);
    Ok(())
}
