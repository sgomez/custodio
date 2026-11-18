//! The table of `custodio list` and the full view of `custodio list <id>`, against the real service on a
//! private `dbus-daemon` (the rig of `list.rs`): the weaker-storage note, the full view, the unknown id, and a
//! certificate whose subject and issuer are hostile text.

use custodio_cli::cert_text::fields;
use custodio_cli::list::WEAKER_NOTE;

mod list_rig;
use list_rig::{
    P256_HOSTILE, P256_OTHER_P12, P256_P12, RSA2048_P12, Rig, TestResult, expected_row, rows,
    view_values,
};

/// True if no byte of `text` is below 0x20 but a line end, and none is DEL.
fn only_layout_bytes(text: &str) -> bool {
    text.bytes().all(|b| (b >= 0x20 && b != 0x7f) || b == b'\n')
}

#[test]
fn the_weaker_storage_note_is_printed_exactly_once_at_the_foot() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("one", P256_P12)?;
    rig.import("two", RSA2048_P12)?;
    let listed = rig.list();
    assert_eq!(listed.status, 0);
    assert_eq!(
        listed.stdout.matches(WEAKER_NOTE).count(),
        1,
        "{}",
        listed.stdout
    );
    assert!(listed.stdout.ends_with(&format!("\n\n{WEAKER_NOTE}\n")));
    // The rows above it are the two keys.
    assert_eq!(rows(&listed.stdout).len(), 2);
    // `list <id>` and `list -v` are not the table: no note.
    assert!(!rig.show("one").stdout.contains(WEAKER_NOTE));
    assert!(!rig.list_verbose().stdout.contains(WEAKER_NOTE));
    Ok(())
}

#[test]
fn a_key_in_full_has_the_values_openssl_prints_for_its_certificate() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("work", P256_OTHER_P12)?;
    rig.import("other", RSA2048_P12)?;
    let asked = rig.polkit_calls();
    let shown = rig.show("work");
    assert_eq!(shown.status, 0);
    assert_eq!(shown.stderr, "");
    // `openssl x509 -noout -serial -fingerprint -sha256 -subject -issuer -startdate -enddate` of the same certificate.
    let (title, values) = view_values(&shown.stdout);
    assert_eq!(title, "work");
    let want = [
        "ecdsa-p256",
        "encrypted-host",
        "CN=custodio test p256-other",
        "CN=custodio test p256-other",
        "1A0DA9C946F9D0B76E0B1925A0550BE816DF3D21",
    ];
    assert_eq!(values[..5], want, "{}", shown.stdout);
    for (value, (day, time)) in values[5..7]
        .iter()
        .zip([("2026-10-27", "16:05:48"), ("2126-10-03", "16:05:48")])
    {
        assert!(value.contains(day) && value.contains(time), "{value}");
    }
    assert_eq!(
        values[7],
        "51:30:3C:19:FF:27:E3:D4:BC:4D:9A:80:56:59:DD:A6:AF:75:47:E3:C1:80:27:64:B8:58:3F:BD:0E:70:D6:42"
    );
    assert_eq!(values.len(), 8, "{}", shown.stdout);
    assert!(!shown.stdout.contains("rsa2048"), "only the asked key");
    assert_eq!(rig.polkit_calls(), asked, "list never asks polkit");
    Ok(())
}

#[test]
fn an_id_the_person_does_not_have_is_a_two_line_error_naming_list() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("work", P256_P12)?;
    let unknown = rig.show("nope");
    assert_eq!(unknown.status, 1);
    assert_eq!(unknown.stdout, "");
    assert_eq!(
        unknown.stderr,
        "custodio: you have no key with the id 'nope'\nRun 'custodio list' to see the ids of your keys.\n"
    );
    // Another person's key is not theirs to see either.
    rig.as_uid(4002);
    assert_eq!(rig.show("work").status, 1);
    // A hostile id is escaped, so it adds no line and no escape sequence.
    let hostile = rig.show("a\nforged line\x1b[31m\x7f");
    assert_eq!(hostile.status, 1);
    assert_eq!(hostile.stderr.lines().count(), 2, "{}", hostile.stderr);
    assert!(
        hostile.stderr.contains("a\\x0aforged line\\x1b[31m\\x7f"),
        "{}",
        hostile.stderr
    );
    assert!(only_layout_bytes(&hostile.stderr));
    Ok(())
}

#[test]
fn a_hostile_certificate_is_listed_escaped_with_one_row_per_key() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("evil", P256_OTHER_P12)?;
    rig.import("good", RSA2048_P12)?;
    // Same public key as the imported one, so the service accepts it.
    rig.replace_certificate("evil", P256_HOSTILE)?;

    let listed = rig.list();
    assert_eq!(listed.status, 0, "{}", listed.stderr);
    assert!(only_layout_bytes(&listed.stdout) && only_layout_bytes(&listed.stderr));
    let lines: Vec<&str> = listed
        .stdout
        .lines()
        .take_while(|l| !l.is_empty())
        .collect();
    assert_eq!(lines.len(), 2, "as many rows as keys: {}", listed.stdout);
    let table = rows(&listed.stdout);
    let hostile = fields(P256_HOSTILE);
    assert_eq!(
        table[0][..4],
        [
            "evil",
            "ecdsa-p256",
            "encrypted-host",
            hostile.subject_short.as_str()
        ]
    );
    assert_eq!(table[1][0], "good");
    assert_eq!(
        table,
        rig.keys().iter().map(expected_row).collect::<Vec<_>>()
    );
    let shown = rig.show("evil");
    assert_eq!(shown.status, 0, "{}", shown.stderr);
    assert!(only_layout_bytes(&shown.stdout) && only_layout_bytes(&shown.stderr));
    let (title, values) = view_values(&shown.stdout);
    assert_eq!(title, "evil");
    assert_eq!(values.len(), 8, "{}", shown.stdout);
    // The whole subject and issuer, escaped as the parser escapes them, each on its own line.
    assert_eq!(values[2], hostile.subject);
    assert_eq!(values[3], hostile.issuer);
    assert_eq!(values[4], hostile.serial);
    Ok(())
}

#[test]
fn verbose_shows_every_key_in_full_as_list_with_its_id_does() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("work", P256_OTHER_P12)?;
    rig.import("other", RSA2048_P12)?;
    let all = rig.list_verbose();
    assert_eq!(all.status, 0, "{}", all.stderr);
    let blocks: Vec<&str> = all.stdout.split("\n\n").collect();
    assert_eq!(blocks.len(), 2, "{}", all.stdout);
    for (block, id) in blocks.iter().zip(["other", "work"]) {
        assert_eq!(view_values(block).0, id);
        assert_eq!(format!("{}\n", block.trim_end()), rig.show(id).stdout);
    }
    Ok(())
}
