use super::*;
use crate::{ArgError, Command, ImportArgs, help, parse_command};
use std::time::{Duration, SystemTime};

const P256: &[u8] = include_bytes!("../../../custodio-it/tests/fixtures/cert-p256-other.der");
const RSA: &[u8] = include_bytes!("../../../custodio-it/tests/fixtures/cert-rsa3072.der");

/// A lister that allows exactly one `ListKeys` call: a second one fails the test.
struct Fixed(Result<Vec<KeyEntry>, ServiceFailure>, std::cell::Cell<u32>);

impl Fixed {
    fn new(reply: Result<Vec<KeyEntry>, ServiceFailure>) -> Self {
        Self(reply, std::cell::Cell::new(0))
    }
}

impl KeyLister for Fixed {
    fn list_keys(&self) -> Result<Vec<KeyEntry>, ServiceFailure> {
        self.1.set(self.1.get() + 1);
        assert_eq!(self.1.get(), 1, "ListKeys is the only call, and only once");
        self.0.clone()
    }
}

fn key(id: &str, key_type: &str, der: &[u8]) -> KeyEntry {
    of_kind(id, key_type, Kind::Tpm, der)
}

fn of_kind(id: &str, key_type: &str, kind: Kind, der: &[u8]) -> KeyEntry {
    KeyEntry {
        id: id.into(),
        key_type: key_type.into(),
        kind,
        certificate: der.to_vec(),
    }
}

/// A time well before the fixtures expire, so no mark is shown unless a test sets one.
fn now() -> SystemTime {
    std::time::UNIX_EPOCH + Duration::from_hours(500_000)
}

fn run(lister: &Fixed) -> (Result<(), ListFailure>, String) {
    run_with(lister, Look::plain(now()), false)
}

fn run_with(lister: &Fixed, look: Look, verbose: bool) -> (Result<(), ListFailure>, String) {
    let mut out = Vec::new();
    let result = run_list(lister, &mut out, look, verbose);
    (result, String::from_utf8_lossy(&out).into_owned())
}

const HOSTILE: &[u8] =
    include_bytes!("../../../custodio-it/tests/fixtures/cert-p256-other-hostile.der");

fn show(lister: &Fixed, id: &str) -> (Result<(), ListFailure>, String) {
    let mut out = Vec::new();
    let result = run_show(lister, id, &mut out, Look::plain(now()));
    (result, String::from_utf8_lossy(&out).into_owned())
}

/// The cells of a row: the text between runs of two or more spaces.
fn cells(row: &str) -> Vec<String> {
    let mut cells = Vec::new();
    let mut rest = row;
    while let Some(at) = rest.find("  ") {
        cells.push(rest[..at].to_owned());
        rest = rest[at..].trim_start_matches(' ');
    }
    if !rest.is_empty() {
        cells.push(rest.to_owned());
    }
    cells
}

/// The row a key must have: id, type, kind, short subject, the day of its end of validity.
fn expected_row(k: &KeyEntry) -> Vec<String> {
    let f = fields(&k.certificate);
    vec![
        escape(&k.id),
        escape(&k.key_type),
        escape(k.kind.wire()),
        f.subject_short,
        f.not_after.split('T').next().unwrap_or_default().to_owned(),
    ]
}

#[test]
fn keys_are_rows_sorted_by_id_with_the_cells_of_their_certificate() {
    let keys = vec![key("bb", "rsa2048", RSA), key("a", "ecdsa-p256", P256)];
    let (result, out) = run(&Fixed::new(Ok(keys.clone())));
    assert!(result.is_ok());
    let rows: Vec<Vec<String>> = out.lines().map(cells).collect();
    assert_eq!(
        rows,
        [expected_row(&keys[1]), expected_row(&keys[0])],
        "{out}"
    );
    let starts: Vec<Vec<usize>> = out.lines().map(rows_starts).collect();
    assert!(
        starts.windows(2).all(|w| w[0] == w[1]),
        "not aligned:\n{out}"
    );
    assert!(!out.contains(NO_KEYS));
    assert!(!out.contains(WEAKER_NOTE));
}

/// Where each cell of a row starts.
fn rows_starts(row: &str) -> Vec<usize> {
    let mut starts = vec![0];
    let mut i = 0;
    let b = row.as_bytes();
    while i + 1 < b.len() {
        if b[i] == b' ' && b[i + 1] == b' ' {
            while i < b.len() && b[i] == b' ' {
                i += 1;
            }
            starts.push(i);
        } else {
            i += 1;
        }
    }
    starts
}

#[test]
fn a_header_row_comes_first_on_a_terminal_only_and_colour_only_adds_escapes() {
    let keys = vec![key("bb", "rsa2048", RSA), key("a", "ecdsa-p256", P256)];
    let plain = run_with(&Fixed::new(Ok(keys.clone())), Look::plain(now()), false).1;
    let terminal = Look {
        terminal: true,
        ..Look::plain(now())
    };
    let with_header = run_with(&Fixed::new(Ok(keys.clone())), terminal, false).1;
    let mut lines = with_header.lines();
    assert_eq!(
        lines.next().map(cells),
        Some(HEADER.map(str::to_owned).to_vec())
    );
    assert_eq!(
        rows_starts(with_header.lines().next().unwrap_or_default()),
        rows_starts(with_header.lines().nth(1).unwrap_or_default())
    );
    let rows: Vec<Vec<String>> = lines.map(cells).collect();
    let plain_rows: Vec<Vec<String>> = plain.lines().map(cells).collect();
    assert_eq!(rows, plain_rows);
    for verbose in [false, true] {
        let coloured = Look {
            colour: true,
            ..terminal
        };
        let expired = Look {
            now: std::time::UNIX_EPOCH + Duration::from_secs(u64::from(u32::MAX) * 4),
            ..coloured
        };
        for look in [coloured, expired] {
            let painted = run_with(&Fixed::new(Ok(keys.clone())), look, verbose).1;
            let unpainted = run_with(
                &Fixed::new(Ok(keys.clone())),
                Look {
                    colour: false,
                    ..look
                },
                verbose,
            )
            .1;
            assert!(painted.contains('\x1b'), "{painted:?}");
            assert_eq!(crate::colour::strip(&painted), unpainted);
        }
    }
}

#[test]
fn expiry_is_judged_at_the_boundaries() {
    let end = now();
    assert_eq!(Expiry::of(None, end), None);
    assert_eq!(Expiry::of(Some(end), end), Some(Expiry::Expired));
    assert_eq!(
        Expiry::of(Some(end), end + Duration::from_secs(1)),
        Some(Expiry::Expired)
    );
    assert_eq!(Expiry::of(Some(end), end - SOON), Some(Expiry::Soon));
    assert_eq!(
        Expiry::of(Some(end), end - SOON - Duration::from_secs(1)),
        Some(Expiry::Valid)
    );
}

#[test]
fn a_key_that_expired_or_soon_will_has_a_mark_after_its_date_and_a_valid_one_has_none() {
    let keys = vec![key("a", "ecdsa-p256", P256)];
    let end = fields(P256)
        .expires
        .expect("the fixture has an end of validity");
    let mut marks = Vec::new();
    for now in [end - SOON - Duration::from_secs(1), end - SOON, end] {
        let (_, out) = run_with(&Fixed::new(Ok(keys.clone())), Look::plain(now), false);
        let row = cells(out.lines().next().unwrap_or_default());
        assert_eq!(row[..5], expected_row(&keys[0])[..], "{out}");
        marks.push(row.get(5).cloned());
    }
    assert_eq!(marks[0], None);
    assert!(
        marks[1].is_some() && marks[2].is_some() && marks[1] != marks[2],
        "{marks:?}"
    );
}

#[test]
fn no_keys_says_so_and_how_to_import_one() {
    let (result, out) = run(&Fixed::new(Ok(Vec::new())));
    assert!(result.is_ok());
    assert_eq!(out, format!("{NO_KEYS}\n{NONE_HINT}\n"));
    assert!(NONE_HINT.contains("custodio import"));
}

#[test]
fn a_failure_prints_no_key_line() {
    let (result, out) = run(&Fixed::new(Err(ServiceFailure::AuthorizationUnavailable)));
    assert!(matches!(
        result,
        Err(ListFailure::Service(
            ServiceFailure::AuthorizationUnavailable
        ))
    ));
    assert_eq!(out, "");
}

#[test]
fn an_unreadable_certificate_never_hides_the_key() {
    let keys = vec![
        key("bad", "rsa2048", b"garbage"),
        key("good", "ecdsa-p256", P256),
    ];
    let (result, out) = run(&Fixed::new(Ok(keys.clone())));
    assert!(matches!(result, Err(ListFailure::Unreadable(1))));
    let rows: Vec<Vec<String>> = out.lines().map(cells).collect();
    assert_eq!(
        rows,
        [expected_row(&keys[0]), expected_row(&keys[1])],
        "{out}"
    );
    assert!(!out.contains("garbage"));
}

#[test]
fn the_weaker_storage_note_is_at_the_foot_once_or_not_at_all() {
    let kinds = [
        Kind::Tpm,
        Kind::EncryptedTpm,
        Kind::EncryptedHost,
        Kind::Unknown("future".into()),
    ];
    // Every combination of kinds over up to three keys.
    for mask in 1_u32..(1 << kinds.len()) {
        let chosen: Vec<&Kind> = kinds
            .iter()
            .enumerate()
            .filter(|(i, _)| mask >> i & 1 == 1)
            .map(|(_, k)| k)
            .collect();
        let keys: Vec<KeyEntry> = chosen
            .iter()
            .enumerate()
            .map(|(i, k)| of_kind(&format!("k{i}"), "rsa2048", (*k).clone(), RSA))
            .collect();
        let (result, out) = run(&Fixed::new(Ok(keys.clone())));
        assert!(result.is_ok());
        let weaker = chosen
            .iter()
            .any(|k| matches!(k, Kind::EncryptedTpm | Kind::EncryptedHost));
        assert_eq!(
            out.matches(WEAKER_NOTE).count(),
            usize::from(weaker),
            "{out}"
        );
        if weaker {
            assert!(out.ends_with(&format!("\n\n{WEAKER_NOTE}\n")), "{out}");
        }
        let rows: Vec<Vec<String>> = out
            .lines()
            .take_while(|l| !l.is_empty())
            .map(cells)
            .collect();
        let want: Vec<Vec<String>> = keys.iter().map(expected_row).collect();
        assert_eq!(rows, want, "{out}");
        let (_, full) = run_with(&Fixed::new(Ok(keys)), Look::plain(now()), true);
        assert!(!full.contains(WEAKER_NOTE), "{full}");
    }
}

#[test]
fn a_hostile_certificate_and_hostile_ids_cannot_forge_a_row_or_drive_the_terminal() {
    for verbose in [false, true] {
        let (result, out) = run_with(
            &Fixed::new(Ok(vec![
                key("a\nforged  row", "rsa\x1b[2J", HOSTILE),
                of_kind("b", "t", Kind::Unknown("x\ny\u{202e}".into()), P256),
            ])),
            Look::plain(now()),
            verbose,
        );
        assert!(result.is_ok());
        let want = if verbose { 2 * 9 + 1 } else { 2 };
        assert_eq!(out.lines().count(), want, "{out}");
        for c in out.chars() {
            assert!(c == '\n' || !c.is_control(), "raw {c:?}");
        }
        assert!(!out.contains('\u{202e}'));
        assert!(out.contains(&escape("a\nforged  row")), "{out}");
        let f = fields(HOSTILE);
        let subject = if verbose { f.subject } else { f.subject_short };
        assert!(out.contains(&subject), "{out}");
    }
}

/// The view of a key: its title, then (label, value) for each indented line.
fn view_parts(text: &str) -> (String, Vec<(String, String)>) {
    let mut lines = text.lines();
    let title = lines.next().unwrap_or_default().to_owned();
    let fields = lines
        .map(|l| {
            assert!(l.starts_with("  ") && !l.starts_with("   "), "{l:?}");
            let c = cells(l.trim_start());
            (c[0].clone(), c[1..].join("  "))
        })
        .collect();
    (title, fields)
}

/// The values a key's view must show, in order; the times as they read, the end with its mark.
fn expected_view(k: &KeyEntry, look: Look) -> Vec<String> {
    let f = fields(&k.certificate);
    let time = |t: &str| {
        t.strip_suffix('Z')
            .and_then(|t| t.split_once('T'))
            .map_or_else(|| t.to_owned(), |(d, h)| format!("{d} {h} UTC"))
    };
    let mut end = time(&f.not_after);
    if let Some(e) = Expiry::of(f.expires, look.now).filter(|e| *e != Expiry::Valid) {
        end = format!("{end}  {}", e.mark(false));
    }
    vec![
        escape(&k.key_type),
        escape(k.kind.wire()),
        f.subject,
        f.issuer,
        f.serial,
        time(&f.not_before),
        end,
        f.fingerprint,
    ]
}

#[test]
fn list_with_an_id_shows_that_key_in_full_from_the_one_reply() {
    let keys = vec![
        key("other", "rsa2048", RSA),
        of_kind("mine", "ecdsa-p256", Kind::EncryptedHost, P256),
    ];
    let lister = Fixed::new(Ok(keys.clone()));
    let (result, out) = show(&lister, "mine");
    assert!(result.is_ok());
    assert_eq!(lister.1.get(), 1);
    let (title, parts) = view_parts(&out);
    assert_eq!(title, "mine");
    let values: Vec<String> = parts.iter().map(|(_, v)| v.clone()).collect();
    assert_eq!(values, expected_view(&keys[1], Look::plain(now())), "{out}");
    let labels: Vec<&String> = parts.iter().map(|(l, _)| l).collect();
    let mut unique = labels.clone();
    unique.dedup();
    assert_eq!(unique.len(), labels.len(), "{out}");
}

#[test]
fn the_end_of_validity_in_full_carries_the_mark() {
    let keys = vec![key("a", "ecdsa-p256", P256)];
    let end = fields(P256).expires.expect("an end of validity");
    let mut seen = Vec::new();
    for now in [end - SOON - Duration::from_secs(1), end - SOON, end] {
        let look = Look::plain(now);
        let mut out = Vec::new();
        assert!(run_show(&Fixed::new(Ok(keys.clone())), "a", &mut out, look).is_ok());
        let out = String::from_utf8_lossy(&out).into_owned();
        let (_, parts) = view_parts(&out);
        let values: Vec<String> = parts.into_iter().map(|(_, v)| v).collect();
        assert_eq!(values, expected_view(&keys[0], look), "{out}");
        seen.push(values[6].clone());
    }
    assert!(
        seen[0] != seen[1] && seen[1] != seen[2] && seen[0] != seen[2],
        "{seen:?}"
    );
}

#[test]
fn verbose_shows_every_key_in_full_sorted_and_one_blank_line_apart() {
    let keys = vec![key("bb", "rsa2048", RSA), key("a", "ecdsa-p256", P256)];
    let (result, out) = run_with(&Fixed::new(Ok(keys.clone())), Look::plain(now()), true);
    assert!(result.is_ok());
    let blocks: Vec<&str> = out.split("\n\n").collect();
    assert_eq!(blocks.len(), 2, "{out}");
    for (block, k) in blocks.iter().zip([&keys[1], &keys[0]]) {
        let (title, parts) = view_parts(block);
        assert_eq!(title, k.id);
        let values: Vec<String> = parts.into_iter().map(|(_, v)| v).collect();
        assert_eq!(values, expected_view(k, Look::plain(now())), "{out}");
        let mut alone = Vec::new();
        assert!(
            run_show(
                &Fixed::new(Ok(keys.clone())),
                &k.id,
                &mut alone,
                Look::plain(now())
            )
            .is_ok()
        );
        assert_eq!(
            format!("{}\n", block.trim_end()),
            String::from_utf8_lossy(&alone)
        );
    }
}

#[test]
fn list_with_an_unknown_id_is_an_error_that_prints_nothing() {
    let lister = Fixed::new(Ok(vec![key("a", "rsa2048", RSA)]));
    let (result, out) = show(&lister, "A");
    assert!(matches!(result, Err(ListFailure::UnknownId(ref id)) if id == "A"));
    assert_eq!(out, "");
    let (result, _) = show(&Fixed::new(Ok(Vec::new())), "a");
    assert!(matches!(result, Err(ListFailure::UnknownId(_))));
    let (result, _) = show(
        &Fixed::new(Err(ServiceFailure::AuthorizationUnavailable)),
        "a",
    );
    assert!(matches!(result, Err(ListFailure::Service(_))));
}

#[test]
fn the_full_view_of_a_hostile_key_is_escaped_and_an_unreadable_one_is_an_error() {
    let keys = vec![key("a", "t", HOSTILE)];
    let (result, out) = show(&Fixed::new(Ok(keys.clone())), "a");
    assert!(result.is_ok());
    let (_, parts) = view_parts(&out);
    let values: Vec<String> = parts.into_iter().map(|(_, v)| v).collect();
    assert_eq!(values, expected_view(&keys[0], Look::plain(now())), "{out}");
    for c in out.chars() {
        assert!(c == '\n' || !c.is_control(), "raw {c:?}");
    }
    let keys = vec![key("a", "t", b"junk")];
    let (result, out) = show(&Fixed::new(Ok(keys.clone())), "a");
    assert!(matches!(result, Err(ListFailure::Unreadable(1))));
    let (_, parts) = view_parts(&out);
    let values: Vec<String> = parts.into_iter().map(|(_, v)| v).collect();
    assert_eq!(values, expected_view(&keys[0], Look::plain(now())), "{out}");
}

#[test]
fn the_debug_form_of_an_entry_has_no_certificate() {
    let shown = format!("{:?}", key("k", "rsa2048", &[0xde, 0xad, 0xbe, 0xef]));
    assert!(
        !shown.contains("222") && !shown.to_lowercase().contains("de, ad"),
        "{shown}"
    );
}

fn args(list: &[&str]) -> Result<Command, ArgError> {
    parse_command(list.iter().map(|s| (*s).to_owned()))
}

fn listed(id: Option<&str>, verbose: bool) -> Command {
    Command::List(ListArgs {
        id: id.map(str::to_owned),
        verbose,
    })
}

#[test]
fn list_takes_a_verbose_flag_then_one_optional_key_id() {
    assert_eq!(args(&["list"]), Ok(listed(None, false)));
    assert_eq!(args(&["list", "-v"]), Ok(listed(None, true)));
    assert_eq!(args(&["list", "--verbose"]), Ok(listed(None, true)));
    assert_eq!(args(&["list", "work"]), Ok(listed(Some("work"), false)));
    assert_eq!(
        args(&["list", "-v", "work"]),
        Ok(listed(Some("work"), true))
    );
    assert_eq!(args(&["list", "--", "-x"]), Ok(listed(Some("-x"), false)));
    assert_eq!(
        args(&["list", "-v", "--", "-x"]),
        Ok(listed(Some("-x"), true))
    );
    for bad in [
        &["list", "extra", "more"][..],
        &["list", "--id", "x"],
        &["list", "-x"],
        &["list", "--"],
        &["list", "--", "a", "b"],
        &["list", "-v", "-v"],
        &["list", "-v", "--verbose"],
        &["list", "work", "-v"],
        &["list", "-V"],
    ] {
        assert!(
            matches!(args(bad), Err(ArgError::CommandUsage("list", _))),
            "{bad:?}"
        );
    }
    assert_eq!(args(&["List"]), Err(ArgError::Unknown("List".into())));
}

#[test]
fn import_still_parses_through_the_dispatcher() {
    assert_eq!(
        args(&["import", "--id", "k", "a.p12"]),
        Ok(Command::Import(ImportArgs {
            file: "a.p12".into(),
            id: "k".into()
        }))
    );
    assert_eq!(args(&["import"]), Err(ArgError::Bare("import")));
}

#[test]
fn the_usage_lists_each_command_as_its_help_does_aligned_under_the_first() {
    let usage = crate::usage();
    let lines: Vec<&str> = usage.lines().collect();
    for (i, c) in help::COMMANDS.iter().enumerate() {
        let prefix = if i == 0 { "usage: " } else { "       " };
        assert_eq!(lines[i], format!("{prefix}{}", c.usage_line()), "{usage}");
    }
}

#[test]
fn a_list_failure_reads_as_a_sentence_with_the_id_escaped() {
    assert_eq!(
        ListFailure::Unreadable(2).to_string(),
        "2 certificate(s) could not be read"
    );
    assert_eq!(
        ListFailure::UnknownId("a\nb".into()).to_string(),
        "you have no key with the id 'a\\x0ab'"
    );
    assert!(
        ListFailure::Output(io::Error::other("full"))
            .to_string()
            .contains("cannot write the list: full")
    );
    assert_eq!(
        ListFailure::Service(ServiceFailure::AuthorizationUnavailable).to_string(),
        ServiceFailure::AuthorizationUnavailable.to_string()
    );
}
