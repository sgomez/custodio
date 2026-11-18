use super::*;
use crate::fingerprint_decide::{Family, file_bytes};
use crate::storage::StateStorage;

fn facts(reader: Reader, fingers: Fingers) -> Facts {
    Facts {
        files: Observed {
            euid: 1000,
            family: Family::Debian,
            polkit_file: FileState::Missing,
            vendor: VendorState::Regular,
            module_present: true,
            fprintd_present: true,
            reader_present: true,
            common_auth: None,
            authselect: None,
            system_auth: None,
            sudo: None,
            gnome_login_schema: false,
            dconf_disables_login_fingerprint: false,
        },
        reader,
        fingers,
        firefox: Firefox::NoProfile,
        journal: Verdict::Persistent(String::new()),
        service: Service::Answered(StateStorage::Encrypted, None),
    }
}

fn states(f: &Facts) -> Vec<State> {
    decide(f).checks.iter().map(|c| c.state).collect()
}

#[test]
fn the_exit_status_counts_a_broken_include_and_checks_4_to_6_only() {
    assert_eq!(exit_status(false, &[]), 0);
    assert_eq!(exit_status(true, &[]), 1);
    assert_eq!(exit_status(false, &[State::Ok, State::Ok]), 0);
    assert_eq!(exit_status(false, &[State::Ok, State::NotOk]), 1);
    assert_eq!(exit_status(false, &[State::CouldNotCheck]), 1);
    assert_eq!(exit_status(false, &[State::Ok, State::Warn]), 0);
    assert_eq!(exit_status(true, &[State::Ok]), 1);
}

#[test]
fn could_not_check_on_the_finger_is_exit_status_0() {
    for fingers in [
        Fingers::Refused("Not Authorized".into()),
        Fingers::Failed("x".into()),
        Fingers::NotAsked,
    ] {
        let report = decide(&facts(Reader::Devices(1), fingers));
        assert_eq!(report.checks[1].state, State::CouldNotCheck);
        assert_eq!(report.exit_status(), 0);
    }
}

#[test]
fn checks_1_to_3_unsatisfied_in_any_mix_are_exit_status_0() {
    for reader in [
        Reader::Devices(0),
        Reader::NoOwner,
        Reader::Failed("x".into()),
    ] {
        let report = decide(&facts(reader, Fingers::NotAsked));
        assert!(
            report
                .checks
                .iter()
                .filter(|c| !c.later)
                .all(|c| c.state != State::Ok)
        );
        assert_eq!(report.exit_status(), 0);
    }
    let report = decide(&facts(Reader::Devices(1), Fingers::NoPrints));
    assert_eq!(
        states(&facts(Reader::Devices(1), Fingers::NoPrints))[1],
        State::NotOk
    );
    assert_eq!(report.exit_status(), 0);
}

#[test]
fn a_broken_include_is_first_and_is_exit_status_1() {
    let mut f = facts(Reader::Devices(1), Fingers::Listed(2));
    f.files.polkit_file = FileState::Regular(file_bytes().to_vec());
    f.files.vendor = VendorState::NotRegular;
    let report = decide(&f);
    assert!(report.broken_include);
    assert_eq!(report.checks[0].name, POLKIT);
    assert_eq!(report.exit_status(), 1);
}

#[test]
fn every_state_of_the_reader_and_the_finger() {
    let ok = |n| (Reader::Devices(n), Fingers::Listed(1));
    let cases = [
        (ok(1), State::Ok, State::Ok),
        (ok(2), State::Ok, State::Ok),
        (
            (Reader::Devices(0), Fingers::NotAsked),
            State::NotOk,
            State::CouldNotCheck,
        ),
        (
            (Reader::NoOwner, Fingers::NotAsked),
            State::CouldNotCheck,
            State::CouldNotCheck,
        ),
        (
            (Reader::Failed("t".into()), Fingers::NotAsked),
            State::CouldNotCheck,
            State::CouldNotCheck,
        ),
        (
            (Reader::Devices(1), Fingers::NoPrints),
            State::Ok,
            State::NotOk,
        ),
        (
            (Reader::Devices(1), Fingers::Listed(0)),
            State::Ok,
            State::NotOk,
        ),
        (
            (Reader::Devices(1), Fingers::Refused("r".into())),
            State::Ok,
            State::CouldNotCheck,
        ),
        (
            (Reader::Devices(1), Fingers::Failed("e".into())),
            State::Ok,
            State::CouldNotCheck,
        ),
    ];
    for ((reader, fingers), want_reader, want_finger) in cases {
        let report = decide(&facts(reader.clone(), fingers.clone()));
        assert_eq!(
            (report.checks[0].state, report.checks[1].state),
            (want_reader, want_finger),
            "{reader:?} {fingers:?}"
        );
    }
}

#[test]
fn a_name_without_an_owner_is_missing_only_when_there_is_no_service_file() {
    let mut f = facts(Reader::NoOwner, Fingers::NotAsked);
    assert_eq!(states(&f)[0], State::CouldNotCheck);
    f.files.fprintd_present = false;
    assert_eq!(states(&f)[0], State::NotOk);
}

/// Reports that between them have every kind of line: each state, notes, a warning, several
/// profiles, text from outside with an escape sequence.
fn varied_reports() -> Vec<Report> {
    let profile = |path: &str, entry| ProfileFact {
        browser: "Firefox",
        path: path.into(),
        copy: None,
        entry,
    };
    let mut all = Vec::new();
    let mut f = facts(Reader::Failed("a\x1b[2Jb".into()), Fingers::NotAsked);
    all.push(decide(&f));
    f.reader = Reader::Devices(1);
    f.fingers = Fingers::Listed(1);
    f.files.polkit_file = FileState::Regular(file_bytes().to_vec());
    all.push(decide(&f));
    f.files.common_auth = Some("auth sufficient pam_fprintd.so\n".to_owned());
    f.firefox = Firefox::Profiles(vec![
        profile("~/a.default", Entry::Missing),
        profile("~/b.default", Entry::Present("x".into())),
    ]);
    f.service = Service::Answered(StateStorage::NotEncrypted, None);
    all.push(decide(&f));
    f.files.vendor = VendorState::Missing;
    f.service = Service::Unreachable("x".into());
    all.push(decide(&f));
    all
}

#[test]
fn the_report_prints_every_check_once_under_its_heading_with_its_lines_indented_below() {
    for report in varied_reports() {
        let text = report.text(false);
        assert!(!text.contains('\x1b'), "{text:?}");
        let lines: Vec<&str> = text.lines().collect();
        let mut at = 0;
        let mut headings: Vec<&str> = Vec::new();
        let mut text_column = None;
        for c in &report.checks {
            if headings.last() != Some(&c.section) {
                assert_eq!(lines[at], c.section, "{text}");
                assert!(
                    !headings.contains(&c.section),
                    "{} twice:\n{text}",
                    c.section
                );
                headings.push(c.section);
                at += 1;
            }
            let line = lines[at];
            assert!(
                line.starts_with("  ") && !line.starts_with("   "),
                "{line:?}"
            );
            assert!(line.contains(c.name) && line.ends_with(&c.text), "{line:?}");
            let column = line.len() - c.text.len();
            assert_eq!(
                *text_column.get_or_insert(column),
                column,
                "not aligned:\n{text}"
            );
            let name_column = line.find(c.name).unwrap_or_default();
            at += 1;
            let under: Vec<&String> = c
                .note
                .iter()
                .chain(c.warning.iter().flat_map(|w| [&w.text, &w.fix]))
                .chain(c.fix.iter())
                .collect();
            for part in under {
                assert!(
                    lines[at].ends_with(part.as_str()),
                    "{part:?} not under {}:\n{text}",
                    c.name
                );
                assert_eq!(
                    lines[at].len() - lines[at].trim_start().len(),
                    name_column,
                    "not under the name: {:?}",
                    lines[at]
                );
                at += 1;
            }
        }
        let problems = report
            .checks
            .iter()
            .filter(|c| matches!(c.state, State::NotOk | State::CouldNotCheck))
            .count();
        let warnings: usize = report
            .checks
            .iter()
            .map(|c| usize::from(c.state == State::Warn) + usize::from(c.warning.is_some()))
            .sum();
        let rest: Vec<&str> = lines[at..]
            .iter()
            .copied()
            .filter(|l| !l.is_empty())
            .collect();
        let want: Vec<usize> = [problems, warnings]
            .into_iter()
            .filter(|n| *n > 0)
            .collect();
        if want.is_empty() {
            assert!(rest.is_empty(), "{text}");
        } else {
            assert_eq!(rest.len(), 1, "{text}");
            let numbers: Vec<usize> = rest[0]
                .split(|c: char| !c.is_ascii_digit())
                .filter_map(|n| n.parse().ok())
                .collect();
            assert_eq!(numbers, want, "{text}");
            assert!(
                problems == 0 || warnings == 0 || rest[0].contains(','),
                "{text}"
            );
        }
    }
}

#[test]
fn the_states_print_differently_and_colour_changes_nothing_but_escape_sequences() {
    let words = [State::Ok, State::NotOk, State::Warn, State::CouldNotCheck].map(State::word);
    for (i, w) in words.iter().enumerate() {
        assert!(!words[i + 1..].contains(w), "{w} twice");
    }
    for report in varied_reports() {
        let coloured = report.text(true);
        assert!(coloured.contains('\x1b'), "{coloured:?}");
        assert_eq!(crate::colour::strip(&coloured), report.text(false));
    }
}

#[test]
fn the_profiles_get_one_line_each_and_one_fix_under_the_last_that_needs_it() {
    let mut f = facts(Reader::Devices(1), Fingers::Listed(1));
    let profile = |path: &str, entry| ProfileFact {
        browser: "Firefox",
        path: path.into(),
        copy: None,
        entry,
    };
    f.firefox = Firefox::Profiles(vec![
        profile("~/.mozilla/firefox/a.default", Entry::Missing),
        profile("~/.mozilla/firefox/b.default", Entry::Stale),
        profile("~/.mozilla/firefox/c.default", Entry::Present("x".into())),
    ]);
    let checks = decide(&f).checks;
    let fox: Vec<&Check> = checks.iter().filter(|c| c.name == "Firefox").collect();
    let states: Vec<State> = fox.iter().map(|c| c.state).collect();
    assert_eq!(states, [State::NotOk, State::NotOk, State::Ok]);
    for (c, dir) in fox.iter().zip(["a.default", "b.default", "c.default"]) {
        assert!(
            c.text.starts_with(dir) && !c.text.contains('/'),
            "{}",
            c.text
        );
    }
    assert_ne!(fox[0].text, fox[1].text, "missing and stale read alike");
    let with_fix: Vec<bool> = fox.iter().map(|c| c.fix.is_some()).collect();
    assert_eq!(with_fix, [false, true, false]);
    assert!(
        fox[1]
            .fix
            .as_deref()
            .is_some_and(|f| f.contains("custodio register"))
    );
}

#[test]
fn a_foreign_polkit_file_without_the_finger_is_not_fixed_by_enable() {
    let mut f = facts(Reader::Devices(1), Fingers::Listed(1));
    for file in [
        FileState::Regular(b"auth include common-auth\n".to_vec()),
        FileState::NotRegular,
    ] {
        f.files.polkit_file = file.clone();
        let polkit = decide(&f)
            .checks
            .into_iter()
            .find(|c| c.name == POLKIT)
            .unwrap();
        assert_eq!(polkit.state, State::NotOk, "{file:?}");
        let fix = polkit.fix.unwrap();
        assert!(
            !fix.starts_with("sudo custodio fingerprint enable"),
            "{fix}"
        );
        assert!(fix.contains("dpkg -S"), "{fix}");
    }
}

#[test]
fn the_failing_checks_are_named_once_each_in_report_order() {
    let mut f = facts(Reader::Devices(1), Fingers::Listed(1));
    assert_eq!(decide(&f).failing(), Vec::<&str>::new());
    f.service = Service::Unreachable("x".into());
    let missing = |path: &str| ProfileFact {
        browser: "Firefox",
        path: path.into(),
        copy: None,
        entry: Entry::Missing,
    };
    f.firefox = Firefox::Profiles(vec![missing("/a"), missing("/b")]);
    f.files.polkit_file = FileState::NotRegular;
    assert_eq!(decide(&f).failing(), ["Firefox", STORAGE]);
}
