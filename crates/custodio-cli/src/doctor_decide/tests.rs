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

#[test]
fn text_from_outside_is_escaped_and_fixes_sit_under_their_check() {
    let f = facts(Reader::Failed("a\x1b[2Jb".into()), Fingers::NotAsked);
    let text = decide(&f).text();
    assert!(!text.contains('\x1b'), "{text:?}");
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines[0].starts_with("could not check fingerprint reader: "));
    assert!(lines[1].trim_start().starts_with("fix: "));
    assert!(lines[1].starts_with(' '));
}
