//! Test support: every command a product text names is one the parser accepts.

/// Every `custodio …` command a message names that the parser does not accept. A command ends at
/// a quote, a comma, a colon, a closing bracket, a full stop or the word `again`.
pub(crate) fn unknown_commands(text: &str) -> Vec<String> {
    let mut bad = Vec::new();
    // A placeholder is a value: `<file.p12>` stands for a word.
    let mut plain = String::new();
    let mut inside = false;
    for c in text.chars() {
        match c {
            '<' => {
                inside = true;
                plain.push('x');
            }
            '>' => inside = false,
            _ if !inside => plain.push(c),
            _ => {}
        }
    }
    let mut rest = plain.as_str();
    while let Some(at) = rest.find("custodio ") {
        let before = &rest[..at];
        let after = &rest[at + "custodio ".len()..];
        // A command starts a line, follows a quote or `sudo `: `the custodio package` is prose.
        let starts =
            before.is_empty() || before.ends_with(['\'', '\n']) || before.ends_with("sudo ");
        if !starts {
            rest = after;
            continue;
        }
        let end = after
            .find(['\'', '"', ',', ':', ')', ';', '.'])
            .unwrap_or(after.len());
        let words = after[..end].trim_end_matches(" again");
        let args: Vec<String> = words.split_whitespace().map(str::to_owned).collect();
        if !matches!(
            crate::parse::parse_command(args),
            Ok(_) | Err(crate::parse::ArgError::Bare(_))
        ) {
            bad.push(format!("custodio {words}"));
        }
        rest = &after[end..];
    }
    bad
}

fn assert_runnable(texts: &[String]) {
    for t in texts {
        assert_eq!(unknown_commands(t), Vec::<String>::new(), "{t}");
    }
}

#[test]
fn the_fingerprint_texts_name_commands_that_parse() {
    use crate::fingerprint_decide::*;
    let mut texts = vec![String::from_utf8_lossy(file_bytes()).replace("# ", "")];
    for done in [
        Done::Enabled { lock_note: true },
        Done::Enabled { lock_note: false },
        Done::AlreadyOn,
        Done::Disabled,
        Done::AlreadyOff,
    ] {
        let l = done_line(done);
        texts.push(l.text.clone());
        texts.extend(l.under);
    }
    let l = no_reader_line();
    texts.push(l.text);
    texts.extend(l.under);
    let regular = |b: &[u8]| FileState::Regular(b.to_vec());
    for euid in [0, 1000] {
        for polkit_file in [
            FileState::Missing,
            FileState::NotRegular,
            regular(file_bytes()),
            regular(b"auth include common-auth\n"),
        ] {
            for vendor in [
                VendorState::Missing,
                VendorState::NotRegular,
                VendorState::Regular,
            ] {
                for (module_present, fprintd_present) in
                    [(false, true), (true, false), (true, true)]
                {
                    for common_auth in [None, Some("auth sufficient pam_fprintd.so\n".to_owned())] {
                        for family in [
                            Family::Debian,
                            Family::Fedora,
                            Family::Arch,
                            Family::Unknown,
                        ] {
                            let o = Observed {
                                euid,
                                family,
                                polkit_file: polkit_file.clone(),
                                vendor,
                                module_present,
                                fprintd_present,
                                reader_present: true,
                                common_auth: common_auth.clone(),
                                authselect: None,
                                system_auth: None,
                                sudo: None,
                                gnome_login_schema: false,
                                dconf_disables_login_fingerprint: false,
                            };
                            if let EnableDecision::Refuse(r) = decide_enable(&o) {
                                texts.push(r.message());
                            }
                            if let DisableDecision::Refuse(r) = decide_disable(&o) {
                                texts.push(r.message());
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(texts.len() > 30);
    assert_runnable(&texts);
}

fn observed(
    euid: u32,
    family: crate::fingerprint_decide::Family,
    polkit_file: crate::fingerprint_decide::FileState,
    vendor: crate::fingerprint_decide::VendorState,
    common_auth: Option<String>,
) -> crate::fingerprint_decide::Observed {
    crate::fingerprint_decide::Observed {
        euid,
        family,
        polkit_file,
        vendor,
        module_present: true,
        fprintd_present: true,
        reader_present: true,
        common_auth,
        authselect: None,
        system_auth: None,
        sudo: None,
        gnome_login_schema: false,
        dconf_disables_login_fingerprint: false,
    }
}

#[test]
fn the_doctor_fixes_name_commands_that_parse() {
    use crate::doctor_decide::*;
    use crate::doctor_later::{Copy, Entry, Firefox, ProfileFact};
    use crate::fingerprint_decide::{FileState, VendorState, file_bytes};
    let entries = [
        Entry::Present("n".into()),
        Entry::PresentElsewhere("n".into()),
        Entry::Missing,
        Entry::Stale,
        Entry::P11Kit,
        Entry::CouldNot("why".into()),
    ];
    let copies = [
        None,
        Some(Copy::Missing),
        Some(Copy::UpToDate),
        Some(Copy::Stale),
        Some(Copy::CouldNot("why".into())),
    ];
    let mut firefoxes = vec![
        Firefox::NoProfile,
        Firefox::CouldNot("why".into()),
        Firefox::NoHome,
    ];
    for entry in &entries {
        for copy in &copies {
            firefoxes.push(Firefox::Profiles(vec![ProfileFact {
                browser: "Firefox",
                path: "/home/u/.mozilla/firefox/x".into(),
                copy: copy.clone(),
                entry: entry.clone(),
            }]));
        }
    }
    let mut texts = Vec::new();
    for firefox in firefoxes {
        for polkit_file in [
            FileState::Missing,
            FileState::NotRegular,
            FileState::Regular(file_bytes().to_vec()),
            FileState::Regular(b"auth include common-auth\n".to_vec()),
            FileState::Regular(b"auth sufficient pam_fprintd.so\n".to_vec()),
        ] {
            for vendor in [
                VendorState::Missing,
                VendorState::NotRegular,
                VendorState::Regular,
            ] {
                for common_auth in [None, Some("auth sufficient pam_fprintd.so\n".to_owned())] {
                    for (reader, fingers) in [
                        (Reader::Devices(1), Fingers::Listed(1)),
                        (Reader::Devices(0), Fingers::NotAsked),
                        (Reader::NoOwner, Fingers::NotAsked),
                        (Reader::Failed("x".into()), Fingers::NotAsked),
                        (Reader::Devices(1), Fingers::NoPrints),
                        (Reader::Devices(1), Fingers::Refused("x".into())),
                        (Reader::Devices(1), Fingers::Failed("x".into())),
                    ] {
                        let f = Facts {
                            files: observed(
                                1000,
                                crate::fingerprint_decide::Family::Debian,
                                polkit_file.clone(),
                                vendor,
                                common_auth.clone(),
                            ),
                            reader,
                            fingers,
                            firefox: firefox.clone(),
                            journal: crate::journald_conf::Verdict::Persistent(String::new()),
                            service: crate::doctor_later::Service::Answered(
                                crate::storage::StateStorage::Encrypted,
                                None,
                            ),
                        };
                        for c in decide(&f).checks {
                            texts.extend(c.fix);
                            texts.extend(c.warning.map(|w| w.fix));
                            texts.extend(c.note);
                        }
                    }
                }
            }
        }
    }
    assert!(
        texts
            .iter()
            .any(|t| t.contains("custodio setup browsers enable"))
    );
    assert!(
        texts
            .iter()
            .any(|t| t.contains("custodio setup fingerprint disable"))
    );
    assert!(
        texts
            .iter()
            .any(|t| t.contains("custodio setup fingerprint enable"))
    );
    assert_runnable(&texts);
}

#[test]
fn the_register_fixes_name_commands_that_parse() {
    use crate::register_cli::register_lines;
    use crate::register_native::{Line, Outcome, Report};
    let mut texts = Vec::new();
    for remove in [false, true] {
        let report = Report {
            lines: vec![Line {
                browser: "Firefox",
                path: "/home/u/.mozilla/firefox/x".into(),
                outcome: Outcome::Held("lock".into()),
            }],
        };
        for l in register_lines(&report, remove) {
            texts.extend(l.under);
        }
    }
    assert!(
        texts
            .iter()
            .any(|t| t.contains("custodio setup browsers disable"))
    );
    assert!(
        texts
            .iter()
            .any(|t| t.contains("custodio setup browsers enable"))
    );
    assert_runnable(&texts);
}

#[test]
fn the_command_check_fails_a_text_naming_a_removed_command() {
    for t in [
        "Undo: sudo custodio fingerprint disable",
        "then: sudo custodio register --remove",
        "custodio register, then restart the browsers",
    ] {
        assert!(!unknown_commands(t).is_empty(), "{t}");
    }
}
