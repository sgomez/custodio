//! The completions of bash, zsh and fish, and the hidden `custodio __key-ids` they call.
//! The service is the real one on a private `dbus-daemon` (the `list` rig); the shells are real.

use std::time::{Duration, Instant};

use custodio_client::{BUS_NAME, OBJECT_PATH};

mod completions_rig;
mod list_rig;
use completions_rig::{key_ids, snapshot, state_dir};
use list_rig::{P256_OTHER_P12, P256_P12, Rig, TestResult};

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn key_ids_prints_the_sorted_ids_and_calls_list_keys_only() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("zed", P256_P12)?;
    rig.import("alpha", P256_OTHER_P12)?;
    // The counting is live: the two imports asked polkit.
    assert_eq!(rig.polkit_calls(), 2);
    let imports = rig.calls(2).len();
    completions_rig::binary()?;
    let state = snapshot(&state_dir(&rig))?;

    let out = key_ids(&rig.bus.address)?;
    assert_eq!(text(&out.stdout), "alpha\nzed\n");
    assert_eq!(text(&out.stderr), "");
    assert!(out.status.success());

    assert_eq!(rig.polkit_calls(), 2, "no polkit request");
    let all = rig.calls(imports + 1);
    let new: Vec<_> = all[imports..]
        .iter()
        .filter(|c| c.0 == BUS_NAME || c.1 == OBJECT_PATH)
        .map(|c| c.3.as_str())
        .collect();
    assert_eq!(new, ["ListKeys"], "{:?}", &all[imports..]);
    // Besides the bus's own `Hello` of the new connection, nothing else was called.
    let others = all[imports..].iter().filter(|c| c.3 != "Hello").count();
    assert_eq!(others, 1, "{:?}", &all[imports..]);
    assert_eq!(snapshot(&state_dir(&rig))?, state, "nothing written");
    Ok(())
}

#[test]
fn key_ids_with_no_keys_prints_nothing_and_succeeds() -> TestResult {
    let rig = Rig::start(true)?;
    let out = key_ids(&rig.bus.address)?;
    assert!(out.status.success());
    assert!(out.stdout.is_empty() && out.stderr.is_empty());
    Ok(())
}

#[test]
fn key_ids_without_the_service_or_the_bus_prints_nothing_and_exits_1() -> TestResult {
    let rig = Rig::start(false)?;
    completions_rig::binary()?; // built before the clock starts
    for address in [rig.bus.address.as_str(), "unix:path=/nonexistent/bus"] {
        let start = Instant::now();
        let out = key_ids(address)?;
        assert_eq!(out.status.code(), Some(1), "{address}");
        assert!(out.stdout.is_empty() && out.stderr.is_empty(), "{address}");
        assert!(start.elapsed() < Duration::from_secs(1), "{address}");
    }
    Ok(())
}

#[test]
fn key_ids_with_a_service_that_never_answers_gives_up_at_its_limit() -> TestResult {
    let rig = Rig::start(false)?;
    // A peer owns the name and never replies.
    let peer = rig.client_connection()?;
    zbus::block_on(peer.request_name(BUS_NAME))?;
    let start = Instant::now();
    let out = key_ids(&rig.bus.address)?;
    let took = start.elapsed();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty() && out.stderr.is_empty());
    assert!(took >= Duration::from_secs(2), "{took:?}");
    assert!(took < Duration::from_secs(4), "{took:?}");
    Ok(())
}

use std::collections::BTreeSet;

use completions_rig::{Setup, Shell};
use custodio_cli::COMMANDS;

fn set(items: &[String]) -> BTreeSet<String> {
    items.iter().cloned().collect()
}

fn set_of<const N: usize>(items: [&str; N]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

/// What the commands and options of the help ask of a completion file; the first difference.
fn check_commands_and_options(setup: &Setup) -> Result<(), String> {
    let first = setup.offer(&["custodio", ""]).map_err(|e| e.to_string())?;
    let names: BTreeSet<String> = COMMANDS.iter().map(|c| c.name.to_owned()).collect();
    if set(&first.items) != names {
        return Err(format!("commands: {:?} instead of {names:?}", first.items));
    }
    let dash = setup.offer(&["custodio", "-"]).map_err(|e| e.to_string())?;
    if set(&dash.items) != set_of(["--help", "-h"]) {
        return Err(format!("tool options: {:?}", dash.items));
    }
    for c in COMMANDS {
        let mut want = set_of(["--help", "-h"]);
        want.extend(c.options.iter().map(|o| o.flag.to_owned()));
        let got = setup
            .offer(&["custodio", c.name, "-"])
            .map_err(|e| e.to_string())?;
        if set(&got.items) != want {
            return Err(format!(
                "options of {}: {:?} instead of {want:?}",
                c.name, got.items
            ));
        }
        // Arguments that are words (`enable`, `disable`), not placeholders.
        if c.args.iter().all(|(a, _)| !a.starts_with('<')) {
            let want: BTreeSet<String> = c.args.iter().map(|(a, _)| (*a).to_owned()).collect();
            let got = setup
                .offer(&["custodio", c.name, ""])
                .map_err(|e| e.to_string())?;
            if set(&got.items) != want {
                return Err(format!(
                    "arguments of {}: {:?} instead of {want:?}",
                    c.name, got.items
                ));
            }
        }
    }
    Ok(())
}

/// The completion text without the option `--remove` of `register`: the word in bash and zsh
/// (one string of options), the line of its own in fish.
fn without_remove(shell: Shell, text: &str) -> String {
    match shell {
        Shell::Bash | Shell::Zsh => text.replace("--remove", ""),
        Shell::Fish => text
            .lines()
            .filter(|l| !l.contains("-l remove"))
            .map(|l| format!("{l}\n"))
            .collect(),
    }
}

fn commands_and_options(shell: Shell) -> TestResult {
    let rig = Rig::start(false)?;
    let text = shell.text()?;
    let setup = Setup::new(shell, &rig.bus.address, &text)?;
    check_commands_and_options(&setup)?;
    // Negative control: the same comparison fails on a copy without `--remove`.
    let cut = Setup::new(shell, &rig.bus.address, &without_remove(shell, &text))?;
    let err = check_commands_and_options(&cut).expect_err("a missing option goes unnoticed");
    assert!(err.contains("register"), "{err}");
    Ok(())
}

#[test]
fn bash_offers_every_command_and_option_of_the_help() -> TestResult {
    commands_and_options(Shell::Bash)
}

fn ids(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

fn key_id_commands() -> impl Iterator<Item = &'static str> {
    COMMANDS
        .iter()
        .filter(|c| c.args.iter().any(|(a, _)| *a == "<key id>"))
        .map(|c| c.name)
}

fn key_ids_of_the_person(shell: Shell) -> TestResult {
    let rig = Rig::start(true)?;
    for id in ["alpha", "alps", "beta"] {
        rig.import(id, P256_P12)?;
    }
    let asked = rig.polkit_calls();
    let setup = Setup::new(shell, &rig.bus.address, &shell.text()?)?;
    let mut seen_commands = 0;
    for cmd in key_id_commands() {
        seen_commands += 1;
        let all = setup.offer(&["custodio", cmd, ""])?;
        assert_eq!(set(&all.items), ids(&["alpha", "alps", "beta"]), "{cmd}");
        let some = setup.offer(&["custodio", cmd, "al"])?;
        assert_eq!(set(&some.items), ids(&["alpha", "alps"]), "{cmd} al");
        let none = setup.offer(&["custodio", cmd, "z"])?;
        assert!(none.items.is_empty(), "{cmd} z: {:?}", none.items);
    }
    assert!(seen_commands >= 2, "list and delete take a key id");
    // `import --id` names a new key: no id is offered.
    let new = setup.offer(&["custodio", "import", "--id", ""])?;
    assert!(
        new.items
            .iter()
            .all(|i| !["alpha", "alps", "beta"].contains(&i.as_str())),
        "{:?}",
        new.items
    );
    assert_eq!(rig.polkit_calls(), asked, "no polkit request");
    Ok(())
}

fn service_absent(shell: Shell) -> TestResult {
    let rig = Rig::start(false)?;
    for address in [rig.bus.address.as_str(), "unix:path=/nonexistent/bus"] {
        let setup = Setup::new(shell, address, &shell.text()?)?;
        for cmd in key_id_commands() {
            let got = setup.offer(&["custodio", cmd, ""])?;
            assert!(got.items.is_empty(), "{cmd}: {:?}", got.items);
            assert_eq!(got.stderr, "", "{cmd} on {address}");
            assert!(got.took < Duration::from_secs(1), "{cmd}: {:?}", got.took);
        }
    }
    Ok(())
}

fn service_hung(shell: Shell) -> TestResult {
    let rig = Rig::start(false)?;
    let peer = rig.client_connection()?;
    zbus::block_on(peer.request_name(BUS_NAME))?;
    let setup = Setup::new(shell, &rig.bus.address, &shell.text()?)?;
    let got = setup.offer(&["custodio", "list", ""])?;
    assert!(got.items.is_empty(), "{:?}", got.items);
    assert_eq!(got.stderr, "");
    assert!(got.took < Duration::from_secs(4), "{:?}", got.took);
    Ok(())
}

fn two_hundred_keys(shell: Shell) -> TestResult {
    let rig = Rig::start(true)?;
    let all: Vec<String> = (0..200).map(|i| format!("key-{i:03}")).collect();
    for id in &all {
        rig.import(id, P256_P12)?;
    }
    let setup = Setup::new(shell, &rig.bus.address, &shell.text()?)?;
    let got = setup.offer(&["custodio", "delete", ""])?;
    assert_eq!(set(&got.items), set(&all));
    assert!(got.took < Duration::from_secs(2), "{:?}", got.took);
    Ok(())
}

#[test]
fn bash_offers_the_key_ids_of_the_person() -> TestResult {
    key_ids_of_the_person(Shell::Bash)
}

#[test]
fn bash_offers_nothing_and_quickly_when_the_service_is_absent() -> TestResult {
    service_absent(Shell::Bash)
}

#[test]
fn bash_offers_nothing_within_the_bound_when_the_service_hangs() -> TestResult {
    service_hung(Shell::Bash)
}

#[test]
fn bash_offers_200_key_ids_within_2_s() -> TestResult {
    two_hundred_keys(Shell::Bash)
}

fn ids_are_data(shell: Shell) -> TestResult {
    let rig = Rig::start(false)?;
    let setup = Setup::new(shell, &rig.bus.address, &shell.text()?)?;
    let mark = setup.home.path().join("MARK");
    // Files that a glob would match, in the directory the shell completes in.
    std::fs::write(setup.home.path().join("glob-me"), "")?;
    let hostile = [
        format!("$(touch {})", mark.display()),
        format!("`touch {}`", mark.display()),
        format!("a;touch {}", mark.display()),
        "a b".to_owned(),
        "*".to_owned(),
        "~".to_owned(),
        "$HOME".to_owned(),
        "\\".to_owned(),
    ];
    let lines: Vec<String> = hostile.iter().map(|l| format!("'{l}'")).collect();
    setup.stand_in(&format!("printf '%s\\n' {}", lines.join(" ")))?;
    for cmd in key_id_commands() {
        let got = setup.offer(&["custodio", cmd, ""])?;
        assert_eq!(set(&got.items), set(&hostile), "{cmd}");
        assert_eq!(got.stderr, "", "{cmd}");
    }
    assert!(!mark.exists(), "a line was run as shell text");
    Ok(())
}

fn writes_nothing_and_asks_no_polkit(shell: Shell) -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("alpha", P256_P12)?;
    let imports = rig.calls(1).len();
    assert_eq!(rig.polkit_calls(), 1, "the counting is live");
    let setup = Setup::new(shell, &rig.bus.address, &shell.text()?)?;
    let state = snapshot(&state_dir(&rig))?;
    let home = snapshot(setup.home.path())?;

    let got = setup.offer(&["custodio", "list", ""])?;
    assert_eq!(got.items, ["alpha"]);
    assert_eq!(got.stderr, "");

    assert_eq!(rig.polkit_calls(), 1, "no polkit request");
    let all = rig.calls(imports + 1);
    let new: Vec<_> = all[imports..]
        .iter()
        .filter(|c| c.0 == BUS_NAME || c.1 == OBJECT_PATH)
        .map(|c| c.3.as_str())
        .collect();
    assert_eq!(new, ["ListKeys"]);
    assert_eq!(snapshot(&state_dir(&rig))?, state, "state directory");
    // A shell keeps its own files (history, caches) under HOME: only what is named for custodio counts.
    let ours = |s: completions_rig::Snapshot| -> completions_rig::Snapshot {
        s.into_iter()
            .filter(|(p, _)| p.to_string_lossy().contains("custodio"))
            .collect()
    };
    let after = snapshot(setup.home.path())?;
    if matches!(shell, Shell::Bash) {
        assert_eq!(after, home, "bash wrote under HOME");
    }
    assert_eq!(ours(after), ours(home), "a file for custodio under HOME");
    Ok(())
}

#[test]
fn bash_takes_the_ids_as_data() -> TestResult {
    ids_are_data(Shell::Bash)
}

#[test]
fn bash_writes_nothing_and_asks_no_polkit() -> TestResult {
    writes_nothing_and_asks_no_polkit(Shell::Bash)
}

#[test]
fn zsh_offers_every_command_and_option_of_the_help() -> TestResult {
    commands_and_options(Shell::Zsh)
}

#[test]
fn zsh_offers_the_key_ids_of_the_person() -> TestResult {
    key_ids_of_the_person(Shell::Zsh)
}

#[test]
fn zsh_offers_nothing_and_quickly_when_the_service_is_absent() -> TestResult {
    service_absent(Shell::Zsh)
}

#[test]
fn zsh_offers_nothing_within_the_bound_when_the_service_hangs() -> TestResult {
    service_hung(Shell::Zsh)
}

#[test]
fn zsh_offers_200_key_ids_within_2_s() -> TestResult {
    two_hundred_keys(Shell::Zsh)
}

#[test]
fn zsh_takes_the_ids_as_data() -> TestResult {
    ids_are_data(Shell::Zsh)
}

#[test]
fn zsh_writes_nothing_and_asks_no_polkit() -> TestResult {
    writes_nothing_and_asks_no_polkit(Shell::Zsh)
}

#[test]
fn fish_offers_every_command_and_option_of_the_help() -> TestResult {
    commands_and_options(Shell::Fish)
}

#[test]
fn fish_offers_the_key_ids_of_the_person() -> TestResult {
    key_ids_of_the_person(Shell::Fish)
}

#[test]
fn fish_offers_nothing_and_quickly_when_the_service_is_absent() -> TestResult {
    service_absent(Shell::Fish)
}

#[test]
fn fish_offers_nothing_within_the_bound_when_the_service_hangs() -> TestResult {
    service_hung(Shell::Fish)
}

#[test]
fn fish_offers_200_key_ids_within_2_s() -> TestResult {
    two_hundred_keys(Shell::Fish)
}

#[test]
fn fish_takes_the_ids_as_data() -> TestResult {
    ids_are_data(Shell::Fish)
}

#[test]
fn fish_writes_nothing_and_asks_no_polkit() -> TestResult {
    writes_nothing_and_asks_no_polkit(Shell::Fish)
}
