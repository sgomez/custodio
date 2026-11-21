//! `custodio setup` (acceptance 23) through the binary on a fixture home: the old commands are
//! unknown, bare levels are usage errors with that level's short help, and `--help` works at every
//! level. What the parser says about a line is proven by its unit tests, not again here.

mod fixture;

use std::fs;
use std::process::Output;

use custodio_cli::help::{self, CommandSpec};
use fixture::Fixture;

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn path() -> std::path::PathBuf {
    std::env::var_os("PATH").unwrap_or_default().into()
}

/// A home with one file in it, and the output of the binary on it: the tree must not change.
fn run(args: &[&str]) -> (Output, bool) {
    let f = Fixture::new();
    fs::write(f.home().join("keep"), "x").unwrap();
    let before = f.snapshot();
    let out = f.binary(args, &path(), &[]);
    (out, before == f.snapshot())
}

fn words(path: &str) -> Vec<&str> {
    path.split(' ').collect()
}

#[test]
fn register_and_fingerprint_are_unknown_commands() {
    for line in [
        &["register"][..],
        &["register", "--remove"],
        &["register", "--refresh-only"],
        &["fingerprint", "enable"],
        &["fingerprint"],
    ] {
        let (out, untouched) = run(line);
        assert_eq!(out.status.code(), Some(2), "{line:?}");
        assert!(out.stdout.is_empty(), "{line:?}");
        assert!(text(&out.stderr).contains("custodio --help"), "{line:?}");
        assert!(untouched, "{line:?}");
    }
}

#[test]
fn a_browsers_disable_with_a_module_is_refused_and_changes_nothing() {
    let (out, untouched) = run(&[
        "setup",
        "browsers",
        "disable",
        "--module",
        "/nonexistent.so",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(untouched);
}

/// The levels that only group: `setup` and each topic.
fn groups() -> Vec<&'static CommandSpec> {
    help::all()
        .into_iter()
        .filter(|c| c.path.starts_with("setup") && !c.children.is_empty())
        .collect()
}

#[test]
fn a_bare_level_is_a_usage_error_with_its_short_help_ending_with_the_next_step() {
    let levels = groups();
    assert_eq!(levels.len(), 3, "setup, browsers, fingerprint");
    for c in levels {
        let (out, untouched) = run(&words(c.path));
        assert_eq!(out.status.code(), Some(2), "{}", c.path);
        assert!(out.stdout.is_empty(), "{}", c.path);
        let err = text(&out.stderr);
        assert_eq!(err.trim_end(), help::short(c.path).unwrap_or_default());
        let last = err.trim_end().lines().last().unwrap_or_default();
        assert_eq!(last, format!("Run 'custodio {} --help' for more.", c.path));
        assert!(untouched, "{}", c.path);
    }
}

#[test]
fn an_unknown_topic_or_action_names_the_help_of_its_level() {
    for (line, level) in [
        (&["setup", "nosuch"][..], "setup"),
        (&["setup", "browsers", "nosuch"], "setup browsers"),
        (&["setup", "fingerprint", "nosuch"], "setup fingerprint"),
    ] {
        let (out, untouched) = run(line);
        assert_eq!(out.status.code(), Some(2), "{line:?}");
        assert!(out.stdout.is_empty(), "{line:?}");
        assert!(
            text(&out.stderr).contains(&format!("custodio {level} --help")),
            "{line:?}"
        );
        assert!(untouched, "{line:?}");
    }
}

#[test]
fn help_at_every_level_prints_what_the_table_says_on_stdout() {
    for c in help::all()
        .into_iter()
        .filter(|c| c.path.starts_with("setup"))
    {
        for flag in ["--help", "-h"] {
            let mut line = words(c.path);
            line.push(flag);
            let (out, untouched) = run(&line);
            assert_eq!(out.status.code(), Some(0), "{line:?}");
            assert!(out.stderr.is_empty(), "{line:?}");
            assert!(untouched, "{line:?}");
            let help = text(&out.stdout);
            let must = [
                format!("custodio {} - {}", c.path, c.summary),
                c.usage_line(),
                c.description.to_owned(),
            ];
            for part in must {
                assert!(help.contains(&part), "{line:?}: no {part:?}");
            }
            assert!(help.lines().any(|l| l.trim() == c.example), "{line:?}");
            assert_eq!(help.contains("Arguments:"), !c.args.is_empty(), "{line:?}");
            assert_eq!(
                help.contains("Commands:"),
                !c.children.is_empty(),
                "{line:?}"
            );
            for o in c.options {
                assert!(help.contains(o.flag) && help.contains(o.text), "{line:?}");
            }
            for k in c.children {
                assert!(
                    help.contains(k.name) && help.contains(k.summary),
                    "{line:?}"
                );
            }
        }
    }
}
