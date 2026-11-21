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

// ---- the documents name only real commands (Design 3) ----

/// The documents that show commands of the current release; the historical ones are not here.
const DOCUMENTS: &[&str] = &[
    "README.md",
    "docs/install.md",
    "docs/guide-ubuntu-2604.md",
    "docs/fingerprint.md",
    "docs/doctor.md",
    "docs/manual-acceptance.md",
    "SECURITY.md",
    "docs/threat-model.md",
    "docs/release-notes-v0.9.0.md",
];

/// What the product puts before an error message of the setup commands: the command whose line
/// the person typed, or its topic when both actions say the same.
const SETUP_PREFIXES: &[&str] = &["setup browsers enable", "setup fingerprint"];

const NEEDS_A_VALUE: &[&str] = &["-u", "-g", "-U", "-h", "-p", "-C", "-D", "-R", "-r", "-t"];

/// The words of one command after `custodio`, with placeholders turned into values.
fn command_words(tokens: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut skipping = false;
    let mut placeholder = false;
    for t in tokens {
        if t.starts_with('>') || t.starts_with("2>") || t.starts_with("&>") || t.starts_with('#') {
            break;
        }
        if t.starts_with('[') {
            skipping = true;
        }
        let closes = t.ends_with(']');
        if skipping {
            skipping = !closes;
            continue;
        }
        if placeholder {
            placeholder = !t.ends_with('>');
            continue;
        }
        if t.starts_with('<') && !t.ends_with('>') {
            placeholder = true;
            out.push("x".to_owned());
            continue;
        }
        let t = t.trim_matches(|c| c == '\'' || c == '"' || c == '\\');
        if t.is_empty() || t == "..." {
            continue;
        }
        out.push(if t.starts_with('<') && t.ends_with('>') {
            "x".to_owned()
        } else {
            t.to_owned()
        });
    }
    out
}

/// The problems of the commands in `text`: where a command starts, what follows is parsed.
fn commands_in(text: &str, where_: &str, problems: &mut Vec<String>) {
    let split = text
        .replace("&&", "\n")
        .replace("||", "\n")
        .replace(['|', ';', '`'], "\n")
        .replace("$(", "\n");
    for segment in split.lines() {
        let tokens: Vec<&str> = segment.split_whitespace().collect();
        let mut i = usize::from(tokens.first() == Some(&"$"));
        if tokens.get(i) == Some(&"sudo") {
            i += 1;
            while tokens.get(i).is_some_and(|t| t.starts_with('-')) {
                let takes = NEEDS_A_VALUE.contains(&tokens[i]);
                i += if tokens[i] == "--" {
                    1
                } else {
                    1 + usize::from(takes)
                };
                if tokens.get(i - 1) == Some(&"--") {
                    break;
                }
            }
        }
        if tokens.get(i) != Some(&"custodio") {
            continue;
        }
        let args = command_words(&tokens[i + 1..]);
        match custodio_cli::parse_command(args.clone()) {
            // A bare command names a real command; its short help is the product's answer.
            Ok(_) | Err(custodio_cli::ArgError::Bare(_)) => {}
            Err(e) => problems.push(format!(
                "{where_}: `custodio {}` is not a command ({e:?})",
                args.join(" ")
            )),
        }
    }
}

/// A line of output that starts `custodio <words>:` is an error message, not a command.
fn error_prefix(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("custodio ")?;
    let end = rest.find(':')?;
    let words = &rest[..end];
    words
        .chars()
        .all(|c| c.is_ascii_lowercase() || c == ' ')
        .then_some(words)
}

fn document_problems(name: &str, text: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let mut fenced = false;
    for (n, line) in text.lines().enumerate() {
        let where_ = format!("{name}:{}", n + 1);
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            if let Some(words) = error_prefix(trimmed) {
                let first = words.split(' ').next().unwrap_or("");
                let real = if first == "setup" {
                    SETUP_PREFIXES.contains(&words)
                } else {
                    help::command(first).is_some_and(|c| c.children.is_empty())
                        && !words.contains(' ')
                };
                if !real {
                    problems.push(format!(
                        "{where_}: `custodio {words}:` is not what the product prints"
                    ));
                }
            } else {
                commands_in(trimmed, &where_, &mut problems);
            }
        } else {
            for (k, span) in line.split('`').enumerate() {
                if k % 2 == 1 {
                    commands_in(span, &where_, &mut problems);
                }
            }
        }
    }
    problems
}

fn read_document(name: &str) -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    fs::read_to_string(root.join(name)).unwrap()
}

#[test]
fn documents_name_only_real_commands() {
    let mut problems = Vec::new();
    for name in DOCUMENTS {
        problems.extend(document_problems(name, &read_document(name)));
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn the_document_check_sees_an_old_name_in_every_place() {
    let manual = read_document("docs/manual-acceptance.md");
    let in_vm_block = format!("{manual}\n  ```sh vm\n  custodio register\n  ```\n");
    let install = read_document("docs/install.md");
    let in_a_span = format!("{install}\nRun `custodio register --remove` first.\n");
    let fingerprint = read_document("docs/fingerprint.md");
    let stale_prefix = format!(
        "{fingerprint}\n```console\ncustodio fingerprint: this changes a system file\n```\n"
    );
    for (name, text) in [
        ("docs/manual-acceptance.md", in_vm_block),
        ("docs/install.md", in_a_span),
        ("docs/fingerprint.md", stale_prefix),
    ] {
        assert!(!document_problems(name, &text).is_empty(), "{name}");
    }
}
