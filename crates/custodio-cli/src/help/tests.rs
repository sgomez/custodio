use super::*;
use crate::{Command, parse_command};

/// The long options named in a text.
fn options_in(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for word in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')) {
        if word.starts_with("--") && word.len() > 2 {
            found.push(word.to_owned());
        }
    }
    found
}

fn all_commands() -> Vec<&'static CommandSpec> {
    all()
}

fn all_helps() -> String {
    let mut all = global();
    for c in all_commands() {
        all.push_str(&for_command(c.path).unwrap_or_default());
    }
    all
}

#[test]
fn every_command_has_its_own_help_with_every_part() {
    for c in all() {
        let text = for_command(c.path).unwrap_or_default();
        for part in ["Usage:", "Options:", "Example:", c.summary, c.description] {
            assert!(text.contains(part), "{}: no {part:?}", c.path);
        }
        assert_eq!(
            c.children.is_empty(),
            !text.contains("Commands:"),
            "{}",
            c.path
        );
        assert_eq!(
            c.args.is_empty(),
            !text.contains("Arguments:"),
            "{}",
            c.name
        );
        for o in c.options {
            assert!(text.contains(o.flag) && text.contains(o.text), "{}", o.flag);
            assert!(
                o.short.is_none_or(|short| text.contains(short)),
                "{}",
                o.flag
            );
        }
        for child in c.children {
            assert!(text.contains(child.name) && text.contains(child.summary));
        }
    }
    for c in COMMANDS {
        assert!(global().contains(c.name) && global().contains(c.summary));
    }
    assert_eq!(for_command("nosuch"), None);
    assert_eq!(text(Some("nosuch")), global());
    assert_eq!(text(None), global());
    assert_ne!(text(Some("list")), global());
}

#[test]
fn the_help_names_no_option_that_is_not_in_the_table() {
    let mut known: Vec<&str> = vec!["--help"];
    known.extend(all().iter().flat_map(|c| c.options.iter().map(|o| o.flag)));
    for found in options_in(&all_helps()) {
        assert!(
            known.contains(&found.as_str()),
            "{found} is not in the table"
        );
    }
}

#[test]
fn every_example_starts_with_its_command_and_is_accepted_by_the_parser() {
    for c in all() {
        let line = c.example.strip_prefix("sudo ").unwrap_or(c.example);
        let words: Vec<String> = line.split(' ').map(str::to_owned).collect();
        let path: Vec<String> = c.path.split(' ').map(str::to_owned).collect();
        assert_eq!(words[0], "custodio");
        assert_eq!(
            words[1..=path.len().min(words.len() - 1)],
            path[..path.len().min(words.len() - 1)],
            "{}",
            c.example
        );
        if !c.children.is_empty() {
            // a group's example is one of its own commands, whole
            assert!(c.children.iter().any(|k| c.example.contains(k.name)));
        }
        let parsed = parse_command(words[1..].iter().cloned());
        assert!(
            matches!(parsed, Ok(ref cmd) if !matches!(cmd, Command::Help(_))),
            "{}: {parsed:?}",
            c.example
        );
    }
}

#[test]
fn the_parser_accepts_every_option_of_the_table() {
    for c in all() {
        for o in c.options {
            for form in std::iter::once(o.flag).chain(o.short) {
                let mut line: Vec<String> = c.path.split(' ').map(str::to_owned).collect();
                line.push(form.to_owned());
                if o.value.is_some() {
                    line.push("x.p12".to_owned());
                }
                if c.path == "import" {
                    line.push("a.p12".to_owned());
                }
                assert!(parse_command(line.clone()).is_ok(), "{line:?}");
            }
        }
    }
}

#[test]
fn the_usage_line_of_each_command_starts_with_it() {
    for c in all() {
        assert!(c.usage_line().starts_with(&format!("custodio {}", c.path)));
        assert!(c.path.ends_with(c.name));
    }
    for c in all() {
        assert_eq!(
            c.usage_line(),
            format!("custodio {} {}", c.path, c.usage).trim_end()
        );
        for a in c.args {
            assert!(
                c.usage.contains(a.0),
                "{}: {} not in the usage",
                c.name,
                a.0
            );
        }
    }
}

/// The children of a level that its short help does not list with their summary.
fn missing_from_short(level: &CommandSpec, text: &str) -> Vec<String> {
    level
        .children
        .iter()
        .filter(|k| {
            !text
                .lines()
                .any(|l| l.starts_with(&format!("  {} ", k.name)) && l.contains(k.summary))
        })
        .map(|k| k.name.to_owned())
        .collect()
}

#[test]
fn the_short_help_has_the_usage_every_argument_and_option_the_example_and_where_the_rest_is() {
    for c in all() {
        let text = short(c.path).unwrap_or_default();
        let mut parts = vec![c.usage_line(), c.example.to_owned()];
        parts.push(format!("custodio {} --help", c.path));
        parts.extend(
            c.children
                .iter()
                .flat_map(|k| [k.name.to_owned(), k.summary.to_owned()]),
        );
        parts.extend(
            c.args
                .iter()
                .flat_map(|(a, t)| [(*a).to_owned(), (*t).to_owned()]),
        );
        parts.extend(
            c.options
                .iter()
                .flat_map(|o| [o.flag.to_owned(), o.text.to_owned()]),
        );
        parts.extend(c.options.iter().filter_map(|o| o.short.map(str::to_owned)));
        for part in parts {
            assert!(text.contains(&part), "{}: no {part:?}", c.name);
        }
        assert!(!text.contains(c.description), "{}", c.path);
        assert_eq!(
            missing_from_short(c, &text),
            Vec::<String>::new(),
            "{}",
            c.path
        );
        // nothing of another level: no sibling, no grandchild
        for other in all().into_iter().filter(|o| !c.path.starts_with(o.path)) {
            if !c.children.iter().any(|k| k.path == other.path) {
                let row = format!("  {} ", other.name);
                let same_name = c.children.iter().any(|k| k.name == other.name)
                    || c.options.iter().any(|o| o.flag == other.name);
                assert!(
                    same_name || !text.lines().any(|l| l.starts_with(&row)),
                    "{}: {}",
                    c.path,
                    other.path
                );
            }
        }
    }
    assert_eq!(short("nosuch"), None);
    assert_eq!(short("setup nosuch"), None);
}

/// Control: dropping one action from a level's short help is seen by the check above.
#[test]
fn the_short_help_check_sees_a_dropped_action() {
    let level = find("setup browsers").unwrap();
    let text = short("setup browsers").unwrap_or_default();
    assert_eq!(missing_from_short(level, &text), Vec::<String>::new());
    let first = &level.children[0];
    let dropped = text
        .lines()
        .filter(|l| !l.starts_with(&format!("  {} ", first.name)))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        missing_from_short(level, &dropped),
        vec![first.name.to_owned()]
    );
}

#[test]
fn find_follows_a_path_down_the_table() {
    assert_eq!(
        find("setup browsers enable").map(|c| c.name),
        Some("enable")
    );
    assert_eq!(find("setup fingerprint").map(|c| c.children.len()), Some(2));
    assert!(find("register").is_none() && find("fingerprint").is_none());
    assert!(find("setup enable").is_none() && find("list enable").is_none());
}
