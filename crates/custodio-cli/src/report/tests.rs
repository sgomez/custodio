use std::path::Path;

use super::*;

fn sample() -> Vec<Line> {
    vec![
        Line::new(State::Ok, "a", "short"),
        Line::new(State::NotOk, "a much longer name", "text")
            .with("a note")
            .fix("do this"),
        Line::new(State::Warn, "mid name", "").with("under an empty text"),
        Line::new(State::CouldNotCheck, "q", "why"),
    ]
}

#[test]
fn the_names_line_up_and_what_is_under_a_line_starts_under_its_name() {
    let lines = sample();
    for indent in ["", "  "] {
        let mut text = String::new();
        let width = width(&lines);
        for l in &lines {
            write(&mut text, l, width, indent, false);
        }
        let printed: Vec<&str> = text.lines().collect();
        let name_column = indent.len() + WORD_WIDTH + 2;
        let mut at = 0;
        for l in &lines {
            let head = printed[at];
            assert!(
                head.starts_with(&format!("{indent}{}", l.state.word())),
                "{head:?}"
            );
            assert_eq!(head.find(&l.name), Some(name_column), "{text}");
            if !l.text.is_empty() {
                assert_eq!(head.find(&l.text), Some(name_column + width + 2), "{text}");
            }
            assert_eq!(head, head.trim_end(), "{head:?}");
            at += 1;
            for u in &l.under {
                assert_eq!(
                    printed[at],
                    format!("{}{u}", " ".repeat(name_column)),
                    "{text}"
                );
                at += 1;
            }
        }
        assert_eq!(at, printed.len(), "{text}");
    }
}

#[test]
fn colour_changes_nothing_but_escape_sequences_and_the_words_differ() {
    let lines = sample();
    let coloured = render(&lines, true);
    assert_ne!(coloured, render(&lines, false));
    assert_eq!(crate::colour::strip(&coloured), render(&lines, false));
    let words = [State::Ok, State::NotOk, State::Warn, State::CouldNotCheck].map(State::word);
    for (i, w) in words.iter().enumerate() {
        assert!(!words[i + 1..].contains(w), "{w} twice");
        assert!(w.len() <= WORD_WIDTH);
    }
}

/// What `sh` makes of `word` with `HOME` set to `home`.
fn read_back(word: &str, home: &Path) -> String {
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("printf %s {word}"))
        .env("HOME", home)
        .output()
        .expect("sh");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn a_shell_path_reads_back_as_the_path_under_home_or_not() {
    let home = Path::new("/home/some one");
    for path in [
        "/tmp/k.p12",
        "/tmp/my cert.p12",
        "/tmp/it's.p12",
        "/tmp/~k.p12",
        "/tmp/$HOME*.p12",
        "/home/some one/Datos/cert 2024.p12",
        "/home/some one/it's.p12",
        "/home/some one/k.p12",
        "/home/some oneX/k.p12",
    ] {
        let word = shell_path(Path::new(path), Some(home));
        assert_eq!(read_back(&word, home), path, "{word}");
        let bare = shell_path(Path::new(path), None);
        assert_eq!(read_back(&bare, home), path, "{bare}");
    }
    assert!(shell_path(Path::new("/home/some one/k.p12"), Some(home)).starts_with("~/"));
}

#[test]
fn tilde_shortens_only_what_is_under_home() {
    let home = Path::new("/home/u");
    assert_eq!(tilde(Path::new("/home/u/a/b"), Some(home)), "~/a/b");
    assert_eq!(tilde(Path::new("/home/uu/a"), Some(home)), "/home/uu/a");
    assert_eq!(tilde(Path::new("/home/u/a"), None), "/home/u/a");
}
