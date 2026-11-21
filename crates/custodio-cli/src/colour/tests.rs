use super::*;

#[test]
fn colour_needs_the_stream_and_standard_output_to_be_terminals_and_no_non_empty_no_color() {
    for stream in [false, true] {
        for stdout in [false, true] {
            for no_color in [None, Some(""), Some("1"), Some("0")] {
                let want = stream && stdout && matches!(no_color, None | Some(""));
                assert_eq!(
                    enabled(stream, stdout, no_color),
                    want,
                    "{stream} {stdout} {no_color:?}"
                );
            }
        }
    }
}

#[test]
fn a_pipe_on_standard_output_turns_off_the_colour_of_a_terminal_standard_error() {
    assert!(!enabled(true, false, None));
}

#[test]
fn bold_wraps_only_when_on() {
    assert_eq!(bold("x", false), "x");
    assert_eq!(bold("x", true), "\x1b[1mx\x1b[0m");
}

#[test]
fn headings_are_bold_and_the_text_is_the_same_without_the_escapes() {
    let help = crate::help::global();
    assert_eq!(headings(&help, false), help);
    let coloured = headings(&help, true);
    assert!(coloured.contains("\x1b[1mUsage:\x1b[0m\n"));
    assert!(coloured.contains("\x1b[1mCommands:\x1b[0m\n"));
    assert!(!coloured.contains("\x1b[1m  "));
    assert_eq!(strip(&coloured), help);
    for line in coloured.lines() {
        let heading = line.starts_with(BOLD);
        assert_eq!(
            heading,
            strip(line).ends_with(':') && !line.starts_with(' '),
            "{line:?}"
        );
    }
    assert!(
        coloured
            .lines()
            .any(|l| !l.starts_with(BOLD) && !l.ends_with(':'))
    );
    for c in crate::help::all() {
        let text = crate::help::text(Some(c.path));
        assert_eq!(strip(&headings(&text, true)), text);
    }
}
