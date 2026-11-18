//! When output may be coloured, and the colouring itself.
//!
//! A stream is coloured only if it is a terminal, standard output is a terminal too, and
//! `NO_COLOR` is unset or empty (<https://no-color.org>: only a non-empty value, `0` included,
//! turns colour off). With standard output not a terminal, neither stream has colour: someone
//! who pipes the output gets plain text on the screen as well.

const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

/// Whether a stream may carry colour.
#[must_use]
pub fn enabled(stream_is_terminal: bool, stdout_is_terminal: bool, no_color: Option<&str>) -> bool {
    stream_is_terminal && stdout_is_terminal && no_color.is_none_or(str::is_empty)
}

/// A colour for [`paint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Paint {
    Green,
    Red,
    Yellow,
}

/// `text` in that colour when `on`, unchanged otherwise.
#[must_use]
pub fn paint(text: &str, colour: Paint, on: bool) -> String {
    let code = match colour {
        Paint::Green => "\x1b[32m",
        Paint::Red => "\x1b[31m",
        Paint::Yellow => "\x1b[33m",
    };
    if on {
        format!("{code}{text}{RESET}")
    } else {
        text.to_owned()
    }
}

/// `text` in bold when `on`, unchanged otherwise.
#[must_use]
pub fn bold(text: &str, on: bool) -> String {
    if on {
        format!("{BOLD}{text}{RESET}")
    } else {
        text.to_owned()
    }
}

/// The help with its headings (the lines that start in the first column and end with a colon)
/// in bold when `on`. Without colour the text is returned as it is.
#[must_use]
pub fn headings(help: &str, on: bool) -> String {
    if !on {
        return help.to_owned();
    }
    let mut out = String::with_capacity(help.len());
    for line in help.split_inclusive('\n') {
        let body = line.trim_end_matches('\n');
        if body.ends_with(':') && !body.starts_with(' ') {
            out.push_str(&bold(body, true));
            out.push_str(&line[body.len()..]);
        } else {
            out.push_str(line);
        }
    }
    out
}

/// `text` with a leading `custodio:` or `custodio <command>:` in bold when `on`.
#[must_use]
pub fn prefix(text: &str, on: bool) -> String {
    let head = text.split_once(':').map(|(h, _)| h).filter(|h| {
        h.strip_prefix("custodio")
            .is_some_and(|c| c.is_empty() || (c.starts_with(' ') && !c[1..].contains(' ')))
    });
    match head {
        Some(head) if on => format!(
            "{}{}",
            bold(&text[..=head.len()], true),
            &text[head.len() + 1..]
        ),
        _ => text.to_owned(),
    }
}

/// `text` without the escape sequences this module writes.
#[must_use]
pub fn strip(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("\x1b[") {
        out.push_str(&rest[..at]);
        let tail = &rest[at + 2..];
        match tail.find('m') {
            Some(end) if tail[..end].bytes().all(|b| b.is_ascii_digit() || b == b';') => {
                rest = &tail[end + 1..];
            }
            _ => {
                out.push_str("\x1b[");
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests;
