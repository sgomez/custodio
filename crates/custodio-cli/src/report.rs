//! The one line format of every command: a state word, a name, a short text, and the lines under
//! it (notes, then `Fix:`), indented under the name so a long text never pushes them right.
//!
//! ```text
//! ok    work  rsa2048  tpm
//!       Restart Firefox to see the key.
//! warn  key storage  not on an encrypted disk (see custodio doctor)
//! ```

use std::fmt::Write as _;
use std::path::Path;

use crate::colour::{self, Paint};

/// The state of one line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Ok,
    NotOk,
    /// Works, with a risk the person should know.
    Warn,
    CouldNotCheck,
}

/// Width of the state column: the longest word.
pub const WORD_WIDTH: usize = 4;

impl State {
    /// The word the line starts with.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NotOk => "FAIL",
            Self::Warn => "warn",
            Self::CouldNotCheck => "?",
        }
    }

    /// [`Self::word`], coloured when `on`, padded to [`WORD_WIDTH`].
    #[must_use]
    pub fn painted(self, on: bool) -> String {
        let paint = match self {
            Self::Ok => Paint::Green,
            Self::NotOk => Paint::Red,
            Self::Warn | Self::CouldNotCheck => Paint::Yellow,
        };
        let pad = " ".repeat(WORD_WIDTH - self.word().len());
        format!("{}{pad}", colour::paint(self.word(), paint, on))
    }
}

/// One line and what goes under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub state: State,
    pub name: String,
    pub text: String,
    /// Each printed under the name, in order.
    pub under: Vec<String>,
}

impl Line {
    #[must_use]
    pub fn new(state: State, name: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            state,
            name: name.into(),
            text: text.into(),
            under: Vec::new(),
        }
    }

    /// This line with `text` added under it.
    #[must_use]
    pub fn with(mut self, text: impl Into<String>) -> Self {
        self.under.push(text.into());
        self
    }

    /// This line with `Fix: fix` added under it.
    #[must_use]
    pub fn fix(self, fix: &str) -> Self {
        self.with(format!("Fix: {fix}"))
    }
}

/// The width of the name column for `lines`.
#[must_use]
pub fn width<'a>(lines: impl IntoIterator<Item = &'a Line>) -> usize {
    lines.into_iter().map(|l| l.name.len()).max().unwrap_or(0)
}

/// Writes `line` after `indent`, its name padded to `width`.
pub fn write(text: &mut String, line: &Line, width: usize, indent: &str, on: bool) {
    let head = format!(
        "{indent}{}  {:<width$}  {}",
        line.state.painted(on),
        line.name,
        line.text
    );
    let _ = writeln!(text, "{}", head.trim_end());
    let under = format!("{indent}{}", " ".repeat(WORD_WIDTH + 2));
    for u in &line.under {
        let _ = writeln!(text, "{under}{u}");
    }
}

/// `lines`, at the left margin, with one name column.
#[must_use]
pub fn render(lines: &[Line], on: bool) -> String {
    let width = width(lines);
    let mut text = String::new();
    for l in lines {
        write(&mut text, l, width, "", on);
    }
    text
}

/// `path` with the home directory written as `~`, for reading.
#[must_use]
pub fn tilde(path: &Path, home: Option<&Path>) -> String {
    home.and_then(|h| path.strip_prefix(h).ok()).map_or_else(
        || path.display().to_string(),
        |rest| format!("~/{}", rest.display()),
    )
}

/// `path` as a shell word that reads back as the path: `~/` for the home directory, then the
/// rest bare when it is plain, else in single quotes.
#[must_use]
pub fn shell_path(path: &Path, home: Option<&Path>) -> String {
    match home.and_then(|h| path.strip_prefix(h).ok()) {
        Some(rest) if !rest.as_os_str().is_empty() => {
            format!("~/{}", shell_word(&rest.display().to_string()))
        }
        _ => shell_word(&path.display().to_string()),
    }
}

/// `word` as the shell reads it back. Control characters are escaped first, so the line cannot
/// drive the terminal.
fn shell_word(word: &str) -> String {
    let word = crate::cert_text::escape(word);
    let plain = !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._/+-,:@%".contains(c));
    if plain {
        word
    } else {
        format!("'{}'", word.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests;
