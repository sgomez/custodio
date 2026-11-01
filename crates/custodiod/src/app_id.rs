//! Parses the flatpak application id out of the name of a caller's cgroup scope.
//!
//! F67 decided that the id comes from the scope flatpak creates, `app-flatpak-<E>-<N>.scope`, where
//! `<E>` is the id escaped by systemd and `<N>` the instance id. This module is pure: it classifies one
//! name given as bytes. It accepts a value only if it is a valid flatpak application id, and the text of
//! anything else is never returned or kept.

/// Longest scope name (a directory-entry name, `.scope` included) that is looked at.
pub const MAX_SCOPE_NAME_LEN: usize = 255;
/// Longest application id flatpak accepts.
pub const MAX_APP_ID_LEN: usize = 255;

const PREFIX: &[u8] = b"app-flatpak-";
const SUFFIX: &[u8] = b".scope";
/// Longest instance id: `u32::MAX` has ten digits.
const MAX_INSTANCE_DIGITS: usize = 10;

/// A validated flatpak application id. Only [`validate`] and [`classify`] build one; there is no public
/// constructor from a string:
///
/// ```compile_fail
/// let _ = custodiod::app_id::AppId(String::from("org.example.App"));
/// ```
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct AppId(String);

impl AppId {
    /// The id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What a scope name says about the caller's flatpak app. No variant besides `Read` carries text.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AppIdOutcome {
    /// A valid flatpak application id.
    Read(AppId),
    /// The caller is not in a flatpak scope (or no name was given).
    None,
    /// The name is a flatpak scope but its id could not be read or is not valid.
    Undetermined,
}

/// Checks `id` against flatpak's rules (`flatpak_is_valid_name`): not empty, at most 255 characters,
/// at least three non-empty elements separated by `.`, elements of `[A-Za-z0-9_-]` not starting with a
/// digit, `-` only in the last element, no leading `.`.
#[must_use]
pub fn validate(id: &[u8]) -> Option<AppId> {
    if id.is_empty() || id.len() > MAX_APP_ID_LEN {
        return None;
    }
    let mut elements = 0usize;
    let mut parts = id.split(|&b| b == b'.').peekable();
    while let Some(element) = parts.next() {
        let last = parts.peek().is_none();
        let first = *element.first()?;
        if first.is_ascii_digit() {
            return None;
        }
        let ok = element.iter().all(|&b| match b {
            b'-' => last,
            b => b.is_ascii_alphanumeric() || b == b'_',
        });
        if !ok {
            return None;
        }
        elements += 1;
    }
    if elements < 3 {
        return None;
    }
    // Every byte is ASCII here, so this never fails.
    String::from_utf8(id.to_vec()).ok().map(AppId)
}

/// Classifies one scope name. `None` input is the absent case.
#[must_use]
pub fn classify(name: Option<&[u8]>) -> AppIdOutcome {
    let Some(name) = name else {
        return AppIdOutcome::None;
    };
    let Some(rest) = name.strip_prefix(PREFIX) else {
        return AppIdOutcome::None;
    };
    // The bound is checked before anything else looks at the bytes.
    if name.len() > MAX_SCOPE_NAME_LEN {
        return AppIdOutcome::Undetermined;
    }
    parse(rest).map_or(AppIdOutcome::Undetermined, AppIdOutcome::Read)
}

fn parse(rest: &[u8]) -> Option<AppId> {
    let middle = rest.strip_suffix(SUFFIX)?;
    // `<E>` holds no raw `-` (systemd writes it as `\x2d`), so exactly one `-` separates it from the instance id.
    let split = middle.iter().position(|&b| b == b'-')?;
    if middle.iter().rposition(|&b| b == b'-') != Some(split) {
        return None;
    }
    let (escaped, instance) = (middle.get(..split)?, middle.get(split + 1..)?);
    if !valid_instance(instance) {
        return None;
    }
    validate(&unescape(escaped)?)
}

fn valid_instance(instance: &[u8]) -> bool {
    !instance.is_empty()
        && instance.len() <= MAX_INSTANCE_DIGITS
        && instance.iter().all(u8::is_ascii_digit)
        && std::str::from_utf8(instance).is_ok_and(|s| s.parse::<u32>().is_ok())
}

/// Undoes systemd's escaping, accepting only `\x2d` (`-`). Upper-case hex (`\x2D`) is rejected on purpose:
/// systemd writes lower-case hex, and the conservative choice is to accept only what it writes.
fn unescape(escaped: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(escaped.len());
    let mut rest = escaped;
    while let Some((&b, tail)) = rest.split_first() {
        if b == b'\\' {
            rest = tail.strip_prefix(b"x2d")?;
            out.push(b'-');
        } else {
            out.push(b);
            rest = tail;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests;
