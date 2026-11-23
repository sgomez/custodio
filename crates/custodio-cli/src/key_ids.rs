//! `custodio __key-ids`: the person's key ids for the shell completions, one per line.
//!
//! Hidden: it is not in [`crate::help::COMMANDS`], the help or the man page. It calls `ListKeys`
//! only (no polkit, nothing written), keeps the ids that fit the grammar of `docs/api.md`
//! (1 to 59 bytes of `[A-Za-z0-9_-]`) so that no terminal or shell metacharacter reaches a
//! completion file, sorts them, and gives the call [`CALL_LIMIT`]. On any failure it returns
//! `None` and the caller prints nothing.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::list::KeyEntry;

/// How long the whole call (connecting included) may take.
pub const CALL_LIMIT: Duration = Duration::from_secs(2);

/// Whether `id` is in the grammar of key ids.
#[must_use]
pub fn is_id(id: &str) -> bool {
    (1..=59).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The text to print for these keys: valid ids, sorted, one per line.
#[must_use]
pub fn render(keys: &[KeyEntry]) -> String {
    let mut ids: Vec<&str> = keys
        .iter()
        .map(|k| k.id.as_str())
        .filter(|i| is_id(i))
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids.iter().flat_map(|i| [*i, "\n"]).collect()
}

/// Runs `call` on its own thread and waits at most `limit`. `None` if it failed or did not
/// answer in time (its thread is left behind; the process exits right after).
pub fn within<T, F>(limit: Duration, call: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> Option<T> + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(call());
    });
    rx.recv_timeout(limit).ok().flatten()
}

#[cfg(test)]
mod tests;
