//! Nothing written holds a plaintext key, temporary files included.

use std::fs;
use std::path::Path;

use super::*;
use secrecy::ExposeSecret;

fn base64(data: &[u8], url: bool) -> String {
    let table: &[u8; 64] = if url {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(char::from(table[(n >> (18 - 6 * i) & 63) as usize]));
        }
    }
    out
}

fn hex(data: &[u8]) -> String {
    use std::fmt::Write;
    data.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Every form the key could take in a file: raw, hex (both cases), base64 (both alphabets).
fn needles(key: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    // A base64 text depends on the alignment: the three alignments of a window of the key.
    let window = &key[key.len() / 2..key.len() / 2 + 24];
    let mut v = vec![
        ("raw", window.to_vec()),
        ("hex", hex(window).into_bytes()),
        ("HEX", hex(window).to_uppercase().into_bytes()),
    ];
    for skip in 0..3 {
        let part = &window[skip..];
        let text = base64(part, false);
        // Drop the characters that depend on the neighbours of the window.
        v.push(("base64", text.as_bytes()[2..text.len() - 2].to_vec()));
        let url = base64(part, true);
        v.push(("base64url", url.as_bytes()[2..url.len() - 2].to_vec()));
    }
    v
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// What in `dir` holds one of the needles.
fn sweep(dir: &Path, needles: &[(&'static str, Vec<u8>)]) -> Vec<String> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            found.extend(sweep(&path, needles));
        } else {
            let data = fs::read(&path).unwrap();
            for (name, needle) in needles {
                if contains(&data, needle) {
                    found.push(format!("{} holds the key as {name}", path.display()));
                }
            }
        }
    }
    found
}

#[test]
fn no_plaintext_anywhere() -> TestResult {
    let parsed = fixture();
    let key = parsed.key.expose_secret().to_vec();
    let needles = needles(&key);
    for (kind, creds) in [
        (Kind::EncryptedHost, MemoryCreds::host()),
        (Kind::EncryptedTpm, MemoryCreds::tpm()),
    ] {
        let (_tmp, store) = fresh();
        let sealed = seal(&creds, "x", &parsed.key)?;
        let record = Record::new(
            OWNER,
            "k",
            kind,
            &parsed.certificate,
            Protected::from_sealed(&sealed),
        )?;
        let mut hooked = false;
        store.put_with_hook(&record, |tmp| {
            // The temporary file is written and not yet linked: it holds the framed record only.
            let data = fs::read(tmp)?;
            for (name, needle) in &needles {
                assert!(
                    !contains(&data, needle),
                    "the temporary file holds the key as {name}"
                );
            }
            hooked = true;
            Ok(())
        })?;
        assert!(hooked, "the hook did not run");
        assert_eq!(sweep(store.dir(), &needles), Vec::<String>::new());
        assert_eq!(store.get(OWNER, "k")?, record);
    }
    Ok(())
}

#[test]
fn the_sweep_finds_a_planted_key() -> TestResult {
    let parsed = fixture();
    let key = parsed.key.expose_secret().to_vec();
    let needles = needles(&key);
    for (name, needle) in &needles {
        let (_tmp, store) = fresh();
        store.put(&host("k", b"cert"))?;
        let mut file = b"prefix-".to_vec();
        file.extend(needle);
        plant(&store, OWNER, "planted", &file);
        let found = sweep(store.dir(), &needles);
        assert!(found.iter().any(|f| f.contains(name)), "{name}: {found:?}");
    }
    Ok(())
}
