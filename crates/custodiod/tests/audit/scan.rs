//! Test-local encoders and the leak scanner. Independent of the production code.

const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn hex(bytes: &[u8], upper: bool) -> String {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut out = String::new();
    for b in bytes {
        for nibble in [b >> 4, b & 15] {
            out.extend(digits.get(usize::from(nibble)).copied().map(char::from));
        }
    }
    out
}

pub fn base64(bytes: &[u8], url: bool, pad: bool) -> String {
    let table = if url { B64_URL } else { B64_STD };
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let n = (b(0) << 16) | (b(1) << 8) | b(2);
        let sextets = chunk.len() + 1;
        for i in 0..4 {
            if i < sextets {
                out.extend(
                    table
                        .get(((n >> (18 - 6 * i)) & 63) as usize)
                        .copied()
                        .map(char::from),
                );
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

/// Every form a value may take in a log line: name and bytes.
pub fn forms(value: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("raw", value.to_vec()),
        ("hex-lower", hex(value, false).into_bytes()),
        ("hex-upper", hex(value, true).into_bytes()),
        ("b64-std-pad", base64(value, false, true).into_bytes()),
        ("b64-std", base64(value, false, false).into_bytes()),
        ("b64-url-pad", base64(value, true, true).into_bytes()),
        ("b64-url", base64(value, true, false).into_bytes()),
    ]
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// The names of the forms of `value` that appear in `hay`.
pub fn leaks(hay: &[u8], value: &[u8]) -> Vec<&'static str> {
    forms(value)
        .into_iter()
        .filter(|(_, f)| contains(hay, f))
        .map(|(n, _)| n)
        .collect()
}
