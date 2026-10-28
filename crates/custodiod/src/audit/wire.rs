//! Native Journal Protocol encoding of a list of fields.

/// Encodes `NAME=value\n` for a value without a newline, else `NAME\n` + 8-byte little-endian length +
/// value + `\n`.
pub(super) fn encode(fields: &[(&str, String)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in fields {
        out.extend_from_slice(name.as_bytes());
        if value.contains('\n') {
            out.push(b'\n');
            out.extend_from_slice(&(value.len() as u64).to_le_bytes());
        } else {
            out.push(b'=');
        }
        out.extend_from_slice(value.as_bytes());
        out.push(b'\n');
    }
    out
}
