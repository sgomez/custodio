//! NSS (Firefox) writes a `.p12` in BER: indefinite lengths and OCTET STRINGs in chunks, in the layers around
//! the encrypted bags. `p12-keystore` reads DER only, so those layers are rewritten here. What the bags hold
//! once decrypted is DER already and never passes through this module.

/// Deepest nesting followed; a PKCS#12 needs about ten levels.
const MAX_DEPTH: usize = 16;

const INTEGER: u8 = 0x02;
const OCTET_STRING: u8 = 0x04;
/// An OCTET STRING in chunks.
const CHUNKED_OCTET_STRING: u8 = 0x24;
const OID: u8 = 0x06;
const SEQUENCE: u8 = 0x30;
const CONSTRUCTED: u8 = 0x20;
/// `[0]`, constructed and primitive.
const CONTEXT_0: u8 = 0xA0;
const CONTEXT_0_PRIMITIVE: u8 = 0x80;
/// `encryptedData` (RFC 5652), the content type of the bags encrypted as a whole.
const ENCRYPTED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x06];

/// Tag, length (`None` when indefinite) and what follows the header.
fn header(d: &[u8]) -> Option<(u8, Option<usize>, &[u8])> {
    let (&tag, rest) = d.split_first()?;
    // A PKCS#12 has no tag above 30.
    if tag & 0x1F == 0x1F {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    match first {
        0x80 => Some((tag, None, rest)),
        short @ ..0x80 => Some((tag, Some(usize::from(short)), rest)),
        long => {
            let (digits, rest) = rest.split_at_checked(usize::from(long & 0x7F))?;
            if digits.len() > 4 {
                return None;
            }
            let len = digits
                .iter()
                .fold(0_usize, |acc, digit| (acc << 8) + usize::from(*digit));
            Some((tag, Some(len), rest))
        }
    }
}

/// One element with a definite length.
fn enc(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match u8::try_from(value.len()) {
        Ok(short) if short < 0x80 => out.push(short),
        _ => {
            let digits: Vec<u8> = value
                .len()
                .to_be_bytes()
                .into_iter()
                .skip_while(|digit| *digit == 0)
                .collect();
            // At most the eight bytes of a `usize`.
            out.push(0x80 + u8::try_from(digits.len()).unwrap_or(8));
            out.extend(digits);
        }
    }
    out.extend_from_slice(value);
    out
}

/// The first element of `d` as DER, and what follows it: lengths made definite and chunked OCTET STRINGs
/// joined. The content of a primitive element is copied as it is.
fn element(d: &[u8], depth: usize) -> Option<(Vec<u8>, &[u8])> {
    if depth > MAX_DEPTH {
        return None;
    }
    let (tag, len, rest) = header(d)?;
    if tag & CONSTRUCTED == 0 {
        let (value, after) = rest.split_at_checked(len?)?;
        return Some((enc(tag, value), after));
    }
    let (mut inside, definite_end) = match len {
        Some(len) => {
            let (value, after) = rest.split_at_checked(len)?;
            (value, Some(after))
        }
        None => (rest, None),
    };
    let mut members = Vec::new();
    let after = loop {
        match definite_end {
            Some(after) if inside.is_empty() => break after,
            None => {
                if let Some(after) = inside.strip_prefix(&[0, 0]) {
                    break after;
                }
            }
            Some(_) => {}
        }
        let (member, next) = element(inside, depth + 1)?;
        members.push(member);
        inside = next;
    };
    if tag == CHUNKED_OCTET_STRING {
        return Some((enc(OCTET_STRING, &joined(&members.concat())?), after));
    }
    Some((enc(tag, &members.concat()), after))
}

/// `d` as DER when it is exactly one element.
fn whole(d: &[u8]) -> Option<Vec<u8>> {
    match element(d, 0)? {
        (der, []) => Some(der),
        _ => None,
    }
}

/// Tag and content of each member of a DER value.
fn members(mut d: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    while !d.is_empty() {
        let (tag, len, rest) = header(d)?;
        let (value, after) = rest.split_at_checked(len?)?;
        out.push((tag, value));
        d = after;
    }
    Some(out)
}

/// The contents of the OCTET STRINGs in `chunks`, one after another.
fn joined(chunks: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for (tag, value) in members(chunks)? {
        if tag != OCTET_STRING {
            return None;
        }
        out.extend_from_slice(value);
    }
    Some(out)
}

/// `EncryptedData` with its `[0] IMPLICIT` ciphertext in one piece. NSS writes it in chunks, which
/// [`element`] cannot tell from an explicit `[0]` and leaves as they are.
fn encrypted_data(content: &[u8]) -> Option<Vec<u8>> {
    let content = members(content)?;
    let [(SEQUENCE, data)] = content.as_slice() else {
        return None;
    };
    let data = members(data)?;
    let [(INTEGER, version), (SEQUENCE, info), rest @ ..] = data.as_slice() else {
        return None;
    };
    let mut fields = Vec::new();
    for &(tag, value) in &members(info)? {
        if tag == CONTEXT_0 {
            fields.extend(enc(CONTEXT_0_PRIMITIVE, &joined(value)?));
        } else {
            fields.extend(enc(tag, value));
        }
    }
    let mut out = enc(INTEGER, version);
    out.extend(enc(SEQUENCE, &fields));
    for &(tag, value) in rest {
        out.extend(enc(tag, value));
    }
    Some(enc(SEQUENCE, &out))
}

/// The `AuthenticatedSafe` in `safe` as DER.
fn authenticated_safe(safe: &[u8]) -> Option<Vec<u8>> {
    let der = whole(safe)?;
    let safe = members(&der)?;
    let [(SEQUENCE, infos)] = safe.as_slice() else {
        return None;
    };
    let mut out = Vec::new();
    for &(tag, info) in &members(infos)? {
        let info = members(info)?;
        let [(OID, kind), (CONTEXT_0, content)] = info.as_slice() else {
            return None;
        };
        if tag != SEQUENCE {
            return None;
        }
        let content = if *kind == ENCRYPTED_DATA {
            encrypted_data(content)?
        } else {
            content.to_vec()
        };
        out.extend(enc(
            SEQUENCE,
            &[enc(OID, kind), enc(CONTEXT_0, &content)].concat(),
        ));
    }
    Some(enc(SEQUENCE, &out))
}

/// `file` with its outer layers as DER. The `AuthenticatedSafe` inside keeps its own bytes, so the MAC of
/// the file still holds for it. `None` when `file` is not one BER element.
pub(super) fn outer(file: &[u8]) -> Option<Vec<u8>> {
    whole(file)
}

/// From the result of [`outer`]: the `AuthenticatedSafe` as DER too, and no MAC, which no longer holds.
/// The caller has checked the MAC on [`outer`] before. `None` when the structure is not that of a PKCS#12.
pub(super) fn inner(outer: &[u8]) -> Option<Vec<u8>> {
    let file = members(outer)?;
    let [(SEQUENCE, pfx)] = file.as_slice() else {
        return None;
    };
    let pfx = members(pfx)?;
    let [(INTEGER, version), (SEQUENCE, auth_safe), ..] = pfx.as_slice() else {
        return None;
    };
    let auth_safe = members(auth_safe)?;
    let [(OID, kind), (CONTEXT_0, content)] = auth_safe.as_slice() else {
        return None;
    };
    let content = members(content)?;
    let [(OCTET_STRING, safe)] = content.as_slice() else {
        return None;
    };
    let safe = enc(OCTET_STRING, &authenticated_safe(safe)?);
    let auth_safe = enc(SEQUENCE, &[enc(OID, kind), enc(CONTEXT_0, &safe)].concat());
    Some(enc(SEQUENCE, &[enc(INTEGER, version), auth_safe].concat()))
}

#[cfg(test)]
mod tests;
