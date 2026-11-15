//! Writes the two-key `.p12` fixtures of F195 (`gen.sh` calls it): `twokeys.p12` with a MAC and
//! `twokeys-nomac.p12` without. No tool in the dev container writes two key bags into one file.
//!
//! Usage: `gen_twokeys <first.p12> <second.p12> <password> <out-dir>`. Both inputs are single-key files made
//! with that password; the output holds both keys, shrouded under the same password.
use p12_keystore::{KeyStore, KeyStoreEntry, Pkcs12ImportPolicy};
use std::error::Error;

type Res<T> = Result<T, Box<dyn Error>>;

fn chain(path: &str, password: &str) -> Res<(String, KeyStoreEntry)> {
    let store = KeyStore::from_pkcs12(&std::fs::read(path)?, password, Pkcs12ImportPolicy::Strict)?;
    let (alias, chain) = store.private_key_chain().ok_or("no key chain")?;
    Ok((
        alias.to_owned(),
        KeyStoreEntry::PrivateKeyChain(chain.clone()),
    ))
}

/// `(header length, content length)` of the DER element at the start of `data`.
fn header(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.get(1)?;
    if first < 0x80 {
        return Some((2, usize::from(first)));
    }
    let n = usize::from(first & 0x7f);
    let len = data
        .get(2..2 + n)?
        .iter()
        .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
    Some((2 + n, len))
}

/// The PFX without its `macData`: `SEQUENCE { version, authSafe }`.
fn strip_mac(pfx: &[u8]) -> Option<Vec<u8>> {
    let (outer_header, _) = header(pfx)?;
    let body = pfx.get(outer_header..)?;
    let version_len = 2 + header(body)?.1;
    let rest = body.get(version_len..)?;
    let (auth_header, auth_len) = header(rest)?;
    let kept = body.get(..version_len + auth_header + auth_len)?;
    let mut out = vec![0x30];
    if kept.len() < 0x80 {
        out.push(u8::try_from(kept.len()).ok()?);
    } else {
        let bytes: Vec<u8> = kept
            .len()
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | u8::try_from(bytes.len()).ok()?);
        out.extend(bytes);
    }
    out.extend_from_slice(kept);
    Some(out)
}

fn main() -> Res<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [first, second, password, out_dir] = args.as_slice() else {
        return Err("usage: gen_twokeys <first.p12> <second.p12> <password> <out-dir>".into());
    };
    let mut store = KeyStore::new();
    for path in [first, second] {
        let (alias, entry) = chain(path, password)?;
        store.add_entry(&alias, entry);
    }
    let with_mac = store.writer(password).write()?;
    let without_mac = strip_mac(&with_mac).ok_or("cannot strip the MAC")?;
    std::fs::write(format!("{out_dir}/twokeys.p12"), with_mac)?;
    std::fs::write(format!("{out_dir}/twokeys-nomac.p12"), without_mac)?;
    Ok(())
}
