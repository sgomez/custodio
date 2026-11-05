#![no_main]

use custodiod::sign::{Mechanism, PssHash};
use custodiod::tpm::sign::Prepared;
use custodiod::tpm::sign::block::{DIGEST, K, Kind, prepare_with};
use libfuzzer_sys::fuzz_target;

#[derive(arbitrary::Arbitrary, Debug)]
struct Input {
    p256: bool,
    mechanism: u8,
    hash: u8,
    // A full `usize`: the bound check in `prepare_with` runs before the salt is allocated, so a huge value must be
    // refused without allocating (libFuzzer's rss limit is the backstop).
    salt_len: usize,
    data: Vec<u8>,
}

// The data and parameters of a signature request are framed or refused, never a panic. An accepted RSA block is `K`
// bytes with the top bit clear, an accepted ECDSA digest is `DIGEST` bytes.
fuzz_target!(|input: Input| {
    let kind = if input.p256 { Kind::P256 } else { Kind::Rsa2048 };
    let hash = match input.hash % 3 {
        0 => PssHash::Sha256,
        1 => PssHash::Sha384,
        _ => PssHash::Sha512,
    };
    let mechanism = match input.mechanism % 3 {
        0 => Mechanism::RsaPkcs,
        1 => Mechanism::RsaPkcsPss {
            hash,
            salt_len: input.salt_len,
        },
        _ => Mechanism::Ecdsa,
    };
    let result = prepare_with(kind, mechanism, &input.data, &mut |salt| salt.fill(0xa5));
    match (result, kind) {
        (Ok(Prepared::Rsa(block)), Kind::Rsa2048) => assert_eq!(block.len(), K),
        (Ok(Prepared::Ecdsa(digest)), Kind::P256) => assert_eq!(digest.len(), DIGEST),
        (Ok(_), _) => panic!("a block of the wrong key type"),
        (Err(_), _) => {}
    }
});
