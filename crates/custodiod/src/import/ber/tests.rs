use super::*;

/// `count` SEQUENCEs of indefinite length, one inside the other.
fn nested(count: usize) -> Vec<u8> {
    [[0x30, 0x80].repeat(count), [0x00, 0x00].repeat(count)].concat()
}

fn octets(tag: u8, len: usize) -> Vec<u8> {
    enc(tag, &vec![0xAB; len])
}

#[test]
fn ber_becomes_der() {
    let long = [&[0x30, 0x80][..], &octets(0x04, 300), &[0x00, 0x00]].concat();
    let cases: [(&[u8], &[u8]); 7] = [
        // DER stays as it is.
        (&[0x02, 0x01, 0x05], &[0x02, 0x01, 0x05]),
        (
            &[0x30, 0x03, 0x02, 0x01, 0x05],
            &[0x30, 0x03, 0x02, 0x01, 0x05],
        ),
        // An indefinite length becomes definite.
        (
            &[0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00],
            &[0x30, 0x03, 0x02, 0x01, 0x05],
        ),
        // Chunks are joined, nested ones too.
        (
            &[
                0x24, 0x80, 0x04, 0x01, 0xAA, 0x04, 0x02, 0xBB, 0xCC, 0x00, 0x00,
            ],
            &[0x04, 0x03, 0xAA, 0xBB, 0xCC],
        ),
        (
            &[
                0x24, 0x80, 0x24, 0x80, 0x04, 0x01, 0xAA, 0x00, 0x00, 0x04, 0x01, 0xBB, 0x00, 0x00,
            ],
            &[0x04, 0x02, 0xAA, 0xBB],
        ),
        // A length written with more bytes than it needs, up to four.
        (
            &[0x04, 0x84, 0x00, 0x00, 0x00, 0x01, 0xAA],
            &[0x04, 0x01, 0xAA],
        ),
        // Lengths over 127 and over 255.
        (&long, &enc(0x30, &octets(0x04, 300))),
    ];
    for (ber, der) in cases {
        assert_eq!(whole(ber).as_deref(), Some(der), "{ber:02X?}");
    }
    assert_eq!(octets(0x04, 127).get(..2), Some(&[0x04, 0x7F][..]));
    assert_eq!(octets(0x04, 128).get(..3), Some(&[0x04, 0x81, 0x80][..]));
    assert_eq!(
        octets(0x04, 300).get(..4),
        Some(&[0x04, 0x82, 0x01, 0x2C][..])
    );
    assert!(whole(&nested(MAX_DEPTH + 1)).is_some());
}

#[test]
fn what_is_not_one_ber_element_is_refused() {
    let cases: [&[u8]; 9] = [
        &[],
        // Bytes after the element.
        &[0x02, 0x01, 0x05, 0x00],
        // No end of contents.
        &[0x30, 0x80, 0x02, 0x01, 0x05],
        // An indefinite length on a primitive element.
        &[0x04, 0x80, 0x00, 0x00],
        // Shorter than its length says.
        &[0x02, 0x05, 0x01],
        &[0x30, 0x05, 0x02, 0x01, 0x05],
        // A tag of more than one byte.
        &[0x1F, 0x01, 0x00],
        // A length of five bytes.
        &[0x04, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAA],
        // A chunk that is not an OCTET STRING.
        &[0x24, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00],
    ];
    for ber in cases {
        assert_eq!(whole(ber), None, "{ber:02X?}");
    }
    assert_eq!(whole(&nested(MAX_DEPTH + 2)), None);
}
