use super::*;

fn test_parms(kind: u16, sym: u16, scheme: &[u8], tail: &[u8]) -> Vec<u8> {
    let mut v = vec![0x80, 0x01, 0, 0, 0, 0, 0, 0, 0x01, 0x8a];
    v.extend(kind.to_be_bytes());
    v.extend(sym.to_be_bytes());
    v.extend(scheme);
    v.extend(tail);
    let n = u32::try_from(v.len()).unwrap();
    v[2..6].copy_from_slice(&n.to_be_bytes());
    v
}

#[test]
fn test_parms_codes() {
    let lacks = Lacks {
        algorithms: vec![alg::RSAPSS, alg::SHA384],
        curves: vec![3],
        ..Lacks::default()
    };
    let rsa = |scheme: &[u8]| test_parms(1, ALG_NULL, scheme, &[0x08, 0x00, 0, 0, 0, 0]);
    assert_eq!(
        refuse(&rsa(&[0, 0x16, 0, 0x0b]), &lacks),
        Some(0x1d2),
        "PSS is a scheme"
    );
    assert_eq!(
        refuse(&rsa(&[0, 0x14, 0, 0x0c]), &lacks),
        Some(0x1c3),
        "SHA-384 is a hash"
    );
    assert_eq!(refuse(&rsa(&[0, 0x14, 0, 0x0b]), &lacks), None);
    let ecc = |scheme: &[u8]| test_parms(ALG_ECC, ALG_NULL, scheme, &[0, 3, 0, 0x10]);
    assert_eq!(
        refuse(&ecc(&[0, 0x18, 0, 0x0b]), &lacks),
        Some(0x1e6),
        "P-256 is a curve"
    );
    assert_eq!(
        refuse(&[0x80, 1, 0, 0, 0, 10, 0, 0, 1, 0x44], &lacks),
        None,
        "other commands pass"
    );
    assert_eq!(refuse(&[1, 2], &lacks), None, "short input passes");
}

#[test]
fn capability_entries_are_removed() {
    let lacks = Lacks {
        algorithms: vec![alg::RSAPSS],
        curves: vec![],
        ..Lacks::default()
    };
    let command = [
        0x80, 1, 0, 0, 0, 22, 0, 0, 1, 0x7a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80,
    ];
    let mut r = vec![0x80, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    for a in [alg::RSASSA, alg::RSAPSS] {
        r.extend(a.to_be_bytes());
        r.extend([0, 0, 0, 9]);
    }
    let n = u32::try_from(r.len()).unwrap();
    r[2..6].copy_from_slice(&n.to_be_bytes());
    let out = rewrite(&command, r, &lacks);
    assert_eq!(out.len(), 25);
    assert_eq!(&out[15..19], &[0, 0, 0, 1]);
    assert_eq!(&out[19..21], &alg::RSASSA.to_be_bytes());
    assert_eq!(&out[2..6], &25u32.to_be_bytes());
}
