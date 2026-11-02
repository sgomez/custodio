use super::*;

const P256_KEY: &[u8] = include_bytes!("../../../tests/fixtures/p256.p12");
const RSA_KEY: &[u8] = include_bytes!("../../../tests/fixtures/rsa2048.p12");
const P256_RECERT: &[u8] = include_bytes!("../../../tests/fixtures/cert-p256-recert.der");
const RSA_RECERT: &[u8] = include_bytes!("../../../tests/fixtures/cert-rsa2048-recert.der");
const P256_EXPIRED: &[u8] = include_bytes!("../../../tests/fixtures/cert-p256-expired.der");
const P256_OTHER: &[u8] = include_bytes!("../../../tests/fixtures/cert-p256-other.der");
const RSA_OTHER: &[u8] = include_bytes!("../../../tests/fixtures/cert-rsa2048-other.der");
const P384: &[u8] = include_bytes!("../../../tests/fixtures/cert-p384.der");
const ED25519: &[u8] = include_bytes!("../../../tests/fixtures/cert-ed25519.der");
const RSA3072: &[u8] = include_bytes!("../../../tests/fixtures/cert-rsa3072.der");

fn parsed(p12: &[u8]) -> Result<crate::import::ParsedP12, crate::import::ImportError> {
    crate::import::parse_p12(
        p12,
        &secrecy::SecretString::from("test-password".to_owned()),
    )
}

#[test]
fn the_bound_is_16_kib_and_exact() {
    assert_eq!(MAX_CERT_LEN, 16384);
    assert!(within_bound(0));
    assert!(within_bound(MAX_CERT_LEN));
    assert!(!within_bound(MAX_CERT_LEN + 1));
}

#[test]
fn the_request_check_refuses_by_id_then_certificate() {
    assert_eq!(parse_replace_request("k1", P256_RECERT), Ok(()));
    assert_eq!(
        parse_replace_request("", P256_RECERT),
        Err(ServiceError::InvalidArgs)
    );
    assert_eq!(
        parse_replace_request("k1", b"x"),
        Err(ServiceError::InvalidArgs)
    );
    let mut padded = P256_RECERT.to_vec();
    padded.resize(MAX_CERT_LEN + 1, 0);
    assert_eq!(
        parse_replace_request("k1", &padded),
        Err(ServiceError::InvalidArgs)
    );
}

#[test]
fn only_exactly_one_certificate_is_accepted() {
    for cert in [P256_RECERT, RSA_RECERT, P256_EXPIRED, P384, ED25519] {
        assert!(is_certificate(cert));
    }
    let mut trailing = P256_RECERT.to_vec();
    trailing.push(0);
    let truncated = P256_RECERT.get(..P256_RECERT.len() - 1).unwrap_or_default();
    let oversized = vec![0_u8; MAX_CERT_LEN + 1];
    // A valid certificate padded past the bound is refused, whatever the parser would say.
    let mut padded = P256_RECERT.to_vec();
    padded.resize(MAX_CERT_LEN + 1, 0);
    // A DER SEQUENCE that is not a certificate.
    let sequence = [0x30, 0x03, 0x02, 0x01, 0x05];
    for bad in [
        &b""[..],
        b"not a certificate",
        &trailing,
        truncated,
        &oversized,
        &padded,
        &sequence,
    ] {
        assert!(!is_certificate(bad));
    }
}

#[test]
fn a_certificate_matches_its_own_key_only() -> Result<(), Box<dyn std::error::Error>> {
    use secrecy::ExposeSecret;
    let ec = parsed(P256_KEY)?;
    let rsa = parsed(RSA_KEY)?;
    let (ec_key, rsa_key) = (ec.key.expose_secret(), rsa.key.expose_secret());
    // The original and a second certificate over the same key.
    assert_eq!(certificate_matches_key(ec_key, &ec.certificate), Some(true));
    assert_eq!(certificate_matches_key(ec_key, P256_RECERT), Some(true));
    assert_eq!(certificate_matches_key(ec_key, P256_EXPIRED), Some(true));
    assert_eq!(
        certificate_matches_key(rsa_key, &rsa.certificate),
        Some(true)
    );
    assert_eq!(certificate_matches_key(rsa_key, RSA_RECERT), Some(true));
    // Another key of the same type, the other supported type, and unsupported types.
    for other in [P256_OTHER, RSA_OTHER, P384, ED25519, RSA3072, RSA_RECERT] {
        assert_eq!(certificate_matches_key(ec_key, other), Some(false));
    }
    for other in [RSA_OTHER, P256_OTHER, P256_RECERT, P384, ED25519, RSA3072] {
        assert_eq!(certificate_matches_key(rsa_key, other), Some(false));
    }
    // A private key of an unsupported type has no comparison.
    assert_eq!(certificate_matches_key(b"junk", P256_RECERT), None);
    Ok(())
}

#[test]
fn the_api_document_states_the_method_its_bound_and_its_guarantees() {
    let text = include_str!("../../../../../docs/api.md");
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let bound = format!("- certificate size: `{MAX_CERT_LEN}` bytes at most.");
    for statement in [
        "### Method `ReplaceCertificate`",
        "- in `certificate`: `ay`",
        bound.as_str(),
        "before the caller, any key, any file or polkit is touched",
        "under the action `com.rfirma.custodio.replace-certificate`",
        "There are no chain, revocation or date checks",
        "The replacement is atomic",
        "never an error or a missing one",
        "fails as `CertificateMismatch` and nothing changes",
        "a `certificate` that is not exactly one DER X.509 certificate",
    ] {
        assert!(flat.contains(statement), "missing: {statement}");
    }
}
