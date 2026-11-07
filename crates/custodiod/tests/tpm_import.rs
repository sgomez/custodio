//! Importing a key into the TPM with `TPM2_Import` (F113), against `swtpm`. The tools of `tpm2-tools` are the oracle: they
//! load the returned blob under their own parent and read what the TPM holds.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

#[path = "tpm_import/flush.rs"]
mod flush;
#[path = "tpm_import/mismatch.rs"]
mod mismatch;
#[path = "tpm_import/support.rs"]
mod support;
#[path = "tpm_import/wire.rs"]
mod wire;

use custodio_it::tpm_filter::{Lacks, cc};
use custodiod::tpm::import::{ImportError, import_pkcs8};
use custodiod::tpm::key::KeyRefusal;
use custodiod::tpm::open::TestTcti;
use support::{BOTH, Kind, Rig, SRK_ATTRS, TestKey, TestResult, field, genpkey, hex, nested};

#[test]
fn other_keys_refused() -> TestResult {
    let rig = Rig::new()?;
    let (filter, record) = rig.filter(Lacks::default())?;
    let access = TestTcti::new(&filter.tcti());
    let p384 = genpkey(&["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"]);
    let exponent3 = genpkey(&[
        "-algorithm",
        "RSA",
        "-pkeyopt",
        "rsa_keygen_bits:2048",
        "-pkeyopt",
        "rsa_keygen_pubexp:3",
    ]);
    let cases = [
        (
            genpkey(&["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:1024"]),
            KeyRefusal::Unsupported,
        ),
        (
            genpkey(&["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"]),
            KeyRefusal::Unsupported,
        ),
        (p384, KeyRefusal::Unsupported),
        (genpkey(&["-algorithm", "ED25519"]), KeyRefusal::Unsupported),
        (exponent3, KeyRefusal::RsaExponent),
    ];
    for (pem, why) in cases {
        assert_eq!(
            import_pkcs8(&access, &support::pkcs8_of(&pem)).unwrap_err(),
            ImportError::Refused(why)
        );
    }
    assert_eq!(
        import_pkcs8(&access, b"garbage").unwrap_err(),
        ImportError::Refused(KeyRefusal::Unsupported)
    );
    assert_eq!(
        record.codes(),
        Vec::<u32>::new(),
        "no command for a refused key"
    );
    // Control: the two accepted types do reach the TPM.
    for kind in BOTH {
        let before = record.codes().len();
        import_pkcs8(&access, &TestKey::new(kind).pkcs8)?;
        assert!(record.codes().len() > before);
        assert!(record.codes().contains(&cc::IMPORT), "{kind:?}");
    }
    Ok(())
}

#[test]
fn parent_is_the_approved_template() -> TestResult {
    let rig = Rig::new()?;
    let access = TestTcti::new(&rig.tcti());
    let persistent = rig.getcap("handles-persistent")?;
    let nv = rig.getcap("handles-nv-index")?;
    for kind in BOTH {
        let imported = import_pkcs8(&access, &TestKey::new(kind).pkcs8)?;
        let name = rig.primary(SRK_ATTRS)?;
        assert_eq!(hex(&imported.parent_name), name, "{kind:?}");
        // Control: one attribute different gives another primary, so the comparison can fail.
        let other = rig.primary(&SRK_ATTRS.replace("|noda", ""))?;
        assert_ne!(hex(&imported.parent_name), other);
    }
    assert_eq!(rig.getcap("handles-persistent")?, persistent);
    assert_eq!(rig.getcap("handles-nv-index")?, nv);
    Ok(())
}

/// The attributes `tpm2_readpublic` shows for a loaded blob.
#[test]
fn attributes_per_key_type() -> TestResult {
    let rig = Rig::new()?;
    let access = TestTcti::new(&rig.tcti());
    rig.primary(SRK_ATTRS)?;
    for kind in BOTH {
        let key = TestKey::new(kind);
        let imported = import_pkcs8(&access, &key.pkcs8)?;
        rig.load(&imported.blob)?;
        let shown = rig.tool("tpm2_readpublic", &["-c", &rig.path("k.ctx")])?;
        // The stored public area, read from the bytes: the same facts.
        let stored = rig.write("stored.pub", imported.blob.public_bytes())?;
        // The tools omit an empty policy line, so also read its size straight from the stored TPM2B_PUBLIC:
        // size(2) type(2) nameAlg(2) attributes(4) authPolicy size(2).
        assert_eq!(
            imported.blob.public_bytes().get(10..12),
            Some(&[0u8, 0][..]),
            "{kind:?}: authPolicy length"
        );
        let printed = rig.tool("tpm2_print", &["-t", "TPM2B_PUBLIC", &stored])?;
        for text in [&shown, &printed] {
            assert_eq!(
                nested(text, "name-alg").as_deref(),
                Some("sha256"),
                "{kind:?}"
            );
            let attributes = nested(text, "attributes").ok_or("no attributes")?;
            let wanted = match kind {
                // sign|decrypt, not restricted; fixedtpm, fixedparent and sensitivedataorigin clear.
                Kind::Rsa => "userwithauth|adminwithpolicy|decrypt|sign",
                Kind::P256 => "userwithauth|adminwithpolicy|sign",
            };
            assert_eq!(attributes, wanted, "{kind:?}");
            assert!(
                field(text, "authorization policy").is_none_or(|p| p.is_empty()),
                "{kind:?}: authPolicy is empty: {text}"
            );
            match kind {
                Kind::Rsa => {
                    assert_eq!(field(text, "bits").as_deref(), Some("2048"));
                    assert_eq!(nested(text, "scheme").as_deref(), Some("null"));
                    assert_eq!(field(text, "exponent").as_deref(), Some("65537"));
                    assert_eq!(field(text, "rsa"), Some(key.public[0].clone()));
                }
                Kind::P256 => {
                    assert_eq!(nested(text, "curve-id").as_deref(), Some("NIST p256"));
                    assert_eq!(nested(text, "scheme").as_deref(), Some("ecdsa"));
                    assert_eq!(field(text, "x"), Some(key.public[0].clone()));
                    assert_eq!(field(text, "y"), Some(key.public[1].clone()));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn empty_auth_and_no_pcr_dependence() -> TestResult {
    let rig = Rig::new()?;
    let access = TestTcti::new(&rig.tcti());
    rig.primary(SRK_ATTRS)?;
    let ctx = rig.path("k.ctx");
    let message = rig.write("msg", b"a message")?;
    // P-256: signs with no password; the signature verifies with the public key the test derived.
    let key = TestKey::new(Kind::P256);
    rig.load(&import_pkcs8(&access, &key.pkcs8)?.blob)?;
    let sig = rig.path("sig");
    rig.tool(
        "tpm2_sign",
        &[
            "-c", &ctx, "-g", "sha256", "-f", "plain", "-o", &sig, &message,
        ],
    )?;
    let public = rig.write("pub.pem", &run_openssl(&["pkey", "-pubout"], &key.pem)?)?;
    rig.write("verify", b"")?;
    let verified = std::process::Command::new("openssl")
        .args([
            "dgst",
            "-sha256",
            "-verify",
            &public,
            "-signature",
            &sig,
            &message,
        ])
        .output()?;
    assert!(verified.status.success(), "the signature verifies");
    let wrong = rig.tool_fails(
        "tpm2_sign",
        &[
            "-c",
            &ctx,
            "-g",
            "sha256",
            "-p",
            "wrong",
            "-f",
            "plain",
            "-o",
            &rig.path("sig2"),
            &message,
        ],
    )?;
    assert!(wrong.contains("auth"), "{wrong}");
    // RSA: decrypts with no password.
    let key = TestKey::new(Kind::Rsa);
    rig.load(&import_pkcs8(&access, &key.pkcs8)?.blob)?;
    let public = rig.write("rsa.pem", &run_openssl(&["pkey", "-pubout"], &key.pem)?)?;
    let secret = rig.write("secret", b"hello tpm")?;
    let cipher = rig.path("cipher");
    let out = std::process::Command::new("openssl")
        .args([
            "pkeyutl", "-encrypt", "-pubin", "-inkey", &public, "-in", &secret, "-out", &cipher,
        ])
        .output()?;
    assert!(out.status.success());
    let plain = rig.tool("tpm2_rsadecrypt", &["-c", &ctx, "-s", "rsaes", &cipher])?;
    assert_eq!(plain, "hello tpm");
    let wrong = rig.tool_fails(
        "tpm2_rsadecrypt",
        &["-c", &ctx, "-s", "rsaes", "-p", "wrong", &cipher],
    )?;
    assert!(wrong.contains("auth"), "{wrong}");
    Ok(())
}

fn run_openssl(args: &[&str], stdin: &[u8]) -> Res<Vec<u8>> {
    use std::io::Write;
    let mut child = std::process::Command::new("openssl")
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    child.stdin.take().ok_or("stdin")?.write_all(stdin)?;
    Ok(child.wait_with_output()?.stdout)
}

use support::Res;
