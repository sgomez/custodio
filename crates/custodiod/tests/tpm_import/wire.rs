//! What crosses the TCTI, what the result holds, and what the blob can do elsewhere.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use custodio_it::tpm_filter::Lacks;
use custodiod::tpm::import::import_pkcs8;
use custodiod::tpm::open::TestTcti;

use super::support::{BOTH, Kind, Rig, SRK_ATTRS, TestKey, TestResult, contains};

#[test]
fn private_key_not_on_the_wire() -> TestResult {
    for kind in BOTH {
        let rig = Rig::new()?;
        let key = TestKey::new(kind);
        let (filter, record) = rig.filter(Lacks::default())?;
        import_pkcs8(&TestTcti::new(&filter.tcti()), &key.pkcs8)?;
        let sent = record.bytes();
        assert!(sent.len() > 300, "the import did go through the filter");
        assert_eq!(key.found_in(&sent), Vec::<&str>::new(), "{kind:?}");
        drop(filter);

        // Control: `tpm2_loadexternal` of the same private key sends the sensitive area in the clear, so the same
        // search over its recording finds the secret.
        let (filter, record) = rig.filter(Lacks::default())?;
        let (alg, pem) = match kind {
            Kind::Rsa => ("rsa", rig.write("key.pem", &key.pem)?),
            Kind::P256 => ("ecc", rig.write("key.pem", &key.pem)?),
        };
        let ok = rig.tool_via(
            &filter.tcti(),
            "tpm2_loadexternal",
            &["-G", alg, "-r", &pem, "-c", &rig.path("ext.ctx")],
        )?;
        assert!(ok, "loadexternal of {kind:?}");
        let found = key.found_in(&record.bytes());
        let secret = match kind {
            Kind::Rsa => "p",
            Kind::P256 => "scalar",
        };
        assert!(found.contains(&secret), "{kind:?}: control finds {found:?}");
    }
    Ok(())
}

#[test]
fn result_holds_no_key_material() -> TestResult {
    let rig = Rig::new()?;
    let access = TestTcti::new(&rig.tcti());
    for kind in BOTH {
        let key = TestKey::new(kind);
        let imported = import_pkcs8(&access, &key.pkcs8)?;
        let mut everything = imported.blob.to_bytes();
        everything.extend_from_slice(imported.blob.public_bytes());
        everything.extend_from_slice(imported.blob.private_bytes());
        everything.extend_from_slice(&imported.parent_name);
        everything.extend_from_slice(format!("{imported:?} {:?}", imported.blob).as_bytes());
        let hex_forms: Vec<String> = key
            .secrets
            .iter()
            .map(|(_, bytes)| super::support::hex(bytes))
            .collect();
        assert_eq!(key.found_in(&everything), Vec::<&str>::new(), "{kind:?}");
        for form in hex_forms {
            assert!(!contains(&everything, form.as_bytes()), "{kind:?} hex");
        }
        // Control: the search finds the key where the test plants it.
        let mut planted = imported.blob.to_bytes();
        planted.extend_from_slice(&key.secrets.last().ok_or("no secret")?.1);
        assert_ne!(key.found_in(&planted), Vec::<&str>::new());
    }
    Ok(())
}

#[test]
fn blob_does_not_load_elsewhere_and_cannot_be_duplicated() -> TestResult {
    let rig = Rig::new()?;
    let access = TestTcti::new(&rig.tcti());
    rig.primary(SRK_ATTRS)?;
    let other = Rig::new()?;
    other.primary(SRK_ATTRS)?;
    for kind in BOTH {
        let imported = import_pkcs8(&access, &TestKey::new(kind).pkcs8)?;
        // Loads under the independent parent of the same TPM, not under the parent of another TPM.
        rig.load(&imported.blob)?;
        let p = other.write("k.pub", imported.blob.public_bytes())?;
        let r = other.write("k.priv", imported.blob.private_bytes())?;
        let refused = other.tool_fails(
            "tpm2_load",
            &[
                "-C",
                &other.path("p.ctx"),
                "-u",
                &p,
                "-r",
                &r,
                "-c",
                &other.path("k.ctx"),
            ],
        )?;
        assert!(refused.contains("integrity"), "{kind:?}: {refused}");

        // Duplication: an authorization or policy failure, not an argument error.
        rig.tool(
            "tpm2_createprimary",
            &["-C", "e", "-c", &rig.path("np.ctx")],
        )?;
        let failure = rig.tool_fails(
            "tpm2_duplicate",
            &[
                "-C",
                &rig.path("np.ctx"),
                "-c",
                &rig.path("k.ctx"),
                "-G",
                "null",
                "-r",
                &rig.path("dup.priv"),
                "-s",
                &rig.path("dup.seed"),
            ],
        )?;
        // TPM_RC_AUTH_TYPE: the duplication role needs a policy session, and the key's empty policy offers none.
        assert!(failure.contains("(0x124)"), "{kind:?}: {failure}");
    }
    duplicable_control(&rig)
}

/// Control: with the same invocation, a key whose policy is `PolicyCommandCode(Duplicate)` duplicates.
fn duplicable_control(rig: &Rig) -> TestResult {
    let (cp, np) = (rig.path("cp.ctx"), rig.path("np.ctx"));
    rig.tool("tpm2_createprimary", &["-C", "o", "-c", &cp])?;
    let (trial, pol) = (rig.path("trial.ctx"), rig.path("pol.dat"));
    rig.tool("tpm2_startauthsession", &["-S", &trial])?;
    rig.tool(
        "tpm2_policycommandcode",
        &["-S", &trial, "-L", &pol, "TPM2_CC_Duplicate"],
    )?;
    rig.tool("tpm2_flushcontext", &[&trial])?;
    let (cpub, cpriv, cctx) = (rig.path("c.pub"), rig.path("c.priv"), rig.path("c.ctx"));
    rig.tool(
        "tpm2_create",
        &[
            "-C",
            &cp,
            "-g",
            "sha256",
            "-G",
            "ecc256",
            "-L",
            &pol,
            "-a",
            "sensitivedataorigin|userwithauth|sign",
            "-u",
            &cpub,
            "-r",
            &cpriv,
        ],
    )?;
    rig.tool(
        "tpm2_load",
        &["-C", &cp, "-u", &cpub, "-r", &cpriv, "-c", &cctx],
    )?;
    let session = rig.path("s.ctx");
    rig.tool(
        "tpm2_startauthsession",
        &["--policy-session", "-S", &session],
    )?;
    rig.tool(
        "tpm2_policycommandcode",
        &["-S", &session, "TPM2_CC_Duplicate"],
    )?;
    let out = rig.tool(
        "tpm2_duplicate",
        &[
            "-C",
            &np,
            "-c",
            &cctx,
            "-G",
            "null",
            "-p",
            &format!("session:{session}"),
            "-r",
            &rig.path("cdup.priv"),
            "-s",
            &rig.path("cdup.seed"),
        ],
    );
    rig.tool("tpm2_flushcontext", &[&session])?;
    out?;
    Ok(())
}
