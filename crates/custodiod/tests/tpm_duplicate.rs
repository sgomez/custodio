//! The TPM keys the service stores cannot be copied (F128): `tpm2-tools` on the stored blobs, not on the value the
//! import returns (F113 checks that one). The service imports on a real `swtpm` through the bus with fake polkit; the
//! test then enumerates the store, takes every `tpm` record and loads its stored public and private parts.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

// The shared helpers are used in full by other tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/bus.rs"]
mod bus;
// The shared helpers are used in full by other tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/common.rs"]
mod common;
// Shared with `storage_choice`: this target does not use every helper of it.
#[allow(dead_code)]
#[path = "storage_choice/rig.rs"]
mod rig;
// Shared with `tpm_import`: this target does not use every helper of it.
#[allow(dead_code, unused_imports)]
#[path = "tpm_import/support.rs"]
mod support;

use custodiod::store::{Kind, Record};
use custodiod::tpm::blob::Blob;
use rig::KindSvc;
use support::{Rig, SRK_ATTRS, field, nested};
use zbus::block_on;

use common::{
    EC_P12, EC_SENTINEL_P12, PASSWORD, RSA_P12, RSA_SENTINEL_P12, SENTINEL_PASSWORD, uid,
};

/// The response the TPM gives `TPM2_Duplicate` under a policy session for a key whose `authPolicy` is empty:
/// `TPM_RC_POLICY_FAIL` (`0x1D | RC_FMT1 0x80 = 0x9d`) with the session number 1 in bits 8..11 (`0x900 | 0x9d`).
const POLICY_FAIL: &str = "(0x99D)";

/// A TPM key as the service stored it.
struct Stored {
    id: String,
    blob: Blob,
    certificate: Vec<u8>,
}

/// The service with `swtpm` behind it and four TPM keys in its store: RSA, P-256, a second P-256 key, and an RSA key
/// imported under an id that was deleted after a first import.
struct Fixture {
    k: KindSvc,
    stale_blob: Vec<u8>,
}

fn fixture() -> Fixture {
    block_on(async {
        let k = KindSvc::start(Kind::Tpm).await.unwrap();
        let svc = &k.svc;
        svc.import("rsa", RSA_SENTINEL_P12, SENTINEL_PASSWORD)
            .await
            .unwrap();
        svc.import("p256", EC_SENTINEL_P12, SENTINEL_PASSWORD)
            .await
            .unwrap();
        svc.import("second", EC_P12, PASSWORD).await.unwrap();
        svc.import("again", EC_P12, PASSWORD).await.unwrap();
        let stale_blob = svc
            .store
            .get(uid(), "again")
            .unwrap()
            .protected()
            .blob()
            .unwrap()
            .0
            .to_bytes();
        svc.call_method("DeleteKey", &("again",)).await.unwrap();
        svc.import("again", RSA_P12, PASSWORD).await.unwrap();
        Fixture { k, stale_blob }
    })
}

/// Every record of kind `tpm` in the whole store: each owner area on disk, each id it lists.
fn tpm_records(k: &KindSvc) -> Vec<Stored> {
    let store = &k.svc.store;
    let mut out = Vec::new();
    let mut owners: Vec<u32> = std::fs::read_dir(store.dir())
        .unwrap()
        .filter_map(|e| e.unwrap().file_name().to_str().and_then(|n| n.parse().ok()))
        .collect();
    owners.sort_unstable();
    for owner in owners {
        for id in store.list(owner).unwrap() {
            let record: Record = store.get(owner, &id).unwrap();
            if record.kind() != Kind::Tpm {
                continue;
            }
            let blob = record.protected().blob().unwrap().0.clone();
            out.push(Stored {
                id,
                blob,
                certificate: record.certificate().to_vec(),
            });
        }
    }
    out
}

fn first_tpm_parent(rig: &Rig) {
    rig.primary(SRK_ATTRS).unwrap();
}

/// The `tpm2_duplicate` invocation both the stored keys and the control use: a policy session on `Duplicate`, `-G null`,
/// and a new parent made in the endorsement hierarchy. Returns the tool's stderr when it fails.
fn duplicate(rig: &Rig, key_ctx: &str) -> Result<Result<(), String>, Box<dyn std::error::Error>> {
    let np = rig.path("np.ctx");
    rig.tool("tpm2_createprimary", &["-C", "e", "-c", &np])?;
    let session = rig.path("s.ctx");
    rig.tool(
        "tpm2_startauthsession",
        &["--policy-session", "-S", &session],
    )?;
    rig.tool(
        "tpm2_policycommandcode",
        &["-S", &session, "TPM2_CC_Duplicate"],
    )?;
    let (out, seed) = (rig.path("dup.priv"), rig.path("dup.seed"));
    let _ = std::fs::remove_file(&out);
    let args = [
        "-C",
        &np,
        "-c",
        key_ctx,
        "-G",
        "null",
        "-p",
        &format!("session:{session}"),
        "-r",
        &out,
        "-s",
        &seed,
    ];
    let result = match rig.tpm.tool("tpm2_duplicate", args)? {
        o if o.status.success() => Ok(()),
        o => Err(String::from_utf8_lossy(&o.stderr).into_owned()),
    };
    rig.tpm.tool_ok("tpm2_flushcontext", ["-t"])?;
    let _ = rig.tool("tpm2_flushcontext", &[&session]);
    Ok(result)
}

/// A key created by the test with the policy `PolicyCommandCode(Duplicate)`, `fixedTPM` and `fixedParent` clear, or
/// with the policy `policy` (a file) when given; loaded as `c.ctx`.
fn made_key(rig: &Rig, duplicable: bool) -> String {
    let cp = rig.path("cp.ctx");
    rig.tool("tpm2_createprimary", &["-C", "o", "-c", &cp])
        .unwrap();
    let (trial, pol) = (rig.path("trial.ctx"), rig.path("pol.dat"));
    rig.tool("tpm2_startauthsession", &["-S", &trial]).unwrap();
    rig.tool(
        "tpm2_policycommandcode",
        &["-S", &trial, "-L", &pol, "TPM2_CC_Duplicate"],
    )
    .unwrap();
    rig.tool("tpm2_flushcontext", &[&trial]).unwrap();
    let attrs = if duplicable {
        "sensitivedataorigin|userwithauth|sign"
    } else {
        "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign"
    };
    let (cpub, cpriv, cctx) = (rig.path("c.pub"), rig.path("c.priv"), rig.path("c.ctx"));
    rig.tool(
        "tpm2_create",
        &[
            "-C", &cp, "-g", "sha256", "-G", "ecc256", "-L", &pol, "-a", attrs, "-u", &cpub, "-r",
            &cpriv,
        ],
    )
    .unwrap();
    rig.tool(
        "tpm2_load",
        &["-C", &cp, "-u", &cpub, "-r", &cpriv, "-c", &cctx],
    )
    .unwrap();
    cctx
}

/// The hex digits of the public key in a DER certificate, as `openssl` prints them.
fn certificate_key_hex(rig: &Rig, der: &[u8]) -> String {
    use std::io::Write;
    let cert = rig.write("cert.der", der).unwrap();
    let pubkey = std::process::Command::new("openssl")
        .args(["x509", "-inform", "DER", "-in", &cert, "-noout", "-pubkey"])
        .output()
        .unwrap();
    assert!(pubkey.status.success());
    let mut child = std::process::Command::new("openssl")
        .args(["pkey", "-pubin", "-text", "-noout"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&pubkey.stdout)
        .unwrap();
    let text = String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap();
    text.chars()
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_lowercase()
}

/// Writes every record of the store as the encoder gives it into a state-directory layout (`<uid>/<id>`, one non-TPM record
/// among them), runs `e2e/tpmdup.py scan` on it and compares what it reads with the blobs.
fn check_guest_reader(k: &KindSvc, stored: &[Stored]) -> support::TestResult {
    use std::process::Command;
    let root = std::env::temp_dir().join(format!("tpmdup-reader-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let area = root.join("state").join(uid().to_string());
    std::fs::create_dir_all(&area)?;
    for s in stored {
        let record: Record = k.svc.store.get(uid(), &s.id)?;
        std::fs::write(area.join(&s.id), record.encode()?)?;
    }
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../e2e/tpmdup.py");
    let out = Command::new("python3")
        .args(["-I", script, "scan"])
        .arg(root.join("state"))
        .arg(root.join("out"))
        .output()?;
    assert!(out.status.success(), "{out:?}");
    let rows: Vec<Vec<String>> = String::from_utf8(out.stdout)?
        .lines()
        .map(|l| l.split('\t').map(str::to_owned).collect())
        .collect();
    assert_eq!(rows.len(), stored.len());
    for s in stored {
        let record: Record = k.svc.store.get(uid(), &s.id)?;
        let (blob, name) = record.protected().blob().unwrap();
        let hex_name = support::hex(name);
        let row = rows.iter().find(|r| r[1] == s.id).unwrap();
        assert_eq!(row[2..], ["tpm".to_owned(), hex_name], "{}", s.id);
        let dir = root.join("out").join(format!("{}-{}", uid(), s.id));
        assert_eq!(std::fs::read(dir.join("k.pub"))?, blob.public_bytes());
        assert_eq!(std::fs::read(dir.join("k.priv"))?, blob.private_bytes());
    }
    std::fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn checks_every_stored_key() -> support::TestResult {
    let f = fixture();
    let rig = &f.k.rig; // the TPM the service imported into
    first_tpm_parent(rig);
    let stored = tpm_records(&f.k);
    let mut ids: Vec<&str> = stored.iter().map(|s| s.id.as_str()).collect();
    ids.sort_unstable();
    assert_eq!(
        ids,
        ["again", "p256", "rsa", "second"],
        "exactly the four keys the test stored"
    );
    for s in &stored {
        // The stored bytes are what is loaded, unchanged, and the public area is the certificate's key.
        s.blob.public_area()?;
        rig.load(&s.blob)?;
        assert_eq!(
            std::fs::read(rig.path("k.pub"))?,
            s.blob.public_bytes(),
            "{}",
            s.id
        );
        assert_eq!(
            std::fs::read(rig.path("k.priv"))?,
            s.blob.private_bytes(),
            "{}",
            s.id
        );
        let shown = rig.tool("tpm2_readpublic", &["-c", &rig.path("k.ctx")])?;
        let cert = certificate_key_hex(rig, &s.certificate);
        let parts: Vec<String> = ["rsa", "x", "y"]
            .iter()
            .filter_map(|k| field(&shown, k))
            .collect();
        assert!(!parts.is_empty(), "{}: {shown}", s.id);
        for part in parts {
            assert!(
                cert.contains(&part.to_lowercase()),
                "{}: {part} not in the certificate's key",
                s.id
            );
        }
    }
    // The guest reads the records with `e2e/tpmdup.py`: it must agree with the encoder that wrote them (F136).
    check_guest_reader(&f.k, &stored)?;
    // The re-imported key replaced the first one: the first blob is nowhere in the store.
    let current: Vec<Vec<u8>> = stored.iter().map(|s| s.blob.to_bytes()).collect();
    assert!(
        !current.contains(&f.stale_blob),
        "a stale record is still stored"
    );
    // Control: a store with no TPM key is not the four.
    let empty = rig::KindSvc::start(Kind::EncryptedHost);
    let empty = block_on(empty)?;
    assert_eq!(tpm_records(&empty).len(), 0);
    Ok(())
}

/// The `authorization policy` of a `tpm2_readpublic` output: `tpm2-tools` leaves the line out when the policy is empty,
/// so an output that is not a public area at all is an error, not an empty policy.
fn auth_policy(shown: &str) -> String {
    assert!(
        field(shown, "name").is_some() && nested(shown, "attributes").is_some(),
        "not a public area: {shown}"
    );
    field(shown, "authorization policy").unwrap_or_default()
}

#[test]
fn stored_auth_policy_is_empty() -> support::TestResult {
    let f = fixture();
    let rig = &f.k.rig;
    first_tpm_parent(rig);
    let stored = tpm_records(&f.k);
    assert_eq!(stored.len(), 4);
    for s in &stored {
        rig.load(&s.blob)?;
        let shown = rig.tool("tpm2_readpublic", &["-c", &rig.path("k.ctx")])?;
        assert_eq!(auth_policy(&shown), "", "{}: {shown}", s.id);
    }
    // Control: a key created with a non-empty policy is read as non-empty.
    let ctx = made_key(rig, false);
    let shown = rig.tool("tpm2_readpublic", &["-c", &ctx])?;
    assert_eq!(auth_policy(&shown).len(), 64, "{shown}");
    Ok(())
}

#[test]
fn stored_key_cannot_be_duplicated() -> support::TestResult {
    let f = fixture();
    let rig = &f.k.rig;
    first_tpm_parent(rig);
    let stored = tpm_records(&f.k);
    assert_eq!(stored.len(), 4);
    for s in &stored {
        rig.load(&s.blob)?;
        let failure =
            duplicate(rig, &rig.path("k.ctx"))?.expect_err(&format!("{} was duplicated", s.id));
        assert!(failure.contains(POLICY_FAIL), "{}: {failure}", s.id);
        assert!(
            !std::path::Path::new(&rig.path("dup.priv")).exists(),
            "{}: a duplicate was written",
            s.id
        );
    }
    // Control: the same command line duplicates a key made duplicable.
    let ctx = made_key(rig, true);
    duplicate(rig, &ctx)?.expect("the control key duplicates");
    assert!(std::fs::metadata(rig.path("dup.priv"))?.len() > 0);
    Ok(())
}

#[test]
fn stored_blob_does_not_load_in_another_tpm() -> support::TestResult {
    let f = fixture();
    let first = &f.k.rig;
    first_tpm_parent(first);
    let other = Rig::new()?; // own state directory, own seed
    other.primary(SRK_ATTRS)?;
    let stored = tpm_records(&f.k);
    assert_eq!(stored.len(), 4);
    let load = |rig: &Rig, s: &Stored| -> support::Res<Result<(), String>> {
        let p = rig.write("k.pub", s.blob.public_bytes())?;
        let r = rig.write("k.priv", s.blob.private_bytes())?;
        let out = rig.tpm.tool(
            "tpm2_load",
            [
                "-C",
                &rig.path("p.ctx"),
                "-u",
                &p,
                "-r",
                &r,
                "-c",
                &rig.path("k.ctx"),
            ],
        )?;
        rig.tpm.tool_ok("tpm2_flushcontext", ["-t"])?;
        Ok(if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).into_owned())
        })
    };
    for s in &stored {
        let refused = load(&other, s)?.expect_err(&format!("{} loaded elsewhere", s.id));
        assert!(refused.contains("integrity"), "{}: {refused}", s.id);
        // Control: on the first TPM the same command loads the same blob.
        load(first, s)?.unwrap_or_else(|e| panic!("{} did not load on its own TPM: {e}", s.id));
    }
    Ok(())
}
