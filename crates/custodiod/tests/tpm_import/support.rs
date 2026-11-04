//! Keys, tools and a TPM to run them against.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::path::PathBuf;
use std::process::{Command, Stdio};

use custodio_it::swtpm::Swtpm;
use custodio_it::tpm_filter::{Lacks, Recorder, TpmFilter};
use p256::elliptic_curve::sec1::ToSec1Point;
use pkcs8::DecodePrivateKey;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};

pub type Res<T> = Result<T, Box<dyn std::error::Error>>;
pub type TestResult = Res<()>;

/// The attributes of the parent template, as `tpm2_createprimary -a` writes them.
pub const SRK_ATTRS: &str =
    "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Rsa,
    P256,
}

pub const BOTH: [Kind; 2] = [Kind::Rsa, Kind::P256];

/// A private key the test generated, with every encoding of it a leak could take.
pub struct TestKey {
    pub pkcs8: Vec<u8>,
    pub pem: Vec<u8>,
    /// (name, bytes) of every secret encoding: raw scalar or primes and exponent, PKCS#1, PKCS#8, SEC1.
    pub secrets: Vec<(&'static str, Vec<u8>)>,
    /// What `tpm2_readpublic` shows for the public key, lower-case hex: the modulus, or `x` and `y`.
    pub public: Vec<String>,
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn run(program: &str, args: &[&str], stdin: &[u8]) -> Vec<u8> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(stdin)
            .expect("write");
    }
    let out = child.wait_with_output().expect("wait");
    assert!(out.status.success(), "{program} {args:?}");
    out.stdout
}

/// The PKCS#8 DER of a PEM private key.
pub fn pkcs8_of(pem: &[u8]) -> Vec<u8> {
    run(
        "openssl",
        &["pkcs8", "-topk8", "-nocrypt", "-outform", "DER"],
        pem,
    )
}

pub fn genpkey(options: &[&str]) -> Vec<u8> {
    let mut args = vec!["genpkey"];
    args.extend_from_slice(options);
    run("openssl", &args, b"")
}

fn trimmed(bytes: &[u8]) -> Vec<u8> {
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(0);
    bytes[start..].to_vec()
}

impl TestKey {
    /// From the PEM `openssl genpkey` printed.
    pub fn from_pem(pem: Vec<u8>) -> Self {
        let pkcs8 = pkcs8_of(&pem);
        let traditional = run(
            "openssl",
            &["pkey", "-outform", "DER", "-traditional"],
            &pem,
        );
        let mut secrets = vec![("pkcs8", pkcs8.clone()), ("traditional", traditional)];
        if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_der(&pkcs8) {
            for (i, p) in key.primes().iter().enumerate() {
                secrets.push((
                    if i == 0 { "p" } else { "q" },
                    trimmed(p.to_be_bytes().as_ref()),
                ));
            }
            secrets.push(("d", trimmed(key.d().to_be_bytes().as_ref())));
            let public = vec![hex(&trimmed(key.n().as_ref().to_be_bytes().as_ref()))];
            return Self {
                pkcs8,
                pem,
                secrets,
                public,
            };
        }
        let key = p256::SecretKey::from_pkcs8_der(&pkcs8).expect("p256 key");
        secrets.push(("scalar", key.to_bytes().to_vec()));
        let point = key.public_key().to_sec1_point(false);
        let public = vec![hex(point.x().expect("x")), hex(point.y().expect("y"))];
        Self {
            pkcs8,
            pem,
            secrets,
            public,
        }
    }

    pub fn new(kind: Kind) -> Self {
        Self::from_pem(match kind {
            Kind::Rsa => genpkey(&["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]),
            Kind::P256 => genpkey(&["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]),
        })
    }

    /// The names of the secret encodings found in `haystack`.
    pub fn found_in(&self, haystack: &[u8]) -> Vec<&'static str> {
        self.secrets
            .iter()
            .filter(|(_, needle)| contains(haystack, needle))
            .map(|(name, _)| *name)
            .collect()
    }
}

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// A software TPM and a scratch directory for the files the tools read and write.
pub struct Rig {
    pub tpm: Swtpm,
    pub dir: PathBuf,
}

impl Rig {
    pub fn new() -> Res<Self> {
        let tpm = Swtpm::start()?;
        let dir = tpm.state_dir().join("work");
        std::fs::create_dir_all(&dir)?;
        Ok(Self { tpm, dir })
    }

    pub fn path(&self, name: &str) -> String {
        self.dir.join(name).display().to_string()
    }

    pub fn write(&self, name: &str, bytes: &[u8]) -> Res<String> {
        std::fs::write(self.dir.join(name), bytes)?;
        Ok(self.path(name))
    }

    /// A tool against the bare TPM. `swtpm` has no resource manager, so a transient object a tool leaves stays: it is
    /// flushed afterwards, except for the tools that flush.
    pub fn tool(&self, name: &str, args: &[&str]) -> Res<String> {
        let out = self.tpm.tool_ok(name, args);
        if name != "tpm2_flushcontext" {
            self.tpm.tool_ok("tpm2_flushcontext", ["-t"])?;
        }
        Ok(out?)
    }

    /// A tool against another TCTI (a filter), with the same flush afterwards. Returns whether it succeeded.
    pub fn tool_via(&self, tcti: &str, name: &str, args: &[&str]) -> Res<bool> {
        let out = Command::new("timeout")
            .args(["--kill-after=5", "60", name])
            .args(args)
            .env("TPM2TOOLS_TCTI", tcti)
            .current_dir(&self.dir)
            .stdin(Stdio::null())
            .output()?;
        self.tpm.tool_ok("tpm2_flushcontext", ["-t"])?;
        Ok(out.status.success())
    }

    /// Like `tool`, giving the failure text (stderr) when the tool fails, and an error when it succeeds.
    pub fn tool_fails(&self, name: &str, args: &[&str]) -> Res<String> {
        let out = self.tpm.tool(name, args)?;
        self.tpm.tool_ok("tpm2_flushcontext", ["-t"])?;
        if out.status.success() {
            return Err(format!("{name} {args:?} succeeded").into());
        }
        Ok(String::from_utf8_lossy(&out.stderr).into_owned())
    }

    /// Creates the primary with these attributes, saves it as `p.ctx` and gives its name (hex).
    pub fn primary(&self, attrs: &str) -> Res<String> {
        let ctx = self.path("p.ctx");
        self.tool(
            "tpm2_createprimary",
            &["-C", "o", "-G", "ecc256:aes128cfb", "-a", attrs, "-c", &ctx],
        )?;
        let out = self.tool("tpm2_readpublic", &["-c", &ctx])?;
        Ok(field(&out, "name").ok_or_else(|| format!("no name in {out:?}"))?)
    }

    /// Writes the blob as `k.pub` / `k.priv`, loads it under the independent parent `p.ctx` and saves `k.ctx`.
    pub fn load(&self, blob: &custodiod::tpm::blob::Blob) -> Res<String> {
        let p = self.write("k.pub", blob.public_bytes())?;
        let r = self.write("k.priv", blob.private_bytes())?;
        self.tool(
            "tpm2_load",
            &[
                "-C",
                &self.path("p.ctx"),
                "-u",
                &p,
                "-r",
                &r,
                "-c",
                &self.path("k.ctx"),
            ],
        )
    }

    pub fn getcap(&self, what: &str) -> Res<String> {
        Ok(self.tpm.tool_ok("tpm2_getcap", [what])?)
    }

    /// Handles of one kind the TPM holds right now.
    pub fn handles(&self, what: &str) -> Res<Vec<String>> {
        Ok(self
            .getcap(what)?
            .lines()
            .filter_map(|l| l.trim().strip_prefix("- "))
            .map(str::to_owned)
            .collect())
    }

    /// Nothing loaded: no transient object, no loaded or saved session.
    pub fn assert_nothing_loaded(&self, context: &str) -> TestResult {
        for what in [
            "handles-transient",
            "handles-loaded-session",
            "handles-saved-session",
        ] {
            assert_eq!(
                self.handles(what)?,
                Vec::<String>::new(),
                "{context}: {what}"
            );
        }
        Ok(())
    }

    pub fn tcti(&self) -> String {
        self.tpm.tcti()
    }

    /// A filter in front of this TPM that records the commands.
    pub fn filter(&self, mut lacks: Lacks) -> Res<(TpmFilter, Recorder)> {
        let record = lacks.record.clone().unwrap_or_default();
        lacks.record = Some(record.clone());
        let upstream: PathBuf = self
            .tpm
            .tcti()
            .strip_prefix("swtpm:path=")
            .ok_or("not an swtpm TCTI")?
            .into();
        let socket = self
            .dir
            .join(format!("filter{}.sock", std::process::id() % 1000));
        let filter = TpmFilter::start(&upstream, &socket, lacks)?;
        Ok((filter, record))
    }
}

/// The value after `key:` on a line of a tool's YAML-like output.
pub fn field(output: &str, key: &str) -> Option<String> {
    output.lines().find_map(|l| {
        l.trim()
            .strip_prefix(key)
            .and_then(|r| r.strip_prefix(':'))
            .map(|v| v.trim().to_owned())
    })
}

/// The value on the line after `key:` (as `attributes:` / `  value: ...`).
pub fn nested(output: &str, key: &str) -> Option<String> {
    let mut lines = output.lines();
    while let Some(l) = lines.next() {
        if l.trim() == format!("{key}:") {
            return lines
                .next()
                .and_then(|v| v.trim().strip_prefix("value:"))
                .map(|v| v.trim().to_owned());
        }
    }
    None
}
