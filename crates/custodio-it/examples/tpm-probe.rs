//! Read-only TPM probe (F106). `tpm-probe parent [--tcti <tcti>]` prints, one `key: value` line each, the facts the
//! "which parent" finding in `docs/findings.md` (section F106) relies on, so a person can repeat them on a hardware TPM.
//!
//! It never calls `EvictControl`, never sets an auth value and never clears: it writes no NV storage and changes no
//! persistent object. It creates transient primaries only and flushes each. Without `--tcti` the environment decides
//! (`TPM2TOOLS_TCTI`, `TCTI`, `TEST_TCTI`, as `just with-swtpm` sets).
//!
//! Exit status: 0 when the TPM answered and the owner hierarchy accepts an empty auth; 1 when the TPM cannot be reached
//! or the owner hierarchy is unusable (every fact that could still be read is printed first, the persistent SRK among
//! them: a persisted SRK works without the owner auth, only provisioning does not); 2 on a usage error.

use std::process::ExitCode;
use std::str::FromStr;
use std::time::Instant;

use sha2::{Digest as _, Sha256};
use tss_esapi::Context;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::{CapabilityType, PropertyTag};
use tss_esapi::handles::{KeyHandle, PersistentTpmHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::reserved_handles::Hierarchy;
use tss_esapi::structures::RsaExponent;
use tss_esapi::structures::{
    CapabilityData, EccPoint, Public, PublicBuilder, PublicEccParametersBuilder, PublicKeyRsa,
    PublicRsaParametersBuilder, SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::traits::Marshall;

/// The persistent handle the TCG provisioning guidance reserves for the storage root key.
const SRK_HANDLE: u32 = 0x8100_0001;
/// Creations timed per template. Small on purpose: RSA 2048 takes seconds on some TPMs. Printed next to the mean.
const TIMED_CALLS: u32 = 5;

type Fail = Box<dyn std::error::Error>;

/// The TCG "TPM v2.0 Provisioning Guidance" SRK template (RSA 2048 or ECC P-256): restricted decryption key,
/// AES-128-CFB, null scheme, SHA-256 name, `noDA`, empty unique field.
fn srk_template(ecc: bool) -> Result<Public, Fail> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()?;
    let builder = PublicBuilder::new()
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes);
    let public = if ecc {
        builder
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_ecc_parameters(
                PublicEccParametersBuilder::new_restricted_decryption_key(
                    SymmetricDefinitionObject::AES_128_CFB,
                    EccCurve::NistP256,
                )
                .build()?,
            )
            .with_ecc_unique_identifier(EccPoint::default())
    } else {
        builder
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_rsa_parameters(
                PublicRsaParametersBuilder::new_restricted_decryption_key(
                    SymmetricDefinitionObject::AES_128_CFB,
                    RsaKeyBits::Rsa2048,
                    RsaExponent::default(),
                )
                .build()?,
            )
            .with_rsa_unique_identifier(PublicKeyRsa::default())
    };
    Ok(public.build()?)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// One transient primary from `template`: its name and the SHA-256 of its marshalled public area. Flushed on return.
fn create_once(ctx: &mut Context, template: &Public) -> Result<(String, String), Fail> {
    let result = ctx.execute_with_nullauth_session(|c| {
        c.create_primary(Hierarchy::Owner, template.clone(), None, None, None, None)
    })?;
    let handle = result.key_handle;
    let facts = (|| -> Result<(String, String), Fail> {
        let (_, name, _) = ctx.read_public(handle)?;
        let digest = Sha256::digest(result.out_public.marshall()?);
        Ok((hex(name.value()), hex(&digest)))
    })();
    ctx.flush_context(handle.into())?;
    facts
}

/// What the occupant of 0x81000001 is: its name and a one-line description of type and attributes.
fn read_persistent(ctx: &mut Context) -> Result<Option<(String, String)>, Fail> {
    let handle = PersistentTpmHandle::new(SRK_HANDLE)?;
    let list = match ctx
        .get_capability(CapabilityType::Handles, SRK_HANDLE, 1)?
        .0
    {
        CapabilityData::Handles(list) => list,
        other => return Err(format!("unexpected capability data {other:?}").into()),
    };
    if !list.iter().any(|h| u32::from(*h) == SRK_HANDLE) {
        return Ok(None);
    }
    let object = ctx.tr_from_tpm_public(TpmHandle::Persistent(handle))?;
    let (public, name, _) = ctx.read_public(KeyHandle::from(object))?;
    let a = public.object_attributes();
    let kind = match &public {
        Public::Rsa { parameters, .. } => format!("rsa{}", u16::from(parameters.key_bits())),
        Public::Ecc { parameters, .. } => format!("ecc {:?}", parameters.ecc_curve()),
        Public::KeyedHash { .. } => "keyedhash".to_owned(),
        Public::SymCipher { .. } => "symcipher".to_owned(),
    };
    let attrs = format!(
        "{kind} fixedtpm={} fixedparent={} sensitivedataorigin={} userwithauth={} noda={} restricted={} decrypt={} sign={}",
        a.fixed_tpm(),
        a.fixed_parent(),
        a.sensitive_data_origin(),
        a.user_with_auth(),
        a.no_da(),
        a.restricted(),
        a.decrypt(),
        a.sign_encrypt()
    );
    // A persistent object cannot be flushed (the TPM answers 0x1C4); only the local ESYS handle is released.
    let mut object = object;
    ctx.tr_close(&mut object)?;
    Ok(Some((hex(name.value()), attrs)))
}

fn print_header(ctx: &mut Context) -> Result<(), Fail> {
    let manufacturer = ctx
        .get_tpm_property(PropertyTag::Manufacturer)?
        .unwrap_or(0);
    println!(
        "manufacturer: 0x{manufacturer:08x} ({})",
        manufacturer
            .to_be_bytes()
            .map(|b| if b.is_ascii_graphic() {
                char::from(b)
            } else {
                ' '
            })
            .iter()
            .collect::<String>()
            .trim_end()
    );

    match ctx
        .get_capability(CapabilityType::Handles, 0x8100_0000, 64)?
        .0
    {
        CapabilityData::Handles(list) => {
            let all: Vec<String> = list
                .iter()
                .map(|h| format!("0x{:08x}", u32::from(*h)))
                .collect();
            println!(
                "persistent_handles: {}",
                if all.is_empty() {
                    "none".into()
                } else {
                    all.join(" ")
                }
            );
        }
        other => return Err(format!("unexpected capability data {other:?}").into()),
    }
    match ctx
        .get_capability(CapabilityType::Handles, 0x0100_0000, 64)?
        .0
    {
        CapabilityData::Handles(list) => println!("nv_indexes: {}", list.iter().count()),
        other => return Err(format!("unexpected capability data {other:?}").into()),
    }
    Ok(())
}

fn parent(tcti: Option<&str>) -> Result<bool, Fail> {
    let conf = match tcti {
        Some(s) => TctiNameConf::from_str(s).map_err(|e| format!("malformed --tcti {s:?}: {e}"))?,
        None => TctiNameConf::from_environment_variable().map_err(|e| {
            format!("no TCTI: pass --tcti or set TPM2TOOLS_TCTI/TCTI/TEST_TCTI: {e}")
        })?,
    };
    let mut ctx = Context::new(conf).map_err(|e| format!("cannot connect to the TPM: {e}"))?;
    print_header(&mut ctx)?;

    let persistent = read_persistent(&mut ctx)?;
    match &persistent {
        None => println!("persistent_0x81000001: empty"),
        Some((name, attrs)) => {
            println!("persistent_0x81000001: occupied");
            println!("persistent_0x81000001_template: {attrs}");
            println!("persistent_0x81000001_name: {name}");
        }
    }

    let mut owner_ok = true;
    let mut srk_names = Vec::new();
    for (label, ecc) in [("rsa2048", false), ("ecc_p256", true)] {
        let template = srk_template(ecc)?;
        let first = match create_once(&mut ctx, &template) {
            Ok(f) => f,
            Err(e) => {
                println!("owner_hierarchy: unusable ({e})");
                owner_ok = false;
                break;
            }
        };
        if label == "rsa2048" {
            println!("owner_hierarchy: accepts empty auth");
        }
        let second = create_once(&mut ctx, &template)?;
        let start = Instant::now();
        for _ in 0..TIMED_CALLS {
            create_once(&mut ctx, &template)?;
        }
        let mean = start.elapsed().as_secs_f64() * 1000.0 / f64::from(TIMED_CALLS);
        println!("{label}_name: {}", first.0);
        println!("{label}_public_sha256: {}", first.1);
        println!(
            "{label}_deterministic: {}",
            if first == second { "yes" } else { "no" }
        );
        println!(
            "{label}_mean_ms: {mean:.1} (N={TIMED_CALLS}, each call includes ReadPublic and FlushContext)"
        );
        srk_names.push((label, first.0));
    }
    let verdict = match &persistent {
        None => "empty".to_owned(),
        Some((name, _)) => match srk_names.iter().find(|(_, n)| n == name) {
            Some((label, _)) => format!("yes ({label})"),
            None if owner_ok => "no".to_owned(),
            None => "unknown (owner hierarchy unusable, no template name to compare)".to_owned(),
        },
    };
    println!("persistent_0x81000001_matches_srk: {verdict}");
    Ok(owner_ok)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: tpm-probe parent [--tcti <tcti>]";
    let tcti = match args.as_slice() {
        [cmd] if cmd == "parent" => None,
        [cmd, flag, value] if cmd == "parent" && flag == "--tcti" => Some(value.as_str()),
        _ => {
            eprintln!("{usage}");
            return ExitCode::from(2);
        }
    };
    match parent(tcti) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("tpm-probe: {e}");
            ExitCode::FAILURE
        }
    }
}
