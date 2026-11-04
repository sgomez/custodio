//! The TPM that lacks something (F107): the filter in front of `swtpm` makes one capability fail with the TPM's response code
//! while the unfiltered `swtpm` answers it. The tests print every answer (`cargo test -p custodio-it --test tpm_filter -- --nocapture`);
//! the lines are pasted into `docs/findings.md`.

use std::str::FromStr;

use custodio_it::swtpm::Swtpm;
use custodio_it::tpm_filter::{CommandFault, FaultAction, Lacks, TpmFilter, alg, cc};
use tss_esapi::Context;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::CapabilityType;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::reserved_handles::Hierarchy;
use tss_esapi::structures::{
    CapabilityData, Digest, EccScheme, HashScheme, PublicBuilder, PublicEccParametersBuilder,
    PublicKeyRsa, PublicParameters, PublicRsaParametersBuilder, RsaExponent, RsaScheme,
    SignatureScheme,
};
use tss_esapi::tcti_ldr::TctiNameConf;

fn context(tcti: &str) -> Context {
    Context::new(TctiNameConf::from_str(tcti).expect("tcti")).expect("context")
}

fn socket_of(tcti: &str) -> std::path::PathBuf {
    tcti.strip_prefix("swtpm:path=").expect("swtpm tcti").into()
}

fn rsa(scheme: RsaScheme) -> PublicParameters {
    PublicParameters::Rsa(
        PublicRsaParametersBuilder::new()
            .with_scheme(scheme)
            .with_key_bits(RsaKeyBits::Rsa2048)
            .with_exponent(RsaExponent::default())
            .build()
            .expect("rsa parameters"),
    )
}

fn ecc(hash: HashingAlgorithm) -> PublicParameters {
    PublicParameters::Ecc(
        PublicEccParametersBuilder::new_unrestricted_signing_key(
            EccScheme::EcDsa(HashScheme::new(hash)),
            EccCurve::NistP256,
        )
        .build()
        .expect("ecc parameters"),
    )
}

/// `supported` or the error text with the TPM's code, and prints it.
fn parms(ctx: &mut Context, label: &str, p: PublicParameters) -> Result<(), String> {
    let r = ctx.test_parms(p).map_err(|e| e.to_string());
    println!(
        "  TestParms {label}: {}",
        r.as_ref()
            .map_or_else(Clone::clone, |()| "supported".into())
    );
    r
}

fn algorithms(ctx: &mut Context) -> Vec<u16> {
    match ctx
        .get_capability(CapabilityType::Algorithms, 0, 80)
        .expect("caps")
        .0
    {
        CapabilityData::Algorithms(l) => l
            .iter()
            .map(|p| u16::from(p.algorithm_identifier()))
            .collect(),
        other => panic!("{other:?}"),
    }
}

fn curves(ctx: &mut Context) -> Vec<u16> {
    match ctx
        .get_capability(CapabilityType::EccCurves, 0, 32)
        .expect("caps")
        .0
    {
        CapabilityData::EccCurves(l) => l.iter().map(|c| u16::from(*c)).collect(),
        other => panic!("{other:?}"),
    }
}

fn rsa_key(ctx: &mut Context) -> tss_esapi::handles::KeyHandle {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .build()
        .expect("attributes");
    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new()
                .with_scheme(RsaScheme::Null)
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_exponent(RsaExponent::default())
                .with_is_signing_key(true)
                .build()
                .expect("rsa"),
        )
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .expect("public");
    ctx.execute_with_nullauth_session(|c| {
        c.create_primary(Hierarchy::Owner, public, None, None, None, None)
    })
    .expect("create_primary passes through the filter")
    .key_handle
}

fn sign(
    ctx: &mut Context,
    key: tss_esapi::handles::KeyHandle,
    scheme: SignatureScheme,
    label: &str,
) -> Result<(), String> {
    let digest = Digest::try_from(vec![7u8; 32]).expect("digest");
    let r = ctx
        .execute_with_nullauth_session(|c| c.sign(key, digest, scheme, None))
        .map(|_| ())
        .map_err(|e| e.to_string());
    println!(
        "  Sign {label}: {}",
        r.as_ref().map_or_else(Clone::clone, |()| "served".into())
    );
    r
}

fn pss(h: HashingAlgorithm) -> SignatureScheme {
    SignatureScheme::RsaPss {
        scheme: HashScheme::new(h),
    }
}
fn ssa(h: HashingAlgorithm) -> SignatureScheme {
    SignatureScheme::RsaSsa {
        scheme: HashScheme::new(h),
    }
}

#[test]
fn lacking_pss_is_a_partial_lack() {
    let tpm = Swtpm::start().expect("swtpm");
    let filter = TpmFilter::start(
        &socket_of(&tpm.tcti()),
        &tpm.state_dir().join("filter.sock"),
        Lacks {
            algorithms: vec![alg::RSAPSS],
            curves: vec![],
            ..Lacks::default()
        },
    )
    .expect("filter");
    println!("plain swtpm:");
    {
        let mut ctx = context(&tpm.tcti());
        assert!(algorithms(&mut ctx).contains(&alg::RSAPSS));
        parms(
            &mut ctx,
            "rsa2048 RSAPSS SHA-256",
            rsa(RsaScheme::RsaPss(HashScheme::new(HashingAlgorithm::Sha256))),
        )
        .expect("plain supports PSS");
        let key = rsa_key(&mut ctx);
        sign(
            &mut ctx,
            key,
            pss(HashingAlgorithm::Sha256),
            "RSAPSS SHA-256",
        )
        .expect("plain signs PSS");
    }
    println!("through the filter (lacks RSAPSS 0x0016):");
    {
        let mut ctx = context(&filter.tcti());
        let algs = algorithms(&mut ctx);
        println!(
            "  GetCapability(ALGS): RSAPSS {}, RSASSA {}",
            if algs.contains(&alg::RSAPSS) {
                "present"
            } else {
                "absent"
            },
            if algs.contains(&alg::RSASSA) {
                "present"
            } else {
                "absent"
            }
        );
        assert!(!algs.contains(&alg::RSAPSS) && algs.contains(&alg::RSASSA));
        let e = parms(
            &mut ctx,
            "rsa2048 RSAPSS SHA-256",
            rsa(RsaScheme::RsaPss(HashScheme::new(HashingAlgorithm::Sha256))),
        )
        .expect_err("filter lacks PSS");
        assert!(e.contains("0x000001D2"), "{e}");
        parms(
            &mut ctx,
            "rsa2048 RSASSA SHA-256",
            rsa(RsaScheme::RsaSsa(HashScheme::new(HashingAlgorithm::Sha256))),
        )
        .expect("RSASSA still supported");
        let key = rsa_key(&mut ctx);
        let e = sign(
            &mut ctx,
            key,
            pss(HashingAlgorithm::Sha256),
            "RSAPSS SHA-256",
        )
        .expect_err("filter refuses PSS");
        assert!(e.contains("0x000002D2"), "{e}");
        sign(
            &mut ctx,
            key,
            ssa(HashingAlgorithm::Sha256),
            "RSASSA SHA-256",
        )
        .expect("RSASSA served");
    }
}

#[test]
fn lacking_sha384_and_a_curve() {
    let tpm = Swtpm::start().expect("swtpm");
    let filter = TpmFilter::start(
        &socket_of(&tpm.tcti()),
        &tpm.state_dir().join("filter.sock"),
        Lacks {
            algorithms: vec![alg::SHA384],
            curves: vec![alg::CURVE_P256],
            ..Lacks::default()
        },
    )
    .expect("filter");
    println!("plain swtpm:");
    {
        let mut ctx = context(&tpm.tcti());
        assert!(algorithms(&mut ctx).contains(&alg::SHA384));
        assert!(curves(&mut ctx).contains(&alg::CURVE_P256));
        parms(
            &mut ctx,
            "rsa2048 RSASSA SHA-384",
            rsa(RsaScheme::RsaSsa(HashScheme::new(HashingAlgorithm::Sha384))),
        )
        .expect("plain");
        parms(
            &mut ctx,
            "ecc_p256 ECDSA SHA-256",
            ecc(HashingAlgorithm::Sha256),
        )
        .expect("plain");
    }
    println!("through the filter (lacks SHA-384 0x000c and curve P-256 0x0003):");
    let mut ctx = context(&filter.tcti());
    assert!(!algorithms(&mut ctx).contains(&alg::SHA384));
    assert!(algorithms(&mut ctx).contains(&alg::SHA256));
    assert!(!curves(&mut ctx).contains(&alg::CURVE_P256));
    println!(
        "  GetCapability(ALGS): SHA-384 absent, SHA-256 present; GetCapability(ECC_CURVES): P-256 absent"
    );
    let e = parms(
        &mut ctx,
        "rsa2048 RSASSA SHA-384",
        rsa(RsaScheme::RsaSsa(HashScheme::new(HashingAlgorithm::Sha384))),
    )
    .expect_err("lacks SHA-384");
    assert!(e.contains("0x000001C3"), "{e}");
    parms(
        &mut ctx,
        "rsa2048 RSASSA SHA-256",
        rsa(RsaScheme::RsaSsa(HashScheme::new(HashingAlgorithm::Sha256))),
    )
    .expect("SHA-256 stays");
    let e = parms(
        &mut ctx,
        "ecc_p256 ECDSA SHA-256",
        ecc(HashingAlgorithm::Sha256),
    )
    .expect_err("lacks the curve");
    assert!(e.contains("0x000001E6"), "{e}");
}

/// What the real `swtpm` answers for items it does not implement, next to the codes the filter returns for a lacking item.
/// The hash code agrees with the real answer. The scheme and curve codes come from the TPM 2.0 Part 2 table and are not measured:
/// `swtpm` implements every scheme and curve, so it has no answer to compare with (a hardware TPM run is F111).
#[test]
fn real_unsupported_hash_matches_the_filter() {
    let tpm = Swtpm::start().expect("swtpm");
    let mut ctx = context(&tpm.tcti());
    println!("real swtpm, items it does not implement:");
    println!("  GetCapability(ECC_CURVES): {:04x?}", curves(&mut ctx));
    let e = parms(
        &mut ctx,
        "rsa2048 RSASSA SM3_256",
        rsa(RsaScheme::RsaSsa(HashScheme::new(
            HashingAlgorithm::Sm3_256,
        ))),
    )
    .expect_err("libtpms has no SM3");
    assert!(e.contains("0x000001C3"), "hash: {e}");
    // libtpms 0.9.2 implements every curve the TPM spec lists, so no real answer for a missing curve exists to compare with.
}

/// Every command code the TPM lists (`TPM2_GetCapability(TPM_CAP_COMMANDS)`, page after page).
fn commands(ctx: &mut Context) -> Result<Vec<u32>, String> {
    let mut out = Vec::new();
    let mut property = 0u32;
    for _ in 0..16 {
        let (data, more) = ctx
            .get_capability(CapabilityType::Command, property, 64)
            .map_err(|e| e.to_string())?;
        let CapabilityData::Commands(list) = data else {
            return Err("not commands".into());
        };
        let page: Vec<u32> = list.iter().map(|a| u32::from(a.command_index())).collect();
        out.extend(&page);
        match page.last() {
            Some(end) if more => property = end + 1,
            _ => return Ok(out),
        }
    }
    Err("too many pages".into())
}

fn filter_with(tpm: &Swtpm, lacks: Lacks) -> TpmFilter {
    TpmFilter::start(
        &socket_of(&tpm.tcti()),
        &tpm.state_dir().join("filter.sock"),
        lacks,
    )
    .expect("filter")
}

#[test]
fn lacking_commands_are_removed_from_the_command_list() {
    let tpm = Swtpm::start().expect("swtpm");
    let wanted = [cc::RSA_DECRYPT, cc::IMPORT, cc::LOAD];
    let plain = commands(&mut context(&tpm.tcti())).expect("plain commands");
    for c in wanted.into_iter().chain([cc::SIGN, cc::CREATE_PRIMARY]) {
        assert!(plain.contains(&c), "plain swtpm lists {c:#x}");
    }
    let filter = filter_with(
        &tpm,
        Lacks {
            commands: wanted.to_vec(),
            ..Lacks::default()
        },
    );
    let filtered = commands(&mut context(&filter.tcti())).expect("filtered commands");
    let removed: Vec<u32> = plain
        .iter()
        .copied()
        .filter(|c| !filtered.contains(c))
        .collect();
    assert_eq!(removed, vec![cc::IMPORT, cc::LOAD, cc::RSA_DECRYPT]);
    assert!(filtered.len() > 10, "the rest of the list stays");
    println!(
        "  GetCapability(COMMANDS): {} plain, {} through the filter, removed {removed:#x?}",
        plain.len(),
        filtered.len()
    );
}

#[test]
fn a_fault_rule_answers_the_chosen_code_for_that_command_only() {
    let tpm = Swtpm::start().expect("swtpm");
    for (faulty, other_works) in [
        (cc::GET_CAPABILITY, cc::TEST_PARMS),
        (cc::TEST_PARMS, cc::GET_CAPABILITY),
    ] {
        let filter = filter_with(
            &tpm,
            Lacks {
                faults: vec![CommandFault {
                    command: faulty,
                    action: FaultAction::Respond(0x101),
                }],
                ..Lacks::default()
            },
        );
        let mut ctx = context(&filter.tcti());
        let run = |ctx: &mut Context, command: u32| -> Result<(), String> {
            if command == cc::GET_CAPABILITY {
                commands(ctx).map(drop)
            } else {
                parms(ctx, "rsa2048 null", rsa(RsaScheme::Null))
            }
        };
        let e = run(&mut ctx, faulty).expect_err("the rule answers");
        assert!(e.contains("0x00000101"), "{e}");
        run(&mut ctx, other_works).expect("a command without a rule succeeds");
        println!("  fault rule on {faulty:#x}: {e}");
    }
    // Without the rule the same commands succeed.
    let mut ctx = context(&tpm.tcti());
    commands(&mut ctx).expect("plain");
    parms(&mut ctx, "rsa2048 null", rsa(RsaScheme::Null)).expect("plain");
}

#[test]
fn a_fault_rule_can_drop_the_connection_in_the_middle_of_the_reply() {
    let tpm = Swtpm::start().expect("swtpm");
    let filter = filter_with(
        &tpm,
        Lacks {
            faults: vec![CommandFault {
                command: cc::GET_CAPABILITY,
                action: FaultAction::DropMidReply,
            }],
            ..Lacks::default()
        },
    );
    let e = commands(&mut context(&filter.tcti())).expect_err("the connection drops");
    assert!(!e.contains("0x00000101"), "no TPM response code in {e}");
    println!("  dropped connection: {e}");
    // The filter serves the next client, and the TPM is unharmed.
    commands(&mut context(&tpm.tcti())).expect("plain swtpm still answers");
}
