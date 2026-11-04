use super::classify::{classify, is_unsupported};
use super::list::{CC_CREATE_PRIMARY, CC_IMPORT, CC_LOAD, CC_RSA_DECRYPT, CC_SIGN};
use super::*;

const BOTH: [KeyType; 2] = [KeyType::Rsa2048, KeyType::EccP256];

fn rc(code: u32) -> Fault {
    Fault::Response(ResponseCode(code))
}

/// A TPM with every item of every list.
fn complete() -> Opened {
    Opened {
        owner: Ok(Owner {
            auth_set: false,
            enabled: true,
        }),
        algorithms: Ok(vec![0x0001, 0x0006, 0x000b, 0x0023]),
        curves: Ok(vec![0x0003]),
        commands: Ok(vec![
            CC_CREATE_PRIMARY,
            CC_IMPORT,
            CC_LOAD,
            CC_RSA_DECRYPT,
            CC_SIGN,
        ]),
        parms: vec![
            (Parms::Parent, Ok(())),
            (Parms::Rsa2048, Ok(())),
            (Parms::EcdsaSha256, Ok(())),
        ],
    }
}

fn without_alg(id: u16) -> Opened {
    let mut o = complete();
    o.algorithms = Ok(vec![0x0001, 0x0006, 0x000b, 0x0023]
        .into_iter()
        .filter(|a| *a != id)
        .collect());
    o
}

fn class(key: KeyType, o: Opened) -> Classification {
    classify(key, &Answers::Opened(o))
}

#[test]
fn absent_and_open_failures() {
    assert_eq!(
        classify(KeyType::EccP256, &Answers::NoDevice),
        Classification::Absent
    );
    for e in [
        TpmError::ResourceManagerMissing,
        TpmError::OpenFailed,
        TpmError::TestTctiRefused,
        TpmError::Transport,
    ] {
        assert_eq!(
            classify(KeyType::Rsa2048, &Answers::OpenFailed(e)),
            Classification::Error(e)
        );
    }
}

#[test]
fn ready_for_both_key_types() {
    for key in BOTH {
        assert_eq!(class(key, complete()), Classification::Ready, "{key:?}");
    }
}

#[test]
fn lacks_names_the_items_of_the_key_type() {
    let mut o = complete();
    o.commands = Ok(vec![CC_CREATE_PRIMARY, CC_IMPORT, CC_LOAD]);
    assert_eq!(
        class(KeyType::Rsa2048, o.clone()),
        Classification::Lacks(vec![Item::CmdRsaDecrypt])
    );
    assert_eq!(
        class(KeyType::EccP256, o),
        Classification::Lacks(vec![Item::CmdSign])
    );
    let mut o = complete();
    o.algorithms = Ok(vec![0x0006, 0x000b, 0x0023]);
    assert_eq!(
        class(KeyType::EccP256, o.clone()),
        Classification::Ready,
        "RSA is not on the ECC list"
    );
    assert_eq!(
        class(KeyType::Rsa2048, o),
        Classification::Lacks(vec![Item::AlgRsa])
    );
}

#[test]
fn every_item_is_named_when_alone_absent() {
    let cases: [(Item, Opened); 13] = [
        (Item::AlgEcc, without_alg(0x0023)),
        (
            Item::CurveP256,
            Opened {
                curves: Ok(vec![]),
                ..complete()
            },
        ),
        (Item::AlgSha256, without_alg(0x000b)),
        (Item::AlgAes, without_alg(0x0006)),
        (
            Item::ParentParms,
            Opened {
                parms: vec![
                    (Parms::Parent, Err(rc(0x1d2))),
                    (Parms::Rsa2048, Ok(())),
                    (Parms::EcdsaSha256, Ok(())),
                ],
                ..complete()
            },
        ),
        (Item::CmdCreatePrimary, command_removed(CC_CREATE_PRIMARY)),
        (Item::CmdImport, command_removed(CC_IMPORT)),
        (Item::CmdLoad, command_removed(CC_LOAD)),
        (Item::AlgRsa, without_alg(0x0001)),
        (
            Item::Rsa2048Parms,
            Opened {
                parms: vec![
                    (Parms::Parent, Ok(())),
                    (Parms::Rsa2048, Err(rc(0x18a))),
                    (Parms::EcdsaSha256, Ok(())),
                ],
                ..complete()
            },
        ),
        (Item::CmdRsaDecrypt, command_removed(CC_RSA_DECRYPT)),
        (
            Item::EcdsaSha256Parms,
            Opened {
                parms: vec![
                    (Parms::Parent, Ok(())),
                    (Parms::Rsa2048, Ok(())),
                    (Parms::EcdsaSha256, Err(rc(0x1c3))),
                ],
                ..complete()
            },
        ),
        (Item::CmdSign, command_removed(CC_SIGN)),
    ];
    for (item, o) in cases {
        for key in BOTH {
            let want = if key.items().contains(&item) {
                Classification::Lacks(vec![item])
            } else {
                Classification::Ready
            };
            assert_eq!(class(key, o.clone()), want, "{item:?} for {key:?}");
        }
    }
}

fn command_removed(cc: u32) -> Opened {
    let mut o = complete();
    o.commands = o
        .commands
        .map(|l| l.into_iter().filter(|c| *c != cc).collect());
    o
}

#[test]
fn dependent_items_named_once() {
    // Each algorithm the TestParms items are made of: only the algorithm (or the curve) is named, for both key types.
    for (o, named) in [
        (without_alg(0x0023), Item::AlgEcc),
        (without_alg(0x0006), Item::AlgAes),
        (
            Opened {
                curves: Ok(vec![]),
                ..complete()
            },
            Item::CurveP256,
        ),
    ] {
        // The refusals a real TPM would also answer for what is made of the absent item; they are not named a second time.
        let refusing = |parms: Item| {
            if parms.depends_on().contains(&named) {
                Err(rc(0x18a))
            } else {
                Ok(())
            }
        };
        let o = Opened {
            parms: vec![
                (Parms::Parent, refusing(Item::ParentParms)),
                (Parms::Rsa2048, refusing(Item::Rsa2048Parms)),
                (Parms::EcdsaSha256, refusing(Item::EcdsaSha256Parms)),
            ],
            ..o
        };
        for key in BOTH {
            assert_eq!(
                class(key, o.clone()),
                Classification::Lacks(vec![named]),
                "{named:?} {key:?}"
            );
        }
    }
    // No ECC at all: the curve list is empty too, and the curve is not named a second time (one answer: the algorithm).
    for key in BOTH {
        let o = Opened {
            curves: Ok(vec![]),
            ..without_alg(0x0023)
        };
        assert_eq!(
            class(key, o),
            Classification::Lacks(vec![Item::AlgEcc]),
            "{key:?}"
        );
    }
    // `Display` of an item is its document name.
    for item in super::list::ALL {
        assert_eq!(item.to_string(), item.name());
        assert_ne!(item.name(), "");
    }
    // RSA absent: the rsa2048 TestParms is not named, and the ECC key type is untouched.
    let o = Opened {
        parms: vec![(Parms::Parent, Ok(())), (Parms::Rsa2048, Err(rc(0x18a)))],
        ..without_alg(0x0001)
    };
    assert_eq!(
        class(KeyType::Rsa2048, o.clone()),
        Classification::Lacks(vec![Item::AlgRsa])
    );
    // SHA-256 absent: ECDSA/SHA-256 is made of it.
    let o = Opened {
        parms: vec![
            (Parms::Parent, Ok(())),
            (Parms::EcdsaSha256, Err(rc(0x1c3))),
        ],
        ..without_alg(0x000b)
    };
    assert_eq!(
        class(KeyType::EccP256, o),
        Classification::Lacks(vec![Item::AlgSha256])
    );
    // Two independent absences are both named, in the order of the list.
    let mut o = without_alg(0x0006);
    o.commands = Ok(vec![CC_CREATE_PRIMARY, CC_IMPORT, CC_LOAD, CC_RSA_DECRYPT]);
    assert_eq!(
        class(KeyType::EccP256, o),
        Classification::Lacks(vec![Item::AlgAes, Item::CmdSign])
    );
}

#[test]
fn error_wins_over_lacks_and_is_never_absent_or_lacks() {
    let lacking = without_alg(0x0001);
    let faults: [Opened; 7] = [
        Opened {
            owner: Ok(Owner {
                auth_set: true,
                enabled: true,
            }),
            ..lacking.clone()
        },
        Opened {
            owner: Ok(Owner {
                auth_set: false,
                enabled: false,
            }),
            ..lacking.clone()
        },
        Opened {
            owner: Err(rc(0x101)),
            ..lacking.clone()
        },
        Opened {
            algorithms: Err(rc(0x101)),
            ..lacking.clone()
        },
        Opened {
            curves: Err(Fault::Transport),
            ..lacking.clone()
        },
        Opened {
            commands: Err(rc(0x101)),
            ..lacking.clone()
        },
        Opened {
            parms: vec![
                (Parms::Parent, Err(rc(0x101))),
                (Parms::Rsa2048, Ok(())),
                (Parms::EcdsaSha256, Ok(())),
            ],
            ..lacking
        },
    ];
    for o in faults {
        for key in BOTH {
            // The ECC key type has nothing absent, so the fault alone must still be an error.
            assert!(
                matches!(class(key, o.clone()), Classification::Error(_)),
                "{key:?} {o:?}"
            );
        }
    }
}

#[test]
fn each_error_has_its_kind() {
    assert_eq!(
        class(
            KeyType::EccP256,
            Opened {
                owner: Ok(Owner {
                    auth_set: true,
                    enabled: true
                }),
                ..complete()
            }
        ),
        Classification::Error(TpmError::OwnerAuthSet)
    );
    assert_eq!(
        class(
            KeyType::EccP256,
            Opened {
                owner: Ok(Owner {
                    auth_set: false,
                    enabled: false
                }),
                ..complete()
            }
        ),
        Classification::Error(TpmError::OwnerDisabled)
    );
    assert_eq!(
        class(
            KeyType::EccP256,
            Opened {
                algorithms: Err(rc(0x101)),
                ..complete()
            }
        ),
        Classification::Error(TpmError::Response(ResponseCode(0x101)))
    );
    assert_eq!(
        class(
            KeyType::EccP256,
            Opened {
                commands: Err(Fault::Transport),
                ..complete()
            }
        ),
        Classification::Error(TpmError::Transport)
    );
    // A TestParms code that is not an "unsupported" one is an error even when the answer looks like a refusal.
    assert_eq!(
        class(
            KeyType::EccP256,
            Opened {
                parms: vec![
                    (Parms::Parent, Ok(())),
                    (Parms::EcdsaSha256, Err(rc(0x101)))
                ],
                ..complete()
            }
        ),
        Classification::Error(TpmError::Response(ResponseCode(0x101)))
    );
    // A query that should have been asked and was not is not "present".
    assert!(matches!(
        class(
            KeyType::EccP256,
            Opened {
                parms: vec![],
                ..complete()
            }
        ),
        Classification::Error(_)
    ));
}

#[test]
fn parameter_qualified_codes() {
    // As a real TPM answers: SHA-512 TestParms 0x1C3 (F111), the filter's PSS scheme 0x1D2 and curve 0x1E6, a type 0x18A.
    for code in [
        0x1c3, 0x1d2, 0x1e6, 0x18a, 0x083, 0x092, 0x0a6, 0x08a, 0xb83, 0x0c3,
    ] {
        assert!(is_unsupported(ResponseCode(code)), "{code:#x}");
    }
    // Not "unsupported": FAILURE, a format-zero code with a low number equal to HASH, a warning, bits above the code,
    // and format-one codes of other kinds (VALUE 0x084, SIZE 0x095, KEY_SIZE 0x087, SYMMETRIC 0x096).
    for code in [
        0x101,
        0x003,
        0x00a,
        0x012,
        0x026,
        0x923,
        0x1_0083,
        0x084,
        0x095,
        0x087,
        0x096,
        0x0,
        0x0001_01c3,
    ] {
        assert!(!is_unsupported(ResponseCode(code)), "{code:#x}");
    }
}

#[test]
fn results_display_and_debug_name_the_cause_only() {
    let shown = [
        Classification::Absent,
        Classification::Ready,
        Classification::Lacks(vec![Item::AlgEcc, Item::CmdSign]),
        Classification::Error(TpmError::Response(ResponseCode(0x1c3))),
        Classification::Error(TpmError::OwnerAuthSet),
    ];
    let mut seen = std::collections::BTreeSet::new();
    for c in &shown {
        assert!(seen.insert(format!("{c}")), "Display of {c:?} repeats");
        assert!(seen.insert(format!("{c:?}")), "Debug of {c:?} repeats");
    }
    assert_eq!(format!("{}", shown[0]), "no TPM");
    assert_eq!(format!("{}", shown[1]), "TPM ready");
    assert_eq!(
        format!("{}", shown[2]),
        "TPM lacks: algorithm ECC, command Sign"
    );
    assert_eq!(format!("{:?}", shown[2]), "Lacks([AlgEcc, CmdSign])");
    assert_eq!(
        format!("{}", shown[3]),
        "TPM error: TPM response code 0x000001C3"
    );
    assert_eq!(format!("{:?}", shown[3]), "Error(Response(0x000001C3))");
    assert_eq!(
        format!("{}", shown[4]),
        "TPM error: owner hierarchy has an authorization value"
    );
    assert_eq!(format!("{:?}", shown[4]), "Error(OwnerAuthSet)");
    for e in [
        TpmError::ResourceManagerMissing,
        TpmError::OpenFailed,
        TpmError::Transport,
        TpmError::OwnerDisabled,
        TpmError::TestTctiRefused,
    ] {
        assert!(
            seen.insert(format!("{}", Classification::Error(e))),
            "{e:?}"
        );
    }
}

mod access;
