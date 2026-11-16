//! The storage classifier gives the same answer for the same storage, and every `unknown` says why
//! (`docs/findings/F189.md`, route 2). One table: each fixture tree maps to its verdict and its reason, so a classifier
//! that merges two groups of causes, returns a constant reason, or turns an `unknown` into `encrypted` fails.

use std::error::Error;
use std::fs;
use std::path::Path;

use StateStorage::{Encrypted, NotEncrypted, Unknown};
use UnknownReason::{
    FscryptNotExcluded, LayerNotClassified, MembersDisagree, NoMount, NotBlockFilesystem,
    StateDirUnresolved, SysfsIncomplete,
};
use custodiod::storage::{StateStorage, UnknownReason, diagnose_with};

type Res = Result<(), Box<dyn Error>>;

#[path = "state_storage/tree.rs"]
mod tree;
use tree::Tree;

/// What the fscrypt check says in a case.
#[derive(Clone, Copy)]
enum Fscrypt {
    Clean,
    Fails,
    Encrypted,
}

type Want = (StateStorage, Option<UnknownReason>);

struct Case {
    name: &'static str,
    fscrypt: Fscrypt,
    build: fn(&mut Tree) -> Res,
    want: Want,
}

const fn case(name: &'static str, build: fn(&mut Tree) -> Res, want: Want) -> Case {
    Case {
        name,
        fscrypt: Fscrypt::Clean,
        build,
        want,
    }
}

/// Disk `nvme0n1` (259:0) with partition `nvme0n1p1` (259:1); returns the partition directory.
fn plain(t: &Tree) -> Result<std::path::PathBuf, Box<dyn Error>> {
    t.disk("nvme0n1", "259:0")?;
    t.part("nvme0n1", "nvme0n1p1", "259:1")
}

/// A second disk, for members next to the first.
fn other_disk(t: &Tree) -> Result<std::path::PathBuf, Box<dyn Error>> {
    t.disk("sda", "8:0")
}

/// `dm-0` (252:0) with the given uuid on the plain partition, mounted as ext4.
fn dm_on_plain(t: &mut Tree, uuid: &str) -> Res {
    let part = plain(t)?;
    t.dm("dm-0", "252:0", uuid, &[&part])?;
    t.on("252:0", "ext4")?;
    Ok(())
}

/// An LVM `dm-0` over a crypt `dm-1` and a plain partition.
fn lvm_mixed(t: &mut Tree, crypt_first: bool) -> Res {
    let part = plain(t)?;
    let crypt = t.dm("dm-1", "252:1", "CRYPT-LUKS2-aa-x", &[&part])?;
    let plain_disk = other_disk(t)?;
    let slaves: [&Path; 2] = if crypt_first {
        [&crypt, &plain_disk]
    } else {
        [&plain_disk, &crypt]
    };
    t.dm("dm-0", "252:0", "LVM-abc", &slaves)?;
    t.on("252:0", "ext4")?;
    Ok(())
}

fn mounted(t: &mut Tree, mm: &str, fstype: &str) -> Res {
    t.on(mm, fstype)?;
    Ok(())
}

fn md_on(t: &mut Tree, members: &[&str]) -> Res {
    let part = plain(t)?;
    let crypt = t.dm("dm-1", "252:1", "CRYPT-LUKS2-aa-x", &[&part])?;
    let sda = other_disk(t)?;
    let paths: Vec<&Path> = members
        .iter()
        .map(|m| {
            if *m == "crypt" {
                crypt.as_path()
            } else {
                sda.as_path()
            }
        })
        .collect();
    t.md("md0", "9:0", &paths)?;
    t.on("9:0", "ext4")?;
    Ok(())
}

// One table of every case: its length is the point, splitting it would only hide a case.
#[allow(clippy::too_many_lines)]
fn cases() -> Vec<Case> {
    let mut cases = vec![
        // Proven answers: no reason.
        case(
            "complete lvm chain",
            |t| dm_on_plain(t, "LVM-abc"),
            (NotEncrypted, None),
        ),
        case(
            "plain partition",
            |t| {
                plain(t)?;
                mounted(t, "259:1", "ext4")
            },
            (NotEncrypted, None),
        ),
        case(
            "luks1",
            |t| dm_on_plain(t, "CRYPT-LUKS1-aa-x"),
            (Encrypted, None),
        ),
        case(
            "luks2",
            |t| dm_on_plain(t, "CRYPT-LUKS2-aa-x"),
            (Encrypted, None),
        ),
        case(
            "plain dm-crypt",
            |t| dm_on_plain(t, "CRYPT-PLAIN-x"),
            (Encrypted, None),
        ),
        case(
            "md of crypt members",
            |t| md_on(t, &["crypt", "crypt"]),
            (Encrypted, None),
        ),
        // The mount.
        case(
            "no covering mount",
            |t| {
                plain(t)?;
                t.mount("/elsewhere", "259:1", "ext4");
                t.write()?;
                Ok(())
            },
            (Unknown, Some(NoMount)),
        ),
        case(
            "unreadable mount table",
            |t| {
                plain(t)?;
                fs::create_dir(t.path().join("proc/self/mountinfo"))?;
                Ok(())
            },
            (Unknown, Some(NoMount)),
        ),
        case(
            "tmpfs",
            |t| mounted(t, "0:30", "tmpfs"),
            (Unknown, Some(NotBlockFilesystem)),
        ),
        case(
            "overlay",
            |t| mounted(t, "0:31", "overlay"),
            (Unknown, Some(NotBlockFilesystem)),
        ),
        case(
            "nfs",
            |t| mounted(t, "0:32", "nfs4"),
            (Unknown, Some(NotBlockFilesystem)),
        ),
        case(
            "block fs on an unlisted type",
            |t| {
                plain(t)?;
                mounted(t, "259:1", "btrfs")
            },
            (Unknown, Some(NotBlockFilesystem)),
        ),
        case(
            "anonymous device",
            |t| {
                plain(t)?;
                mounted(t, "0:45", "ext4")
            },
            (Unknown, Some(NotBlockFilesystem)),
        ),
        // The sysfs chain.
        case(
            "block node missing",
            |t| mounted(t, "259:9", "ext4"),
            (Unknown, Some(SysfsIncomplete)),
        ),
        case(
            "dm directory without uuid",
            |t| {
                let part = plain(t)?;
                let dm = t.dm("dm-0", "252:0", "LVM-abc", &[&part])?;
                fs::remove_file(dm.join("dm/uuid"))?;
                mounted(t, "252:0", "ext4")
            },
            (Unknown, Some(SysfsIncomplete)),
        ),
        case(
            "dm uuid empty",
            |t| dm_on_plain(t, ""),
            (Unknown, Some(SysfsIncomplete)),
        ),
        case(
            "slaves missing",
            |t| {
                let part = plain(t)?;
                let dm = t.dm("dm-0", "252:0", "LVM-abc", &[&part])?;
                fs::remove_dir_all(dm.join("slaves"))?;
                mounted(t, "252:0", "ext4")
            },
            (Unknown, Some(SysfsIncomplete)),
        ),
        case(
            "slaves empty",
            |t| {
                plain(t)?;
                t.dm("dm-0", "252:0", "LVM-abc", &[])?;
                mounted(t, "252:0", "ext4")
            },
            (Unknown, Some(SysfsIncomplete)),
        ),
        case(
            "partition whose disk has no dev",
            |t| {
                fs::create_dir_all(t.path().join("sys/devices/pci/nvme0n1/device"))?;
                t.part("nvme0n1", "nvme0n1p1", "259:1")?;
                mounted(t, "259:1", "ext4")
            },
            (Unknown, Some(SysfsIncomplete)),
        ),
        case(
            "partition whose disk is a partition",
            |t| {
                plain(t)?;
                t.part("nvme0n1/nvme0n1p1", "nvme0n1p1p1", "259:2")?;
                mounted(t, "259:2", "ext4")
            },
            (Unknown, Some(SysfsIncomplete)),
        ),
        case(
            "loop in slaves",
            |t| {
                plain(t)?;
                let a = t.dm("dm-0", "252:0", "LVM-a", &[])?;
                let b = t.dm("dm-1", "252:1", "LVM-b", &[&a])?;
                Tree::link_slaves(&a, &[&b])?;
                mounted(t, "252:0", "ext4")
            },
            (Unknown, Some(SysfsIncomplete)),
        ),
        case(
            "chain deeper than the limit",
            |t| {
                let part = plain(t)?;
                let mut below = part;
                for i in (0..20).rev() {
                    below = t.dm(&format!("dm-{i}"), &format!("252:{i}"), "LVM-x", &[&below])?;
                }
                mounted(t, "252:0", "ext4")
            },
            (Unknown, Some(SysfsIncomplete)),
        ),
        // Layers that are not classified.
        case(
            "dm uuid CRYPT-VERITY",
            |t| dm_on_plain(t, "CRYPT-VERITY-aa-x"),
            (Unknown, Some(LayerNotClassified)),
        ),
        case(
            "dm uuid CRYPT-INTEGRITY",
            |t| dm_on_plain(t, "CRYPT-INTEGRITY-aa-x"),
            (Unknown, Some(LayerNotClassified)),
        ),
        case(
            "dm uuid of another subsystem",
            |t| dm_on_plain(t, "mpath-36000"),
            (Unknown, Some(LayerNotClassified)),
        ),
        case(
            "md of plain members",
            |t| md_on(t, &["plain", "plain"]),
            (Unknown, Some(LayerNotClassified)),
        ),
        case(
            "dm node without dm directory",
            |t| {
                // F189's kernel gap: `slaves/` is already full, `dm/` does not exist yet.
                let part = plain(t)?;
                let dm = t.node("virtual/block/dm-0", "252:0")?;
                Tree::link_slaves(&dm, &[&part])?;
                mounted(t, "252:0", "ext4")
            },
            (Unknown, Some(SysfsIncomplete)),
        ),
        case(
            "disk without a device link",
            |t| {
                t.node("virtual/block/loop0", "7:0")?;
                mounted(t, "7:0", "ext4")
            },
            (Unknown, Some(LayerNotClassified)),
        ),
        case(
            "disk with devices stacked on it",
            |t| {
                let disk = t.disk("nvme0n1", "259:0")?;
                let sda = other_disk(t)?;
                Tree::link_slaves(&disk, &[&sda])?;
                mounted(t, "259:0", "ext4")
            },
            (Unknown, Some(LayerNotClassified)),
        ),
        // Members.
        case(
            "lvm of crypt and plain",
            |t| lvm_mixed(t, true),
            (Unknown, Some(MembersDisagree)),
        ),
        case(
            "lvm of plain and crypt",
            |t| lvm_mixed(t, false),
            (Unknown, Some(MembersDisagree)),
        ),
        case(
            "md of crypt and plain",
            |t| md_on(t, &["crypt", "plain"]),
            (Unknown, Some(MembersDisagree)),
        ),
    ];
    // The state directory itself.
    cases.push(Case {
        name: "state directory not there",
        fscrypt: Fscrypt::Clean,
        build: |t| {
            fs::remove_dir(t.state())?;
            plain(t)?;
            Ok(())
        },
        want: (Unknown, Some(StateDirUnresolved)),
    });
    // fscrypt: only a chain that would be `not-encrypted` is asked.
    for (name, fscrypt) in [
        ("fscrypt check fails", Fscrypt::Fails),
        ("fscrypt says encrypted", Fscrypt::Encrypted),
    ] {
        cases.push(Case {
            name,
            fscrypt,
            build: |t| dm_on_plain(t, "LVM-abc"),
            want: (Unknown, Some(FscryptNotExcluded)),
        });
    }
    cases
}

fn run(c: &Case) -> Result<Want, Box<dyn Error>> {
    let mut t = Tree::new()?;
    (c.build)(&mut t)?;
    let fscrypt: &dyn Fn(&Path) -> std::io::Result<bool> = match c.fscrypt {
        Fscrypt::Clean => &|_| Ok(false),
        Fscrypt::Fails => &|_| Err(std::io::Error::other("no statx")),
        Fscrypt::Encrypted => &|_| Ok(true),
    };
    let state = t.state();
    let first = diagnose_with(&t.path(), &state, fscrypt);
    // The same tree again gives the same answer, and the verdict is the one `classify_with` has always given.
    let again = diagnose_with(&t.path(), &state, fscrypt);
    assert_eq!(first, again, "{}: differs between two reads", c.name);
    if matches!(c.fscrypt, Fscrypt::Clean) {
        assert_eq!(t.verdict(), first.storage(), "{}", c.name);
    }
    Ok((first.storage(), first.reason()))
}

#[test]
fn every_case_has_its_verdict_and_its_reason() -> Res {
    let mut wrong = Vec::new();
    for c in cases() {
        let got = run(&c)?;
        if got != c.want {
            wrong.push(format!("{}: got {got:?}, want {:?}", c.name, c.want));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
    Ok(())
}

#[test]
fn every_reason_value_is_used_and_has_its_own_wire_string() {
    let used: Vec<_> = cases().iter().filter_map(|c| c.want.1).collect();
    let mut names = Vec::new();
    for reason in UnknownReason::ALL {
        assert!(used.contains(&reason), "no case for {reason:?}");
        assert!(!names.contains(&reason.name()), "{reason:?} repeats a name");
        names.push(reason.name());
    }
}

#[test]
fn a_chain_that_becomes_complete_changes_from_unknown_to_not_encrypted() -> Res {
    // F189: the same machine can answer `unknown` while sysfs is incomplete and `not-encrypted` once it is whole;
    // never `encrypted`, and the reason is that of the missing piece.
    let mut t = Tree::new()?;
    let part = plain(&t)?;
    let dm = t.dm("dm-0", "252:0", "", &[&part])?;
    t.on("252:0", "ext4")?;
    let state = t.state();
    let ask = || diagnose_with(&t.path(), &state, &|_| Ok(false));
    assert_eq!(ask().reason(), Some(SysfsIncomplete));
    fs::write(dm.join("dm/uuid"), "LVM-abc\n")?;
    assert_eq!(ask().storage(), NotEncrypted);
    assert_eq!(ask().reason(), None);
    Ok(())
}
