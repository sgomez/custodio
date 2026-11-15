//! The state directory classifier over fixture `/proc` and `/sys` trees, one test per case of
//! `docs/findings/F180.md`, and the production entry point on the real root.

use std::error::Error;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use StateStorage::{Encrypted, NotEncrypted, Unknown};
use custodiod::storage::{
    StateStorage, classify, classify_state_dir, classify_with, fscrypt_flag, has_fscrypt,
};
use rustix::fs::StatxAttributes;

type Res = Result<(), Box<dyn Error>>;

#[path = "state_storage/tree.rs"]
mod tree;
use tree::Tree;

/// `disk` `nvme0n1`, partition `nvme0n1p1` (8:1) on it; returns the partition directory.
fn plain(t: &Tree) -> Result<PathBuf, Box<dyn Error>> {
    t.disk("nvme0n1", "259:0")?;
    t.part("nvme0n1", "nvme0n1p1", "259:1")
}

#[test]
fn plain_partition_is_not_encrypted() -> Res {
    let mut t = Tree::new()?;
    plain(&t)?;
    assert_eq!(t.on("259:1", "ext4")?.verdict(), NotEncrypted);
    Ok(())
}

#[test]
fn every_block_filesystem_on_a_plain_partition_is_not_encrypted() -> Res {
    for fs in [
        "ext2", "ext3", "ext4", "xfs", "f2fs", "jfs", "vfat", "exfat",
    ] {
        let mut t = Tree::new()?;
        plain(&t)?;
        assert_eq!(t.on("259:1", fs)?.verdict(), NotEncrypted, "{fs}");
    }
    Ok(())
}

#[test]
fn a_whole_disk_is_not_encrypted() -> Res {
    let mut t = Tree::new()?;
    t.disk("sda", "8:0")?;
    assert_eq!(t.on("8:0", "xfs")?.verdict(), NotEncrypted);
    Ok(())
}

#[test]
fn luks_is_encrypted() -> Res {
    let mut t = Tree::new()?;
    let p = plain(&t)?;
    t.dm("dm-0", "253:0", "CRYPT-LUKS2-abc-root", &[&p])?;
    assert_eq!(t.on("253:0", "ext4")?.verdict(), Encrypted);
    Ok(())
}

#[test]
fn lvm_on_luks_is_encrypted() -> Res {
    let mut t = Tree::new()?;
    let p = plain(&t)?;
    let luks = t.dm("dm-0", "253:0", "CRYPT-LUKS2-abc-pv", &[&p])?;
    t.dm("dm-1", "253:1", "LVM-vgXlvY", &[&luks])?;
    assert_eq!(t.on("253:1", "ext4")?.verdict(), Encrypted);
    Ok(())
}

#[test]
fn luks_on_lvm_is_encrypted() -> Res {
    let mut t = Tree::new()?;
    let p = plain(&t)?;
    let lvm = t.dm("dm-0", "253:0", "LVM-vgXlvY", &[&p])?;
    t.dm("dm-1", "253:1", "CRYPT-LUKS2-abc-root", &[&lvm])?;
    assert_eq!(t.on("253:1", "ext4")?.verdict(), Encrypted);
    Ok(())
}

#[test]
fn lvm_without_crypt_is_not_encrypted() -> Res {
    let mut t = Tree::new()?;
    let p = plain(&t)?;
    t.dm("dm-0", "253:0", "LVM-vgXlvY", &[&p])?;
    assert_eq!(t.on("253:0", "ext4")?.verdict(), NotEncrypted);
    Ok(())
}

#[test]
fn lvm_over_crypt_and_plain_members_is_unknown() -> Res {
    let mut t = Tree::new()?;
    let p = plain(&t)?;
    let other = t.disk("sdb", "8:16")?;
    let luks = t.dm("dm-0", "253:0", "CRYPT-LUKS2-abc-pv", &[&p])?;
    t.dm("dm-1", "253:1", "LVM-vgXlvY", &[&luks, &other])?;
    assert_eq!(t.on("253:1", "ext4")?.verdict(), Unknown);
    Ok(())
}

#[test]
fn lvm_over_two_crypt_members_is_encrypted() -> Res {
    let mut t = Tree::new()?;
    let p = plain(&t)?;
    let b = t.disk("sdb", "8:16")?;
    let c1 = t.dm("dm-0", "253:0", "CRYPT-LUKS2-a-pv1", &[&p])?;
    let c2 = t.dm("dm-1", "253:1", "CRYPT-LUKS2-b-pv2", &[&b])?;
    t.dm("dm-2", "253:2", "LVM-vgXlvY", &[&c1, &c2])?;
    assert_eq!(t.on("253:2", "ext4")?.verdict(), Encrypted);
    Ok(())
}

#[test]
fn a_dm_device_named_crypt_without_the_uuid_is_unknown() -> Res {
    let mut t = Tree::new()?;
    let p = plain(&t)?;
    t.dm("crypt-root", "253:0", "mpath-3600", &[&p])?;
    assert_eq!(t.on("253:0", "ext4")?.verdict(), Unknown);
    Ok(())
}

#[test]
fn integrity_is_unknown() -> Res {
    let mut t = Tree::new()?;
    let p = plain(&t)?;
    t.dm("dm-0", "253:0", "CRYPT-INTEGRITY-abc-x", &[&p])?;
    assert_eq!(t.on("253:0", "ext4")?.verdict(), Unknown);
    Ok(())
}

#[test]
fn other_cryptsetup_types_are_unknown() -> Res {
    for kind in ["VERITY", "SUBDEV", "TEMP", "INTEGRITY"] {
        let mut t = Tree::new()?;
        let p = plain(&t)?;
        t.dm("dm-0", "253:0", &format!("CRYPT-{kind}-abc-x"), &[&p])?;
        assert_eq!(t.on("253:0", "ext4")?.verdict(), Unknown, "{kind}");
    }
    Ok(())
}

#[test]
fn integrity_over_crypt_is_unknown_and_under_crypt_is_encrypted() -> Res {
    let mut t = Tree::new()?;
    let p = plain(&t)?;
    let luks = t.dm("dm-0", "253:0", "CRYPT-LUKS2-abc-x", &[&p])?;
    t.dm("dm-1", "253:1", "CRYPT-INTEGRITY-abc-x", &[&luks])?;
    assert_eq!(t.on("253:1", "ext4")?.verdict(), Unknown);

    let mut t = Tree::new()?;
    let p = plain(&t)?;
    let integ = t.dm("dm-0", "253:0", "CRYPT-INTEGRITY-abc-x", &[&p])?;
    t.dm("dm-1", "253:1", "CRYPT-LUKS2-abc-x", &[&integ])?;
    assert_eq!(t.on("253:1", "ext4")?.verdict(), Encrypted);
    Ok(())
}

#[test]
fn raid_is_unknown() -> Res {
    let mut t = Tree::new()?;
    let a = t.disk("sda", "8:0")?;
    let b = t.disk("sdb", "8:16")?;
    t.md("md0", "9:0", &[&a, &b])?;
    assert_eq!(t.on("9:0", "ext4")?.verdict(), Unknown);
    Ok(())
}

#[test]
fn raid_over_crypt_is_encrypted_only_when_every_member_is() -> Res {
    let mut t = Tree::new()?;
    let a = t.disk("sda", "8:0")?;
    let b = t.disk("sdb", "8:16")?;
    let ca = t.dm("dm-0", "253:0", "CRYPT-LUKS2-a-x", &[&a])?;
    let cb = t.dm("dm-1", "253:1", "CRYPT-LUKS2-b-x", &[&b])?;
    t.md("md0", "9:0", &[&ca, &cb])?;
    assert_eq!(t.on("9:0", "ext4")?.verdict(), Encrypted);

    let mut t = Tree::new()?;
    let a = t.disk("sda", "8:0")?;
    let b = t.disk("sdb", "8:16")?;
    let ca = t.dm("dm-0", "253:0", "CRYPT-LUKS2-a-x", &[&a])?;
    t.md("md0", "9:0", &[&ca, &b])?;
    assert_eq!(t.on("9:0", "ext4")?.verdict(), Unknown);
    Ok(())
}

#[test]
fn crypt_over_raid_is_encrypted() -> Res {
    let mut t = Tree::new()?;
    let a = t.disk("sda", "8:0")?;
    let b = t.disk("sdb", "8:16")?;
    let md = t.md("md0", "9:0", &[&a, &b])?;
    t.dm("dm-0", "253:0", "CRYPT-LUKS2-abc-x", &[&md])?;
    assert_eq!(t.on("253:0", "ext4")?.verdict(), Encrypted);
    Ok(())
}

#[test]
fn btrfs_multi_device_is_unknown() -> Res {
    // btrfs reports an anonymous device (major 0); even a number that names a plain disk does not help.
    let mut t = Tree::new()?;
    plain(&t)?;
    t.node("anon/a", "0:45")?;
    assert_eq!(t.on("0:45", "btrfs")?.verdict(), Unknown);
    // The same on a real partition number is still not on the block list.
    let mut t = Tree::new()?;
    plain(&t)?;
    assert_eq!(t.on("259:1", "btrfs")?.verdict(), Unknown);
    Ok(())
}

#[test]
fn an_anonymous_device_on_the_block_list_is_unknown() -> Res {
    let mut t = Tree::new()?;
    let d = t.disk("sda", "0:7")?;
    assert!(d.exists());
    assert_eq!(t.on("0:7", "ext4")?.verdict(), Unknown);
    Ok(())
}

/// Each of these fstypes sits on a chain that would be *not encrypted* if the fstype did not stop it.
#[test]
fn zfs_is_unknown() -> Res {
    only_the_fstype_decides("zfs")
}

#[test]
fn network_fs_is_unknown() -> Res {
    for fs in [
        "nfs",
        "nfs4",
        "cifs",
        "smb3",
        "fuse",
        "fuse.sshfs",
        "fuseblk",
        "9p",
    ] {
        only_the_fstype_decides(fs)?;
    }
    Ok(())
}

#[test]
fn overlay_is_unknown() -> Res {
    only_the_fstype_decides("overlay")
}

#[test]
fn tmpfs_is_unknown() -> Res {
    only_the_fstype_decides("tmpfs")
}

#[test]
fn fscrypt_is_unknown() -> Res {
    let mut t = Tree::new()?;
    plain(&t)?;
    t.on("259:1", "ext4")?;
    assert_eq!(classify_with(&t.path(), &t.state(), &|_| Ok(true)), Unknown);
    // A failing check proves nothing either.
    let failing = |_: &Path| Err(std::io::Error::other("no"));
    assert_eq!(classify_with(&t.path(), &t.state(), &failing), Unknown);
    // Negative control: the same tree with the check clean.
    assert_eq!(
        classify_with(&t.path(), &t.state(), &|_| Ok(false)),
        NotEncrypted
    );
    Ok(())
}

#[test]
fn fscrypt_does_not_change_an_encrypted_verdict() -> Res {
    let mut t = Tree::new()?;
    let p = plain(&t)?;
    t.dm("dm-0", "253:0", "CRYPT-LUKS2-abc-x", &[&p])?;
    t.on("253:0", "ext4")?;
    let failing = |_: &Path| Err(std::io::Error::other("no"));
    assert_eq!(classify_with(&t.path(), &t.state(), &failing), Encrypted);
    Ok(())
}

fn only_the_fstype_decides(fstype: &str) -> Res {
    let mut t = Tree::new()?;
    plain(&t)?;
    assert_eq!(t.on("259:1", "ext4")?.verdict(), NotEncrypted, "control");
    let mut t = Tree::new()?;
    plain(&t)?;
    assert_eq!(t.on("259:1", fstype)?.verdict(), Unknown, "{fstype}");
    Ok(())
}

#[test]
fn unreadable_uuid_is_unknown() -> Res {
    let mut t = Tree::new()?;
    let p = plain(&t)?;
    let luks = t.dm("dm-0", "253:0", "CRYPT-LUKS2-abc-x", &[&p])?;
    fs::remove_file(luks.join("dm/uuid"))?;
    fs::create_dir(luks.join("dm/uuid"))?;
    assert_eq!(t.on("253:0", "ext4")?.verdict(), Unknown);
    Ok(())
}

#[test]
fn missing_slaves_is_unknown() -> Res {
    let mut t = Tree::new()?;
    let p = plain(&t)?;
    let lvm = t.dm("dm-0", "253:0", "LVM-vgXlvY", &[&p])?;
    fs::remove_dir_all(lvm.join("slaves"))?;
    assert_eq!(t.on("253:0", "ext4")?.verdict(), Unknown);
    // An empty `slaves` is no chain either.
    fs::create_dir(lvm.join("slaves"))?;
    assert_eq!(t.verdict(), Unknown);
    Ok(())
}

#[test]
fn cycle_is_unknown() -> Res {
    let mut t = Tree::new()?;
    let a = t.dm("dm-0", "253:0", "LVM-a", &[])?;
    let b = t.dm("dm-1", "253:1", "LVM-b", &[&a])?;
    Tree::link_slaves(&a, &[&b])?;
    assert_eq!(t.on("253:0", "ext4")?.verdict(), Unknown);
    Ok(())
}

#[test]
fn a_chain_deeper_than_the_bound_is_unknown() -> Res {
    let deep = |levels: usize| -> Result<StateStorage, Box<dyn Error>> {
        let mut t = Tree::new()?;
        let mut below = plain(&t)?;
        for i in 0..levels {
            below = t.dm(&format!("dm-{i}"), &format!("253:{i}"), "LVM-x", &[&below])?;
        }
        Ok(t.on(&format!("253:{}", levels - 1), "ext4")?.verdict())
    };
    assert_eq!(deep(10)?, NotEncrypted);
    assert_eq!(deep(14)?, NotEncrypted);
    assert_eq!(deep(15)?, Unknown);
    assert_eq!(deep(40)?, Unknown);
    Ok(())
}

#[test]
fn unmatched_mount_is_unknown() -> Res {
    let mut t = Tree::new()?;
    plain(&t)?;
    t.mount("/somewhere/else", "259:1", "ext4");
    t.write()?;
    assert_eq!(t.verdict(), Unknown);
    // No table at all.
    fs::remove_file(t.path().join("proc/self/mountinfo"))?;
    assert_eq!(t.verdict(), Unknown);
    Ok(())
}

#[test]
fn a_missing_state_directory_or_device_is_unknown() -> Res {
    let mut t = Tree::new()?;
    plain(&t)?;
    t.on("259:1", "ext4")?;
    assert_eq!(
        classify_with(&t.path(), &t.path().join("nope"), &|_| Ok(false)),
        Unknown
    );
    let mut t = Tree::new()?;
    t.on("259:9", "ext4")?; // no such device in /sys
    assert_eq!(t.verdict(), Unknown);
    Ok(())
}

#[test]
fn crypt_off_chain_is_ignored() -> Res {
    let mut t = Tree::new()?;
    let p = plain(&t)?;
    let other = t.disk("sdb", "8:16")?;
    t.dm("dm-9", "253:9", "CRYPT-LUKS2-other-x", &[&other])?;
    t.dm("dm-0", "253:0", "LVM-vgXlvY", &[&p])?;
    assert_eq!(t.on("253:0", "ext4")?.verdict(), NotEncrypted);
    Ok(())
}

#[test]
fn unreadable_link_flips_encrypted_to_unknown() -> Res {
    let build = |break_link: bool| -> Result<StateStorage, Box<dyn Error>> {
        let mut t = Tree::new()?;
        let p = plain(&t)?;
        let luks = t.dm("dm-0", "253:0", "CRYPT-LUKS2-abc-pv", &[&p])?;
        let lvm = t.dm("dm-1", "253:1", "LVM-vgXlvY", &[&luks])?;
        if break_link {
            fs::remove_file(lvm.join("slaves/s0"))?;
            symlink(t.path().join("sys/devices/gone"), lvm.join("slaves/s0"))?;
        }
        Ok(t.on("253:1", "ext4")?.verdict())
    };
    assert_eq!(build(false)?, Encrypted);
    assert_eq!(build(true)?, Unknown);
    Ok(())
}

#[test]
fn a_partition_whose_parent_is_not_a_disk_is_unknown() -> Res {
    let mut t = Tree::new()?;
    // Parent directory without a `dev` file.
    let dir = t.root.path().join("sys/devices/pci/orphan/orphanp1");
    fs::create_dir_all(&dir)?;
    fs::write(dir.join("dev"), "259:1\n")?;
    fs::write(dir.join("partition"), "1\n")?;
    symlink(&dir, t.root.path().join("sys/dev/block/259:1"))?;
    assert_eq!(t.on("259:1", "ext4")?.verdict(), Unknown);
    Ok(())
}

#[test]
fn loop_and_stacked_disks_are_unknown() -> Res {
    // No `device` link: a loop device.
    let mut t = Tree::new()?;
    t.node("virtual/block/loop0", "7:0")?;
    assert_eq!(t.on("7:0", "ext4")?.verdict(), Unknown);
    // A disk with something under it in `slaves`.
    let mut t = Tree::new()?;
    let d = t.disk("sda", "8:0")?;
    let other = t.disk("sdb", "8:16")?;
    Tree::link_slaves(&d, &[&other])?;
    assert_eq!(t.on("8:0", "ext4")?.verdict(), Unknown);
    Ok(())
}

#[test]
fn state_dir_symlink() -> Res {
    let mut t = Tree::new()?;
    plain(&t)?;
    let link = t.path().join("link");
    symlink(t.state(), &link)?;
    t.on("259:1", "ext4")?;
    assert_eq!(
        classify_with(&t.path(), &link, &|_| Ok(false)),
        NotEncrypted
    );
    // The link is resolved, not matched as written: a table naming only the link's own path finds nothing.
    let mut t2 = Tree::new()?;
    plain(&t2)?;
    let link2 = t2.path().join("link");
    symlink(t2.state(), &link2)?;
    t2.mount(&link2.to_string_lossy(), "259:1", "ext4");
    t2.write()?;
    assert_eq!(classify_with(&t2.path(), &link2, &|_| Ok(false)), Unknown);
    Ok(())
}

#[test]
fn state_dir_private_bind_mount() -> Res {
    // DynamicUser: /var/lib/private/custodio on the backing filesystem, bind-mounted at /var/lib/custodio. The entry
    // has a root that is not "/" and a mount point that differs from where the data is; the device is the backing one.
    let mut t = Tree::new()?;
    plain(&t)?;
    let point = t.state().to_string_lossy().into_owned();
    t.mounts.push(
        "20 1 259:1 /lib/private/custodio ".to_owned()
            + &point
            + " rw,relatime shared:1 - ext4 /dev/nvme0n1p1 rw",
    );
    t.write()?;
    assert_eq!(t.verdict(), NotEncrypted);
    Ok(())
}

#[test]
fn longest_prefix_mount() -> Res {
    let mut t = Tree::new()?;
    plain(&t)?;
    t.disk("sdb", "8:16")?;
    let p = t.state().to_string_lossy().into_owned();
    let parent = t.path().to_string_lossy().into_owned();
    // The deeper mount wins wherever it stands in the table; an unrelated sibling with a longer name does not match.
    t.mount("/", "8:16", "tmpfs");
    t.mount(&p, "259:1", "ext4");
    t.mount(&parent, "8:16", "tmpfs");
    t.mount(&format!("{p}x"), "8:16", "tmpfs");
    t.write()?;
    assert_eq!(t.verdict(), NotEncrypted);
    // Same point twice: the later entry is on top.
    let mut t = Tree::new()?;
    plain(&t)?;
    let p = t.state().to_string_lossy().into_owned();
    t.mount(&p, "259:1", "ext4");
    t.mount(&p, "8:16", "tmpfs");
    t.write()?;
    assert_eq!(t.verdict(), Unknown);
    let mut t = Tree::new()?;
    plain(&t)?;
    let p = t.state().to_string_lossy().into_owned();
    t.mount(&p, "8:16", "tmpfs");
    t.mount(&p, "259:1", "ext4");
    t.write()?;
    assert_eq!(t.verdict(), NotEncrypted);
    Ok(())
}

#[test]
fn a_mount_point_with_escapes_is_matched() -> Res {
    let mut t = Tree::new()?;
    plain(&t)?;
    let space = t.path().join("a b\\c");
    fs::create_dir_all(space.join("state"))?;
    let escaped = space
        .to_string_lossy()
        .replace('\\', "\\134")
        .replace(' ', "\\040");
    t.mount(&escaped, "259:1", "ext4");
    t.write()?;
    assert_eq!(
        classify_with(&t.path(), &space.join("state"), &|_| Ok(false)),
        NotEncrypted
    );
    // An unescaped reading would not match.
    let mut t = Tree::new()?;
    plain(&t)?;
    t.mount("/a\\040b", "259:1", "ext4");
    t.write()?;
    assert_eq!(t.verdict(), Unknown);
    Ok(())
}

#[test]
fn a_line_that_is_not_a_mount_entry_is_skipped() -> Res {
    let mut t = Tree::new()?;
    plain(&t)?;
    t.mounts.push("garbage".to_owned());
    t.mounts.push("1 2 3".to_owned());
    t.on("259:1", "ext4")?;
    assert_eq!(t.verdict(), NotEncrypted);
    Ok(())
}

#[test]
fn the_names_are_the_documented_values() {
    let names: Vec<_> = StateStorage::all().iter().map(|s| s.name()).collect();
    assert_eq!(names, ["encrypted", "not-encrypted", "unknown"]);
}

/// The mount entry covering `path` on the real system: `(fstype, major:minor)`.
fn real_mount(path: &Path) -> Option<(String, String)> {
    let path = fs::canonicalize(path).ok()?;
    let table = fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mut best: Option<(usize, String, String)> = None;
    for line in table.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let dash = f.iter().position(|x| *x == "-")?;
        let point = f.get(4)?.replace("\\040", " ");
        if path.starts_with(&point) {
            let depth = Path::new(&point).components().count();
            if best.as_ref().is_none_or(|(d, _, _)| depth >= *d) {
                best = Some((
                    depth,
                    (*f.get(dash + 1)?).to_owned(),
                    (*f.get(2)?).to_owned(),
                ));
            }
        }
    }
    best.map(|(_, fs, mm)| (fs, mm))
}

#[test]
fn entry_point_real_root() {
    let shm = Path::new("/dev/shm");
    for path in [shm, Path::new(env!("CARGO_MANIFEST_DIR"))] {
        let entry = classify_state_dir(Some(path.as_os_str().to_owned()));
        // The entry point reads the real root and the verdict is that of the path, not of `/`.
        assert_eq!(entry, classify(Path::new("/"), path), "{}", path.display());
    }
    // The checkout's own verdict is not asserted: it is `Unknown` on storage the classifier does not prove (a CI runner's disk).
    let mount = real_mount(shm);
    assert_eq!(
        mount.as_ref().map(|(fs, _)| fs.as_str()),
        Some("tmpfs"),
        "{mount:?}"
    );
    assert_eq!(
        classify_state_dir(Some(shm.as_os_str().to_owned())),
        Unknown
    );
}

#[test]
fn entry_point_unset_state_directory_is_unknown() {
    if Path::new("/var/lib/custodio").exists() {
        eprintln!("note: /var/lib/custodio exists here, skipped");
        return;
    }
    assert_eq!(classify_state_dir(None), Unknown);
    assert_eq!(
        classify_state_dir(Some("/nonexistent/custodio".into())),
        Unknown
    );
}

#[test]
fn the_fscrypt_bit_needs_the_mask_and_the_attribute() {
    let on = StatxAttributes::ENCRYPTED;
    let off = StatxAttributes::empty();
    assert!(fscrypt_flag(on, on));
    assert!(!fscrypt_flag(on, off));
    assert!(!fscrypt_flag(off, on));
    assert!(!fscrypt_flag(off, off));
}

#[test]
fn has_fscrypt_reads_the_real_directory() -> Res {
    let dir = tempfile::tempdir()?;
    assert!(!has_fscrypt(dir.path())?);
    assert!(has_fscrypt(&dir.path().join("missing")).is_err());
    Ok(())
}

#[test]
fn a_partition_of_a_partition_is_unknown() -> Res {
    let mut t = Tree::new()?;
    plain(&t)?;
    t.part("nvme0n1/nvme0n1p1", "nvme0n1p1p1", "259:2")?;
    assert_eq!(t.on("259:2", "ext4")?.verdict(), Unknown);
    Ok(())
}

#[test]
fn octal_looking_digits_without_a_backslash_are_kept() -> Res {
    let mut t = Tree::new()?;
    plain(&t)?;
    let dir = t.path().join("x040");
    fs::create_dir(&dir)?;
    t.mount(&dir.to_string_lossy(), "259:1", "ext4");
    t.write()?;
    assert_eq!(classify_with(&t.path(), &dir, &|_| Ok(false)), NotEncrypted);
    Ok(())
}
