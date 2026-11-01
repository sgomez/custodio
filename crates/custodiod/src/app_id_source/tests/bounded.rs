use super::super::bounded::{ReadError, open_regular, read_bounded};
use super::TestResult;
use rustix::fs::{CWD, FileType, Mode, mknodat};
use std::fs;
use std::io::Write;

fn t<T>(r: Result<T, ReadError>) -> Result<T, String> {
    r.map_err(|e| format!("{e:?}"))
}

fn dir_of(path: &std::path::Path) -> std::io::Result<fs::File> {
    fs::File::open(path)
}

#[test]
fn regular_file_is_read() -> TestResult {
    let tmp = tempfile::tempdir()?;
    fs::write(tmp.path().join("f"), "abc")?;
    let fd = t(open_regular(dir_of(tmp.path())?, "f"))?;
    assert_eq!(t(read_bounded(fd, 10))?, b"abc");
    Ok(())
}

#[test]
fn missing_file_is_missing() -> TestResult {
    let tmp = tempfile::tempdir()?;
    assert_eq!(
        open_regular(dir_of(tmp.path())?, "nope").err(),
        Some(ReadError::Missing)
    );
    Ok(())
}

#[test]
fn symlink_is_refused() -> TestResult {
    let tmp = tempfile::tempdir()?;
    fs::write(tmp.path().join("real"), "abc")?;
    std::os::unix::fs::symlink("real", tmp.path().join("link"))?;
    assert_eq!(
        open_regular(dir_of(tmp.path())?, "link").err(),
        Some(ReadError::Refused)
    );
    Ok(())
}

#[test]
fn fifo_is_refused_without_blocking() -> TestResult {
    let tmp = tempfile::tempdir()?;
    mknodat(
        CWD,
        tmp.path().join("fifo"),
        FileType::Fifo,
        Mode::from_bits_truncate(0o644),
        0,
    )?;
    let started = std::time::Instant::now();
    assert_eq!(
        open_regular(dir_of(tmp.path())?, "fifo").err(),
        Some(ReadError::Refused)
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    Ok(())
}

#[test]
fn device_is_refused_as_not_regular() -> TestResult {
    assert_eq!(
        open_regular(dir_of(std::path::Path::new("/dev"))?, "zero").err(),
        Some(ReadError::Refused)
    );
    Ok(())
}

#[test]
fn directory_is_refused() -> TestResult {
    let tmp = tempfile::tempdir()?;
    fs::create_dir(tmp.path().join("d"))?;
    assert_eq!(
        open_regular(dir_of(tmp.path())?, "d").err(),
        Some(ReadError::Refused)
    );
    Ok(())
}

#[test]
fn size_bound_is_exact() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let mut f = fs::File::create(tmp.path().join("f"))?;
    f.write_all(&vec![b'a'; 20_000])?;
    let dir = dir_of(tmp.path())?;
    let at = t(open_regular(&dir, "f"))?;
    assert_eq!(t(read_bounded(at, 20_000))?.len(), 20_000);
    let over = t(open_regular(&dir, "f"))?;
    assert_eq!(read_bounded(over, 19_999).err(), Some(ReadError::Refused));
    fs::File::create(tmp.path().join("e"))?;
    assert_eq!(t(read_bounded(t(open_regular(&dir, "e"))?, 0))?, b"");
    Ok(())
}
