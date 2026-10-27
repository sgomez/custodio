use super::*;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn state_dir_resolves_the_dynamic_user_symlink() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let real = tmp.path().join("private").join("custodio");
    fs::create_dir_all(real.parent().ok_or("no parent")?)?;
    KeyStore::open(&real)?;
    let link = tmp.path().join("custodio");
    std::os::unix::fs::symlink(&real, &link)?;
    let dir = state_dir(Some(link.into()));
    assert_eq!(dir, fs::canonicalize(&real)?);
    KeyStore::open(dir)?;
    Ok(())
}

#[test]
fn state_dir_defaults_and_keeps_a_missing_path() {
    assert_eq!(state_dir(None), PathBuf::from("/var/lib/custodio"));
    let missing = PathBuf::from("/nonexistent/custodio");
    assert_eq!(state_dir(Some(missing.clone().into())), missing);
}
