#!/usr/bin/env bash
# F142: container-free checks of the upgrade-m3-* cases: the placement and accounting (e2e/cases.list, group other-mode, never skipped, the host's guest run and mounts) and the build script
# scripts/package-m3.sh with stubbed tools (stamp reuse, a partly deleted output rebuilt, a missing tag, the other package directories untouched). The judgements of e2e/upgradem3.py are
# tested by scripts/test-e2e-m3-judge.sh, and a stub-driven run of e2e/upgrade-m3.sh by scripts/test-e2e-m3-run.sh.
# NOT checked here: a real run (`just e2e-cases debian13 'upgrade-m3-*'` and fedora44).
# shellcheck disable=SC2086 # the ids are words
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_NAME=test-e2e-m3
# shellcheck source=scripts/lib/e2e-host-fixtures.sh
. "$ROOT/scripts/lib/e2e-host-fixtures.sh" # tmp, fail, bad, the stub podman, expect_ok, expect_fail, and the fixture packages
ids="upgrade-m3-state-purged upgrade-m3-list-empty upgrade-m3-journal-purge upgrade-m3-reimport"
um3() { python3 -I "$ROOT/e2e/upgradem3.py" "$@"; }

# --- placement and accounting
[ "$(um3 cases | sort)" = "$(printf '%s\n' $ids | sort)" ] || bad "upgradem3.py cases differ from the four cases"
# shellcheck source=e2e/select.sh
source "$ROOT/e2e/select.sh"
for id in $ids; do
    grep -qx "$id" "$ROOT/e2e/cases.list" || bad "$id is not in e2e/cases.list"
    ! grep -qx "$id" "$ROOT"/e2e/targets/*/cases.list || bad "$id is in a per-target cases.list"
    ! grep -q "^$id" "$ROOT"/e2e/targets/*/skip.list || bad "$id is on a skip list: the cases run in every target and mode"
    [ "$(case_group "$id")" = other-mode ] || bad "case_group $id is '$(case_group "$id")', expected other-mode"
    STUB_OMIT=$id expect_fail "omitted $id" fedora44 || true
    grep -q "'$id' was not reported" "$tmp/out" || bad "an omitted $id was not named: $(tail -n 3 "$tmp/out")"
    STUB_SKIP=$id expect_fail "skipped $id" fedora44 || true
    grep -q "'$id' was skipped and is not on the skip list" "$tmp/out" || bad "a skipped $id was not named: $(tail -n 3 "$tmp/out")"
    for m in swtpm none lacking; do
        STUB_SKIP=$id E2E_TPM=$m expect_fail "skipped $id in $m" fedora44 || true
    done
done
[ "$(case_group upgrade-oldpath-keys-listed)" = other-mode ] || bad "the old-path cases changed group"
[ "$(case_group upgrade-keys-listed)" = upgrade ] || bad "the main upgrade cases changed group"
# the m3 run is made, with the M3 package mounted, on every target that installs a package (debian13 by a selection: the stub reports its none-mode skips as run, as in test-e2e-host-oldpath.sh)
for T in fedora44 alma10 arch ubuntu2604; do
    expect_ok "m3 cases on $T" $T || continue
    grep -q 'cases accounted for' "$tmp/out" || bad "$T did not account for the cases"
    [ "$(grep -c "guest.sh $T m3" "$tmp/log")" = 1 ] || bad "$T: the m3 guest run was not made exactly once"
    grep -q ':/pkg-m3/' "$tmp/log" || bad "$T: the M3 package is not mounted"
done
expect_ok "refusal-only" ubuntu2404 || true
! grep -q 'guest.sh ubuntu2404 m3' "$tmp/log" || bad "a refusal-only target made the m3 run"
STUB_FAIL_M3=fedora44 expect_fail "the m3 run fails" fedora44 || true
grep -q 'upgrade from the M3 build' "$tmp/out" || bad "a failed m3 run was not named: $(tail -n 3 "$tmp/out")"
# a selection: the m3 run is made when an upgrade-m3 case is selected, and only then
expect_ok "select m3" debian13 --cases 'upgrade-m3-*' || true
grep -q "guest.sh debian13 m3" "$tmp/log" || bad "the m3 run was not made for upgrade-m3-*"
grep -q '4 cases accounted for' "$tmp/out" || bad "a selection of the four cases did not account for four: $(grep accounted "$tmp/out")"
expect_ok "select other" debian13 --cases 'upgrade-oldpath-*' || true
! grep -q "guest.sh debian13 m3" "$tmp/log" || bad "the m3 run was made for a selection without upgrade-m3 cases"
# the host refuses a missing M3 package, N or its copy before the engine is called
mkdir -p "$tmp/nom3"
: > "$tmp/log"
if STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/pkgs" E2E_PACKAGES_M3="$tmp/nom3" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" fedora44 > "$tmp/out" 2>&1; then bad "a run without the M3 package passed"; fi
grep -q 'no M3 package' "$tmp/out" || bad "a missing M3 package was not named: $(tail -n 3 "$tmp/out")"
! grep -Eq '^(build|run|exec) ' "$tmp/log" || bad "the engine ran without the M3 package"
if STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/pkgs" E2E_PACKAGES_M3="$tmp/pkgs" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" fedora44 > "$tmp/out" 2>&1; then bad "a run with N as the M3 package passed"; fi
grep -q 'M3 package is the same file' "$tmp/out" || bad "N as the M3 package was not named: $(tail -n 3 "$tmp/out")"
mkdir -p "$tmp/copyofn"
cp "$(fx_file cur rpm)" "$tmp/copyofn/"
if STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/pkgs" E2E_PACKAGES_M3="$tmp/copyofn" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" fedora44 > "$tmp/out" 2>&1; then bad "a run with a copy of N as the M3 package passed"; fi
grep -q 'M3 package has the same content as N' "$tmp/out" || bad "a copy of N as the M3 package was not named: $(tail -n 3 "$tmp/out")"
# the recipe builds it, and this test is in the list
grep -q 'scripts/package-m3.sh' <(sed -n '/^e2e-packages:/,/^$/p' "$ROOT/justfile") || bad "the e2e-packages recipe does not run scripts/package-m3.sh"
for t in test-e2e-m3 test-e2e-m3-judge test-e2e-m3-run; do grep -q "scripts/$t.sh" "$ROOT/justfile" || bad "scripts/$t.sh is not in the justfile"; done

# --- scripts/package-m3.sh with a stubbed git history, just and cargo
R=$tmp/repo
mkdir -p "$R/scripts" "$R/bin" "$R/target/packages" "$R/target/packages-next" "$R/target/packages-oldpath"
cp "$ROOT/scripts/package-m3.sh" "$R/scripts/"
echo n > "$R/target/packages/n.deb"; echo x > "$R/target/packages-next/x.deb"; echo o > "$R/target/packages-oldpath/o.deb"
git -C "$R" init -q
git -C "$R" -c user.name=t -c user.email=t@t commit -q --allow-empty -m one
echo tree > "$R/treefile"
git -C "$R" add treefile
git -C "$R" -c user.name=t -c user.email=t@t commit -q -m two
git -C "$R" tag v0.5.0 HEAD
echo later > "$R/treefile" # the working tree differs from the tag: the build must read the tag
cat > "$R/bin/just" <<'STUB'
#!/usr/bin/env bash
# the stub of the tag's `just package version=V`: records the arguments and the content of the tree it was given, writes the three packages
echo "$*" >> "$STUB_BUILDS"
cat treefile >> "$STUB_BUILDS"
mkdir -p target/packages
for n in custodio_0.0.9-1_amd64.deb custodio-0.0.9-1.x86_64.rpm custodio-0.0.9-1-x86_64.pkg.tar.zst; do echo "$n" > "target/packages/$n"; done
[ -z "${STUB_BUILD_FAIL:-}" ] || { echo "stub build failed"; exit 1; }
STUB
printf '#!/usr/bin/env bash\nexit 0\n' > "$R/bin/cargo"
chmod +x "$R/bin/just" "$R/bin/cargo"
export STUB_BUILDS=$tmp/builds
m3() { (cd "$R" && env "$@" PATH="$R/bin:$PATH" M3_ROOT="$R" bash "$R/scripts/package-m3.sh"); }
: > "$STUB_BUILDS"
m3 X=1 > "$tmp/m3.out" 2>&1 || bad "the build failed: $(tail -n 3 "$tmp/m3.out")"
for f in '*.deb' '*.rpm' '*.pkg.tar.zst'; do [ -n "$(find "$R/target/packages-m3" -name "$f")" ] || bad "no $f in target/packages-m3"; done
[ "$(grep -c '^package version=0.0.9$' "$STUB_BUILDS")" = 1 ] || bad "the tag's recipe was not called once with the lower version: $(cat "$STUB_BUILDS")"
grep -qx tree "$STUB_BUILDS" || bad "the build did not read the tree of the tag: $(cat "$STUB_BUILDS")"
! grep -qx later "$STUB_BUILDS" || bad "the build read the working tree"
m3 X=1 > "$tmp/m3.out" 2>&1 || bad "the second run failed"
grep -q 'not rebuilt' "$tmp/m3.out" || bad "the second run did not reuse the build: $(cat "$tmp/m3.out")"
[ "$(grep -c '^package' "$STUB_BUILDS")" = 1 ] || bad "the second run built again"
rm -f "$R"/target/packages-m3/*.rpm # a partly deleted output is rebuilt, not reused
m3 X=1 > "$tmp/m3.out" 2>&1 || bad "the run after a deleted file failed"
[ "$(grep -c '^package' "$STUB_BUILDS")" = 2 ] || bad "a partly deleted output was not rebuilt"
[ -n "$(find "$R/target/packages-m3" -name '*.rpm')" ] || bad "the rpm is not back"
m3 M3_VERSION=0.0.8 > "$tmp/m3.out" 2>&1 || bad "a new version failed"
[ "$(grep -c '^package' "$STUB_BUILDS")" = 3 ] || bad "a changed version was not rebuilt"
git -C "$R" tag -d v0.5.0 > /dev/null
if m3 X=1 > "$tmp/m3.out" 2>&1; then bad "a missing tag passed"; fi
grep -q 'tag v0.5.0 is missing' "$tmp/m3.out" || bad "a missing tag was not named: $(cat "$tmp/m3.out")"
git -C "$R" tag v0.5.0 HEAD
rm -rf "${R:?}/target/packages-m3" "${R:?}/target/m3-build"
if m3 STUB_BUILD_FAIL=1 > "$tmp/m3.out" 2>&1; then bad "a failed build passed"; fi
grep -q 'the build of v0.5.0 failed' "$tmp/m3.out" || bad "a failed build was not named: $(cat "$tmp/m3.out")"
[ ! -f "$R/target/m3-build/stamp" ] || bad "a failed build left a stamp"
if m3 M3_VERSION=1.2 > "$tmp/m3.out" 2>&1; then bad "a bad version passed"; fi
[ "$(cat "$R/target/packages/n.deb" "$R/target/packages-next/x.deb" "$R/target/packages-oldpath/o.deb" | tr -d '\n')" = nxo ] || bad "the packages of N, N+1 or the old path were touched"
[ "$(find "$R/target/packages" "$R/target/packages-next" "$R/target/packages-oldpath" -type f | wc -l)" = 3 ] || bad "files were added to the other package directories"

exit "$fail"
