#!/usr/bin/env bash
# F49: the removal, purge and reinstall cases of the e2e suite. Checked here: the self-test of the checks (e2e/lifecycle-selftest.sh), the case
# ids (removal and reinstall ids on every target, purge ids on the two deb targets and nowhere else), remove.sh on every target and purge.sh on
# the deb targets only, purge.sh a different command from remove.sh, the case accounting for an omitted or a misplaced id, the order in the guest,
# and the package lists read from real fixture packages. NOT checked here: that the services stop and the keys survive; that is `just e2e`.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"
tmp=$(mktemp -d)
fx_init
trap 'fx_cleanup; rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-lifecycle: $*" >&2; fail=1; }

bash "$ROOT/e2e/lifecycle-selftest.sh" > /dev/null || bad "the lifecycle self-test failed"

removal_ids="removal-service-stopped removal-no-packaged-files removal-not-activatable removal-state-unchanged removal-account-kept removal-notice-keys reinstall-keys-listed reinstall-signs-with-polkit reinstall-no-import"
purge_ids="purge-service-stopped purge-no-packaged-files purge-not-activatable purge-state-unchanged purge-account-kept purge-notice-keys reinstall-after-purge-keys-listed reinstall-after-purge-signs-with-polkit reinstall-after-purge-no-import"
ids_of() { grep -v '^[[:space:]]*\(#\|$\)' "$1" 2> /dev/null || true; }

for id in $removal_ids; do grep -qx "$id" "$ROOT/e2e/cases.list" || bad "e2e/cases.list lacks $id"; done
for id in $purge_ids; do grep -qx "$id" "$ROOT/e2e/cases.list" && bad "$id is in the common cases.list, so every target would owe it"; done

for T in $(cd "$ROOT/e2e/targets" && echo *); do
    d=$ROOT/e2e/targets/$T
    [ ! -f "$d/refusal-only" ] || continue # F50: a refusal-only target installs nothing, so it has no lifecycle
    [ -f "$d/remove.sh" ] || bad "$T has no remove.sh"
    case $T in
    debian13 | ubuntu2604)
        # exactly the purge ids, once each
        got=$(ids_of "$d/cases.list" | grep -E '^(purge|reinstall-after-purge)-' | sort | tr '\n' ' ')
        # shellcheck disable=SC2086 # the id lists are words on purpose
        want=$(printf '%s\n' $purge_ids | sort | tr '\n' ' ')
        [ "$got" = "$want" ] || bad "$T: the purge ids in cases.list are '$got', not '$want'"
        [ -f "$d/purge.sh" ] || { bad "$T has no purge.sh"; continue; }
        grep -Eq 'apt-get[[:space:]]+purge[[:space:]]' "$d/purge.sh" || bad "$T: purge.sh does not run apt-get purge"
        grep -Eq 'apt-get[[:space:]]+remove[[:space:]]' "$d/remove.sh" || bad "$T: remove.sh does not run apt-get remove"
        grep -Eq 'apt-get[[:space:]]+remove' "$d/purge.sh" && bad "$T: purge.sh removes only"
        grep -Eq 'purge' "$d/remove.sh" && bad "$T: remove.sh purges"
        cmp -s "$d/purge.sh" "$d/remove.sh" && bad "$T: purge.sh is remove.sh"
        ;;
    fedora44 | alma10)
        grep -Eq '^dnf remove -y custodio$' "$d/remove.sh" || bad "$T: remove.sh does not run dnf remove"
        [ ! -e "$d/purge.sh" ] || bad "$T has a purge.sh"
        ids_of "$d/cases.list" | grep -Eq '^(purge|reinstall-after-purge)-' && bad "$T has purge ids"
        ;;
    arch)
        grep -Eq '^pacman -R --noconfirm custodio$' "$d/remove.sh" || bad "$T: remove.sh does not run pacman -R"
        [ ! -e "$d/purge.sh" ] || bad "$T has a purge.sh"
        ids_of "$d/cases.list" | grep -Eq '^(purge|reinstall-after-purge)-' && bad "$T has purge ids"
        ;;
    *) bad "$T is a target this test does not know" ;;
    esac
    grep -q 'dev/null' "$d/remove.sh" && bad "$T: remove.sh discards output"
done

# --- the accounting, with the real lists: an omitted id fails, a purge id on a target without purge is unknown
for T in $(cd "$ROOT/e2e/targets" && echo *); do
    d=$ROOT/e2e/targets/$T
    [ ! -f "$d/refusal-only" ] || continue # F50: a refusal-only target installs nothing, so it has no lifecycle
    { ids_of "$ROOT/e2e/cases.list"; ids_of "$d/cases.list" | grep -v '^upgrade-cargo-deb-' || true; } > "$tmp/ids"
    cat "$ROOT/e2e/cases.list" > "$tmp/cases"
    [ ! -f "$d/cases.list" ] || cat "$d/cases.list" >> "$tmp/cases"
    sed 's/^/E2E-CASE run /' "$tmp/ids" > "$tmp/out.all"
    # the cargo-deb ids belong to the second run of debian13
    { ids_of "$d/cases.list" | grep '^upgrade-cargo-deb-' | sed 's/^/E2E-CASE run /' || true; } >> "$tmp/out.all"
    bash "$ROOT/e2e/check-cases.sh" check "$tmp/cases" "$d/skip.list" "$tmp/out.all" > /dev/null 2>&1 || bad "$T: the complete report was not accepted"
    for id in $removal_ids; do
        grep -vx "E2E-CASE run $id" "$tmp/out.all" > "$tmp/out.omit"
        if bash "$ROOT/e2e/check-cases.sh" check "$tmp/cases" "$d/skip.list" "$tmp/out.omit" > "$tmp/res" 2>&1; then bad "$T: a run that omits $id was accepted"
        else grep -q "'$id' was not reported" "$tmp/res" || bad "$T: the omitted $id was not named"; fi
    done
    if [ -f "$d/purge.sh" ]; then
        for id in $purge_ids; do
            grep -vx "E2E-CASE run $id" "$tmp/out.all" > "$tmp/out.omit"
            if bash "$ROOT/e2e/check-cases.sh" check "$tmp/cases" "$d/skip.list" "$tmp/out.omit" > "$tmp/res" 2>&1; then bad "$T: a run that omits $id was accepted"
            else grep -q "'$id' was not reported" "$tmp/res" || bad "$T: the omitted $id was not named"; fi
        done
    else
        { cat "$tmp/out.all"; echo "E2E-CASE run purge-service-stopped"; } > "$tmp/out.extra"
        if bash "$ROOT/e2e/check-cases.sh" check "$tmp/cases" "$d/skip.list" "$tmp/out.extra" > "$tmp/res" 2>&1; then bad "$T: a purge id was accepted on a target without purge"
        else grep -q "unknown case 'purge-service-stopped'" "$tmp/res" || bad "$T: the misplaced purge id was not named"; fi
    fi
    grep -v '^[[:space:]]*\(#\|$\)' "$d/skip.list" | grep -E '^(removal|purge|reinstall)' && bad "$T skips a lifecycle case"
done

# --- the guest runs the case after the upgrade, with the library and the script
# shellcheck disable=SC2016 # the text searched for holds literal dollar signs
up=$(grep -n 'e2e/upgrade.sh "\$pkg" "\$pkg_next"' "$ROOT/e2e/guest.sh" | head -n 1 | cut -d: -f1)
lc=$(grep -n 'e2e/lifecycle.sh' "$ROOT/e2e/guest.sh" | head -n 1 | cut -d: -f1)
{ [ -n "$up" ] && [ -n "$lc" ] && [ "$up" -lt "$lc" ]; } || bad "the guest does not run lifecycle.sh after the upgrade case"
if grep -n 'lifecycle.sh' "$ROOT/e2e/guest.sh" | grep -q 'old'; then bad "the old-package run runs the lifecycle case"; fi
grep -q 'lifecycle-selftest.sh' "$ROOT/e2e/lifecycle.sh" || bad "the lifecycle case does not run its self-test"
grep -q 'lifecycle_static_problems' "$ROOT/e2e/lifecycle.sh" || bad "the lifecycle case does not run the static check"
grep -q 'remove.sh' "$ROOT/e2e/lifecycle.sh" || bad "the lifecycle case does not name remove.sh"
grep -q 'purge.sh' "$ROOT/e2e/lifecycle.sh" || bad "the lifecycle case does not name purge.sh"
grep -q 'install.sh' "$ROOT/e2e/lifecycle.sh" || bad "the lifecycle case does not reinstall with install.sh"

# --- the package lists read from real packages
# shellcheck source=e2e/lifecycle-lib.sh
. "$ROOT/e2e/lifecycle-lib.sh"
fx_build cur 0.1.0 '' none
for fmt in deb rpm; do
    f=$(fx_file cur "$fmt")
    packaged_entries "$fmt" "$f" > "$tmp/list.$fmt" || bad "$fmt: the list cannot be read"
    out=$(entries_problems "$tmp/list.$fmt" "$fmt" 2>&1) || bad "$fmt: the list of the real package is rejected: $out"
    grep -qx 'd /usr/lib/custodio' "$tmp/list.$fmt" || bad "$fmt: /usr/lib/custodio is not a directory of the package"
    grep -qx 'd /usr/share/doc/custodio' "$tmp/list.$fmt" || bad "$fmt: /usr/share/doc/custodio is not a directory of the package"
    grep -qx 'd /usr/libexec/custodio' "$tmp/list.$fmt" || bad "$fmt: /usr/libexec/custodio is not a directory of the package"
    grep -qx 'f /usr/libexec/custodio/custodiod' "$tmp/list.$fmt" || bad "$fmt: the daemon is not in the list"
    ! grep -qx 'f /usr/lib/custodio/custodiod' "$tmp/list.$fmt" || bad "$fmt: the daemon is also at the Arch path"
done
# the Arch package is read by bsdtar here (pacman -Qlp prints the same names with the package name before them)
bsdtar -tf "$(fx_file cur archlinux)" | grep -v '^\.' | sed 's/^/custodio \//' | entries_from_arch | with_ancestors > "$tmp/list.arch"
entries_problems "$tmp/list.arch" arch > /dev/null 2>&1 || bad "arch: the list of the real package is rejected: $(entries_problems "$tmp/list.arch" arch 2>&1)"
# a leftover directory of the real list is seen: the doc directory of the package, left behind in a fixture root
mkdir -p "$tmp/root/usr/share/doc/custodio"
out=$(leftover_problems "$tmp/list.deb" false "$tmp/root" 2>&1) && bad "a left-over doc directory of the real list was accepted"
grep -q 'directory /usr/share/doc/custodio' <<< "$out" || bad "the left-over doc directory was not named: $out"

exit "$fail"
