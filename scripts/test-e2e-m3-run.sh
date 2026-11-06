#!/usr/bin/env bash
# F142: a stub-driven run of e2e/upgrade-m3.sh against a simulated service (stubbed su, systemctl, journalctl, id, dpkg-query and install.sh; real fixture packages): good evidence is reported once
# per case, each bad evidence (an old file left, a purged key listed, no or a missing purge entry, a failed import) stops it, a copy that leaves the judgements out accepts the same bad evidence, a
# judgement that crashes stops the run, and a package that is not newer is refused before anything is installed.
# NOT checked here: a real run (`just e2e-cases debian13 'upgrade-m3-*'`).
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_NAME=test-e2e-m3-run
# shellcheck source=scripts/lib/e2e-host-fixtures.sh
. "$ROOT/scripts/lib/e2e-host-fixtures.sh" # tmp, fail, bad, the fixture packages
ids="upgrade-m3-state-purged upgrade-m3-list-empty upgrade-m3-journal-purge upgrade-m3-reimport"
# --- a stub-driven run of e2e/upgrade-m3.sh
S=$tmp/sim
mkdir -p "$S/bin" "$S/state" "$S/e2e"
cp "$ROOT"/e2e/*.sh "$ROOT"/e2e/*.py "$S/e2e/"
cat > "$S/bin/su" <<'STUB'
#!/usr/bin/env bash
# su -l USER -c "WORK=W bash /e2e/upgrade-m3-user.sh MODE [DIR]": plays the user's session against the simulated service
user=$2
cmd=$4
# shellcheck disable=SC2086
set -- ${cmd##*upgrade-m3-user.sh }
mode=$1
dir=${2:-}
uid=1000; [ "$user" != bob ] || uid=4711
case $user in alice) ids='rsa1 ec1' ;; bob) ids='rsa1 bobonly' ;; esac
case $mode in
seed)
    mkdir -p "$SIM_STATE/$uid"
    for i in $ids; do echo "old $user $i" > "$SIM_STATE/$uid/$i"; echo "old cert $user $i" > "$SIM_STATE/$uid/$i-cert"; done
    ;;
import)
    for i in $ids; do echo "new $user $i" > "$SIM_DIR/imported-$user-$i"; echo "${SIM_IMPORT_RC:-0}" > "$WORK/upgrade-m3/reimported/import/$user-$i.rc"; done
    ;;
collect)
    : > "$dir/$user.api"; : > "$dir/$user.cli"; echo 0 > "$dir/$user.api.rc"; echo 0 > "$dir/$user.cli.rc"
    for i in $ids; do
        if [ -e "$SIM_DIR/imported-$user-$i" ] || { [ -n "${SIM_LIST:-}" ] && [ -e "$SIM_DIR/installed" ]; }; then
            printf '%s\trsa2048\ttpm\n' "$i" >> "$dir/$user.api"
            printf 'id: %s\n  type: rsa2048\n' "$i" >> "$dir/$user.cli"
        fi
    done
    ;;
esac
STUB
cat > "$S/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
case "$*" in
*MainPID*) if [ -e "$SIM_DIR/installed" ]; then echo 222; else echo 111; fi ;;
esac
exit 0
STUB
cat > "$S/bin/dpkg-query" <<'STUB'
#!/usr/bin/env bash
if [ -e "$SIM_DIR/installed" ]; then printf '%s' "$SIM_NEW_VERSION"; else printf '%s' "$SIM_OLD_VERSION"; fi
STUB
cat > "$S/bin/journalctl" <<'STUB'
#!/usr/bin/env bash
case "$*" in
*show-cursor*) echo "-- cursor: s=abc" ;;
*after-cursor*) [ -z "${SIM_NOJOURNAL:-}" ] || exit 0; cat "$SIM_DIR/journal" 2> /dev/null || true ;;
esac
exit 0
STUB
cat > "$S/bin/id" <<'STUB'
#!/usr/bin/env bash
case "$*" in
"-u alice") echo 1000 ;;
"-u bob") echo 4711 ;;
"-u custodio") echo 990 ;;
*) exit 0 ;;
esac
STUB
cat > "$S/install.sh" <<'STUB'
#!/usr/bin/env bash
# the new package's start: purges the old files and writes one entry each, unless the simulation says otherwise
touch "$SIM_DIR/installed"
: > "$SIM_DIR/journal"
for f in "$SIM_STATE"/*/*; do
    [ -e "$f" ] || continue
    if [ -n "${SIM_LEAVE_OLD:-}" ] && [ "${f##*/}" = ec1 ]; then continue; fi
    rm -f "$f"
done
for kv in 1000:rsa1 1000:ec1 4711:rsa1 4711:bobonly; do
    [ "$kv" != "${SIM_DROP:-}" ] || continue
    [ -z "${SIM_NOJOURNAL:-}" ] || continue
    echo "{\"CUSTODIO_OPERATION\":\"purge\",\"CUSTODIO_OUTCOME\":\"purged\",\"CUSTODIO_OWNER_UID\":\"${kv%%:*}\",\"CUSTODIO_KEY_ID\":\"${kv##*:}\"}" >> "$SIM_DIR/journal"
done
STUB
chmod +x "$S"/bin/* "$S/install.sh"
export SIM_DIR=$S/simdir SIM_STATE=$S/state
OLD_DEB=$(fx_file m3 deb)
NEW_DEB=$(fx_file cur deb)
sim() { # NAME SCRIPTDIR [VAR=VALUE...]: one run of upgrade-m3.sh against the simulation; output in $tmp/sim.out
    local dir=$2
    shift 2
    rm -rf "${SIM_DIR:?}" "${S:?}/work" "${SIM_STATE:?}"
    mkdir -p "$SIM_DIR" "$S/work" "$SIM_STATE"
    env "$@" PATH="$S/bin:$PATH" WORK="$S/work" STATE_LINK="$SIM_STATE" E2E_INSTALL="$S/install.sh" E2E_SELECT_FILE="$tmp/nosel" \
        SIM_OLD_VERSION="$(dpkg-deb -f "$OLD_DEB" Version)" SIM_NEW_VERSION="$(dpkg-deb -f "$NEW_DEB" Version)" \
        bash "$dir/upgrade-m3.sh" "$OLD_DEB" "$NEW_DEB" > "$tmp/sim.out" 2>&1
}
if sim good "$S/e2e" X=1; then
    for id in $ids; do [ "$(grep -c "^E2E-CASE run $id\$" "$tmp/sim.out")" = 1 ] || bad "good evidence: $id not reported exactly once: $(tail -n 5 "$tmp/sim.out")"; done
else
    bad "good evidence refused: $(tail -n 8 "$tmp/sim.out")"
fi
simbad() { # WHAT PATTERN VAR=VALUE...: the run stops, naming the problem
    local what=$1 pat=$2
    shift 2
    if sim "$what" "$S/e2e" "$@"; then bad "$what: bad evidence accepted"; return; fi
    grep -q -- "$pat" "$tmp/sim.out" || bad "$what: not refused with '$pat': $(tail -n 4 "$tmp/sim.out")"
}
simbad "old file left" 'old file .* is still there' SIM_LEAVE_OLD=1
simbad "purged key listed" 'is shown' SIM_LIST=1
simbad "no journal entries" 'purge entries' SIM_NOJOURNAL=1
simbad "one entry missing" 'owner 4711 key bobonly: 0 purge entries' SIM_DROP=4711:bobonly
simbad "import fails" 'did not succeed' SIM_IMPORT_RC=1
# a copy that leaves the judgements out accepts the same bad evidence: the verdict comes from them
mkdir -p "$S/mutant"
cp "$S"/e2e/* "$S/mutant/"
sed -i 's#^    p=$(um3 "$@") || fail "$c: the judgement did not run"#    p=#' "$S/mutant/upgrade-m3.sh"
grep -q '^    p=$' "$S/mutant/upgrade-m3.sh" || bad "the mutant was not made"
for v in SIM_LEAVE_OLD SIM_LIST SIM_NOJOURNAL; do
    sim mutant "$S/mutant" "$v=1" || bad "$v: the copy without judgements failed as well, so the failure is not the judgement's: $(tail -n 3 "$tmp/sim.out")"
done
# a judgement that crashes stops the run
mkdir -p "$S/crash"
cp "$S"/e2e/* "$S/crash/"
printf '#!/usr/bin/python3 -I\nimport sys\nsys.exit(3)\n' > "$S/crash/upgradem3.py"
if sim crash "$S/crash" X=1; then bad "a crashing judgement was accepted"; fi
grep -q 'judgement did not run' "$tmp/sim.out" || bad "a crashing judgement was not named: $(tail -n 3 "$tmp/sim.out")"
# the gate: an older new package is refused before anything is installed
OLD_SAVE=$OLD_DEB
OLD_DEB=$NEW_DEB
NEW_DEB=$OLD_SAVE
if sim gate "$S/e2e" X=1; then bad "a downgrade was accepted"; fi
[ ! -e "$SIM_DIR/installed" ] || bad "the downgrade was installed"
grep -q 'gate' "$tmp/sim.out" || bad "the gate did not speak: $(tail -n 3 "$tmp/sim.out")"

exit "$fail"
