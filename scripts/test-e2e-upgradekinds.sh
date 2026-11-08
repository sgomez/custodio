#!/usr/bin/env bash
# F141: container-free checks of the upgrade-kinds-* cases: the placement (debian13 list and skip list, not e2e/cases.list, no other target), the accounting (a skip of the three
# run cases refused in any mode, a run of upgrade-kinds-tpmbound refused), the judgements of e2e/upgradekinds.py on good and bad evidence per mode (a kind other than the mode's before
# the install, a kind changed by the upgrade for every pair, an id or an owner missing, added or swapped, a CLI row whose kind or type differs, a journal entry of another kind, missing,
# double, from before the cursor or of another operation, and a run in which every key has the same wrong kind), and a stub-driven run of e2e/upgrade-kinds.sh (good evidence is reported,
# bad evidence stops it, and a copy of the script that leaves the judgements out is caught). NOT checked here: a real run (`just e2e-cases debian13 'upgrade-*'` in swtpm, none, lacking).
# shellcheck disable=SC2086 # the ids are words
# shellcheck disable=SC2016 # the patterns handed to before are text for grep: single quotes keep the dollar signs literal
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-upgradekinds: $*" >&2; fail=1; }
D=$ROOT/e2e/targets/debian13
ids="upgrade-kinds-before upgrade-kinds-kept upgrade-kinds-signs upgrade-kinds-tpmbound"
uk() { python3 -I "$ROOT/e2e/upgradekinds.py" "$@"; }

# --- placement
for id in $ids; do
    grep -qx "$id" "$D/cases.list" || bad "$id is not in $D/cases.list"
    ! grep -qx "$id" "$ROOT/e2e/cases.list" || bad "$id is in e2e/cases.list (every target)"
    for t in "$ROOT"/e2e/targets/*/; do
        [ "$t" = "$D/" ] || ! grep -qx "$id" "$t/cases.list" 2> /dev/null || bad "$id is listed by $t"
    done
done
grep -q '^upgrade-kinds-tpmbound:.*F134' "$D/skip.list" || bad "upgrade-kinds-tpmbound is not on the skip list of debian13 with the deviation named"
for id in upgrade-kinds-before upgrade-kinds-kept upgrade-kinds-signs; do ! grep -q "^$id:" "$D/skip.list" || bad "$id is on the skip list"; done
[ "$(grep -c '^upgrade-kinds-' "$D/cases.list")" = 4 ] || bad "debian13 cases.list lists other upgrade-kinds cases than the four"
[ "$(uk cases | sort)" = "$(printf '%s\n' $ids | sort)" ] || bad "upgradekinds.py cases differ from the listed cases"
# shellcheck source=e2e/select.sh
source "$ROOT/e2e/select.sh"
for id in $ids; do [ "$(case_group "$id")" = upgrade ] || bad "case_group $id is '$(case_group "$id")', expected upgrade"; done
[ "$(case_group upgrade-oldpath-keys-listed)" = other-mode ] || bad "the old-path cases changed group"
# the case is reported only where the target lists it, for the N to N+1 run, and when one is selected
mkdir -p "$tmp/t-no" "$tmp/t-yes"
printf 'upgrade-version-greater\n' > "$tmp/t-no/cases.list"
cp "$D/cases.list" "$tmp/t-yes/cases.list"
enabled() { E2E_TARGET_DIR=$1 WORK=$tmp bash "$ROOT/e2e/upgrade-kinds.sh" enabled "$2"; }
enabled "$tmp/t-yes" upgrade || bad "not enabled on a target that lists the cases"
! enabled "$tmp/t-no" upgrade || bad "enabled on a target that does not list the cases"
! enabled "$tmp/t-yes" upgrade-oldpath || bad "enabled in the old-path run"
! enabled "$tmp/nowhere" upgrade || bad "enabled with no cases.list"
printf 'upgrade-version-greater\n' > "$tmp/sel"
! E2E_SELECT_FILE=$tmp/sel enabled "$tmp/t-yes" upgrade || bad "enabled when no kinds case is selected"
printf 'upgrade-kinds-kept\n' > "$tmp/sel"
E2E_SELECT_FILE=$tmp/sel enabled "$tmp/t-yes" upgrade || bad "not enabled when a kinds case is selected"

# --- accounting
printf '%s\n' $ids > "$tmp/cases"
for id in $ids; do echo "E2E-CASE run $id"; done > "$tmp/out-run"
sed 's/^E2E-CASE run upgrade-kinds-tpmbound$/E2E-CASE skipped upgrade-kinds-tpmbound/' "$tmp/out-run" > "$tmp/out-ok"
check() { CHECK_TPM_MODE=$1 bash "$ROOT/e2e/check-cases.sh" check "$tmp/cases" "$D/skip.list" "$2" > /dev/null 2>&1; }
for m in swtpm none lacking; do
    check $m "$tmp/out-ok" || bad "mode $m: three run and one skipped is refused"
    ! check $m "$tmp/out-run" || bad "mode $m: upgrade-kinds-tpmbound reported run is accepted"
    for id in upgrade-kinds-before upgrade-kinds-kept upgrade-kinds-signs; do
        sed "s/^E2E-CASE run $id\$/E2E-CASE skipped $id/" "$tmp/out-ok" > "$tmp/out-skip"
        ! check $m "$tmp/out-skip" || bad "mode $m: $id skipped is accepted"
    done
done

# --- the judgements. Evidence of a good run: the kind of the mode for every key of both users, in the API list and in the CLI list.
# shellcheck disable=SC2034 # read through eval in mklist
KEYS_alice="ec1:ecdsa-p256 rsa1:rsa2048"
# shellcheck disable=SC2034 # read through eval in mklist
KEYS_bob="bobonly:rsa2048 rsa1:rsa2048"
mklist() { # DIR KIND: the four files with the kind KIND everywhere
    local d=$1 k=$2 u spec specs
    mkdir -p "$d"
    for u in alice bob; do
        : > "$d/$u.api"
        : > "$d/$u.cli"
        eval "specs=\$KEYS_$u"
        for spec in $specs; do
            printf '%s\t%s\t%s\n' "${spec%%:*}" "${spec##*:}" "$k" >> "$d/$u.api"
            printf 'id: %s\n  type: %s\n  kind: %s\n  created: x\n' "${spec%%:*}" "${spec##*:}" "$k" >> "$d/$u.cli"
        done
    done
}
want_of() { case $1 in none) echo encrypted-host ;; *) echo tpm ;; esac; }
accepts() { local what=$1 out; shift; out=$(uk "$@") || { bad "$what: the judgement failed to run"; return; }; [ -z "$out" ] || bad "$what: rejected: $out"; }
rejects() { local what=$1 out; shift; out=$(uk "$@") || { bad "$what: the judgement failed to run"; return; }; [ -n "$out" ] || bad "$what: accepted"; }
# variant MODE FROM TO: TO is a copy of FROM that the caller then changes
variant() { rm -rf "${tmp:?}/$1/$3"; cp -r "$tmp/$1/$2" "$tmp/$1/$3"; }
for m in swtpm none lacking; do
    k=$(want_of $m)
    [ "$(uk kind $m)" = "$k" ] || bad "mode $m: kind is not $k"
    mklist "$tmp/$m/b" "$k"
    mklist "$tmp/$m/a" "$k"
    accepts "mode $m: good listing" listing $m "$tmp/$m/b"
    accepts "mode $m: good kept" kept $m "$tmp/$m/b" "$tmp/$m/a"
    # every kind the mode does not have: everywhere, and for one row of one user in the API list or in the CLI list
    for other in tpm encrypted-tpm encrypted-host; do
        [ "$other" != "$k" ] || continue
        mklist "$tmp/$m/wrong" "$other"
        rejects "mode $m: every key $other (listing)" listing $m "$tmp/$m/wrong"
        rejects "mode $m: every key $other before and after (kept)" kept $m "$tmp/$m/wrong" "$tmp/$m/wrong"
        rejects "mode $m: kinds $k -> $other (kept)" kept $m "$tmp/$m/b" "$tmp/$m/wrong"
        rejects "mode $m: kinds $other -> $k (kept)" kept $m "$tmp/$m/wrong" "$tmp/$m/b"
        for u in alice bob; do
            for ext in api cli; do
                variant $m b one
                if [ $ext = api ]; then sed -i "1s/\t$k\$/\t$other/" "$tmp/$m/one/$u.api"; else sed -i "0,/kind: $k/s//kind: $other/" "$tmp/$m/one/$u.cli"; fi
                rejects "mode $m: one $u $ext row $other (listing)" listing $m "$tmp/$m/one"
                rejects "mode $m: one $u $ext row $other after the upgrade (kept)" kept $m "$tmp/$m/b" "$tmp/$m/one"
            done
        done
    done
    # an id missing, added, taken from the other owner; a list empty or missing; a type changed; a row twice
    for u in alice bob; do
        o=$([ $u = alice ] && echo bob || echo alice)
        for ext in api cli; do
            f=$u.$ext
            variant $m b x
            if [ $ext = api ]; then sed -i 1d "$tmp/$m/x/$f"; else sed -i 1,4d "$tmp/$m/x/$f"; fi
            rejects "mode $m: a $u $ext row missing after the upgrade" kept $m "$tmp/$m/b" "$tmp/$m/x"
            variant $m b x
            if [ $ext = api ]; then printf 'extra\trsa2048\t%s\n' "$k" >> "$tmp/$m/x/$f"; else printf 'id: extra\n  type: rsa2048\n  kind: %s\n' "$k" >> "$tmp/$m/x/$f"; fi
            rejects "mode $m: a $u $ext row added" kept $m "$tmp/$m/b" "$tmp/$m/x"
            variant $m b x
            cp "$tmp/$m/b/$o.$ext" "$tmp/$m/x/$f"
            rejects "mode $m: $u shows $o's keys ($ext)" kept $m "$tmp/$m/b" "$tmp/$m/x"
            variant $m b x
            : > "$tmp/$m/x/$f"
            rejects "mode $m: $u's $ext list empty" kept $m "$tmp/$m/b" "$tmp/$m/x"
            rm -f "$tmp/$m/x/$f"
            rejects "mode $m: $u's $ext list missing" kept $m "$tmp/$m/b" "$tmp/$m/x"
            variant $m b x
            if [ $ext = api ]; then sed -i 's/rsa2048/rsa3072/' "$tmp/$m/x/$f"; else sed -i 's/type: rsa2048/type: rsa3072/' "$tmp/$m/x/$f"; fi
            rejects "mode $m: a $u $ext type changed" kept $m "$tmp/$m/b" "$tmp/$m/x"
            variant $m b x
            if [ $ext = api ]; then head -n 1 "$tmp/$m/b/$f" >> "$tmp/$m/x/$f"; else head -n 4 "$tmp/$m/b/$f" >> "$tmp/$m/x/$f"; fi
            rejects "mode $m: a $u $ext row twice" listing $m "$tmp/$m/x"
        done
    done
    variant $m b x
    sed -i '/kind:/d' "$tmp/$m/x/alice.cli"
    rejects "mode $m: no kind line in the CLI" listing $m "$tmp/$m/x"
done
if uk kind nowhere > /dev/null 2>&1; then bad "an unknown mode is accepted"; fi

# the journal: entries of the round (alice uid 1000, bob uid 1001), 9 requests
entry() { # UID KEY KIND [OPERATION]
    local kind=''
    [ -z "$3" ] || kind=$(printf ',"CUSTODIO_STORAGE_KIND":"%s"' "$3")
    printf '{"CUSTODIO_OPERATION":"%s","CUSTODIO_UID":"%s","CUSTODIO_KEY_ID":"%s","CUSTODIO_OUTCOME":"ok"%s}\n' "${4:-sign}" "$1" "$2" "$kind"
}
round() { # KIND: nine entries, every key at least once
    local k=$1
    entry 1000 rsa1 "$k"; entry 1000 ec1 "$k"; entry 1000 rsa1 "$k"
    entry 1000 ec1 "$k"; entry 1000 rsa1 "$k"; entry 1000 ec1 "$k"
    entry 1001 bobonly "$k"; entry 1001 rsa1 "$k"; entry 1001 rsa1 "$k"
}
j() { uk journal "$1" "$tmp/j.json" 1000 1001 "${2:-9}"; }
for m in swtpm none lacking; do
    k=$(want_of $m)
    round "$k" > "$tmp/j.json"
    out=$(j $m)
    [ -z "$out" ] || bad "mode $m: a good round is rejected: $out"
    [ -n "$(j $m 8)" ] || bad "mode $m: 9 entries for 8 requests accepted"
    [ -n "$(j $m 10)" ] || bad "mode $m: 9 entries for 10 requests accepted"
    # an extra entry from before the cursor, as an unwindowed read would give
    { entry 1000 rsa1 "$k"; round "$k"; } > "$tmp/j.json"
    [ -n "$(j $m)" ] || bad "mode $m: an extra entry from before the cursor is accepted"
    for other in tpm encrypted-tpm encrypted-host ''; do
        [ "$other" != "$k" ] || continue
        round "$other" > "$tmp/j.json"
        [ -n "$(j $m)" ] || bad "mode $m: every entry of kind '$other' is accepted"
        { round "$k" | sed -n 1,8p; entry 1001 rsa1 "$other"; } > "$tmp/j.json"
        [ -n "$(j $m)" ] || bad "mode $m: one entry of kind '$other' is accepted"
    done
    { round "$k" | sed 1d; entry 1000 rsa1 "$k"; } > "$tmp/j.json"
    out=$(j $m)
    [ -z "$out" ] || bad "mode $m: another split of the entries over the same keys is rejected: $out"
    { round "$k" | grep -v '"CUSTODIO_KEY_ID":"bobonly"'; entry 1000 rsa1 "$k"; } > "$tmp/j.json"
    [ -n "$(j $m)" ] || bad "mode $m: no entry for bob's bobonly accepted"
    { round "$k" | sed -n 1,8p; entry 1000 bobonly "$k"; } > "$tmp/j.json"
    [ -n "$(j $m)" ] || bad "mode $m: an entry for bobonly under alice's uid accepted"
    { round "$k" | sed -n 1,8p; entry 1002 rsa1 "$k"; } > "$tmp/j.json"
    [ -n "$(j $m)" ] || bad "mode $m: an entry for another uid accepted"
    { round "$k" | sed -n 1,8p; entry 1001 rsa1 "$k" delete; } > "$tmp/j.json"
    [ -n "$(j $m)" ] || bad "mode $m: an entry of another operation accepted"
    : > "$tmp/j.json"
    [ -n "$(j $m)" ] || bad "mode $m: an empty journal accepted"
    rm -f "$tmp/j.json"
    [ -n "$(j $m)" ] || bad "mode $m: a missing journal accepted"
done
[ -n "$(uk journal swtpm /dev/null 1000 1001 x)" ] || bad "a non-numeric request count is accepted"

# --- a stub-driven run of upgrade-kinds.sh: su copies the evidence the test prepared for the phase into the directory the real script writes; journalctl prints the prepared journal
mkdir -p "$tmp/bin" "$tmp/work/agent-upgrade" "$tmp/work/upgrade-acct/agent-alice" "$tmp/work/upgrade-acct/agent-bob"
cat > "$tmp/bin/su" <<'STUB'
#!/bin/sh
# su -l USER -c "WORK=... bash /e2e/upgrade-accts-user.sh kinds PHASE"
user=$2
phase=${4##* }
mkdir -p "$WORK/upgrade-acct/kinds/$phase"
cp "$EV/$phase/$user".api "$EV/$phase/$user".cli "$WORK/upgrade-acct/kinds/$phase/"
STUB
cat > "$tmp/bin/journalctl" <<'STUB'
#!/bin/sh
case "$*" in
--sync) ;;
*--show-cursor*) echo "-- cursor: s=stub" ;;
*--after-cursor=s=stub*) cat "$EV/journal.json" ;;
*) echo "unexpected journalctl $*" >&2; exit 9 ;;
esac
STUB
cat > "$tmp/bin/id" <<'STUB'
#!/bin/sh
case "$2" in alice) echo 1000 ;; bob) echo 1001 ;; *) exit 1 ;; esac
STUB
chmod +x "$tmp/bin/"*
requests() { seq 3 > "$tmp/work/agent-upgrade/requests"; seq 3 > "$tmp/work/upgrade-acct/agent-alice/requests"; seq "${1:-3}" > "$tmp/work/upgrade-acct/agent-bob/requests"; }
requests
# runuk MODE EVDIR SCRIPT: all steps of the script in order, the output in $tmp/out; fails at the first step that fails
runuk() {
    local step
    rm -rf "$tmp/work/upgrade-acct/kinds"
    : > "$tmp/out"
    for step in "collect before" before "collect after" kept cursor "collect round" signs tpmbound; do
        env PATH="$tmp/bin:$PATH" EV="$2" WORK="$tmp/work" E2E_TPM="$1" bash "$3" $step >> "$tmp/out" 2>&1 || return 1
    done
}
# stops_on_bad MODE SCRIPT: every kind of bad evidence stops the run of SCRIPT with the kinds message and without the case it spoils
stops_on_bad() {
    local m=$1 s=$2 k other phase ok=0
    k=$(want_of $m)
    other=$([ "$k" = tpm ] && echo encrypted-host || echo tpm)
    for pair in before:before after:kept round:signs; do
        phase=${pair%%:*}
        rm -rf "$tmp/ev2"; cp -r "$tmp/ev-$m" "$tmp/ev2"
        mklist "$tmp/ev2/$phase" "$other"
        if runuk $m "$tmp/ev2" "$s"; then ok=1; fi
    done
    rm -rf "$tmp/ev2"; cp -r "$tmp/ev-$m" "$tmp/ev2"
    { entry 1000 rsa1 "$other"; round "$k" | sed 1d; } > "$tmp/ev2/journal.json"
    if runuk $m "$tmp/ev2" "$s"; then ok=1; fi
    cp "$tmp/ev-$m/journal.json" "$tmp/ev2/journal.json"
    requests 1
    if runuk $m "$tmp/ev2" "$s"; then ok=1; fi
    requests
    return "$ok"
}
for m in swtpm none lacking; do
    k=$(want_of $m)
    ev=$tmp/ev-$m
    mkdir -p "$ev"
    for p in before after round; do mklist "$ev/$p" "$k"; done
    round "$k" > "$ev/journal.json"
    if runuk $m "$ev" "$ROOT/e2e/upgrade-kinds.sh"; then
        for id in $ids; do
            if [ "$id" = upgrade-kinds-tpmbound ]; then grep -qx "E2E-CASE skipped $id" "$tmp/out" || bad "mode $m: $id is not reported skipped"
            else grep -qx "E2E-CASE run $id" "$tmp/out" || bad "mode $m: $id is not reported run"; fi
        done
        [ "$(grep -c '^E2E-CASE' "$tmp/out")" = 4 ] || bad "mode $m: not exactly four cases reported"
    else
        bad "mode $m: good evidence stopped the run: $(tail -n 3 "$tmp/out")"
    fi
    stops_on_bad $m "$ROOT/e2e/upgrade-kinds.sh" || bad "mode $m: some bad evidence did not stop the run"
done
# the mutant: the same script with the judgement left out (the problems are not looked at) lets bad evidence through, so stops_on_bad must report it
cp "$ROOT/e2e/report.sh" "$ROOT/e2e/select.sh" "$ROOT/e2e/upgradekinds.py" "$tmp/"
sed 's/\[ -z "\$p" \] || {/true || {/' "$ROOT/e2e/upgrade-kinds.sh" > "$tmp/upgrade-kinds.sh"
if cmp -s "$tmp/upgrade-kinds.sh" "$ROOT/e2e/upgrade-kinds.sh"; then bad "the mutant of the judgement changed nothing"; fi
if stops_on_bad swtpm "$tmp/upgrade-kinds.sh"; then bad "the mutant that leaves the judgement out is not caught"; fi

# a judgement that crashes (here: python exits at once) stops the run and reports no case
mkdir -p "$tmp/crash"
cp "$ROOT/e2e/report.sh" "$ROOT/e2e/select.sh" "$ROOT/e2e/upgrade-kinds.sh" "$tmp/crash/"
printf 'import sys\nsys.exit("crash")\n' > "$tmp/crash/upgradekinds.py"
if runuk swtpm "$tmp/ev-swtpm" "$tmp/crash/upgrade-kinds.sh"; then bad "a crashed judgement did not stop the run"; fi
grep -q '^E2E-CASE run' "$tmp/out" && bad "a crashed judgement still reported a case run"

# shellcheck disable=SC1091 # the section is a part of this script, linted on its own as shellcheck shell=bash
source "$ROOT/scripts/lib/e2e-upgradekinds-vm-section.sh"

# --- upgrade.sh calls the step where each case needs it
line() { grep -n -- "$1" "$ROOT/e2e/upgrade.sh" | head -n 1 | cut -d: -f1; }
before() { # WHAT A B: line A is found and comes before line B
    local a b
    a=$(line "$2")
    b=$(line "$3")
    { [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]; } || bad "upgrade.sh: $1 does not come before it should ('$2' at '${a:-none}', '$3' at '${b:-none}')"
}
before "the listing before the install" 'kinds collect before' 'bash "$install"'
before "the judgement before the install" 'kinds before' 'bash "$install"'
before "the listing after the install" 'kinds collect after' 'kinds kept'
before "the kept judgement" 'kinds kept' 'case_run "$id-keys-listed"'
before "the cursor" 'kinds cursor' 'user_run sign'
before "the round's listing" 'kinds collect round' 'kinds signs'
before "the signs judgement" 'kinds signs' 'accts cleanup'
before "the skip" 'kinds tpmbound' '^# END upgrade-case'
before "the reader before the install" 'kinds reader' 'bash "$install"'
exit "$fail"
