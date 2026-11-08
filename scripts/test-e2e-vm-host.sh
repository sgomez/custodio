#!/usr/bin/env bash
# F160: the host driver of a VM run (e2e/vm/run.sh) against a stub VM (scripts/lib/e2e-vm-stub): no QEMU, no apt, no network. Sections:
#   good       the steps in order, the install command, E2E_TPM per mode, the record, nothing installed on the host
#   failure    each failure path: non-zero exit with the cause, stop once (never when no VM started), no temporary file, the record
#   recipes    `just e2e-vm`, `just e2e-vm-cases` on a copy of the justfile whose e2e-packages is stubbed
#   guest, vm-only   scripts/lib/e2e-vm-host-guest.sh
# A negative control is a copy of the driver (or the recipe, or the guest script) with one behaviour removed, shown to differ with cmp; the check run on it must fail.
# shellcheck disable=SC2329,SC2016,SC2015 # SC2329: check functions are called through names; SC2016: sed programs and stub text in single quotes; SC2015: A && B || bad is the check
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
STUB=$ROOT/scripts/lib/e2e-vm-stub
tmp=$(mktemp -d)
trap '[ -n "${KEEP:-}" ] || rm -rf "$tmp"; [ -z "${KEEP:-}" ] || echo "kept: $tmp" >&2' EXIT
fail=0
bad() { echo "test-e2e-vm-host: $*" >&2; fail=1; }
differs() { cmp -s "$1" "$2" && bad "$3: the control is identical to the original"; return 0; }
# the tree the driver runs in: its own copy (the driver works from the directory above e2e/vm)
R=$tmp/root
mkdir -p "$R/docs" "$R/scripts" "$R/crates/custodiod/src"
cp -a "$ROOT/e2e" "$R/e2e"; find "$R/e2e" -name __pycache__ -prune -exec rm -rf {} +
cp "$ROOT/justfile" "$R/justfile"; cp "$ROOT/docs/audit.md" "$R/docs/"; cp "$ROOT"/scripts/check-no-plaintext.sh "$ROOT"/scripts/check_no_plaintext.py "$R/scripts/"
cp "$ROOT/crates/custodiod/src/app_id_source.rs" "$R/crates/custodiod/src/"
DRV=$R/e2e/vm/run.sh
# fake packages: N, N+1, and one that depends on a test tool
mkdeb() { # mkdeb DIR VERSION [DEPENDS]
    local d=$tmp/b-$2${3:-} dep=''
    [ -z "${3:-}" ] || dep="Depends: $3"
    mkdir -p "$d/DEBIAN" "$1"
    printf 'Package: custodio\nVersion: %s\nArchitecture: amd64\nMaintainer: t <t@example.org>\nDescription: fake\n%s\n' "$2" "$dep" > "$d/DEBIAN/control"
    dpkg-deb --root-owner-group -b "$d" "$1/custodio_${2}_amd64.deb" > /dev/null
}
mkdeb "$tmp/pk" 1.2.3; mkdeb "$tmp/pkn" 1.2.4; mkdeb "$tmp/pkbad" 1.2.3 tpm2-tools; mkdir "$tmp/empty"
# the host's apt-get, dpkg and apt: logging stubs ahead of any real one
mkdir "$tmp/hostbin"
for t in apt-get dpkg apt; do printf '#!/bin/sh\necho "%s $*" >> "$HOSTLOG"\n' "$t" > "$tmp/hostbin/$t"; chmod +x "$tmp/hostbin/$t"; done
grep -v '^[[:space:]]*\(#\|$\)' "$R/e2e/vm/cases.list" | sed 's/^/E2E-CASE run /' > "$tmp/cases.ok"
{ cat "$tmp/cases.ok"; echo "E2E-CASE run sign-rsa-pkcs"; } > "$tmp/cases.twice"
grep -v 'pcr-restarted-signs' "$tmp/cases.ok" > "$tmp/cases.missing"
{ cat "$tmp/cases.ok"; echo "E2E-CASE run bogus-case"; } > "$tmp/cases.unknown"

declare -A PID=()
launch() { # launch NAME DRIVER MODE [VAR=VALUE...]: starts a run in the background; $tmp/NAME/{out,rc,log,stops,rec}
    local n=$1 drv=$2 mode=$3; shift 3
    mkdir -p "$tmp/$n/tmp" "$tmp/$n/vmdir" "$tmp/$n/out"
    local runner=(bash)
    case " $* " in *" SIGNAL_RUN=1 "*)
        # a background job ignores SIGINT; the runner restores it, records its pid (the new group's id) and becomes the driver
        runner=(sh -c 'echo $$ > "$0"; exec setsid python3 -I -c "import os,signal,sys;signal.signal(signal.SIGINT,signal.SIG_DFL);os.execvp(\"bash\",[\"bash\"]+sys.argv[1:])" "$@"' "$tmp/$n/pgid") ;;
    esac
    (
        env PATH="$tmp/hostbin:$PATH" HOSTLOG="$tmp/$n/host" STUB_LOG="$tmp/$n/log" STUB_VMDIR="$tmp/$n/vmdir" TMPDIR="$tmp/$n/tmp" E2E_OUT="${E2E_OUT_DIR:-$tmp/$n/out}" \
            VM_SH="$STUB/vm.sh" VM_IMAGE_SH="$STUB/image.sh" VM_SWTPM="$STUB/swtpm" E2E_PACKAGES="$tmp/pk" E2E_PACKAGES_NEXT="$tmp/pkn" "$@" \
            "${runner[@]}" "$drv" "$mode" > "$tmp/$n/out.txt" 2>&1 && echo 0 > "$tmp/$n/rc" || echo $? > "$tmp/$n/rc"
    ) &
    PID[$n]=$!
}
mkctl() { # mkctl NAME SED-PROGRAM: a copy of the driver with one behaviour removed
    cp "$DRV" "$R/e2e/vm/run-$1.sh"; sed -i "$2" "$R/e2e/vm/run-$1.sh"; differs "$DRV" "$R/e2e/vm/run-$1.sh" "$1"
}
stops() { cat "$tmp/$1/log.stops" 2> /dev/null | wc -l; }
order() { # order NAME PATTERN...: the patterns occur in the stub log in this order
    local n=$1 last=0 p ln; shift
    for p in "$@"; do
        ln=$(grep -n -m1 -- "$p" <(tail -n +$((last + 1)) "$tmp/$n/log") | cut -d: -f1) || ln=
        [ -n "$ln" ] || { echo "no '$p' after line $last"; return 1; }
        last=$((last + ln))
    done
}
rcof() { cat "$tmp/$1/rc" 2> /dev/null || echo none; }

# ---- start everything at once
STEPS_ORDER=('^image' '^vm start' 'tar -C / --no-same-owner -xf /dev/disk/by-id/virtio-custodio-payload' 'apt-get update' 'install -y --no-install-recommends /pkg/custodio_1.2.3' 'systemd-analyze has-tpm2' 'install -y --no-install-recommends tpm2-tools' 'guest.sh' '^vm stop')
mkctl noflag 's/ --no-install-recommends \/pkg\// \/pkg\//'
mkctl dpkgi 's/sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \/pkg\//sudo dpkg -i \/pkg\//'
mkctl toolsfirst '/^gt 900 .*\$TOOLS/d; /gt 300 "sudo apt-get update"/i gt 900 "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $TOOLS" >> "$log" 2>\&1'
mkctl tpmfull 's/E2E_TPM=\$tpm /E2E_TPM=lacking /'
mkctl notpm 's/E2E_TPM=\$tpm //'
mkctl noserial 's/for k in target tpm image_serial kernel/for k in target tpm kernel/'
mkctl notimes '/echo "step_/d'
mkctl wrongmode 's/\[tpm\]=\$mode/[tpm]=lacking/'
mkctl hostapt '/^started=/i apt-get install -y tpm2-tools >/dev/null 2>\&1 || true'
mkctl nopayload 's/^started=\$(VM_PAYLOAD="\$tmp\/payload.tar" /started=$(/'
mkctl putdeb '/^step boot$/a "\$VM_SH" put "\$vmdir" "\$deb" /tmp/x || true'
mkctl notrap 's/^trap cleanup EXIT$/:/; s/^trap .echo "e2e-vm: interrupted.*$/:/; s/^trap .echo "e2e-vm: terminated.*$/:/'
mkctl noaccount 's/^CHECK_VM=1 CHECK_TPM_MODE=\$tpm bash e2e\/check-cases.sh/true # /'
# the control copies are all written before any run starts: the driver tars the e2e tree and must not see it change
E2E_OUT_DIR=$tmp/shared launch good-full "$DRV" full STUB_CASES=
E2E_OUT_DIR=$tmp/shared launch good-lacking "$DRV" lacking STUB_CASES=
launch good-sel "$DRV" full STUB_CASES=
launch c-noflag "$R/e2e/vm/run-noflag.sh" full STUB_CASES=
launch c-dpkgi "$R/e2e/vm/run-dpkgi.sh" full STUB_CASES=
launch c-toolsfirst "$R/e2e/vm/run-toolsfirst.sh" full STUB_CASES=
launch c-tpmfull "$R/e2e/vm/run-tpmfull.sh" full STUB_CASES=
launch c-notpm "$R/e2e/vm/run-notpm.sh" full STUB_CASES=
launch c-noserial "$R/e2e/vm/run-noserial.sh" full STUB_CASES=
launch c-notimes "$R/e2e/vm/run-notimes.sh" full STUB_CASES=
launch c-wrongmode "$R/e2e/vm/run-wrongmode.sh" full STUB_CASES=
launch c-nopayload "$R/e2e/vm/run-nopayload.sh" full STUB_CASES=
launch c-putdeb "$R/e2e/vm/run-putdeb.sh" full STUB_CASES=
launch c-hostapt "$R/e2e/vm/run-hostapt.sh" full STUB_CASES=
# failure paths
launch f-image "$DRV" full STUB_FAIL_IMAGE=1
launch f-start "$DRV" full STUB_FAIL_START=1
launch f-nopkg "$DRV" full E2E_PACKAGES="$tmp/empty"
launch f-nonext "$DRV" full E2E_PACKAGES_NEXT="$tmp/empty"
launch f-baddeb "$DRV" full E2E_PACKAGES="$tmp/pkbad"
launch f-install "$DRV" full STUB_FAIL_INSTALL=1
launch f-has2 "$DRV" full STUB_HAS2=partial
launch f-has2rc "$DRV" full STUB_HAS2=yes STUB_HAS2_RC=16
launch f-twice "$DRV" full STUB_CASES="$tmp/cases.twice"
launch f-missing "$DRV" full STUB_CASES="$tmp/cases.missing"
launch f-unknown "$DRV" full STUB_CASES="$tmp/cases.unknown"
launch f-guest "$DRV" full STUB_GUEST_RC=1 STUB_CASES="$tmp/cases.ok"
launch c-notrap "$R/e2e/vm/run-notrap.sh" full STUB_FAIL_INSTALL=1
launch c-noaccount "$R/e2e/vm/run-noaccount.sh" full STUB_CASES="$tmp/cases.missing"
# signals during the guest run: the run is its own process group (as a terminal's foreground group) and the whole group gets the signal
for sig in INT TERM; do
    mkdir -p "$tmp/s-$sig/hold"
    launch "s-$sig" "$DRV" full STUB_HOLD="$tmp/s-$sig/hold" STUB_CASES="$tmp/cases.ok" SIGNAL_RUN=1
done
sigsend() { # sigsend NAME SIGNAL: waits for the guest to start, then signals the group of the driver
    local n=$1 sig=$2
    for _ in $(seq 400); do [ -e "$tmp/$n/hold/in-guest" ] && break; sleep 0.05; done
    [ -e "$tmp/$n/hold/in-guest" ] || { bad "$n: the guest never started"; return; }
    kill -s "$sig" -- "-$(cat "$tmp/$n/pgid")" 2> /dev/null || bad "$n: no process group to signal"
}
sigsend s-INT INT
sigsend s-TERM TERM
for n in "${!PID[@]}"; do wait "${PID[$n]}" 2> /dev/null || true; done

# ---- recipes (run while the above finish): a justfile whose e2e-packages only logs
python3 - "$R/justfile" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p).read()
s = re.sub(r"^e2e-packages: package\n(    .*\n)+", "e2e-packages:\n    echo e2e-packages >> \"$STUB_LOG\"\n", s, flags=re.M)
open(p, "w").write(s)
PY
grep -q 'echo e2e-packages' "$R/justfile" || bad "recipes: the justfile copy was not stubbed"
sed '/^e2e-vm-check mode/,/^$/ s/^    bash e2e\/vm\/run.sh --check.*/    true/' "$R/justfile" > "$R/justfile.nocheck"
differs "$R/justfile" "$R/justfile.nocheck" nocheck
rj() { # rj NAME JUSTFILE ARGS...: runs a recipe with the stub environment
    local n=$1 jf=$2; shift 2
    mkdir -p "$tmp/$n/tmp" "$tmp/$n/vmdir" "$tmp/$n/out"
    env STUB_LOG="$tmp/$n/log" STUB_VMDIR="$tmp/$n/vmdir" TMPDIR="$tmp/$n/tmp" E2E_OUT="$tmp/$n/out" STUB_CASES= \
        VM_SH="$STUB/vm.sh" VM_IMAGE_SH="$STUB/image.sh" VM_SWTPM="$STUB/swtpm" E2E_PACKAGES="$tmp/pk" E2E_PACKAGES_NEXT="$tmp/pkn" \
        just --justfile "$jf" --working-directory "$R" "$@" > "$tmp/$n/out.txt" 2>&1 && echo 0 > "$tmp/$n/rc" || echo $? > "$tmp/$n/rc"
}
rj r-full "$R/justfile" e2e-vm full &
rj r-sel "$R/justfile" e2e-vm-cases full 'sign-*' noplain-rsa &
for m in partial FULL ''; do rj "r-bad-${m:-empty}" "$R/justfile" e2e-vm "$m" & done
rj r-nomode "$R/justfile" e2e-vm &
rj r-nomatch "$R/justfile" e2e-vm-cases full 'nosuch-*' &
rj r-ctl "$R/justfile.nocheck" e2e-vm partial &
wait

# ---- the payload: the files travel as one tar on the VM's payload drive, never with `vm put`
# shellcheck source=scripts/lib/e2e-vm-payload.sh
. "$ROOT/scripts/lib/e2e-vm-payload.sh"

# ---- good
for m in full lacking; do
    n=good-$m
    [ "$(rcof "$n")" = 0 ] || bad "good $m: exit $(rcof "$n"): $(tail -n 5 "$tmp/$n/out.txt")"
    o=$(order "$n" "${STEPS_ORDER[@]}") || bad "good $m: the steps are not in the order of the contract: $o"
    grep -q "^vm start $m\$" "$tmp/$n/log" || bad "good $m: the mode did not reach start"
    want=$([ "$m" = full ] && echo swtpm || echo lacking)
    grep -q "E2E_VM=1 E2E_TPM=$want " "$tmp/$n/log" || bad "good $m: the guest command lacks E2E_TPM=$want"
    r=$(ck_payload "$n" 2>&1) || bad "good $m: payload: $r"
    ! grep -q 'dpkg -i' "$tmp/$n/log" || bad "good $m: dpkg -i"
    grep 'apt-get install' "$tmp/$n/log" | grep -v 'apt-get update' | while read -r l; do
        case $l in *"apt-get install -y --no-install-recommends "*) ;; *) echo "install without the flag: $l" >&2; echo x > "$tmp/$n/noflag" ;; esac
    done
    [ ! -e "$tmp/$n/noflag" ] || bad "good $m: an install without --no-install-recommends"
    [ "$(stops "$n")" = 1 ] || bad "good $m: stop called $(stops "$n") times"
    [ -z "$(ls -A "$tmp/$n/tmp")" ] || bad "good $m: temporary files are left"
    [ ! -s "$tmp/$n/host" ] || bad "good $m: the driver installed on the host: $(cat "$tmp/$n/host")"
    rec=$tmp/shared/vm.$m.record
    [ -s "$rec" ] || { bad "good $m: no record"; continue; }
    for kv in "target=vm" "tpm=$m" "image_serial=20261105" "kernel=6.14.0-stub" "systemd=systemd 257 (257.9-stub)" "package_version=1.2.3" \
        "swtpm_version=TPM emulator version 0.10.2-stub, Copyright" "has_tpm2=yes (exit 0)"; do
        grep -qxF -- "$kv" "$rec" || bad "good $m: the record lacks '$kv'"
        grep -qxF -- "$kv" "$tmp/$n/out.txt" || bad "good $m: the printed record lacks '$kv'"
    done
    for st in image boot copy install tools setup sign pcr upgrade teardown; do grep -Eq "^step_$st=[0-9]+\$" "$rec" || bad "good $m: no time for step $st"; done
    ! grep -q '^step_noplain' "$rec" || bad "good $m: a time for a step that did not run"
    [ -s "$tmp/shared/vm.$m.phases.tsv" ] && [ -s "$tmp/shared/vm.$m.log" ] || bad "good $m: phases or log not saved"
done
grep -q '^tpm=lacking$' "$tmp/shared/vm.lacking.record" && grep -q '^tpm=full$' "$tmp/shared/vm.full.record" || bad "good: the two modes did not each write their own record"
grep -q "E2E_SELECT='sign-kind-matches-mode" "$tmp/good-full/log" || bad "good: the guest command carries no selection"
# ---- controls of good
c="c-noflag"; grep 'apt-get install' "$tmp/$c/log" | grep -q 'install -y /pkg/' || bad "control noflag: the log shows the flag still (the control is not a control)"
c="c-dpkgi"; grep -q 'dpkg -i' "$tmp/$c/log" || bad "control dpkgi: the log shows no dpkg -i"
c="c-toolsfirst"; o=$(order "$c" "${STEPS_ORDER[@]}") && bad "control toolsfirst: the order check passed"
for c in c-tpmfull c-notpm; do grep -q "E2E_VM=1 E2E_TPM=swtpm " "$tmp/$c/log" && bad "control $c: the mapping check passed"; done
c="c-noserial"; grep -qx 'image_serial=20261105' "$tmp/shared/../$c/out/vm.full.record" && bad "control noserial: the record has the serial"
c="c-notimes"; grep -q '^step_' "$tmp/$c/out/vm.full.record" && bad "control notimes: the record has times"
c="c-wrongmode"; grep -qx 'tpm=full' "$tmp/$c/out/vm.full.record" && bad "control wrongmode: the record says the asked mode"
ck_payload c-putdeb > /dev/null 2>&1 && bad "control putdeb: the payload check passed on a driver that copies a package with vm put"
ck_payload c-nopayload > /dev/null 2>&1 && bad "control nopayload: the payload check passed on a driver that starts the VM without VM_PAYLOAD"
c="c-hostapt"; [ -s "$tmp/$c/host" ] || bad "control hostapt: the host check did not see the local install"

# ---- failure paths
fp() { # fp NAME MESSAGE STOPS [STEP-PRESENT...]: exits non-zero, the message names the cause, stop calls, no temp file, record when a VM started
    local n=$1 msg=$2 st=$3; shift 3
    [ "$(rcof "$n")" != 0 ] && [ "$(rcof "$n")" != none ] || bad "$n: exit $(rcof "$n")"
    grep -qF -- "$msg" "$tmp/$n/out.txt" || bad "$n: no message '$msg': $(tail -n 3 "$tmp/$n/out.txt")"
    [ "$(stops "$n")" = "$st" ] || bad "$n: stop called $(stops "$n") times, expected $st"
    [ -z "$(ls -A "$tmp/$n/tmp")" ] || bad "$n: temporary files are left"
    if [ "$st" = 1 ]; then
        [ -s "$tmp/$n/out/vm.full.record" ] || bad "$n: no record although a VM was started"
        grep -q '^step_boot=' "$tmp/$n/out/vm.full.record" || bad "$n: the record does not name the steps that ran"
    fi
}
fp f-image "image is not available" 0; ! grep -q '^vm ' "$tmp/f-image/log" || bad "f-image: a later step ran"
fp f-start "vm.sh start full failed" 0; ! grep -q '^vm put' "$tmp/f-start/log" || bad "f-start: a later step ran"
fp f-nopkg "no package custodio_*.deb" 0; ! test -e "$tmp/f-nopkg/log" || bad "f-nopkg: something started"
fp f-nonext "no package N+1" 0; ! test -e "$tmp/f-nonext/log" || bad "f-nonext: something started"
fp f-baddeb "test tool tpm2-tools" 0; ! test -e "$tmp/f-baddeb/log" || bad "f-baddeb: something started"
fp f-install "apt-get install of the package failed" 1; ! grep -q 'tpm2-tools' "$tmp/f-install/log" || bad "f-install: the tools were installed"
fp f-has2 "has-tpm2 printed 'partial'" 1; ! grep -q 'install -y --no-install-recommends tpm2-tools' "$tmp/f-has2/log" || bad "f-has2: the tools were installed"
fp f-has2rc "exited 16" 1
fp f-twice "case 'sign-rsa-pkcs' reported twice" 1
fp f-missing "case 'pcr-restarted-signs' was not reported" 1
fp f-unknown "unknown case 'bogus-case'" 1
fp f-guest "the guest run failed with status 1" 1
for sig in INT TERM; do fp "s-$sig" "" 1; done
grep -q 'interrupted' "$tmp/s-INT/out.txt" || bad "s-INT: no message naming the signal"
grep -q 'terminated' "$tmp/s-TERM/out.txt" || bad "s-TERM: no message naming the signal"
# controls of the failure paths
[ "$(stops c-notrap)" != 1 ] || bad "control notrap: the VM was still stopped"
[ "$(rcof c-noaccount)" != 0 ] && bad "control noaccount: a missing case still failed the run"
# host: nothing installed locally (the driver's own calls)
for n in good-full good-lacking; do grep -q 'tpm2-tools' "$tmp/$n/log" || bad "$n: the tools install is not in the guest log"; done
c="f-baddeb"; deps=$(dpkg-deb -f "$tmp/pkbad/custodio_1.2.3_amd64.deb" Depends); grep -qw tpm2-tools <<< "$deps" || bad "the fake .deb does not depend on tpm2-tools"
deps=$(dpkg-deb -f "$tmp/pk/custodio_1.2.3_amd64.deb" Depends Recommends Pre-Depends || true); ! grep -qwE 'tpm2-tools|openssl|opensc|pkcs11-provider|libnss3-tools|python3-gi' <<< "$deps" || bad "the fake package names a test tool"

# ---- recipes: checks
grep -q 'e2e-packages' "$tmp/r-full/log" && grep -q '^image' "$tmp/r-full/log" && [ "$(rcof r-full)" = 0 ] || bad "recipes: e2e-vm full: $(tail -n 3 "$tmp/r-full/out.txt")"
[ "$(grep -n -m1 e2e-packages "$tmp/r-full/log" | cut -d: -f1)" -lt "$(grep -n -m1 '^image' "$tmp/r-full/log" | cut -d: -f1)" ] || bad "recipes: e2e-packages after the driver"
just --justfile "$R/justfile" --working-directory "$R" --dry-run e2e-vm lacking 2>&1 | grep -q 'run.sh lacking' || bad "recipes: the dry run does not show the mode"
[ "$(rcof r-sel)" = 0 ] && grep -q "E2E_SELECT='sign-kind-matches-mode" "$tmp/r-sel/log" && ! grep -q "pcr-" "$tmp/r-sel/log" || bad "recipes: e2e-vm-cases full 'sign-*': $(tail -n 3 "$tmp/r-sel/out.txt")"
for n in r-bad-partial r-bad-FULL r-bad-empty r-nomode r-nomatch; do
    [ "$(rcof $n)" != 0 ] || bad "recipes: $n exited 0"
    [ ! -e "$tmp/$n/log" ] || bad "recipes: $n started something: $(cat "$tmp/$n/log")"
done
for n in r-bad-partial r-bad-FULL r-bad-empty; do grep -q 'full, lacking' "$tmp/$n/out.txt" || bad "recipes: $n does not name the allowed values"; done
grep -q 'no case matches' "$tmp/r-nomatch/out.txt" || bad "recipes: no message for a name that matches nothing"
[ -e "$tmp/r-ctl/log" ] || bad "recipes control: without the check, nothing started (the control is not a control)"
grep -q e2e-packages "$tmp/r-ctl/log" 2> /dev/null || bad "recipes control: the packages were not built without the check"

# ---- guest and vm-only
# shellcheck source=scripts/lib/e2e-vm-host-guest.sh
source "$ROOT/scripts/lib/e2e-vm-host-guest.sh"

[ "$fail" -eq 0 ] || exit 1
echo "test-e2e-vm-host: ok"
