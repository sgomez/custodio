#!/usr/bin/env bash
# Self-test of upgrade-accts-lib.sh (F96), run by upgrade-accts.sh before it relies on the library and by `just test-scripts`. A good fixture of
# the evidence (real keys, certificates and signatures) passes every judgement; each bad-evidence case fails its judgement with the expected text.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/upgrade-accts-lib.sh
source "$here/upgrade-accts-lib.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failures=0
bad() { echo "upgrade-accts-selftest: FAIL: $*" >&2; failures=$((failures + 1)); }

A=$tmp/acc
mkdir -p "$A/before" "$A/after" "$A/sign"
head -c 2000 /dev/urandom > "$A/sign/data.bin"
mkkey() { # NAME rsa|ec: key and certificate (DER) of subject CN=NAME
    case $2 in
    rsa) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tmp/$1.key" 2> /dev/null ;;
    ec) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$tmp/$1.key" 2> /dev/null ;;
    esac
}
mkcert() { # NAME OUT SUBJECT
    openssl req -new -x509 -key "$tmp/$1.key" -subj "/CN=$3" -days 30 -outform DER -out "$2"
}
mkkey alice-rsa1 rsa; mkkey alice-ec1 ec; mkkey bob-rsa1 rsa; mkkey bob-bobonly rsa
for k in alice-rsa1 alice-ec1 bob-bobonly; do mkcert "$k" "$A/before/$k.der" "$k"; done
mkcert bob-rsa1 "$A/bob-old.der" bob-old
mkcert bob-rsa1 "$A/bob-new.der" bob-new
cp "$A/bob-new.der" "$A/before/bob-rsa1.der"
list() { # USER ID...: the shape of `custodio list`
    local u=$1
    shift
    for id in "$@"; do printf 'id: %s\n  type: x\n  subject: CN=%s-%s\n' "$id" "$u" "$id"; done
}
list alice ec1 rsa1 > "$A/before/alice.list"
list bob bobonly rsa1 > "$A/before/bob.list"
cp "$A"/before/* "$A/after/"
sign() { # USER ID: signature of data.bin with the key, into sign/USER-ID.sig
    case $2 in
    ec1) openssl dgst -sha256 -sign "$tmp/$1-ec1.key" -out "$A/sign/$1-$2.sig" "$A/sign/data.bin" ;;
    *) openssl dgst -sha256 -sign "$tmp/$1-$2.key" -out "$A/sign/$1-$2.sig" "$A/sign/data.bin" ;;
    esac
    echo 1 > "$A/sign/$1-$2.requests"
}
for id in ec1 rsa1; do sign alice "$id"; done
for id in bobonly rsa1; do sign bob "$id"; done
for u in alice bob; do echo "1 1 0" > "$A/sign/$u-denied"; done

# good fixture
ok() { local what=$1 out; shift; out=$("$@" 2>&1) || true; [ -z "$out" ] || bad "$what: $out"; }
# rejects WHAT TEXT FUNCTION ARGS...: the function prints a problem containing TEXT
rejects() {
    local what=$1 text=$2 out
    shift 2
    out=$("$@" 2>&1) || true
    [ -n "$out" ] || { bad "$what: accepted"; return; }
    grep -q -- "$text" <<< "$out" || bad "$what: rejected without '$text': $out"
}
ok "good seed" acct_seed_problems "$A"
ok "good after" acct_after_problems "$A"
ok "good alice signatures" acct_sign_problems "$A" alice
ok "good bob signatures" acct_sign_problems "$A" bob
cat > "$tmp/state.good" <<'S'
d 998 998 700 - .
d 998 998 700 - ./1000
f 998 998 600 aaaa ./1000/ec1
f 998 998 600 a1a1 ./1000/ec1-cert
f 998 998 600 bbbb ./1000/rsa1
f 998 998 600 b1b1 ./1000/rsa1-cert
d 998 998 700 - ./4711
f 998 998 600 cccc ./4711/bobonly
f 998 998 600 c1c1 ./4711/bobonly-cert
f 998 998 600 dddd ./4711/rsa1
f 998 998 600 d1d1 ./4711/rsa1-cert
S
ok "good state" acct_state_problems "$tmp/state.good" 1000 4711 998

# a copy of the good evidence with one change, for a judgement
variant() { # NAME: ACC copy in $tmp/v-NAME
    rm -rf "$tmp/v-$1"
    cp -r "$A" "$tmp/v-$1"
}
# lists
variant foreign
printf 'id: bobonly\n  type: x\n' >> "$tmp/v-foreign/after/alice.list"
rejects "a key of the other account in a list" "shows bobonly, which is not one of his or her keys" acct_after_problems "$tmp/v-foreign"
variant extra; printf 'id: zzz\n' >> "$tmp/v-extra/before/bob.list"
rejects "an extra key" "shows zzz" acct_seed_problems "$tmp/v-extra"
variant missing; list bob rsa1 > "$tmp/v-missing/after/bob.list"
rejects "a missing key" "the list does not show bobonly" acct_after_problems "$tmp/v-missing"
variant bobasalice; cp "$A/before/bob.list" "$tmp/v-bobasalice/after/alice.list"
rejects "bob's list taken as alice's" "alice: the list shows bobonly" acct_after_problems "$tmp/v-bobasalice"
variant listchanged; sed -i 's/CN=alice-ec1/CN=other/' "$tmp/v-listchanged/after/alice.list"
rejects "a subject that changed" "alice: the list after the upgrade differs" acct_after_problems "$tmp/v-listchanged"
variant nolist; rm "$tmp/v-nolist/after/alice.list"
rejects "no list" "missing or empty" acct_after_problems "$tmp/v-nolist"
# certificates
variant oldcert; cp "$A/bob-old.der" "$tmp/v-oldcert/after/bob-rsa1.der"
rejects "the old certificate after the upgrade" "shows the original certificate" acct_after_problems "$tmp/v-oldcert"
rejects "the old certificate changes the key" "bob: the certificate of rsa1 changed" acct_after_problems "$tmp/v-oldcert"
variant othercert; cp "$A/before/alice-ec1.der" "$tmp/v-othercert/after/bob-rsa1.der"
rejects "a certificate that is neither" "bob's rsa1 is not the replacing certificate" acct_after_problems "$tmp/v-othercert"
variant oldseed; cp "$A/bob-old.der" "$tmp/v-oldseed/before/bob-rsa1.der"
rejects "the replacement never happened" "still shows the original certificate" acct_seed_problems "$tmp/v-oldseed"
variant samecert; cp "$A/before/alice-rsa1.der" "$tmp/v-samecert/after/bob-rsa1.der"
rejects "one certificate for two owners" "same certificate to alice and to bob" acct_after_problems "$tmp/v-samecert"
variant nodiff; cp "$A/bob-new.der" "$tmp/v-nodiff/bob-old.der"
rejects "replacement equal to the original" "is the original one" acct_seed_problems "$tmp/v-nodiff"
variant changedother; cp "$A/before/alice-ec1.der" "$tmp/v-changedother/after/alice-rsa1.der"
rejects "a certificate that changed" "alice: the certificate of rsa1 changed" acct_after_problems "$tmp/v-changedother"
# state
sed 's#^f 998 998 600 dddd ./4711/rsa1#f 998 998 600 dddd ./1000/rsa1x#' "$tmp/state.good" > "$tmp/state.moved"
rejects "a file that moved to the other uid" "is not one of alice's keys" acct_state_problems "$tmp/state.moved" 1000 4711 998
rejects "a file that moved: bob's is missing" "no file ./4711/rsa1" acct_state_problems "$tmp/state.moved" 1000 4711 998
sed 's#^f 998 998 600 cccc ./4711/bobonly#f 0 0 600 cccc ./4711/bobonly#' "$tmp/state.good" > "$tmp/state.owner"
rejects "a file of another owner" "owned by 0, not custodio" acct_state_problems "$tmp/state.owner" 1000 4711 998
sed 's#^f 998 998 600 aaaa#f 998 998 644 aaaa#' "$tmp/state.good" > "$tmp/state.mode"
rejects "a file with another mode" "has mode 644, expected 600" acct_state_problems "$tmp/state.mode" 1000 4711 998
sed 's#^d 998 998 700 - ./4711#d 998 998 755 - ./4711#' "$tmp/state.good" > "$tmp/state.dir"
rejects "a directory with another mode" "./4711 has mode 755" acct_state_problems "$tmp/state.dir" 1000 4711 998
sed 's#dddd#bbbb#' "$tmp/state.good" > "$tmp/state.same"
rejects "the same file for two owners" "hold the same file" acct_state_problems "$tmp/state.same" 1000 4711 998
grep -v 4711 "$tmp/state.good" > "$tmp/state.nobob"
rejects "no entries for bob" "no file ./4711/bobonly" acct_state_problems "$tmp/state.nobob" 1000 4711 998
grep -v '4711/rsa1-cert' "$tmp/state.good" > "$tmp/state.nocert"
rejects "a key without its certificate file" "no file ./4711/rsa1-cert" acct_state_problems "$tmp/state.nocert" 1000 4711 998
# signatures
variant norequest; rm "$tmp/v-norequest/sign/bob-rsa1.requests"
rejects "a missing request" "bob: the signature with rsa1 made 'no' requests" acct_sign_problems "$tmp/v-norequest" bob
variant tworequests; echo 2 > "$tmp/v-tworequests/sign/alice-ec1.requests"
rejects "two requests" "alice: the signature with ec1 made '2' requests" acct_sign_problems "$tmp/v-tworequests" alice
variant crosssig; cp "$A/sign/alice-rsa1.sig" "$tmp/v-crosssig/sign/bob-rsa1.sig"
rejects "bob's signature made with alice's key" "bob: the signature with rsa1 does not verify" acct_sign_problems "$tmp/v-crosssig" bob
variant bothcert; cp "$A/after/alice-rsa1.der" "$tmp/v-bothcert/after/bob-rsa1.der"; cp "$A/sign/alice-rsa1.sig" "$tmp/v-bothcert/sign/bob-rsa1.sig"
rejects "a signature that verifies against the other's certificate" "verifies against alice's rsa1" acct_sign_problems "$tmp/v-bothcert" bob
variant nosig; rm "$tmp/v-nosig/sign/alice-rsa1.sig"
rejects "no signature" "alice: no signature with rsa1" acct_sign_problems "$tmp/v-nosig" alice
variant deniedok; echo "0 1 64" > "$tmp/v-deniedok/sign/alice-denied"
rejects "a denied signature that worked" "did not fail" acct_sign_problems "$tmp/v-deniedok" alice
rejects "a denied signature that wrote" "wrote '64' bytes" acct_sign_problems "$tmp/v-deniedok" alice
variant deniednoask; echo "1 0 0" > "$tmp/v-deniednoask/sign/bob-denied"
rejects "a denied signature never asked" "bob: the denied signature made '0' requests" acct_sign_problems "$tmp/v-deniednoask" bob
variant nodenied; rm "$tmp/v-nodenied/sign/bob-denied"
rejects "no record of the denied signature" "no record of the denied" acct_sign_problems "$tmp/v-nodenied" bob
exit "$failures"
