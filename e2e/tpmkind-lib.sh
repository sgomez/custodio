# shellcheck shell=bash
# Sourced by tpmkind-run.sh and tpmkind-selftest.sh (F133): what the tpm-kind-* cases need besides tpmkind.py.
TK_PASSWORD=e2e-password

# fixture_problems P12 rsa|ec: the key inside the .p12 is RSA with a 2048-bit modulus, or EC on P-256, as OpenSSL reads it (not as the file is named)
fixture_problems() {
    local text
    text=$(openssl pkcs12 -in "$1" -passin "pass:$TK_PASSWORD" -nocerts -nodes 2> /dev/null | openssl pkey -noout -text 2> /dev/null) || { echo "$1: OpenSSL cannot read the key"; return; }
    case $2 in
    rsa) grep -qE '^(Private-Key|RSA Private-Key): \(2048 bit' <<< "$text" && grep -q '^modulus:' <<< "$text" || echo "$1: not an RSA key of 2048 bits" ;;
    ec) grep -q '^ASN1 OID: prime256v1$' <<< "$text" || echo "$1: not an EC key on P-256" ;;
    *) echo "fixture_problems: unknown type $2" ;;
    esac
}

# tk_make DIR [NAME]: DIR/rsa.p12 and DIR/ec.p12 (the key never stays on disk); NAME (default tpm-kind) is in the subject and the friendly name
tk_make() {
    local d=$1 n=${2:-tpm-kind} t
    for t in rsa ec; do
        if [ "$t" = rsa ]; then openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$d/$t.key" 2> /dev/null
        else openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$d/$t.key" 2> /dev/null; fi
        openssl req -new -x509 -key "$d/$t.key" -subj "/CN=custodio e2e $n $t" -days 30 -out "$d/$t.crt"
        openssl pkcs12 -export -inkey "$d/$t.key" -in "$d/$t.crt" -name "$n-$t" -passout "pass:$TK_PASSWORD" -out "$d/$t.p12"
        rm -f "$d/$t.key"
    done
}

# tpmkind_judge MODE DIR JOURNAL_PROBLEMS (F161): judges the files of the step in DIR and reports (case_run) the cases that have no problem. The problems of the others are
# collected in TK_PROBLEMS, one block per case (empty when all is right). MODE is the mode of tpmkind.py: swtpm (container; kind tpm), full or lacking (a VM run).
TK_PROBLEMS=''
tpmkind_judge() {
    local m=$1 d=$2 jp=$3 here
    here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    TK_PROBLEMS=''
    tk_one() { # CASE PROBLEMS: the case is reported when it has no problem
        local p
        p=$(printf '%s\n' "$2" | sed '/^$/d')
        if [ -z "$p" ]; then case_run "$1"; else TK_PROBLEMS="$TK_PROBLEMS
$1:
$p"; fi
    }
    tk_py() { python3 -I "$here/tpmkind.py" --mode "$m" "$@"; }
    tk_one tpm-kind-import-rsa "$(tk_py import "$d/import-rsa.out" tk-rsa rsa2048)"
    tk_one tpm-kind-import-ec "$(tk_py import "$d/import-ec.out" tk-ec ecdsa-p256)"
    tk_one tpm-kind-api-list "$(tk_py api "$d/api.out" tk-rsa:rsa2048 tk-ec:ecdsa-p256)"
    tk_one tpm-kind-cli-list "$(tk_py cli "$d/cli.out" tk-rsa:rsa2048 tk-ec:ecdsa-p256)"
    tk_one tpm-kind-journal "$jp"
    if grep -qE '^tk-(rsa|ec)	' "$d/api-after.out"; then TK_PROBLEMS="$TK_PROBLEMS
end:
a key of the cases is still listed after the deletes"; fi
}
