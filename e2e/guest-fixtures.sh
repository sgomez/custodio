# shellcheck shell=bash
# Sourced by guest.sh: the keys, certificates and files the import step and the cases use (F160: moved out of guest.sh unchanged).
# make_fixtures DIR: writes them into DIR.
make_fixtures() {
    local kind genopt
    for kind in rsa ec; do
        case $kind in
            rsa) genopt=(-algorithm RSA -pkeyopt rsa_keygen_bits:2048) ;;
            ec) genopt=(-algorithm EC -pkeyopt ec_paramgen_curve:P-256) ;;
        esac
        openssl genpkey "${genopt[@]}" -out "$1/$kind.key" 2>/dev/null
        openssl req -new -x509 -key "$1/$kind.key" -subj "/CN=custodio e2e $kind" -days 30 -out "$1/$kind.crt"
        openssl pkcs12 -export -inkey "$1/$kind.key" -in "$1/$kind.crt" -name "${kind}1" \
            -passout pass:e2e-password -out "$1/${kind}1.p12"
    done
    # A CSR for NSS to sign with the custodied RSA key (the CSR's own key is a throwaway).
    openssl req -new -newkey rsa:2048 -nodes -keyout "$1/csr.key" -subj "/CN=e2e subject" -out "$1/csr.pem" 2>/dev/null
    openssl req -in "$1/csr.pem" -outform DER -out "$1/csr.der"
    head -c 32 /dev/urandom > "$1/data.bin"
    for kind in rsa ec; do openssl x509 -in "$1/$kind.crt" -pubkey -noout > "$1/$kind.pub"; done
    chmod 644 "$1"/*
}
