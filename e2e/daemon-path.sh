# shellcheck shell=bash
# Sourced by upgrade-lib.sh and lifecycle-lib.sh. Where each package format installs the service binary (F61): the .deb and the .rpm under
# /usr/libexec, where Debian and Fedora want internal binaries (on Fedora it is bin_t, so the service runs in unconfined_service_t), and the Arch package
# under /usr/lib, because Arch has no /usr/libexec.

# daemon_path FORMAT: where the package of that format installs the daemon; other_daemon_path: where a package of another format does.
daemon_path() {
    case $1 in
    deb | rpm) echo /usr/libexec/custodio/custodiod ;;
    arch) echo /usr/lib/custodio/custodiod ;;
    *) echo "daemon_path: unknown format '$1'" >&2; return 1 ;;
    esac
}
other_daemon_path() {
    case $1 in
    deb | rpm) echo /usr/lib/custodio/custodiod ;;
    arch) echo /usr/libexec/custodio/custodiod ;;
    *) echo "other_daemon_path: unknown format '$1'" >&2; return 1 ;;
    esac
}
# The path of the daemon in the packages that have an old-path fixture (the current M2 .deb and .rpm, F61): where it was before the move.
export OLD_DAEMON_PATH=/usr/lib/custodio/custodiod
