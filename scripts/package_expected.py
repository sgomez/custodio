"""What the package gate expects (see check_packages.py). Taken from the assets of M1's .deb, not from nfpm.yaml."""

# The service binary of each format (F61): where its distribution wants internal binaries. Arch has no /usr/libexec.
DAEMON = {
    "deb": "/usr/libexec/custodio/custodiod",
    "rpm": "/usr/libexec/custodio/custodiod",
    "arch": "/usr/lib/custodio/custodiod",
}

# Installed files of every package, the service binary apart (DAEMON): path -> mode.
FILES = {
    "/usr/bin/custodio": 0o755,
    "/usr/lib/custodio/libcustodio_pkcs11.so": 0o644,
    "/usr/lib/systemd/system/custodio.service": 0o644,
    "/usr/lib/sysusers.d/custodio.conf": 0o644,
    "/usr/lib/tmpfiles.d/custodio.conf": 0o644,
    "/usr/share/dbus-1/system.d/com.rfirma.Custodio1.conf": 0o644,
    "/usr/share/dbus-1/system-services/com.rfirma.Custodio1.service": 0o644,
    "/usr/share/polkit-1/actions/com.rfirma.custodio.policy": 0o644,
    "/usr/share/p11-kit/modules/custodio.module": 0o644,
    "/usr/lib/systemd/catalog/custodio.catalog": 0o644,
    "/usr/share/licenses/custodio/LICENSE": 0o644,
    "/usr/share/doc/custodio/copyright": 0o644,
    "/usr/share/man/man1/custodio.1.gz": 0o644,
    "/usr/share/doc/custodio/changelog.Debian.gz": 0o644,
}

# Files only the Arch package installs (nfpm `packager: archlinux`): the alpm hook that refuses an upgrade or reinstall while the (F58: and the restart hook)
# system bus lacks ProcessFD, and the check it runs (F42). packaging/parity-exceptions.txt lists them.
ARCH_ONLY_FILES = {
    "/usr/share/libalpm/hooks/custodio-bus-check.hook": 0o644,
    "/usr/share/libalpm/scripts/custodio-bus-check": 0o755,
    "/usr/share/libalpm/hooks/zz-custodio-restart.hook": 0o644,
}

# Directories only the rpm lists (nfpm `type: dir`, `packager: rpm`): rpm owns no directory it is not told about, so without these `dnf remove`
# leaves them behind (F49); dpkg and pacman own the parents of the files they list. Path -> mode.
RPM_ONLY_DIRS = {
    "/usr/lib/custodio": 0o755,
    "/usr/libexec/custodio": 0o755,
    "/usr/share/doc/custodio": 0o755,
    "/usr/share/licenses/custodio": 0o755,
}

UNIT = "/usr/lib/systemd/system/custodio.service"
ACTIVATION = "/usr/share/dbus-1/system-services/com.rfirma.Custodio1.service"
ACTIVATION_LINES = ("Exec=/bin/false", "SystemdService=custodio.service")

# Keys an `overrides.<format>` block of nfpm.yaml may hold: metadata, dependency names and script file paths.
OVERRIDE_KEYS = {"depends", "provides", "conflicts", "replaces", "recommends", "scripts", "deb", "rpm", "apk", "archlinux"}

# Formats: label used in messages, nfpm name, package glob.
FORMATS = (("deb", "deb", "*.deb"), ("rpm", "rpm", "*.rpm"), ("arch", "archlinux", "*.pkg.tar.zst"))

# Dependencies every package must declare, exactly as the format writes them (whitespace normalised). libc and libgcc are
# listed because the Rust binaries always link them; nfpm does not compute shared-library dependencies.
DEPS = {
    "deb": ["libc6", "libgcc-s1", "polkitd (>= 124)", "dbus-system-bus", "p11-kit"],
    "rpm": ["glibc", "libgcc", "polkit >= 124", "systemd", "dbus", "p11-kit"],
    "arch": ["glibc", "gcc-libs", "polkit>=124", "systemd", "dbus", "p11-kit"],
}
# The deb's Pre-Depends field, entry by entry, exactly as dpkg-deb -f writes it. systemd is here and not in Depends because the preinst runs
# systemd-sysusers and dpkg guarantees Depends only for the postinst (docs/decisions.md, F43). Only the deb has the field.
PRE_DEPS = {"deb": ["systemd"]}
# Names that must not appear as a dependency: the unversioned polkit of the old package, the M1 bare dbus, the wrong polkit.
FORBIDDEN_DEPS = {"deb": {"polkit", "dbus"}, "rpm": {"polkitd"}, "arch": {"polkitd"}}

# NEEDED soname -> package name per format (deb, rpm, arch). A soname missing here fails the gate.
NEEDED = {
    "libc.so.6": ("libc6", "glibc", "glibc"),
    "libm.so.6": ("libc6", "glibc", "glibc"),
    "libdl.so.2": ("libc6", "glibc", "glibc"),
    "libpthread.so.0": ("libc6", "glibc", "glibc"),
    "librt.so.1": ("libc6", "glibc", "glibc"),
    "libgcc_s.so.1": ("libgcc-s1", "libgcc", "gcc-libs"),
}
# The dynamic loader (PT_INTERP) is shipped by the glibc package that libc.so.6 already requires.
NEEDED_EXEMPT = {"ld-linux-x86-64.so.2"}
ELF_FILES = ("/usr/bin/custodio", "/usr/lib/custodio/libcustodio_pkcs11.so")  # and the DAEMON of the format

# Lifecycle scripts per format: exactly these exist (deb maintainer scripts, rpm scriptlet tags, Arch .INSTALL functions).
DEB_SCRIPTS = {"preinst", "postinst", "prerm", "postrm"}
RPM_SCRIPTS = {"pre", "post", "preun", "postun"}
ARCH_FUNCTIONS = {"pre_install", "pre_upgrade", "post_install", "post_upgrade", "pre_remove", "post_remove"}
# The check and the account creation embedded in the pre scripts are functions of their own in the .INSTALL (F42, F58); they are not lifecycle functions.
ARCH_HELPERS = {"custodio_bus_check", "custodio_create_account"}
