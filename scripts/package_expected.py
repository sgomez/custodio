"""What the package gate expects (see check_packages.py). Taken from the assets of M1's .deb, not from nfpm.yaml."""

# Installed files of every package: path -> mode. /usr/lib/custodio/custodiod is the only path that moved from M1.
FILES = {
    "/usr/lib/custodio/custodiod": 0o755,
    "/usr/bin/custodio": 0o755,
    "/usr/lib/custodio/libcustodio_pkcs11.so": 0o644,
    "/usr/lib/systemd/system/custodio.service": 0o644,
    "/usr/lib/sysusers.d/custodio.conf": 0o644,
    "/usr/share/dbus-1/system.d/com.rfirma.Custodio1.conf": 0o644,
    "/usr/share/dbus-1/system-services/com.rfirma.Custodio1.service": 0o644,
    "/usr/share/polkit-1/actions/com.rfirma.custodio.policy": 0o644,
    "/usr/share/p11-kit/modules/custodio.module": 0o644,
    "/usr/lib/systemd/catalog/custodio.catalog": 0o644,
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
    "deb": ["libc6", "libgcc-s1", "polkitd (>= 124)", "systemd", "dbus-system-bus", "p11-kit"],
    "rpm": ["glibc", "libgcc", "polkit >= 124", "systemd", "dbus", "p11-kit"],
    "arch": ["glibc", "gcc-libs", "polkit>=124", "systemd", "dbus", "p11-kit"],
}
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
ELF_FILES = ("/usr/lib/custodio/custodiod", "/usr/bin/custodio", "/usr/lib/custodio/libcustodio_pkcs11.so")

# Lifecycle scripts per format: exactly these exist (deb maintainer scripts, rpm scriptlet tags, Arch .INSTALL functions).
DEB_SCRIPTS = {"postinst"}
RPM_SCRIPTS = {"post"}
ARCH_FUNCTIONS = {"post_install", "post_upgrade"}
