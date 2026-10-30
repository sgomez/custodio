"""What the package gate expects (see check_packages.py). Taken from M1's [package.metadata.deb] assets, not from nfpm.yaml."""

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
