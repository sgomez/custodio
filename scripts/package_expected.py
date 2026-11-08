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

# TPM2 Software Stack (F125). Package names confirmed in the dev container (debian13: dpkg -S, apt-cache depends) and on packages.ubuntu.com
# (noble and resolute carry the same t64 names). The rpm and Arch packages are inferred: `tpm2-tss` owns every libtss2-*.so.0 there (F109
# found it owns the udev rules and brings the `tss` group on fedora44, alma10 and arch).
# The package that creates the `tss` group (F109); the unit's SupplementaryGroups=tss needs it, or the unit does not start.
TSS_GROUP = {"deb": "tpm-udev", "rpm": "tpm2-tss", "arch": "tpm2-tss"}
# libtss2-tcti-device is loaded by dlopen (libtss2-tctildr), so no NEEDED entry names it: the deb declares it besides the three linked
# libraries (libtss2-tctildr0t64 depends on it and on tpm-udev too, checked with apt-cache depends on debian13 and packages.ubuntu.com
# noble); the rpm and Arch packages ship it inside tpm2-tss. libtss2-rc0t64 is also a dlopen one: systemd loads libtss2-rc and Ubuntu only
# recommends the package (F154).
TSS_DLOPEN = {"deb": ["libtss2-tcti-device0t64", "libtss2-rc0t64"], "rpm": [], "arch": []}
# The systemd bound per format (docs/findings/F110.md, F154): every package requires 257, the first systemd with the user-scoped credential
# calls over Varlink that the service uses; ubuntu2404 (255) is not supported. The deb carries it in Pre-Depends (PRE_DEPS), the others in
# their dependency list.
TSS_NEEDED = {  # soname -> package (deb, rpm, arch); check-tss-deps.sh reads these
    "libtss2-esys.so.0": ("libtss2-esys-3.0.2-0t64", "tpm2-tss", "tpm2-tss"),
    "libtss2-tctildr.so.0": ("libtss2-tctildr0t64", "tpm2-tss", "tpm2-tss"),
    "libtss2-mu.so.0": ("libtss2-mu-4.0.1-0t64", "tpm2-tss", "tpm2-tss"),
}
# What each format declares for the stack: the packages of the linked sonames (once each), the dlopen ones and the one that creates `tss`.
TSS_LIBS = {
    label: list(dict.fromkeys([names[i] for names in TSS_NEEDED.values()] + TSS_DLOPEN[label] + [TSS_GROUP[label]]))
    for i, label in enumerate(("deb", "rpm", "arch"))
}
SYSTEMD = {"deb": "systemd (>= 257)", "rpm": "systemd >= 257", "arch": "systemd>=257"}

# Dependencies every package must declare, exactly as the format writes them (whitespace normalised). libc and libgcc are
# listed because the Rust binaries always link them; nfpm does not compute shared-library dependencies.
DEPS = {
    "deb": ["libc6", "libgcc-s1", "polkitd (>= 124)", "dbus-system-bus", "p11-kit", *TSS_LIBS["deb"]],
    "rpm": ["glibc", "libgcc", "polkit >= 124", SYSTEMD["rpm"], "dbus", "p11-kit", "util-linux", *TSS_LIBS["rpm"]],
    "arch": ["glibc", "gcc-libs", "polkit>=124", SYSTEMD["arch"], "dbus", "p11-kit", "util-linux", *TSS_LIBS["arch"]],
}
# The CLI runs `setpriv --pdeathsig=KILL -- pkttyagent ...` (F89). setpriv comes from util-linux and pkttyagent from the polkit package
# the lists above already carry (polkitd on Debian, polkit on Fedora/Alma/Arch), so only rpm and arch add util-linux. The deb leaves it
# out on purpose: util-linux is Essential on Debian and Ubuntu, and an unversioned dependency on an Essential package is a lintian
# finding (see FORBIDDEN_DEPS). Probes (F90): `dnf provides /usr/bin/setpriv` is util-linux on alma10 and fedora44, `pacman -F` util-linux.
# The deb's Pre-Depends field, entry by entry, exactly as dpkg-deb -f writes it. systemd is here and not in Depends because the preinst runs
# systemd-sysusers and dpkg guarantees Depends only for the postinst (docs/decisions.md, F43). Only the deb has the field.
PRE_DEPS = {"deb": [SYSTEMD["deb"]]}
# Names that must not appear as a dependency: the unversioned polkit of the old package, the M1 bare dbus, the wrong polkit.
FORBIDDEN_DEPS = {"deb": {"polkit", "dbus", "util-linux"}, "rpm": {"polkitd"}, "arch": {"polkitd"}}

# NEEDED soname -> package name per format (deb, rpm, arch). A soname missing here fails the gate.
NEEDED = {
    "libc.so.6": ("libc6", "glibc", "glibc"),
    "libm.so.6": ("libc6", "glibc", "glibc"),
    "libdl.so.2": ("libc6", "glibc", "glibc"),
    "libpthread.so.0": ("libc6", "glibc", "glibc"),
    "librt.so.1": ("libc6", "glibc", "glibc"),
    "libgcc_s.so.1": ("libgcc-s1", "libgcc", "gcc-libs"),
    **TSS_NEEDED,
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
