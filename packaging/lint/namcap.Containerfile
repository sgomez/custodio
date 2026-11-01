# namcap for `just package-lint` (F38). BASE, ALA_DATE and NAMCAP come from pins.txt. The only pacman mirror is a
# dated Arch Linux Archive snapshot, so the pinned version stays installable.
ARG BASE
FROM ${BASE}
ARG ALA_DATE
ARG NAMCAP
# --disable-sandbox: pacman cannot chown its download directory inside a nested rootless container.
RUN echo "Server = https://archive.archlinux.org/repos/${ALA_DATE}/\$repo/os/\$arch" > /etc/pacman.d/mirrorlist \
    && pacman --disable-sandbox -Syyuu --noconfirm \
    && pacman --disable-sandbox -S --noconfirm "namcap=${NAMCAP}" \
    && test "$(pacman -Q namcap | cut -d' ' -f2)" = "${NAMCAP}"
