# lintian for `just package-lint` (F38). Built by scripts/package-lint.sh with BASE, DEBIAN_SNAPSHOT and
# LINTIAN taken from pins.txt. The only apt source is the dated snapshot, so the pinned version stays installable.
ARG BASE
FROM ${BASE}
ARG DEBIAN_SNAPSHOT
ARG LINTIAN
# http: the base image has no CA bundle; apt checks the signed Release file. APT::Sandbox::User=root and the statoverride
# (man-db wants /var/cache/man owned by `man`): a nested rootless container maps one uid only.
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* \
    && echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ trixie main" \
         > /etc/apt/sources.list.d/snapshot.list \
    && dpkg-statoverride --update --add root root 0755 /var/cache/man \
    && apt-get -o Acquire::Check-Valid-Until=false -o APT::Sandbox::User=root update \
    && apt-get -o APT::Sandbox::User=root install -y --no-install-recommends "lintian=${LINTIAN}" \
    && rm -rf /var/lib/apt/lists/* \
    && test "$(lintian --print-version)" = "${LINTIAN}"
