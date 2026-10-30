# rpmlint for `just package-lint` (F38). BASE, RPMLINT and RPMLINT_SHA256 come from pins.txt. The pinned koji
# build is fetched by hash because the updates repository keeps only the newest build. /etc/xdg/rpmlint is emptied
# so no distribution filter applies besides the committed lists.
ARG BASE
FROM ${BASE}
ARG RPMLINT
ARG RPMLINT_KOJI
ARG RPMLINT_SHA256
RUN curl -fsSLo /tmp/rpmlint.rpm "${RPMLINT_KOJI}" \
    && echo "${RPMLINT_SHA256}  /tmp/rpmlint.rpm" | sha256sum -c - \
    && dnf install -y /tmp/rpmlint.rpm \
    && rm -f /tmp/rpmlint.rpm \
    && dnf clean all \
    && rm -f /etc/xdg/rpmlint/*.toml \
    && test "$(rpm -q --qf '%{VERSION}-%{RELEASE}' rpmlint)" = "${RPMLINT}"
