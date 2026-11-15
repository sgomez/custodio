#!/usr/bin/env bash
# scripts/list-shell-scripts.sh lists tracked shell scripts by extension or shebang, whatever their file names.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-shell-scripts: $*" >&2; fail=1; }

git -C "$tmp" init -q
mkdir -p "$tmp/pkg/deb" "$tmp/dir"
printf '#!/bin/sh\nexit 0\n' > "$tmp/pkg/deb/postinst"
printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/pkg/post_install"
printf '#!/bin/dash\nexit 0\n' > "$tmp/pkg/dash-script"
printf 'exit 0\n' > "$tmp/plain.sh"
printf '#!/usr/bin/env python3\nprint(1)\n' > "$tmp/tool.py"
printf '#!/usr/bin/env python3\nprint(1)\n' > "$tmp/pytool"
printf 'just text with sh in it\n' > "$tmp/README"
printf 'echo "#!/bin/sh"\n' > "$tmp/notshebang"
ln -s dir "$tmp/link"
git -C "$tmp" add -A

got=$(cd "$tmp" && "$ROOT/scripts/list-shell-scripts.sh" | sort)
want=$(printf '%s\n' pkg/deb/postinst pkg/dash-script pkg/post_install plain.sh | sort)
[ "$got" = "$want" ] || bad "listed: $(echo "$got" | tr '\n' ' ') wanted: $(echo "$want" | tr '\n' ' ')"

# Every maintainer script of the repository is covered.
repo=$(cd "$ROOT" && scripts/list-shell-scripts.sh)
for f in packaging/deb/postinst packaging/deb/prerm packaging/deb/postrm packaging/rpm/post packaging/arch/post_install packaging/arch/post_upgrade \
    packaging/deb/preinst packaging/rpm/pre packaging/arch/pre_install packaging/arch/pre_upgrade packaging/arch/custodio-bus-check packaging/bus-check.sh; do
    grep -qx "$f" <<<"$repo" || bad "$f is not covered"
done

exit "$fail"
