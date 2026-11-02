#!/usr/bin/env bash
# The checks of the appid judgements (appid.py, with jo.py under it) on made-up evidence, good and bad (F95). Container-free; the guest runs it first.
# APPID_DOC names the document of the queries (default: /e2e-docs/audit.md, which e2e/run.sh mounts in the guest, else docs/audit.md of this tree).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
audit_doc() { if [ -f /e2e-docs/audit.md ]; then echo /e2e-docs/audit.md; else echo "$here/../docs/audit.md"; fi; }
python3 -I "$here/appid-selftest.py" "$here" "${APPID_DOC:-$(audit_doc)}"
