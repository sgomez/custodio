#!/usr/bin/env bash
# The checks of the journal-ops judgements (jo.py and the sweep of journal.py) on made-up evidence, good and bad (F94). Container-free; the guest runs it first.
# JO_DOC names the document of the queries (default: /e2e-docs/audit.md, which e2e/run.sh mounts in the guest, else docs/audit.md of this tree).
set -euo pipefail
audit_doc() { if [ -f /e2e-docs/audit.md ]; then echo /e2e-docs/audit.md; else echo "$here/../docs/audit.md"; fi; }
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
python3 -I "$here/jo-selftest.py" "$here" "${JO_DOC:-$(audit_doc)}"
