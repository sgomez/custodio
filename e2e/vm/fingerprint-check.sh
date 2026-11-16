#!/bin/bash
# User side of the polkit cases (F200): asks polkit to authorize an action with the text agent `pkttyagent`, and leaves the marker file $1 when it is approved.
# `pkexec` cannot be used: its in-process agent answers `No session for cookie` under `su` (docs/findings/F200.md). Exit status: pkcheck's.
marker=$1
exec 3< <(pkttyagent --process $$ --notify-fd 1 --fallback)
read -r -n1 -u3 _ # the agent is registered
pkcheck --action-id org.freedesktop.policykit.exec --process $$ -u
rc=$?
if [ "$rc" = 0 ]; then : > "$marker"; fi
exit "$rc"
