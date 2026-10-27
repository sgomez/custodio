#!/usr/bin/env bash
# Shared helpers for the harness scripts. Source it; do not run it.

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
die() { log "$1" >&2; exit "${2:-1}"; }

sha() {
  if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi | cut -d' ' -f1
}

# What a person approves. The features hash ignores `passes`, which the loop changes.
hash_spec() { sha < SPEC.md; }
hash_features() { jq -S 'del(.features[].passes)' features.json | sha; }

approved() {
  [ "${AUTO_APPROVE:-0}" = 1 ] && return 0
  [ -f APPROVALS ] && grep -qx "$1 $("hash_$1")" APPROVALS
}

tracked_changes() { [ -n "$(git status --porcelain --untracked-files=no)" ]; }

commit() { git add -- "${@:2}" && git commit -q -m "$1"; }
