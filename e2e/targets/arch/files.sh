#!/usr/bin/env bash
# The files the installed package owns, one path per line (F131: none of them may be a test drop-in of custodio.service).
set -euo pipefail
pacman -Ql custodio | cut -d" " -f2-
