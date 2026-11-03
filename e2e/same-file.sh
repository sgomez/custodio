#!/usr/bin/env bash
# same_file A B: succeeds when both files (or "-" for stdin) have the same content. Uses sha256sum, not cmp: diffutils is not on
# every target image (alma10, arch).
same_file() {
    local a b
    if [ "$1" = "-" ]; then a=$(sha256sum) || return 1; else a=$(sha256sum < "$1") || return 1; fi
    if [ "$2" = "-" ]; then b=$(sha256sum) || return 1; else b=$(sha256sum < "$2") || return 1; fi
    [ "$a" = "$b" ]
}
