"""Rename the GLIBC_2.34 version requirement of a fixture ELF (run as `python3 -I`).

usage: elf_patch.py SRC DST NEWVERSION   e.g. 2.10 -> GLIBC_2.10
The name is NUL-padded into the slot of "GLIBC_2.34" in .dynstr and must not be longer. The old name must occur exactly
once, so the patch cannot hit a string another entry shares.
"""
import sys

src, dst, version = sys.argv[1:4]
data = open(src, "rb").read()
old, new = b"GLIBC_2.34\0", f"GLIBC_{version}".encode() + b"\0"
if data.count(old) != 1 or len(new) > len(old):
    sys.exit(f"elf_patch: GLIBC_2.34 occurs {data.count(old)} times or GLIBC_{version} is too long")
open(dst, "wb").write(data.replace(old, new.ljust(len(old), b"\0")))
