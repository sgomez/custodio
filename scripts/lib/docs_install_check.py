#!/usr/bin/env python3
"""Checks of docs/install.md for scripts/test-docs-install-register.sh (F186).

  docs_install_check.py order DOC             in "Removing and purging" the `custodio register --remove` block comes
                                              before the block that removes the package
  docs_install_check.py fallback DOC STUBLOG OUTDIR
                                              the manual `modutil` blocks of the "Firefox" section have the form of what
                                              `custodio register` passed to the stub modutil (STUBLOG), but for the options
                                              named in LEFT_OUT; writes add.sh and del.sh to OUTDIR, with the placeholder
                                              `<profile directory>` replaced by the directory in $PROFILE
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import docs_check as dc  # noqa: E402

PLACEHOLDER = "<profile directory>"
LEFT_OUT = ("-force",)  # what register passes and the page leaves to modutil's own question


def section(text, title):
    """The lines of the `## title` section, up to the next `## ` heading outside a fenced block."""
    out, on, fence = [], False, False
    for line in text.split("\n"):
        if line.startswith("```"):
            fence = not fence
        if not fence and line.startswith("## "):
            on = line[3:].strip() == title
        if on:
            out.append(line)
    return "\n".join(out)


def order(doc):
    sec = section(dc.read(doc), "Removing and purging")
    if not sec:
        return ["no section 'Removing and purging'"]
    kinds = []
    for info, body, _ in dc.blocks(sec):
        text = "\n".join(body)
        if info.split()[:1] == ["console"] and "$ custodio register --remove" in text:
            kinds.append("unregister")
        elif re.search(r"\b(apt-get|dnf|pacman|rpm-ostree)\b.*\b(remove|-R|uninstall)\b", text):
            kinds.append("remove")
    if "unregister" not in kinds:
        return ["'Removing and purging' has no `custodio register --remove` block"]
    if "remove" not in kinds:
        return ["'Removing and purging' has no block that removes the package"]
    if kinds.index("unregister") > kinds.index("remove"):
        return ["the `custodio register --remove` block comes after the block that removes the package"]
    return []


def tokens(cmd):
    return cmd.replace("\\\n", " ").split()


def fallback(doc, stublog, outdir):
    sec = section(dc.read(doc), "Firefox")
    cmds = []
    for info, body, _ in dc.blocks(sec):
        if info.split()[:1] == ["bash"] and body and body[0].startswith("modutil "):
            cmds.append(" ".join(body))
    adds = [c for c in cmds if " -add " in c]
    dels = [c for c in cmds if " -delete " in c]
    if len(adds) != 1 or len(dels) != 1:
        return [f"the 'Firefox' section needs one `modutil -add` and one `modutil -delete` block, it has {len(adds)} and {len(dels)}"]
    stub = [ln for ln in dc.read(stublog).split("\n") if ln]
    bad = []
    for word, mine in (("-add", adds[0]), ("-delete", dels[0])):
        # the installed module's profile (the line whose -libfile is under /usr/lib), else the first line
        lines = [ln for ln in stub if f" {word} " in ln]
        lines.sort(key=lambda ln: "-libfile /usr/lib/" not in ln)
        if not lines:
            bad.append(f"register passed no `{word}` to modutil")
            continue
        shown = tokens(mine.replace(PLACEHOLDER, "P"))[1:]
        real = ["sql:P" if t.startswith("sql:") else t for t in tokens(lines[0]) if t not in LEFT_OUT]
        if word == "-add" and "-libfile /usr/lib/" not in lines[0]:
            real = [t for t in real if not t.startswith("/")]  # the host skipped the native profile: the copy's path is not the page's
            shown = [t for t in shown if not t.startswith("/")]
        if shown != real:
            bad.append(f"the page's `modutil {word}` has the options {shown}, `custodio register` passes {real} (left out: {', '.join(LEFT_OUT)})")
    profile = os.environ.get("PROFILE", "")
    for name, cmd in (("add.sh", adds[0]), ("del.sh", dels[0])):
        with open(os.path.join(outdir, name), "w", encoding="utf-8") as f:
            f.write(cmd.replace(PLACEHOLDER, profile) + "\n")
    return bad


def main(argv):
    if len(argv) == 3 and argv[1] == "order":
        bad = order(argv[2])
    elif len(argv) == 5 and argv[1] == "fallback":
        bad = fallback(argv[2], argv[3], argv[4])
    else:
        print(__doc__, file=sys.stderr)
        return 2
    for b in bad:
        print(f"{argv[2]}: {b}", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
