"""Sets the workspace version: see set-version.sh. Writes nothing unless every file parses."""
import pathlib
import re
import sys

SEMVER = re.compile(r"\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?")


def main(root, version):
    version = version.removeprefix("v")
    if not SEMVER.fullmatch(version):
        sys.exit(f"set-version: bad version '{version}'")
    root = pathlib.Path(root)
    new = {}

    top = root / "Cargo.toml"
    text = top.read_text()
    out, n = re.subn(r'(?ms)^(\[workspace\.package\]\n(?:(?!\[).*\n)*?version = ")[^"]*(")',
                     rf"\g<1>{version}\g<2>", text, count=1)
    if n != 1:
        sys.exit(f"set-version: no version in [workspace.package] of {top}")
    new[top] = out

    members = set()
    for f in sorted(root.glob("crates/*/Cargo.toml")):
        text = f.read_text()
        name = re.search(r'(?m)^name = "([^"]+)"', text)
        if name and re.search(r"(?m)^version\.workspace = true", text):
            members.add(name.group(1))
        new[f] = re.sub(r'(\{ *path = "[^"]*"[^}\n]*?version = ")[^"]*(")', rf"\g<1>{version}\g<2>", text)

    for f in sorted([root / "Cargo.lock", *root.glob("crates/*/fuzz/Cargo.lock")]):
        if not f.exists():
            continue
        blocks = f.read_text().split("\n[[package]]\n")
        for i, b in enumerate(blocks[1:], 1):
            name = re.search(r'(?m)^name = "([^"]+)"', b)
            if name and name.group(1) in members and not re.search(r"(?m)^source = ", b):
                blocks[i] = re.sub(r'(?m)^version = "[^"]*"$', f'version = "{version}"', b, count=1)
        new[f] = "\n[[package]]\n".join(blocks)

    for f, text in new.items():
        if f.read_text() != text:
            f.write_text(text)
            print(f.relative_to(root))


if __name__ == "__main__":
    main(*sys.argv[1:])
