"""Rewrite README.md for the PyPI page, in place, before a release build.

PyPI shows the README without the repository around it, so relative links
and images break there. This turns them into absolute GitHub URLs at the
release tag: images to raw.githubusercontent.com, other links to the file
on github.com. PyPI also drops <picture> and <source>, so each <picture> is
replaced by its light <img>.

Usage: python scripts/pypi_readme.py v0.3.0
Run it only in the release job; the committed README stays relative.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = "DCchoudhury15/Taintward"


def rewrite(text: str, ref: str) -> str:
    raw = f"https://raw.githubusercontent.com/{REPO}/{ref}/"
    blob = f"https://github.com/{REPO}/blob/{ref}/"

    def absolute(url: str, base: str) -> str:
        if re.match(r"^[a-z][a-z0-9+.-]*:|^#|^/", url, re.I):
            return url
        return base + url.removeprefix("./")

    # <picture>...<img ...></picture> -> the <img> alone
    text = re.sub(r"<picture>.*?(<img\b[^>]*>).*?</picture>", r"\1", text, flags=re.S)
    text = re.sub(r'(<img\b[^>]*\bsrc=")([^"]+)"',
                  lambda m: f'{m.group(1)}{absolute(m.group(2), raw)}"', text)
    text = re.sub(r'(<a\b[^>]*\bhref=")([^"]+)"',
                  lambda m: f'{m.group(1)}{absolute(m.group(2), blob)}"', text)
    # markdown images first, then links
    text = re.sub(r"!\[([^\]]*)\]\(([^)\s]+)\)",
                  lambda m: f"![{m.group(1)}]({absolute(m.group(2), raw)})", text)
    text = re.sub(r"(?<!!)\[([^\]]*)\]\(([^)\s]+)\)",
                  lambda m: f"[{m.group(1)}]({absolute(m.group(2), blob)})", text)
    return text


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python scripts/pypi_readme.py <tag>", file=sys.stderr)
        return 2
    path = Path("README.md")
    path.write_text(rewrite(path.read_text(encoding="utf-8"), sys.argv[1]), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
