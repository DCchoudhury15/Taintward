"""MkDocs hook: turn links to repo files outside docs/ into GitHub links.

Pages link to source files and load test results with relative paths such as
``../taintward/sdk/detect.py`` or ``../loadtest/results/collector.md``. That
works when reading the files on GitHub, but on the built site the target is
not a page. This hook rewrites such a link to the file on GitHub when the
file exists in the repository. Links to missing files are left alone, so
``mkdocs build --strict`` still reports them.
"""

from __future__ import annotations

import posixpath
import re
from pathlib import Path

_LINK = re.compile(r"(\]\()([^)\s]+)(\))")
_FENCE = re.compile(r"^\s*(```|~~~)")


def _rewrite(target: str, page_dir: str, repo_root: Path, docs_dir: Path, base: str) -> str:
    if "://" in target or target.startswith(("#", "/", "mailto:")):
        return target
    path, _, anchor = target.partition("#")
    if not path:
        return target
    joined = posixpath.normpath(posixpath.join(page_dir, path))
    if not joined.startswith("../"):
        return target  # inside docs/, MkDocs checks it
    rel = posixpath.normpath(posixpath.join(docs_dir.name, joined))
    full = repo_root / rel
    if not full.exists():
        return target
    kind = "tree" if full.is_dir() else "blob"
    url = f"{base}/{kind}/main/{rel}"
    return f"{url}#{anchor}" if anchor else url


def on_page_markdown(markdown, page, config, files):
    base = (config.get("repo_url") or "").rstrip("/")
    if not base:
        return markdown
    docs_dir = Path(config["docs_dir"]).resolve()
    repo_root = docs_dir.parent
    page_dir = posixpath.dirname(page.file.src_uri)

    out = []
    in_fence = False
    for line in markdown.split("\n"):
        if _FENCE.match(line):
            in_fence = not in_fence
        if not in_fence:
            line = _LINK.sub(
                lambda m: m.group(1)
                + _rewrite(m.group(2), page_dir, repo_root, docs_dir, base)
                + m.group(3),
                line,
            )
        out.append(line)
    return "\n".join(out)
