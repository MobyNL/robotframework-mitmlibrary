"""Builds the landing page for the published keyword documentation.

The documentation is published per version, so a reader can look up the version they
actually have installed rather than whatever happens to be newest. This renders the page
that lists them, from the `versions.json` the publishing workflow maintains.

It lives here rather than inside the workflow so that the page can be tested, and so that
the workflow stays readable.
"""

import argparse
import html
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

DOCUMENT = "MitmLibraryKeywords.html"

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MitmLibrary keyword documentation</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
    line-height: 1.5;
    margin: 0 auto;
    max-width: 44rem;
    padding: 2rem 1.5rem 4rem;
  }}
  h1 {{ margin-bottom: 0.25rem; }}
  p.lead {{ margin-top: 0; opacity: 0.75; }}
  ul {{ list-style: none; padding: 0; }}
  li {{
    align-items: baseline;
    border-top: 1px solid rgba(128, 128, 128, 0.3);
    display: flex;
    gap: 0.75rem;
    padding: 0.6rem 0;
  }}
  li a {{ font-weight: 600; }}
  .tag {{
    border: 1px solid rgba(128, 128, 128, 0.5);
    border-radius: 999px;
    font-size: 0.75rem;
    opacity: 0.8;
    padding: 0.1rem 0.5rem;
  }}
  footer {{ font-size: 0.875rem; margin-top: 2.5rem; opacity: 0.75; }}
</style>
</head>
<body>
<h1>MitmLibrary</h1>
<p class="lead">Keyword documentation, per released version.</p>
<ul>
{entries}
</ul>
<footer>
<p>Versions before 1.0.0 are not published here. The keyword surface was not stable
before then, so an older page would describe an interface that no longer exists; the
<a href="https://github.com/MobyNL/robotframework-mitmlibrary/blob/main/CHANGELOG.md">changelog</a>
records what changed.</p>
<p><a href="https://github.com/MobyNL/robotframework-mitmlibrary">Source on GitHub</a></p>
</footer>
</body>
</html>
"""


def _entry(version: Dict[str, Any]) -> str:
    """Renders one line of the list."""
    name = html.escape(str(version["version"]))
    path = html.escape(str(version["path"]))
    tags = "".join(
        f'<span class="tag">{html.escape(tag)}</span>' for tag in version.get("tags", [])
    )
    return f'  <li><a href="{path}/{DOCUMENT}">{name}</a>{tags}</li>'


def render(versions: List[Dict[str, Any]]) -> str:
    """Renders the landing page for the given versions, newest first."""
    if not versions:
        entries = "  <li>No documentation has been published yet.</li>"
    else:
        entries = "\n".join(_entry(version) for version in versions)
    return TEMPLATE.format(entries=entries)


UNRELEASED = "unreleased"


def update_versions(
    versions: List[Dict[str, Any]], path: str, is_release: bool
) -> List[Dict[str, Any]]:
    """Records a published version, and works out which release is the newest.

    `path` is the directory it was published under: a version number for a release, or
    `dev` for the current main. Publishing the same one twice replaces its entry rather
    than adding a second.
    """
    versions = [version for version in versions if version["path"] != path]
    versions.append(
        {
            "version": path if is_release else "main (unreleased)",
            "path": path,
            "tags": [] if is_release else [UNRELEASED],
        }
    )
    releases = [
        version for version in versions if UNRELEASED not in version.get("tags", [])
    ]
    if releases:
        newest = max(releases, key=lambda version: _release_order(version["path"]))
        for version in releases:
            version["tags"] = ["latest"] if version is newest else []
    return versions


def _release_order(path: str) -> Any:
    """Orders release directories by version number, treating odd ones as oldest."""
    try:
        return tuple(int(part) for part in path.split("."))
    except ValueError:
        return ()


def _sort_key(version: Dict[str, Any]) -> Any:
    """Orders releases newest first, with anything unreleased above them."""
    raw = str(version["version"])
    parts = raw.split(".")
    try:
        return (0, tuple(-int(part) for part in parts))
    except ValueError:
        # 'dev' and anything else that is not a release number.
        return (-1, ())


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("versions", type=Path, help="the versions.json to read and write")
    parser.add_argument("output", type=Path, help="where to write index.html")
    parser.add_argument(
        "--add", help="the directory a version was just published under", default=None
    )
    parser.add_argument(
        "--release",
        action="store_true",
        help="the published version is a release rather than the current main",
    )
    arguments = parser.parse_args(argv)

    versions: List[Dict[str, Any]] = []
    if arguments.versions.exists():
        versions = json.loads(arguments.versions.read_text(encoding="utf-8"))
    if arguments.add is not None:
        versions = update_versions(versions, arguments.add, arguments.release)
        arguments.versions.write_text(
            json.dumps(versions, indent=2) + "\n", encoding="utf-8"
        )

    versions.sort(key=_sort_key)
    arguments.output.write_text(render(versions), encoding="utf-8")
    return 0


if __name__ == "__main__":  # pragma: no cover - entry point
    raise SystemExit(main(sys.argv[1:]))
