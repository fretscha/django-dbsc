"""README.md is also the PyPI project page, where relative links resolve against pypi.org and break."""

import re
from pathlib import Path

README = Path(__file__).resolve().parent.parent / "README.md"
LINK = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)")


def test_readme_links_are_absolute():
    relative = [target for target in LINK.findall(README.read_text()) if not target.startswith(("https://", "mailto:"))]

    assert relative == [], f"use absolute https:// URLs in README.md (PyPI can't resolve these): {relative}"
