"""Keep repository documentation links valid after folder changes."""

import re
import unittest
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parent.parent


class LayoutTests(unittest.TestCase):
    def test_local_markdown_links_resolve(self):
        documents = [*ROOT.glob("*.md"), *ROOT.glob("docs/*.md"),
                     *ROOT.glob("data/*.md"), *ROOT.glob(".codex/*.md")]
        broken = []
        for document in documents:
            for target in re.findall(r"!?\[[^\]]*\]\(([^)]+)\)",
                                     document.read_text(encoding="utf-8")):
                target = target.strip("<>")
                parts = urlsplit(target)
                if parts.scheme or parts.netloc or not parts.path:
                    continue
                resolved = (document.parent / unquote(parts.path)).resolve()
                if not resolved.is_file():
                    broken.append(f"{document.relative_to(ROOT)} -> {target}")
        self.assertEqual(broken, [])


if __name__ == "__main__":
    unittest.main()
