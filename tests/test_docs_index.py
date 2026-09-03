"""Tests for the tool that builds the published documentation index.

This code runs once per release, in a workflow, where a mistake is only noticed after the
fact and shows up as a broken or misleading documentation site. That is a good reason to
test it here rather than by publishing and looking.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import build_docs_index


class TestUpdateVersions(unittest.TestCase):
    def test_the_first_release_becomes_the_latest(self):
        versions = build_docs_index.update_versions([], "1.0.0", is_release=True)
        self.assertEqual(versions[0]["version"], "1.0.0")
        self.assertEqual(versions[0]["tags"], ["latest"])

    def test_a_newer_release_takes_the_latest_tag_over(self):
        versions = build_docs_index.update_versions([], "1.0.0", is_release=True)
        versions = build_docs_index.update_versions(versions, "1.1.0", is_release=True)
        tags = {version["path"]: version["tags"] for version in versions}
        self.assertEqual(tags["1.1.0"], ["latest"])
        self.assertEqual(tags["1.0.0"], [])

    def test_an_older_release_published_late_does_not_steal_latest(self):
        """A patch to an old line is still an older version than the newest one."""
        versions = build_docs_index.update_versions([], "1.1.0", is_release=True)
        versions = build_docs_index.update_versions(versions, "1.0.1", is_release=True)
        tags = {version["path"]: version["tags"] for version in versions}
        self.assertEqual(tags["1.1.0"], ["latest"])
        self.assertEqual(tags["1.0.1"], [])

    def test_versions_are_compared_as_numbers_not_as_text(self):
        """As text, '1.10.0' sorts before '1.9.0', which would be wrong."""
        versions = build_docs_index.update_versions([], "1.9.0", is_release=True)
        versions = build_docs_index.update_versions(versions, "1.10.0", is_release=True)
        tags = {version["path"]: version["tags"] for version in versions}
        self.assertEqual(tags["1.10.0"], ["latest"])
        self.assertEqual(tags["1.9.0"], [])

    def test_the_development_build_is_never_the_latest(self):
        versions = build_docs_index.update_versions([], "1.0.0", is_release=True)
        versions = build_docs_index.update_versions(versions, "dev", is_release=False)
        tags = {version["path"]: version["tags"] for version in versions}
        self.assertEqual(tags["dev"], ["unreleased"])
        self.assertEqual(tags["1.0.0"], ["latest"])

    def test_publishing_the_same_path_twice_replaces_its_entry(self):
        """main is published on every push, and must not accumulate entries."""
        versions = build_docs_index.update_versions([], "dev", is_release=False)
        versions = build_docs_index.update_versions(versions, "dev", is_release=False)
        self.assertEqual(len(versions), 1)

    def test_a_release_published_twice_replaces_its_entry(self):
        versions = build_docs_index.update_versions([], "1.0.0", is_release=True)
        versions = build_docs_index.update_versions(versions, "1.0.0", is_release=True)
        self.assertEqual(len(versions), 1)
        self.assertEqual(versions[0]["tags"], ["latest"])


class TestRendering(unittest.TestCase):
    def test_versions_are_listed_newest_first_with_development_above_them(self):
        versions = [
            {"version": "1.0.0", "path": "1.0.0", "tags": []},
            {"version": "main (unreleased)", "path": "dev", "tags": ["unreleased"]},
            {"version": "1.1.0", "path": "1.1.0", "tags": ["latest"]},
        ]
        versions.sort(key=build_docs_index._sort_key)
        self.assertEqual(
            [version["path"] for version in versions], ["dev", "1.1.0", "1.0.0"]
        )

    def test_each_version_links_to_its_own_page(self):
        page = build_docs_index.render(
            [{"version": "1.0.0", "path": "1.0.0", "tags": ["latest"]}]
        )
        self.assertIn('href="1.0.0/MitmLibraryKeywords.html"', page)
        self.assertIn("latest", page)

    def test_an_empty_site_says_so_rather_than_rendering_nothing(self):
        self.assertIn("No documentation has been published", build_docs_index.render([]))

    def test_the_page_explains_why_older_versions_are_missing(self):
        """A gap with no explanation reads as something broken."""
        page = build_docs_index.render([])
        self.assertIn("before 1.0.0 are not published", page)

    def test_version_names_are_escaped(self):
        """The name comes from a tag, and a tag can contain anything."""
        page = build_docs_index.render(
            [{"version": "<script>", "path": "x", "tags": []}]
        )
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)


class TestCommandLine(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())
        self.versions = self.directory / "versions.json"
        self.index = self.directory / "index.html"

    def test_a_first_run_creates_both_files(self):
        """The very first publish has no versions.json to read."""
        build_docs_index.main(
            [str(self.versions), str(self.index), "--add", "1.0.0", "--release"]
        )
        self.assertTrue(self.index.exists())
        self.assertEqual(json.loads(self.versions.read_text())[0]["path"], "1.0.0")

    def test_a_later_run_keeps_what_was_published_before(self):
        build_docs_index.main(
            [str(self.versions), str(self.index), "--add", "1.0.0", "--release"]
        )
        build_docs_index.main([str(self.versions), str(self.index), "--add", "dev"])
        paths = {entry["path"] for entry in json.loads(self.versions.read_text())}
        self.assertEqual(paths, {"1.0.0", "dev"})
        self.assertIn('href="1.0.0/MitmLibraryKeywords.html"', self.index.read_text())

    def test_rendering_without_adding_anything_leaves_the_list_alone(self):
        build_docs_index.main(
            [str(self.versions), str(self.index), "--add", "1.0.0", "--release"]
        )
        before = self.versions.read_text()
        build_docs_index.main([str(self.versions), str(self.index)])
        self.assertEqual(self.versions.read_text(), before)


if __name__ == "__main__":
    unittest.main()
