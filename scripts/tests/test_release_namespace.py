"""Test the exact inline guard executed before source checkout."""
from pathlib import Path
import io
import json
import textwrap
import unittest
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[2]
text = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
body = text.split("# BEGIN GATE_RELEASE_NAMESPACE_GUARD\n", 1)[1].split("          # END GATE_RELEASE_NAMESPACE_GUARD", 1)[0]
namespace = {"__name__": "release_guard_fixture"}
exec(compile(textwrap.dedent(body), "inline-release-namespace-guard", "exec"), namespace)
assert_unpublished = namespace["assert_unpublished"]


class ReleaseNamespaceTests(unittest.TestCase):
    def test_only_unreserved_missing_version_is_allowed(self):
        def missing(request, timeout):
            if "/releases?" in request.full_url:
                return io.StringIO("[]")
            raise HTTPError(request.full_url, 404, "missing", {}, None)
        assert_unpublished("org/repo", "1.1.0+nexus.amd64.1", "", missing)

    def test_tagless_draft_is_reserved_on_first_and_later_pages(self):
        for page in (1, 2):
            def inventory(request, timeout):
                if "/releases?" not in request.full_url:
                    raise HTTPError(request.full_url, 404, "missing", {}, None)
                if page == 2 and request.full_url.endswith("&page=1"):
                    return io.StringIO(json.dumps([{"tag_name": "other"}] * 100))
                return io.StringIO(json.dumps([{"tag_name": "v1.1.0+nexus.amd64.1", "draft": True}]))
            with self.assertRaisesRegex(ValueError, "Draft/release version already exists"):
                assert_unpublished("org/repo", "1.1.0+nexus.amd64.1", "", inventory)

    def test_inventory_errors_and_malformed_responses_fail_closed(self):
        for status in (401, 403, 500):
            def denied(request, timeout):
                if "/releases?" not in request.full_url:
                    raise HTTPError(request.full_url, 404, "missing", {}, None)
                raise HTTPError(request.full_url, status, "denied", {}, None)
            with self.assertRaises(ValueError):
                assert_unpublished("org/repo", "0.2.0+n2.riscv64.1", "", denied)
        for body in ("{}", "[null]", "not-json"):
            def malformed(request, timeout):
                if "/releases?" in request.full_url:
                    return io.StringIO(body)
                raise HTTPError(request.full_url, 404, "missing", {}, None)
            with self.assertRaises(ValueError):
                assert_unpublished("org/repo", "0.2.0+n2.riscv64.1", "", malformed)

    def test_guard_precedes_checkout_and_inventory_is_bounded(self):
        self.assertLess(text.index("# BEGIN GATE_RELEASE_NAMESPACE_GUARD"), text.index("- name: Checkout the pinned source"))
        def endless(request, timeout):
            if "/releases?" in request.full_url:
                return io.StringIO(json.dumps([{"tag_name": "other"}] * 100))
            raise HTTPError(request.full_url, 404, "missing", {}, None)
        with self.assertRaisesRegex(ValueError, "limit"):
            assert_unpublished("org/repo", "0.2.0+n2.riscv64.1", "", endless)


if __name__ == "__main__":
    unittest.main()
