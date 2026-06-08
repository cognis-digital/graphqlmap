"""Smoke tests for GRAPHQLMAP. No network. Pure stdlib + unittest.

The test builds its own introspection fixture (rather than depending on the
shared demos/ directory) so it is fully self-contained.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graphqlmap import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    Severity,
    analyze_introspection,
    load_introspection,
)
from graphqlmap.cli import main, _render_html  # noqa: E402


FIXTURE = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "subscriptionType": None,
            "directives": [{"name": "include"}, {"name": "skip"}],
            "types": [
                {"kind": "OBJECT", "name": "Query", "fields": [
                    {"name": "me", "type": {"kind": "OBJECT", "name": "User", "ofType": None},
                     "isDeprecated": False},
                ]},
                {"kind": "OBJECT", "name": "Mutation", "fields": [
                    {"name": "deleteUser", "type": {"kind": "SCALAR", "name": "Boolean", "ofType": None},
                     "isDeprecated": False},
                    {"name": "resetPassword", "type": {"kind": "SCALAR", "name": "Boolean", "ofType": None},
                     "isDeprecated": False},
                    {"name": "updateUserRole", "type": {"kind": "OBJECT", "name": "User", "ofType": None},
                     "isDeprecated": False},
                ]},
                {"kind": "OBJECT", "name": "User", "fields": [
                    {"name": "id", "type": {"kind": "SCALAR", "name": "ID", "ofType": None},
                     "isDeprecated": False},
                    {"name": "passwordHash", "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                     "isDeprecated": False},
                    {"name": "apiKey", "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                     "isDeprecated": False},
                    {"name": "ssn", "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                     "isDeprecated": False},
                    {"name": "legacyToken", "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                     "isDeprecated": True},
                    {"name": "orders", "type": {"kind": "LIST", "name": None,
                     "ofType": {"kind": "OBJECT", "name": "Order", "ofType": None}}, "isDeprecated": False},
                ]},
                {"kind": "OBJECT", "name": "Order", "fields": [
                    {"name": "id", "type": {"kind": "SCALAR", "name": "ID", "ofType": None},
                     "isDeprecated": False},
                    {"name": "creditCardNumber", "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                     "isDeprecated": False},
                    {"name": "owner", "type": {"kind": "OBJECT", "name": "User", "ofType": None},
                     "isDeprecated": False},
                ]},
            ],
        }
    }
}


def _schema():
    return FIXTURE["data"]["__schema"]


def _write_fixture(directory):
    path = os.path.join(directory, "introspection.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(FIXTURE, fh)
    return path


class TestCore(unittest.TestCase):
    def test_exports(self):
        self.assertEqual(TOOL_NAME, "graphqlmap")
        self.assertTrue(TOOL_VERSION)

    def test_load_introspection_envelope(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_fixture(td)
            schema = load_introspection(path)
            self.assertEqual(schema["queryType"]["name"], "Query")

    def test_finds_credentials(self):
        report = analyze_introspection(_schema())
        crit = {f.location for f in report.findings if f.severity == Severity.CRITICAL}
        self.assertIn("User.passwordHash", crit)
        self.assertIn("User.apiKey", crit)

    def test_finds_dangerous_mutations(self):
        report = analyze_introspection(_schema())
        titles = " ".join(f.title for f in report.findings)
        self.assertIn("deleteUser", titles)
        self.assertIn("resetPassword", titles)
        self.assertIn("updateUserRole", titles)

    def test_pii_severity(self):
        report = analyze_introspection(_schema())
        by_loc = {f.location: f for f in report.findings}
        self.assertEqual(by_loc["User.ssn"].severity, Severity.HIGH)
        self.assertEqual(by_loc["Order.creditCardNumber"].severity, Severity.HIGH)

    def test_deprecated_field_info(self):
        report = analyze_introspection(_schema())
        dep = [f for f in report.findings if "Deprecated" in f.title]
        self.assertEqual(len(dep), 1)
        self.assertEqual(dep[0].severity, Severity.INFO)

    def test_missing_authz_directive(self):
        report = analyze_introspection(_schema())
        self.assertTrue(any("authorization directive" in f.title.lower()
                            for f in report.findings))

    def test_depth_threshold_flags(self):
        report = analyze_introspection(_schema(), depth_threshold=2)
        self.assertTrue(any("nesting depth" in f.title for f in report.findings))

    def test_max_severity_and_exit_signal(self):
        report = analyze_introspection(_schema())
        self.assertEqual(report.max_severity, Severity.CRITICAL)
        self.assertTrue(report.has_findings(Severity.HIGH))

    def test_serialization_roundtrip(self):
        report = analyze_introspection(_schema())
        d = report.to_dict()
        json.dumps(d)
        self.assertEqual(d["tool"], "graphqlmap")
        self.assertIn("severity_counts", d)


class TestCLI(unittest.TestCase):
    def test_analyze_json_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_fixture(td)
            rc = main(["analyze", path, "--format", "json"])
            self.assertEqual(rc, 1)

    def test_html_output_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_fixture(td)
            out = os.path.join(td, "r.html")
            rc = main(["analyze", path, "--format", "html", "-o", out])
            self.assertEqual(rc, 1)
            with open(out, encoding="utf-8") as fh:
                body = fh.read()
            self.assertIn("<!DOCTYPE html>", body)
            self.assertIn("CRITICAL", body)

    def test_fail_on_critical(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_fixture(td)
            rc = main(["analyze", path, "--format", "json", "--fail-on", "CRITICAL"])
            self.assertEqual(rc, 1)

    def test_missing_file_returns_2(self):
        rc = main(["analyze", os.path.join("nope", "missing.json")])
        self.assertEqual(rc, 2)

    def test_html_renderer(self):
        out = _render_html(analyze_introspection(_schema()))
        self.assertIn("graphqlmap", out)
        self.assertIn("</html>", out)


if __name__ == "__main__":
    unittest.main()
