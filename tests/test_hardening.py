"""Tests for input validation, error handling, and edge-case hardening.

Covers: missing file, empty file, bad JSON, malformed schema envelope,
wrong types for analyze_introspection, invalid depth_threshold, and the
CLI --depth-threshold guard.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graphqlmap.core import (
    load_introspection,
    analyze_introspection,
    _extract_schema,
)
from graphqlmap.cli import main


# ---------------------------------------------------------------------------
# Minimal valid schema fixture
# ---------------------------------------------------------------------------
_MINIMAL_SCHEMA = {
    "queryType": {"name": "Query"},
    "mutationType": None,
    "subscriptionType": None,
    "directives": [],
    "types": [
        {
            "kind": "OBJECT",
            "name": "Query",
            "fields": [
                {
                    "name": "ping",
                    "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                    "isDeprecated": False,
                }
            ],
        }
    ],
}

_MINIMAL_ENVELOPE = {"data": {"__schema": _MINIMAL_SCHEMA}}


def _write(directory: str, name: str, content: str) -> str:
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


# ---------------------------------------------------------------------------
# load_introspection edge cases
# ---------------------------------------------------------------------------

class TestLoadIntrospection(unittest.TestCase):

    def test_missing_file_raises_file_not_found(self):
        with self.assertRaises(FileNotFoundError) as ctx:
            load_introspection("/no/such/path/x.json")
        self.assertIn("not found", str(ctx.exception).lower())

    def test_empty_file_raises_value_error(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write(td, "empty.json", "")
            with self.assertRaises(ValueError) as ctx:
                load_introspection(path)
            self.assertIn("empty", str(ctx.exception).lower())

    def test_whitespace_only_file_raises_value_error(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write(td, "ws.json", "   \n\t\n")
            with self.assertRaises(ValueError) as ctx:
                load_introspection(path)
            self.assertIn("whitespace", str(ctx.exception).lower())

    def test_invalid_json_raises_json_decode_error(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write(td, "bad.json", "{not valid json")
            with self.assertRaises(json.JSONDecodeError):
                load_introspection(path)

    def test_json_array_raises_value_error(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write(td, "arr.json", json.dumps([1, 2, 3]))
            with self.assertRaises(ValueError) as ctx:
                load_introspection(path)
            self.assertIn("JSON object", str(ctx.exception))

    def test_valid_envelope_loads_correctly(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write(td, "ok.json", json.dumps(_MINIMAL_ENVELOPE))
            schema = load_introspection(path)
            self.assertEqual(schema["queryType"]["name"], "Query")

    def test_bare_schema_object_loads_correctly(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write(td, "bare.json", json.dumps(_MINIMAL_SCHEMA))
            schema = load_introspection(path)
            self.assertEqual(schema["queryType"]["name"], "Query")


# ---------------------------------------------------------------------------
# _extract_schema edge cases
# ---------------------------------------------------------------------------

class TestExtractSchema(unittest.TestCase):

    def test_non_dict_raises(self):
        with self.assertRaises(ValueError) as ctx:
            _extract_schema([1, 2, 3])
        self.assertIn("JSON object", str(ctx.exception))

    def test_schema_key_non_dict_raises(self):
        with self.assertRaises(ValueError) as ctx:
            _extract_schema({"__schema": "oops"})
        self.assertIn("JSON object", str(ctx.exception))

    def test_data_schema_non_dict_raises(self):
        with self.assertRaises(ValueError) as ctx:
            _extract_schema({"data": {"__schema": 42}})
        self.assertIn("JSON object", str(ctx.exception))

    def test_no_schema_key_raises(self):
        with self.assertRaises(ValueError) as ctx:
            _extract_schema({"foo": "bar"})
        self.assertIn("Could not locate", str(ctx.exception))

    def test_explicit_schema_key(self):
        result = _extract_schema({"__schema": _MINIMAL_SCHEMA})
        self.assertEqual(result["queryType"]["name"], "Query")


# ---------------------------------------------------------------------------
# analyze_introspection validation
# ---------------------------------------------------------------------------

class TestAnalyzeValidation(unittest.TestCase):

    def test_non_dict_schema_raises_type_error(self):
        with self.assertRaises(TypeError) as ctx:
            analyze_introspection("not a dict")
        self.assertIn("dict", str(ctx.exception))

    def test_depth_threshold_zero_raises(self):
        with self.assertRaises(ValueError) as ctx:
            analyze_introspection(_MINIMAL_SCHEMA, depth_threshold=0)
        self.assertIn("depth_threshold", str(ctx.exception))

    def test_depth_threshold_negative_raises(self):
        with self.assertRaises(ValueError) as ctx:
            analyze_introspection(_MINIMAL_SCHEMA, depth_threshold=-5)
        self.assertIn("depth_threshold", str(ctx.exception))

    def test_depth_threshold_bool_raises(self):
        # bool is a subclass of int in Python; we explicitly reject it
        with self.assertRaises(TypeError) as ctx:
            analyze_introspection(_MINIMAL_SCHEMA, depth_threshold=True)
        self.assertIn("depth_threshold", str(ctx.exception))

    def test_depth_threshold_float_raises(self):
        with self.assertRaises(TypeError) as ctx:
            analyze_introspection(_MINIMAL_SCHEMA, depth_threshold=4.0)
        self.assertIn("depth_threshold", str(ctx.exception))

    def test_empty_tool_string_raises(self):
        with self.assertRaises(ValueError) as ctx:
            analyze_introspection(_MINIMAL_SCHEMA, tool="   ")
        self.assertIn("tool", str(ctx.exception))

    def test_empty_version_string_raises(self):
        with self.assertRaises(ValueError) as ctx:
            analyze_introspection(_MINIMAL_SCHEMA, version="")
        self.assertIn("version", str(ctx.exception))

    def test_empty_types_list(self):
        """Schema with no types should not crash; produces minimal findings."""
        empty_schema = {
            "queryType": None,
            "mutationType": None,
            "subscriptionType": None,
            "directives": [],
            "types": [],
        }
        report = analyze_introspection(empty_schema)
        # Must complete without error; introspection-enabled finding always present
        self.assertGreaterEqual(len(report.findings), 1)

    def test_missing_types_key(self):
        """Schema without a 'types' key should not crash."""
        schema = {"queryType": {"name": "Query"}, "directives": []}
        report = analyze_introspection(schema)
        self.assertIsNotNone(report)

    def test_depth_threshold_one_does_not_raise(self):
        """Minimum valid threshold (1) should work without error."""
        report = analyze_introspection(_MINIMAL_SCHEMA, depth_threshold=1)
        self.assertIsNotNone(report)


# ---------------------------------------------------------------------------
# CLI depth-threshold guard
# ---------------------------------------------------------------------------

class TestCLIDepthThresholdGuard(unittest.TestCase):

    def test_zero_depth_threshold_returns_2(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write(td, "ok.json", json.dumps(_MINIMAL_ENVELOPE))
            rc = main(["analyze", path, "--depth-threshold", "0"])
        self.assertEqual(rc, 2)

    def test_negative_depth_threshold_returns_2(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write(td, "ok.json", json.dumps(_MINIMAL_ENVELOPE))
            rc = main(["analyze", path, "--depth-threshold", "-3"])
        self.assertEqual(rc, 2)


# ---------------------------------------------------------------------------
# Additional CLI edge cases
# ---------------------------------------------------------------------------

class TestCLIEdgeCases(unittest.TestCase):

    def test_malformed_json_returns_2(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write(td, "bad.json", "{bad json")
            rc = main(["analyze", path])
        self.assertEqual(rc, 2)

    def test_empty_file_returns_2(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write(td, "empty.json", "")
            rc = main(["analyze", path])
        self.assertEqual(rc, 2)

    def test_json_array_returns_2(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write(td, "arr.json", json.dumps([]))
            rc = main(["analyze", path])
        self.assertEqual(rc, 2)

    def test_no_findings_schema_clean_exit(self):
        """Schema with no CRITICAL findings returns 0 when --fail-on CRITICAL."""
        # Minimal schema with no sensitive fields, no mutations, no depth issues
        clean_schema = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": None,
                    "subscriptionType": None,
                    "directives": [{"name": "auth"}],
                    "types": [
                        {
                            "kind": "OBJECT",
                            "name": "Query",
                            "fields": [
                                {
                                    "name": "ping",
                                    "type": {
                                        "kind": "SCALAR",
                                        "name": "String",
                                        "ofType": None,
                                    },
                                    "isDeprecated": False,
                                }
                            ],
                        }
                    ],
                }
            }
        }
        with tempfile.TemporaryDirectory() as td:
            path = _write(td, "clean.json", json.dumps(clean_schema))
            # With --fail-on CRITICAL and no CRITICAL findings, exit should be 0
            rc = main(["analyze", path, "--fail-on", "CRITICAL"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
