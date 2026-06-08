"""GRAPHQLMAP - GraphQL introspection attack-surface analyzer.

Defensive forensics/analysis tool: parses a GraphQL introspection result
(that you own / are authorized to assess) and reports risky fields,
schema depth, and authorization gaps.
"""

from .core import (
    Finding,
    Severity,
    AnalysisReport,
    analyze_introspection,
    load_introspection,
)

TOOL_NAME = "graphqlmap"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "Severity",
    "AnalysisReport",
    "analyze_introspection",
    "load_introspection",
]
