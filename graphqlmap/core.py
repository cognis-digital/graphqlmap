"""Core analysis engine for GRAPHQLMAP.

Consumes a standard GraphQL introspection JSON document (the result of the
`__schema` introspection query) and produces structured findings about the
schema's attack surface: sensitive/risky fields, excessive query depth,
mutation exposure, deprecated fields, and authorization-related signals.

Standard library only.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {
            "INFO": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }[self.value]


# Patterns that frequently indicate sensitive data or dangerous operations.
SENSITIVE_FIELD_PATTERNS: List[Tuple[str, Severity, str]] = [
    (r"(?i)password|passwd|pwd", Severity.CRITICAL, "Password / credential field exposed in schema"),
    (r"(?i)secret|api[_-]?key|access[_-]?token|refresh[_-]?token|private[_-]?key",
     Severity.CRITICAL, "Secret / token field exposed in schema"),
    (r"(?i)ssn|social[_-]?security|national[_-]?id|passport", Severity.HIGH, "Government identifier field"),
    (r"(?i)credit[_-]?card|card[_-]?number|cvv|iban|routing[_-]?number", Severity.HIGH, "Financial PII field"),
    (r"(?i)mfa|otp|two[_-]?factor|2fa|seed[_-]?phrase|mnemonic", Severity.HIGH, "Authentication secret field"),
    (r"(?i)session[_-]?id|cookie|csrf", Severity.MEDIUM, "Session/CSRF artifact field"),
    (r"(?i)is[_-]?admin|isadmin|role|permission|privilege|scope", Severity.MEDIUM, "Authorization attribute field"),
    (r"(?i)email|phone|address|dob|date[_-]?of[_-]?birth", Severity.LOW, "Personal contact PII field"),
    (r"(?i)internal|debug|_raw|backdoor", Severity.MEDIUM, "Internal/debug field that may leak data"),
]

# Mutation name patterns that are dangerous if unauthenticated.
DANGEROUS_MUTATION_PATTERNS: List[Tuple[str, str]] = [
    (r"(?i)delete|drop|purge|wipe|destroy", "Destructive mutation"),
    (r"(?i)create.*user|register|signup", "Account-creation mutation"),
    (r"(?i)update.*role|grant|elevate|promote|setadmin|impersonate", "Privilege-changing mutation"),
    (r"(?i)reset.*password|change.*password|set.*password", "Credential-changing mutation"),
    (r"(?i)exec|eval|run.*command|shell", "Command-execution-shaped mutation"),
]

# Default heuristic threshold for excessive nesting depth.
DEFAULT_DEPTH_THRESHOLD = 8


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    location: str
    detail: str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class AnalysisReport:
    tool: str
    version: str
    findings: List[Finding] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)

    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def severity_counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def has_findings(self, min_severity: Severity = Severity.LOW) -> bool:
        return any(f.severity.rank >= min_severity.rank for f in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "version": self.version,
            "stats": self.stats,
            "severity_counts": self.severity_counts(),
            "max_severity": self.max_severity.value if self.max_severity else None,
            "findings": [f.to_dict() for f in self.findings],
        }


def load_introspection(path: str) -> Dict[str, Any]:
    """Load an introspection JSON file and return the __schema object."""
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    return _extract_schema(doc)


def _extract_schema(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Tolerate the common envelopes: {data:{__schema}}, {__schema}, or schema itself."""
    if not isinstance(doc, dict):
        raise ValueError("Introspection document must be a JSON object")
    if "data" in doc and isinstance(doc["data"], dict) and "__schema" in doc["data"]:
        return doc["data"]["__schema"]
    if "__schema" in doc:
        return doc["__schema"]
    if "types" in doc and "queryType" in doc:
        return doc
    raise ValueError("Could not locate a __schema object in introspection document")


def _named_type(type_ref: Optional[Dict[str, Any]]) -> Optional[str]:
    """Unwrap NON_NULL / LIST wrappers to find the underlying named type."""
    while isinstance(type_ref, dict):
        if type_ref.get("name"):
            return type_ref["name"]
        type_ref = type_ref.get("ofType")
    return None


def _index_types(schema: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {t["name"]: t for t in schema.get("types", []) if isinstance(t, dict) and t.get("name")}


def _root_type_name(schema: Dict[str, Any], key: str) -> Optional[str]:
    ref = schema.get(key)
    if isinstance(ref, dict):
        return ref.get("name")
    return None


def _compute_max_depth(type_name: str, types: Dict[str, Dict[str, Any]],
                       cap: int = 25) -> int:
    """Compute longest non-cyclic object-traversal depth from a root type.

    Uses DFS with a visited-on-path set to avoid infinite loops on recursive
    schemas; depth is capped so pathological schemas terminate.
    """

    def walk(name: Optional[str], on_path: set, depth: int) -> int:
        if name is None or depth >= cap:
            return depth
        t = types.get(name)
        if not t or t.get("kind") not in ("OBJECT", "INTERFACE"):
            return depth
        if name in on_path:
            return depth
        fields = t.get("fields") or []
        if not fields:
            return depth
        best = depth
        on_path = on_path | {name}
        for f in fields:
            child = _named_type(f.get("type"))
            best = max(best, walk(child, on_path, depth + 1))
        return best

    return walk(type_name, set(), 0)


def analyze_introspection(schema: Dict[str, Any],
                          depth_threshold: int = DEFAULT_DEPTH_THRESHOLD,
                          tool: str = "graphqlmap",
                          version: str = "1.0.0") -> AnalysisReport:
    """Run all heuristic checks against an introspection __schema object."""
    types = _index_types(schema)
    report = AnalysisReport(tool=tool, version=version)

    query_root = _root_type_name(schema, "queryType")
    mutation_root = _root_type_name(schema, "mutationType")
    subscription_root = _root_type_name(schema, "subscriptionType")

    # ---- stats ----
    user_types = [n for n, t in types.items()
                  if not n.startswith("__") and t.get("kind") in ("OBJECT", "INTERFACE", "INPUT_OBJECT")]
    total_fields = 0
    for t in types.values():
        if isinstance(t.get("fields"), list):
            total_fields += len(t["fields"])

    max_depth = _compute_max_depth(query_root, types) if query_root else 0
    report.stats = {
        "query_type": query_root,
        "mutation_type": mutation_root,
        "subscription_type": subscription_root,
        "total_types": len(types),
        "user_types": len(user_types),
        "total_fields": total_fields,
        "max_query_depth": max_depth,
    }

    fid = _id_gen()

    # ---- Check 1: introspection enabled at all ----
    report.findings.append(Finding(
        id=fid(),
        title="Introspection is enabled",
        severity=Severity.LOW,
        location="__schema",
        detail=("The endpoint returned a full introspection schema. In production this "
                "discloses the entire API surface to any client."),
        recommendation="Disable introspection in production (e.g. NoSchemaIntrospectionCustomRule) "
                       "or restrict it to authenticated internal roles.",
    ))

    # ---- Check 2: sensitive fields ----
    for type_name, t in types.items():
        if type_name.startswith("__"):
            continue
        for fld in (t.get("fields") or []):
            fname = fld.get("name", "")
            for pattern, sev, label in SENSITIVE_FIELD_PATTERNS:
                if re.search(pattern, fname):
                    report.findings.append(Finding(
                        id=fid(),
                        title=f"Sensitive field exposed: {type_name}.{fname}",
                        severity=sev,
                        location=f"{type_name}.{fname}",
                        detail=f"{label}. Returned type: {_named_type(fld.get('type')) or 'unknown'}.",
                        recommendation="Confirm this field requires authorization and is not "
                                       "queryable by unauthenticated or low-privilege roles. "
                                       "Remove from schema if it should never be client-readable.",
                    ))
                    break  # one finding per field

    # ---- Check 3: dangerous mutations ----
    if mutation_root and mutation_root in types:
        for fld in (types[mutation_root].get("fields") or []):
            mname = fld.get("name", "")
            for pattern, label in DANGEROUS_MUTATION_PATTERNS:
                if re.search(pattern, mname):
                    report.findings.append(Finding(
                        id=fid(),
                        title=f"High-impact mutation: {mname}",
                        severity=Severity.HIGH,
                        location=f"{mutation_root}.{mname}",
                        detail=f"{label}. Mutations of this shape cause state change and are "
                               f"prime targets for broken-access-control abuse.",
                        recommendation="Verify server-side authorization on this mutation and add "
                                       "rate limiting / audit logging.",
                    ))
                    break

    # ---- Check 4: excessive depth (DoS surface) ----
    if max_depth >= depth_threshold:
        report.findings.append(Finding(
            id=fid(),
            title=f"Excessive query nesting depth ({max_depth})",
            severity=Severity.MEDIUM,
            location=query_root or "Query",
            detail=(f"The schema permits object traversal at least {max_depth} levels deep "
                    f"(threshold {depth_threshold}). Deeply nested queries enable "
                    f"denial-of-service amplification."),
            recommendation="Enforce a query-depth limit and query-cost/complexity analysis "
                           "at the gateway.",
        ))

    # ---- Check 5: deprecated fields still queryable ----
    deprecated = []
    for type_name, t in types.items():
        if type_name.startswith("__"):
            continue
        for fld in (t.get("fields") or []):
            if fld.get("isDeprecated"):
                deprecated.append(f"{type_name}.{fld.get('name')}")
    if deprecated:
        sample = ", ".join(deprecated[:8]) + (" ..." if len(deprecated) > 8 else "")
        report.findings.append(Finding(
            id=fid(),
            title=f"Deprecated fields still exposed ({len(deprecated)})",
            severity=Severity.INFO,
            location="schema",
            detail=f"Deprecated fields remain queryable: {sample}",
            recommendation="Track removal of deprecated fields; legacy fields often miss "
                           "current authorization checks.",
        ))

    # ---- Check 6: missing/weak authz signal ----
    # Heuristic: a sensitive type with NO directives and a non-null entry point.
    if not _schema_has_directives(schema, ("auth", "requireAuth", "hasRole", "authz", "isAuthenticated")):
        report.findings.append(Finding(
            id=fid(),
            title="No authorization directives detected in schema",
            severity=Severity.MEDIUM,
            location="__schema.directives",
            detail=("The schema declares no recognizable authorization directive "
                    "(@auth/@hasRole/@requireAuth/etc). Authz may be enforced elsewhere, "
                    "but its absence here is worth confirming."),
            recommendation="Confirm authorization is enforced in resolvers/middleware. "
                           "Schema-level authz directives make the policy auditable.",
        ))

    report.findings.sort(key=lambda f: (-f.severity.rank, f.location))
    return report


def _schema_has_directives(schema: Dict[str, Any], names: Tuple[str, ...]) -> bool:
    lowered = {n.lower() for n in names}
    for d in (schema.get("directives") or []):
        if isinstance(d, dict) and (d.get("name") or "").lower() in lowered:
            return True
    return False


def _id_gen():
    counter = {"n": 0}

    def nxt() -> str:
        counter["n"] += 1
        return f"GQL-{counter['n']:03d}"

    return nxt
