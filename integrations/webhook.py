#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request

def main() -> int:
    ap = argparse.ArgumentParser(
        description="POST JSON findings from stdin to a webhook URL."
    )
    ap.add_argument("--url", required=True, help="Destination URL (http/https)")
    ap.add_argument("--header", action="append", default=[],
                    help="Extra request header in 'Key: Value' form (repeatable)")
    args = ap.parse_args()

    # Validate URL scheme before attempting network I/O.
    if not args.url.startswith(("http://", "https://")):
        print("error: --url must start with http:// or https://", file=sys.stderr)
        return 2

    # Validate header format up front so we fail early with a clear message.
    for h in args.header:
        if ":" not in h:
            print(
                f"error: --header {h!r} is not in 'Key: Value' format",
                file=sys.stderr,
            )
            return 2

    payload = sys.stdin.read().encode("utf-8")
    if not payload.strip():
        print(
            "error: no input received on stdin"
            " - pipe JSON findings into this command",
            file=sys.stderr,
        )
        return 2

    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        k, _, v = h.partition(":")
        req.add_header(k.strip(), v.strip())
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except urllib.error.HTTPError as e:
        print(f"webhook error: HTTP {e.code} {e.reason}", file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        print(f"webhook error: {e.reason}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"webhook error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
