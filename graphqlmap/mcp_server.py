"""GRAPHQLMAP MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from graphqlmap.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-graphqlmap[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-graphqlmap[mcp]'")
        return 1
    app = FastMCP("graphqlmap")

    @app.tool()
    def graphqlmap_scan(target: str) -> str:
        """Analyze GraphQL introspection for risky fields, depth, and authz gaps. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
