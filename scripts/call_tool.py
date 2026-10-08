"""Call the MCP server like a real MCP client (local smoke test, no Inspector needed).

  uv run python scripts/call_tool.py                              # list tools
  uv run python scripts/call_tool.py get_overview                 # call a tool (args = JSON)
  uv run python scripts/call_tool.py search_logs '{"start": "2026-10-05T08:00:00Z", "levels": ["ERROR"]}'
  MCP_TOKEN=<api key | JWT> uv run python scripts/call_tool.py get_overview
  MCP_URL=http://localhost:9000/mcp uv run python scripts/call_tool.py

Exit code 1 if the tool returns isError (handy for agent coding checks).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client


async def main(argv: list[str]) -> int:
    url = os.environ.get("MCP_URL", "http://localhost:8080/mcp")
    token = os.environ.get("MCP_TOKEN")
    headers = {"Authorization": f"Bearer {token}"} if token else None
    async with create_mcp_http_client(headers=headers) as http:
        async with streamable_http_client(url, http_client=http) as (r, w, _):
            async with ClientSession(r, w) as s:
                await s.initialize()
                if not argv:
                    for t in (await s.list_tools()).tools:
                        print(f"{t.name}: {(t.description or '').strip().splitlines()[0]}")
                    return 0
                args = json.loads(argv[1]) if len(argv) > 1 else {}
                res = await s.call_tool(argv[0], args)
                if res.structuredContent is not None and not res.isError:
                    print(json.dumps(res.structuredContent, ensure_ascii=False, indent=2))
                else:
                    for c in res.content:
                        print(getattr(c, "text", c))
                return 1 if res.isError else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1:])))
