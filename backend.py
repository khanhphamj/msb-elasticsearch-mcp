"""Client for the Elasticsearch cluster the tools read from.

Pattern: one shared httpx.AsyncClient (connection pool), explicit timeout, every failure mapped to a short
ToolError the LLM can act on — never leak stack traces, internal URLs or raw upstream bodies.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
from mcp.server.fastmcp.exceptions import ToolError

log = logging.getLogger(__name__)


class Backend:
    def __init__(
        self,
        base_url: str,
        timeout_s: float,
        token: str = "",
        transport: httpx.AsyncBaseTransport | None = None,  # tests inject httpx.MockTransport
        *,
        username: str = "",
        password: str = "",
    ):
        headers = {"Authorization": f"Bearer {token}"} if token else None
        auth = httpx.BasicAuth(username, password) if username and password else None
        self._client = (
            httpx.AsyncClient(
                base_url=base_url,
                timeout=timeout_s,
                headers=headers,
                auth=auth,
                transport=transport,
            )
            if base_url
            else None
        )

    async def search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        """`POST /<index>/_search` → parsed JSON object."""
        if self._client is None:
            raise ToolError("Elasticsearch is not configured (MCP_BACKEND_URL is empty).")
        path = f"/{index}/_search"
        try:
            r = await self._client.post(path, json=body)
        except httpx.TimeoutException:
            log.warning("backend timeout path=%s", path)
            raise ToolError(
                "Elasticsearch timed out. Try a narrower time range or try again later."
            ) from None
        except httpx.HTTPError as e:
            log.warning("backend unreachable path=%s err=%s", path, type(e).__name__)
            raise ToolError("Elasticsearch is unreachable. Try again later.") from None

        status = r.status_code
        if status == 404:
            log.error("backend index not found path=%s", path)
            raise ToolError(
                "The log/metric index was not found. Ask the administrator to check the configuration."
            )
        if status in (401, 403):
            log.error("backend rejected our credential status=%s path=%s", status, path)
            raise ToolError("This MCP server is not allowed to access that data.")
        if status == 400:
            log.warning("backend rejected the query path=%s type=%s", path, _error_type(r))
            raise ToolError(
                "Elasticsearch rejected the query. Narrow the time range or reduce limit/offset."
            )
        if status == 429:
            log.warning("backend rate limited path=%s", path)
            raise ToolError("Elasticsearch is overloaded. Try again in a moment.")
        if status >= 400:
            log.error("backend error status=%s path=%s type=%s", status, path, _error_type(r))
            raise ToolError(f"Elasticsearch error ({status}). Try again later.")

        try:
            data = r.json()
        except ValueError:
            data = None
        if not isinstance(data, dict):
            log.error("backend returned a non-JSON-object body path=%s", path)
            raise ToolError("Elasticsearch returned an unexpected response. Try again later.")
        return data


def _error_type(r: httpx.Response) -> str:
    """Elasticsearch's `error.type` for the server log only (never shown to the LLM)."""
    try:
        err = r.json().get("error")
        return str(err.get("type")) if isinstance(err, dict) else "unknown"
    except (ValueError, AttributeError):
        return "unknown"
