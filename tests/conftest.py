"""Test harness: real server (uvicorn, in a thread) + real MCP client over streamable HTTP.

Adding a tool? Write its tests in tests/test_tools.py with these fixtures — no harness code needed:
  local_server  — MCP_AUTH_MODE=none (no Elasticsearch configured)
  jwt_server    — MCP_AUTH_MODE=jwt; mint tokens with make_token("alice", scope="…")
  api_key_server— MCP_AUTH_MODE=api_key; token = API_KEY (granted the scopes in MCP_REQUIRED_SCOPES)
  start_server(env, backend=handler) — any env + a fake Elasticsearch (see es_handler)
  es_handler(reply) — build that fake: reply(path, body) -> JSON dict (or httpx.Response); also records calls
  call(base, token, tool, args) / list_tools(base, token)
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import socket
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

import httpx
import jwt
import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client
from mcp.types import CallToolResult, Tool

ROOT = Path(__file__).resolve().parents[1]
API_KEY = "test-key-123"
RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ISSUER, AUDIENCE = "https://idp.test", "mcp-api"
ALL_SCOPES = "logs.read metrics.read"

LOCAL_ENV = {"MCP_APP_ENV": "local", "MCP_AUTH_MODE": "none"}
API_KEY_ENV = {
    "MCP_APP_ENV": "dev",
    "MCP_AUTH_MODE": "api_key",
    "MCP_API_KEY_SHA256": f'["{hashlib.sha256(API_KEY.encode()).hexdigest()}"]',
    "MCP_REQUIRED_SCOPES": '["logs.read","metrics.read"]',  # api_key mode: scopes granted to the key
}
JWT_ENV = {
    "MCP_APP_ENV": "dev",
    "MCP_AUTH_MODE": "jwt",
    "MCP_ISSUER": ISSUER,
    "MCP_JWKS_URL": f"{ISSUER}/jwks",
    "MCP_AUDIENCE": AUDIENCE,
}


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch, tmp_path):
    """Run in an empty dir (no developer .env) with no MCP_* vars from the shell."""
    monkeypatch.chdir(tmp_path)
    for k in list(os.environ):
        if k.startswith("MCP_"):
            monkeypatch.delenv(k)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def es_handler(reply: Callable[[str, dict], dict | httpx.Response]):
    """Fake Elasticsearch for `start_server(env, backend=handler)`.

    `reply(path, body)` returns the JSON to answer with (or a ready httpx.Response; it may also raise an
    httpx error to simulate a timeout). Returns `(handler, calls)`; `calls` records every request.
    """
    calls: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        calls.append({"path": request.url.path, "body": body})
        out = reply(request.url.path, body)
        return out if isinstance(out, httpx.Response) else httpx.Response(200, json=out)

    return handler, calls


@pytest.fixture
def start_server(monkeypatch) -> Callable[..., str]:
    servers: list[uvicorn.Server] = []

    def _start(
        env: dict[str, str], backend: Callable[[httpx.Request], httpx.Response] | None = None
    ):
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        for mod in ("settings", "auth", "backend", "server"):
            sys.modules.pop(mod, None)
        server = importlib.import_module("server")
        if (
            env.get("MCP_AUTH_MODE") == "jwt"
        ):  # verify test tokens with RSA_KEY instead of a real JWKS
            import auth

            class _Key:
                key = RSA_KEY.public_key()

            class _Jwks:
                def get_signing_key_from_jwt(self, token):
                    return _Key()

            monkeypatch.setattr(auth, "_jwks", lambda url: _Jwks())
        if backend is not None:
            from backend import Backend

            server.backend = Backend(
                "http://backend.test", 2, transport=httpx.MockTransport(backend)
            )
        port = free_port()
        srv = uvicorn.Server(
            uvicorn.Config(
                server.mcp.streamable_http_app(), host="127.0.0.1", port=port, log_level="warning"
            )
        )
        threading.Thread(target=srv.run, daemon=True).start()
        for _ in range(100):
            if srv.started:
                break
            time.sleep(0.05)
        servers.append(srv)
        return f"http://127.0.0.1:{port}"

    yield _start
    for srv in servers:
        srv.should_exit = True


@pytest.fixture
def local_server(start_server) -> str:
    return start_server(LOCAL_ENV)


@pytest.fixture
def api_key_server(start_server) -> str:
    return start_server(API_KEY_ENV)


@pytest.fixture
def jwt_server(start_server) -> str:
    return start_server(JWT_ENV)


def make_token(sub: str, scope: str = ALL_SCOPES, **override) -> str:
    now = int(time.time())
    claims = {
        "sub": sub,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 300,
        "scope": scope,
        "azp": "agent-client",
        **override,
    }
    return jwt.encode(claims, RSA_KEY, algorithm="RS256")


async def _session(base: str, token: str | None, fn):
    headers = {"Authorization": f"Bearer {token}"} if token else None
    async with create_mcp_http_client(headers=headers) as http:
        async with streamable_http_client(f"{base}/mcp", http_client=http) as (r, w, _):
            async with ClientSession(r, w) as s:
                await s.initialize()
                return await fn(s)


async def call(base: str, token: str | None, tool: str, args: dict | None = None) -> CallToolResult:
    return await _session(base, token, lambda s: s.call_tool(tool, args or {}))


async def list_tools(base: str, token: str | None = None) -> list[Tool]:
    async def _list(s):
        return (await s.list_tools()).tools

    return await _session(base, token, _list)


def text(res: CallToolResult) -> str:
    return " ".join(getattr(c, "text", "") for c in res.content)
